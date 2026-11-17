"""Pruebas de la tríada CID: confidencialidad, integridad y disponibilidad."""
import hashlib
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main
import security
from audit import audit_logger
from conftest import AUTH
from core import live_capture
from core.packet_store import process_frame
from core.pcap_reader import read_capture

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "ejemplo.pcap"


@pytest.fixture()
def client():
    with TestClient(main.app, headers=AUTH) as c:
        c.post("/api/reset")
        yield c


@pytest.fixture()
def anon():
    with TestClient(main.app) as c:
        yield c


# ======================= CONFIDENCIALIDAD =======================

def test_api_exige_token(anon):
    assert anon.get("/api/statistics").status_code == 401
    assert anon.get("/api/statistics", headers={"X-NetCheck-Token": "adivinado"}).status_code == 401
    assert anon.get("/api/packets/live").status_code == 401
    assert anon.get("/api/statistics", headers=AUTH).status_code == 200


def test_host_desconocido_se_rechaza_dns_rebinding(client):
    assert client.get("/api/statistics", headers={"Host": "atacante.com"}).status_code == 400
    assert client.get("/", headers={"Host": "atacante.com:8000"}).status_code == 400
    assert client.get("/api/statistics", headers={"Host": "localhost:8000"}).status_code == 200


def test_peticiones_de_otro_sitio_se_bloquean_csrf(client):
    assert client.post("/api/capture/stop", headers={"Origin": "http://atacante.com"}).status_code == 403
    assert client.post("/api/reset", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/api/reset", headers={"Origin": "http://testserver"}).status_code == 200


def test_cabeceras_de_seguridad(client):
    for path in ("/", "/api/statistics"):
        h = client.get(path).headers
        assert "script-src 'self'" in h["content-security-policy"]
        assert "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer" and h["cache-control"] == "no-store"


def test_panel_recibe_el_token_y_no_tiene_scripts_en_linea(client):
    html = client.get("/").text
    assert 'content="token-de-prueba"' in html and "{{NETCHECK_TOKEN}}" not in html
    assert "<script>" not in html and '<script src="/static/app.js">' in html


def _frame_con_payload():
    payload = b"SECRETO-USUARIO:clave123" * 4
    udp = struct.pack("!HHHH", 5000, 53, 8 + len(payload), 0) + payload
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                               bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])))
    from core.packet_inspector import ipv4_checksum
    ip[10:12] = ipv4_checksum(bytes(ip)).to_bytes(2, "big")
    return b"\x11" * 6 + b"\x22" * 6 + b"\x08\x00" + bytes(ip) + udp, payload


def test_payload_oculto_en_detalle_y_exportacion(client):
    frame, payload = _frame_con_payload()
    store = main.stores["live"]
    store.clear()
    store.add(process_frame(1, 1.0, 1, frame))
    oculto = client.get("/api/packets/live/1").json()
    assert oculto["payload_hidden"] and oculto["hex"] == frame[:42].hex()
    assert payload.hex() not in oculto["hex"]
    assert payload.hex() in client.get("/api/packets/live/1?payload=true").json()["hex"]

    frames, _ = read_capture(client.get("/api/packets/live/export").content)
    assert frames[0]["data"] == frame[:42] and frames[0]["orig_len"] == len(frame)
    completo, _ = read_capture(client.get("/api/packets/live/export?payload=true").content)
    assert completo[0]["data"] == frame


def test_el_log_no_guarda_payload(client):
    client.post("/api/analyze-sample")
    texto = audit_logger.LOG_FILE.read_text(encoding="utf-8")
    assert "NETCHECK" not in texto  # los paquetes de ejemplo llevan ese texto como contenido


# ======================= INTEGRIDAD =======================

def test_cada_linea_del_log_va_firmada_y_la_cadena_verifica(client):
    client.post("/api/simulate", json=dict(interface="eth0", ip="10.1.1.1", headerLength=20,
                                           checksum="invalid", issue="none", action="DROP"))
    ultima = audit_logger.LOG_FILE.read_text(encoding="utf-8").strip().splitlines()[-1]
    assert " | MAC=" in ultima and len(ultima.rsplit("MAC=", 1)[1]) == 64
    r = client.get("/api/audit/verify").json()
    assert r["ok"] and r["signed"] >= 1


@pytest.mark.parametrize("ataque", ["modificar", "borrar_intermedia", "insertar_sin_firma", "borrar_final", "reordenar"])
def test_manipular_el_log_se_detecta(client, ataque):
    for i in range(4):
        audit_logger.log_operator("PRUEBA", f"evento {i}")
    original = audit_logger.LOG_FILE.read_text(encoding="utf-8")
    lines = original.splitlines(keepends=True)
    try:
        if ataque == "modificar":
            lines[-2] = lines[-2].replace("evento 2", "evento X")
        elif ataque == "borrar_intermedia":
            del lines[-3]
        elif ataque == "insertar_sin_firma":
            lines.insert(-1, "2026-01-01 00:00:00 UTC | WARNING | IP_SRC=1.2.3.4 | IP_DST=5.6.7.8 | ACTION=DROP | REASON=falso\n")
        elif ataque == "borrar_final":
            del lines[-1]
        elif ataque == "reordenar":
            lines[-2], lines[-3] = lines[-3], lines[-2]
        audit_logger.LOG_FILE.write_text("".join(lines), encoding="utf-8")
        assert audit_logger.verify_log()["ok"] is False
    finally:
        audit_logger.LOG_FILE.write_text(original, encoding="utf-8")
    assert audit_logger.verify_log()["ok"]


def test_la_firma_depende_de_la_clave():
    assert audit_logger._mac("0" * 64, "linea") != __import__("hmac").new(
        b"otra-clave", ("0" * 64 + "\nlinea").encode(), hashlib.sha256).hexdigest()


def test_acciones_del_operador_quedan_registradas(client):
    client.post("/api/alerts/ack")
    acciones = [a["action"] for a in client.get("/api/alerts").json()["alerts"]]
    assert "ALERTS_ACK" in acciones and "RESET" in acciones


def test_huellas_sha256_de_archivos(client):
    raw = SAMPLE.read_bytes()
    res = client.post("/api/analyze-pcap", content=raw, headers={"Content-Type": "application/octet-stream"})
    assert res.json()["sha256"] == hashlib.sha256(raw).hexdigest()
    exp = client.get("/api/packets/pcap/export")
    assert exp.headers["x-content-sha256"] == hashlib.sha256(exp.content).hexdigest()
    assert client.get("/api/security").json()["integrity"]["last_export"]["sha256"] == exp.headers["x-content-sha256"]


# ======================= DISPONIBILIDAD =======================

def test_limite_de_peticiones(client, monkeypatch):
    monkeypatch.setattr(security, "RATE_PER_SECOND", 0.0)
    monkeypatch.setitem(security._bucket, "tokens", 2.0)
    codes = [client.get("/api/statistics").status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and codes[2:] == [429, 429]
    monkeypatch.setitem(security._bucket, "tokens", security.RATE_BURST)


def test_un_solo_analisis_a_la_vez(client):
    assert main._analysis_lock.acquire(blocking=False)
    try:
        assert client.post("/api/analyze-sample").status_code == 429
    finally:
        main._analysis_lock.release()
    assert client.post("/api/analyze-sample").status_code == 200


def test_rotacion_del_log_mantiene_la_cadena(monkeypatch):
    handler = audit_logger._handler
    monkeypatch.setattr(handler, "maxBytes", 2000)
    for i in range(40):
        audit_logger.log_operator("PRUEBA", f"rotacion {i:03d} " + "x" * 40)
    assert (audit_logger.LOG_DIR / "netcheck.log.1").exists()
    r = audit_logger.verify_log()
    assert r["ok"] and len(r["files"]) > 1
    # tamaño acotado: nunca más de BACKUPS+1 archivos y el actual no supera el límite
    assert len(audit_logger._log_files()) <= audit_logger.BACKUPS + 1
    assert audit_logger.LOG_FILE.stat().st_size <= 2000 + 400
    for i in range(200):  # aunque sigan llegando eventos, no aparecen más archivos
        audit_logger.log_operator("PRUEBA", f"inundacion {i:03d} " + "x" * 40)
    assert len(audit_logger._log_files()) == audit_logger.BACKUPS + 1
    assert audit_logger.verify_log()["ok"]  # la cadena sigue verificable tras descartar lo más viejo


class _FakeLib:
    def pcap_stats(self, *a):
        return -1

    def pcap_close(self, *a):
        pass


def _cap_sin_driver():
    cap = live_capture.LiveCapture.__new__(live_capture.LiveCapture)
    cap.lib, cap.iface, cap.handle = _FakeLib(), "x", object()
    cap.stop_event = __import__("threading").Event()
    cap.reconnects, cap.error = 0, None
    cap.stats = {"received": 0, "dropped": 0, "if_dropped": 0}
    cap._stats_base = dict(cap.stats)
    return cap


def test_la_captura_se_reconecta_si_la_tarjeta_falla(monkeypatch):
    monkeypatch.setattr(live_capture, "RECONNECT_DELAY", 0)
    intentos = iter([live_capture.NpcapUnavailable("caida"), live_capture.NpcapUnavailable("caida"), "manejador"])

    def fake_open(lib, iface):
        r = next(intentos)
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(live_capture, "_open", fake_open)
    cap = _cap_sin_driver()
    assert cap._reconnect() and cap.reconnects == 3 and cap.handle == "manejador" and cap.error is None


def test_la_captura_se_rinde_tras_varios_intentos(monkeypatch):
    monkeypatch.setattr(live_capture, "RECONNECT_DELAY", 0)
    monkeypatch.setattr(live_capture, "_open", lambda *a: (_ for _ in ()).throw(live_capture.NpcapUnavailable("no")))
    cap = _cap_sin_driver()
    assert cap._reconnect() is False and cap.reconnects == live_capture.MAX_RECONNECTS


def test_estado_de_la_triada(client):
    s = client.get("/api/security").json()
    assert set(s) == {"confidentiality", "integrity", "availability"}
    assert s["confidentiality"]["token_required"] and not s["confidentiality"]["promiscuous"]
    assert s["integrity"]["log"]["ok"]
    assert s["availability"]["log_rotation"]["files"] == 6
