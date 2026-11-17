"""Pruebas del modo monitor en vivo, el disector y la exportación .pcapng."""
import struct
import time

import pytest
from fastapi.testclient import TestClient

import generar_ejemplo as gen
import main
from core import live_capture
from core.dissector import dissect
from core.packet_inspector import inspect_ipv4_packet, ipv4_checksum
from core.packet_store import PacketStore, process_frame
from core.pcap_reader import read_capture

LOCAL = "192.168.1.11"


def ip_packet(src=LOCAL, dst="8.8.8.8", proto=17, checksum=None, total=None, payload=b"\x00" * 8):
    body = payload
    hdr = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, total if total is not None else 20 + len(body),
                                1, 0x4000, 64, proto, 0, bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))))
    hdr[10:12] = (ipv4_checksum(bytes(hdr)) if checksum is None else checksum).to_bytes(2, "big")
    return bytes(hdr) + body


def eth(packet, ethertype=b"\x08\x00"):
    return b"\x11" * 6 + b"\x22" * 6 + ethertype + packet


# ---- Checksum offload (paquetes salientes capturados en el mismo equipo) ----

def test_saliente_con_checksum_cero_es_offload_y_no_falso_positivo():
    pkt = ip_packet(checksum=0)
    r = inspect_ipv4_packet(pkt, local_outgoing=True)
    assert r["status"] == "VALID" and r["details"]["checksum_offload"]


def test_offload_solo_tolera_exactamente_cero():
    assert inspect_ipv4_packet(ip_packet(checksum=0x1234), local_outgoing=True)["status"] == "INVALID"


def test_entrante_con_checksum_cero_si_es_anomalia():
    assert inspect_ipv4_packet(ip_packet(src="8.8.8.8", dst=LOCAL, checksum=0))["status"] == "INVALID"


def test_large_send_offload_longitud_cero():
    r = inspect_ipv4_packet(ip_packet(checksum=0, total=0), local_outgoing=True)
    assert r["status"] == "VALID" and r["details"]["length_offload"]


def test_process_frame_detecta_direccion_y_offload():
    local = frozenset({LOCAL})
    out = process_frame(1, 0.0, 1, eth(ip_packet(checksum=0)), local_ips=local)
    inc = process_frame(2, 0.0, 1, eth(ip_packet(src="8.8.8.8", dst=LOCAL, checksum=0)), local_ips=local)
    assert out["direction"] == "saliente" and out["action"] == "ALLOW"
    assert inc["direction"] == "entrante" and inc["action"] == "DROP"


# ---- Disector ----

def test_disector_marca_checksum_incorrecto_y_sus_bytes():
    frame = eth(ip_packet(checksum=0xDEAD))
    rec = process_frame(1, 0.0, 1, frame)
    d = dissect(1, frame, rec["ip"], rec["inspection"])
    assert [l["name"] for l in d["layers"]][:3] == ["Ethernet II", "IPv4", "UDP"]
    ck = next(f for f in d["layers"][1]["fields"] if f["name"] == "Checksum de cabecera")
    assert ck["state"] == "bad" and ck["offset"] == 24 and ck["length"] == 2
    assert d["hex"][48:52] == "dead"


def test_disector_tcp_flags_y_puertos():
    tcp = struct.pack("!HHIIBBHHH", 51000, 443, 1, 0, 5 << 4, 0x02, 64240, 0, 0)
    frame = eth(ip_packet(proto=6, payload=tcp))
    rec = process_frame(1, 0.0, 1, frame)
    assert rec["protocol"] == "TCP" and "443 (HTTPS)" in rec["info"] and "SYN" in rec["info"]


def test_ipv6_se_muestra_pero_no_se_inspecciona():
    v6 = bytes([0x60, 0, 0, 0, 0, 8, 17, 64]) + bytes(15) + b"\x01" + bytes(15) + b"\x02" + struct.pack("!HHHH", 5353, 5353, 8, 0)
    rec = process_frame(1, 0.0, 1, eth(v6, b"\x86\xdd"))
    assert rec["status"] == "SKIPPED" and rec["src"] == "::1" and rec["dst"] == "::2"


# ---- Búfer y exportación ----

def test_exportar_pcapng_y_releerlo_da_los_mismos_bytes():
    store = PacketStore(100)
    frames = [eth(ip_packet()), eth(ip_packet(checksum=0xBEEF)), eth(b"\x00" * 28, b"\x08\x06")]
    for i, f in enumerate(frames, 1):
        store.add(process_frame(i, 1_700_000_000 + i, 1, f))
    leidos, meta = read_capture(store.to_pcapng())
    assert meta["format"] == "pcapng" and [f["data"] for f in leidos] == frames
    assert store.counts == {"total": 3, "ipv4": 2, "valid": 1, "invalid": 1, "unverified": 0, "skipped": 1}


def test_bufer_circular_descarta_los_mas_viejos():
    store = PacketStore(3)
    for i in range(1, 6):
        store.add(process_frame(i, 0.0, 101, ip_packet()))
    assert [r["no"] for r in store.rows()] == [3, 4, 5] and store.get(1) is None


@pytest.mark.parametrize("kind,motivo", [("checksum", "Checksum"), ("ttl", "TTL"),
                                         ("version", "Versión"), ("length", "Longitud total")])
def test_paquetes_de_prueba_de_loopback(kind, motivo):
    frame = live_capture.build_loopback_probe(kind, 0)
    rec = process_frame(1, 0.0, 0, frame, local_ips=frozenset({"127.0.0.1"}))
    assert rec["action"] == "DROP" and motivo in rec["reason"]
    assert process_frame(1, 0.0, 0, live_capture.build_loopback_probe("ok", 0))["status"] == "VALID"


# ---- API con una captura falsa (no necesita Npcap) ----

class FakeCapture:
    def __init__(self, iface, on_frame):
        self.iface, self.on_frame, self.linktype = iface, on_frame, 1
        self.started_at, self.error, self.running, self.sent = time.time(), None, True, []
        self.reconnects, self.packet_errors = 0, 0
        self.stats = {"received": 0, "dropped": 0, "if_dropped": 0}

    def stop(self):
        self.running = False

    def send(self, frame):
        self.sent.append(frame)


@pytest.fixture()
def client(monkeypatch):
    ifaces = [{"id": "wifi", "description": "Wi-Fi de prueba", "ips": [LOCAL], "loopback": False,
               "wireless": True, "up": True, "connected": True},
              {"id": "lo", "description": "Loopback", "ips": ["127.0.0.1"], "loopback": True,
               "wireless": False, "up": True, "connected": True}]
    monkeypatch.setattr(live_capture, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(live_capture, "LiveCapture", FakeCapture)
    with TestClient(main.app, headers={"X-NetCheck-Token": "token-de-prueba"}) as c:
        c.post("/api/reset")
        yield c
        c.post("/api/capture/stop")


def test_api_captura_en_vivo_completa(client):
    assert client.post("/api/capture/start", json={"interface": "no-existe"}).status_code == 400
    assert client.post("/api/capture/start", json={"interface": "wifi"}).json()["running"]
    cap = main.live["capture"]
    cap.on_frame(time.time(), 1, eth(ip_packet(src="8.8.8.8", dst=LOCAL)), 42)       # entrante válido
    cap.on_frame(time.time(), 1, eth(ip_packet(checksum=0)), 42)                      # saliente offload
    cap.on_frame(time.time(), 1, eth(ip_packet(src="8.8.8.8", dst=LOCAL, checksum=7)), 42)  # anomalía

    rows = client.get("/api/packets/live").json()["rows"]
    assert [r["status"] for r in rows] == ["VALID", "VALID", "INVALID"]
    assert client.get("/api/packets/live?only=anomalies").json()["rows"][0]["no"] == 3
    detail = client.get("/api/packets/live/3").json()
    assert detail["layers"][1]["name"] == "IPv4" and detail["action"] == "DROP"
    assert any("[vivo #3 · monitor]" in a["reason"] for a in client.get("/api/alerts").json()["alerts"])
    assert client.get("/api/packets/live/export").content[:4] == b"\x0a\x0d\x0d\x0a"
    assert client.get("/api/capture/status").json()["counts"]["invalid"] == 1


def test_api_inyeccion_solo_en_loopback(client):
    client.post("/api/capture/start", json={"interface": "wifi"})
    assert client.post("/api/capture/probe", json={"kind": "ttl"}).status_code == 409
    client.post("/api/capture/start", json={"interface": "lo"})
    assert client.post("/api/capture/probe", json={"kind": "ttl"}).status_code == 200
    assert main.live["capture"].sent
    assert client.post("/api/capture/probe", json={"kind": "borrar"}).status_code == 422


def test_api_pcap_y_laboratorio_quedan_inspeccionables(client):
    client.post("/api/analyze-sample")
    assert client.get("/api/packets/pcap/4").json()["reason"] == "Checksum de cabecera incorrecto"
    res = client.post("/api/simulate", json=dict(interface="eth0", ip="10.0.0.5", headerLength=24,
                                                 checksum="valid", issue="none", action="DROP")).json()
    d = client.get(f"/api/packets/lab/{res['packet_no']}").json()
    assert any(f["name"] == "Opciones" for f in d["layers"][0]["fields"])
    assert client.get("/api/packets/otra/1").status_code == 422


# ---- Captura real (solo si el equipo tiene Npcap/libpcap) ----

@pytest.mark.skipif(not live_capture.backend_info()["available"], reason="Npcap/libpcap no instalado")
def test_captura_real_en_loopback_detecta_paquete_inyectado():
    lo = next((i for i in live_capture.list_interfaces() if i["loopback"]), None)
    if not lo:
        pytest.skip("Sin interfaz de loopback")
    store = PacketStore(1000)
    n = [0]

    def on_frame(ts, lt, data, orig):
        n[0] += 1
        store.add(process_frame(n[0], ts, lt, data, orig, frozenset(lo["ips"])))

    cap = live_capture.LiveCapture(lo["id"], on_frame)
    try:
        time.sleep(0.3)
        cap.send(live_capture.build_loopback_probe("checksum", cap.linktype))
        deadline = time.time() + 3
        while time.time() < deadline and not store.rows(only="anomalies"):
            time.sleep(0.1)
    finally:
        cap.stop()
    hits = [r for r in store.rows(only="anomalies") if r["dst_port"] == 9]
    assert hits and "Checksum" in hits[0]["reason"]
