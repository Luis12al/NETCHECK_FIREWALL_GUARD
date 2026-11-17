import pytest
from fastapi.testclient import TestClient

import generar_ejemplo as gen
import main

OCTETS = {"Content-Type": "application/octet-stream"}


@pytest.fixture()
def client():
    with TestClient(main.app, headers={"X-NetCheck-Token": "token-de-prueba"}) as c:
        c.post("/api/reset")
        yield c


def simular(client, **cambios):
    cuerpo = dict(interface="eth0", ip="192.168.1.10", headerLength=20,
                  checksum="valid", issue="none", action="DROP")
    cuerpo.update(cambios)
    return client.post("/api/simulate", json=cuerpo)


def test_simulacion_valida_y_con_error(client):
    ok = simular(client).json()
    assert ok["result"] == "VALID" and ok["action"] == "ALLOW"
    mal = simular(client, checksum="invalid").json()
    assert mal["result"] == "INVALID" and mal["action"] == "DROP"
    assert client.get("/api/statistics").json() == {"total": 2, "valid": 1, "dropped": 1, "pending": 1}


def test_conflicto_manual(client):
    assert simular(client, checksum="invalid", action="ALLOW").json()["manual_conflict"] is True


@pytest.mark.parametrize("cambios", [
    {"ip": "999.1.1.1"}, {"ip": "no-es-ip"}, {"headerLength": 22}, {"headerLength": 100},
    {"checksum": "x\nFALSO"}, {"issue": "otro"}, {"interface": "eth9"}, {"action": "BORRAR"},
])
def test_entradas_invalidas_dan_422(client, cambios):
    assert simular(client, **cambios).status_code == 422


def test_analizar_ejemplo_incluido(client):
    res = client.post("/api/analyze-sample")
    assert res.status_code == 200
    data = res.json()
    assert data["ipv4_analyzed"] == 11 and data["invalid"] == 6 and data["valid"] == 5
    assert client.get("/api/statistics").json()["total"] == 11
    alertas = client.get("/api/alerts").json()["alerts"]
    assert any("[ejemplo #4]" in a["reason"] for a in alertas)


def test_subir_pcap_y_pcapng(client):
    for raw in (gen.build_pcap_bytes(), gen.build_pcapng_bytes()):
        res = client.post("/api/analyze-pcap", content=raw, headers=OCTETS)
        assert res.status_code == 200 and res.json()["invalid"] == 6


def test_subida_rechaza_archivos_malos(client, monkeypatch):
    assert client.post("/api/analyze-pcap", content=b"", headers=OCTETS).status_code == 400
    mal = client.post("/api/analyze-pcap", content=b"texto cualquiera de prueba", headers=OCTETS)
    assert mal.status_code == 400 and "Formato no reconocido" in mal.json()["detail"]
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 100)
    assert client.post("/api/analyze-pcap", content=b"x" * 500, headers=OCTETS).status_code == 413


def test_limite_de_lineas_de_log(client, monkeypatch):
    monkeypatch.setattr(main, "LOG_LIMIT_PER_CAPTURE", 2)
    data = client.post("/api/analyze-sample").json()
    assert data["logged"] == 2 and data["invalid"] == 6  # se analiza todo, se registran solo 2


def test_reset_y_ack(client):
    simular(client, checksum="invalid")
    assert client.post("/api/alerts/ack").json()["pending"] == 0
    assert client.post("/api/reset").json() == {"total": 0, "valid": 0, "dropped": 0, "pending": 0}
    assert client.get("/api/events").json() == []


def test_el_log_no_permite_inyectar_lineas():
    from audit.audit_logger import _clean
    limpio = _clean("a\nIP_SRC=1.1.1.1 | ACTION=ALLOW\r")
    assert "\n" not in limpio and "\r" not in limpio and "|" not in limpio


def test_panel_y_documentacion(client):
    assert client.get("/").status_code == 200
    assert client.get("/docs").status_code == 200
