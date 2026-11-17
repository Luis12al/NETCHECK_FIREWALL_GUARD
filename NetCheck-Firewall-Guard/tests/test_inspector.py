from core.packet_inspector import inspect_ipv4_packet, ipv4_checksum
from core.packet_simulator import build_test_packet
from core.decision_engine import decide_action


def packet(checksum="valid", issue="none", header=20):
    return build_test_packet("192.168.1.10", "192.168.1.1", header, checksum, issue)


def fix_checksum(raw: bytearray) -> bytes:
    header_len = (raw[0] & 0x0F) * 4
    raw[10:12] = b"\x00\x00"
    raw[10:12] = ipv4_checksum(bytes(raw[:header_len])).to_bytes(2, "big")
    return bytes(raw)


def test_paquete_valido_se_permite():
    result = inspect_ipv4_packet(packet())
    assert result["status"] == "VALID" and decide_action(result) == "ALLOW"


def test_cabecera_con_opciones_es_valida():
    for size in (24, 40, 60):
        assert inspect_ipv4_packet(packet(header=size))["status"] == "VALID"


def test_checksum_incorrecto_se_descarta():
    for kwargs in ({"checksum": "invalid"}, {"issue": "checksum"}):
        result = inspect_ipv4_packet(packet(**kwargs))
        assert result["status"] == "INVALID"
        assert "Checksum de cabecera incorrecto" in result["reason"]
        assert decide_action(result) == "DROP"


def test_version_invalida():
    result = inspect_ipv4_packet(packet(issue="header"))
    assert result["status"] == "INVALID"
    assert result["reason"] == "Versión IP distinta de 4 (5)"  # solo esta anomalía: el checksum se recalcula


def test_longitud_total_mayor_que_bytes_recibidos():
    result = inspect_ipv4_packet(packet(issue="length"))
    assert result["status"] == "INVALID"
    assert "mayor que los bytes recibidos" in result["reason"]


def test_ttl_cero():
    raw = bytearray(packet())
    raw[8] = 0
    result = inspect_ipv4_packet(fix_checksum(raw))
    assert result["status"] == "INVALID" and result["reason"] == "TTL fuera de rango (0)"


def test_ihl_menor_que_cinco():
    raw = bytearray(packet())
    raw[0] = 0x43
    result = inspect_ipv4_packet(bytes(raw))
    assert "Longitud de cabecera fuera de rango (12 bytes)" in result["reason"]


def test_cabecera_truncada():
    raw = bytearray(packet())
    raw[0] = 0x4F  # IHL 15 = 60 bytes, pero el paquete trae menos
    assert "Cabecera truncada" in inspect_ipv4_packet(bytes(raw))["reason"]


def test_paquete_demasiado_corto():
    result = inspect_ipv4_packet(packet()[:10])
    assert result["status"] == "INVALID" and "demasiado corto" in result["reason"]


def test_varias_anomalias_se_reportan_juntas():
    raw = bytearray(packet("invalid"))
    raw[8] = 0
    reason = inspect_ipv4_packet(bytes(raw))["reason"]
    assert "TTL" in reason and "Checksum" in reason


def test_sin_comprobar_checksum_queda_no_verificado():
    result = inspect_ipv4_packet(packet(), verify_checksum=False)
    assert result["status"] == "UNVERIFIED" and decide_action(result) == "DROP"


def test_captura_truncada_no_compara_longitudes():
    raw = packet(issue="length")
    assert inspect_ipv4_packet(raw)["status"] == "INVALID"
    assert inspect_ipv4_packet(raw, capture_truncated=True)["status"] == "VALID"


def test_checksum_rfc1071_ejemplo_conocido():
    # Cabecera de ejemplo ampliamente documentada: el checksum correcto es 0xB861.
    header = bytes.fromhex("4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7".replace(" ", ""))
    assert ipv4_checksum(header) == 0xB861
    assert ipv4_checksum(header[:10] + b"\xb8\x61" + header[12:]) == 0
