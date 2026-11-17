import struct

import pytest
import generar_ejemplo as gen
from core import pcap_reader
from core.pcap_analysis import analyze_capture
from core.pcap_reader import PcapError, read_capture


def check_against_expected(summary):
    por_paquete = {a["frame"]: a for a in summary["anomalies"]}
    for numero, resultado, texto in gen.ESPERADO:
        if resultado == "INVALID":
            assert numero in por_paquete, f"el paquete {numero} debía ser anomalía"
            assert texto in por_paquete[numero]["reason"], (numero, por_paquete[numero]["reason"])
            assert por_paquete[numero]["action"] == "DROP"
        elif resultado == "VALID":
            assert numero not in por_paquete, f"el paquete {numero} debía ser válido"
    assert summary["frames_total"] == 13
    assert summary["ipv4_analyzed"] == 11
    assert summary["skipped_non_ipv4"] == 2
    assert summary["valid"] == 5 and summary["invalid"] == 6 and summary["unverified"] == 0


def test_pcap_clasico():
    summary = analyze_capture(gen.build_pcap_bytes())
    assert summary["format"] == "pcap" and summary["linktype_name"] == "Ethernet"
    check_against_expected(summary)
    assert summary["skipped_reasons"] == {"No es IPv4 (ARP)": 1, "No es IPv4 (IPv6)": 1}


def test_pcapng():
    summary = analyze_capture(gen.build_pcapng_bytes())
    assert summary["format"] == "pcapng"
    check_against_expected(summary)


def test_archivo_de_ejemplo_en_disco_coincide_con_el_generador():
    from pathlib import Path
    ejemplo = Path(gen.__file__).with_name("ejemplo.pcap").read_bytes()
    assert ejemplo == gen.build_pcap_bytes()


def test_callback_recibe_cada_paquete_ipv4():
    vistos = []
    analyze_capture(gen.build_pcap_bytes(), on_packet=lambda *a: vistos.append(a[0]))
    assert vistos == [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13]


def test_pcap_big_endian_y_nanosegundos():
    frames = gen.frames()[:1]
    data = frames[0]
    be = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack(">IIII", 5, 7, len(data), len(data)) + data
    ns = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 5, 500_000_000, len(data), len(data)) + data
    assert read_capture(be)[0][0]["timestamp"] == pytest.approx(5.000007)
    assert read_capture(ns)[0][0]["timestamp"] == pytest.approx(5.5)


def pcap_with_linktype(linktype, frame):
    return (struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
            + struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame)


def test_ip_crudo_y_otros_enlaces():
    ip = gen.ip_packet("10.0.0.1", "10.0.0.2", 1, b"\x08\x00\x00\x00")
    casos = {
        101: ip,                                                        # Raw IP
        113: b"\x00" * 14 + b"\x08\x00" + ip,                           # Linux cooked
        276: b"\x08\x00" + b"\x00" * 18 + ip,                           # Linux cooked v2
        0: b"\x02\x00\x00\x00" + ip,                                    # loopback BSD
    }
    for linktype, frame in casos.items():
        summary = analyze_capture(pcap_with_linktype(linktype, frame))
        assert summary["valid"] == 1, linktype


def test_vlan_8021q():
    ip = gen.ip_packet("10.0.0.1", "10.0.0.2", 1, b"\x08\x00\x00\x00")
    frame = gen.MAC_DST + gen.MAC_SRC + b"\x81\x00\x00\x64\x08\x00" + ip
    assert analyze_capture(pcap_with_linktype(1, frame.ljust(60, b"\x00")))["valid"] == 1


def test_ip_crudo_con_version_6_se_omite_y_otra_version_se_reporta():
    v6 = b"\x60" + b"\x00" * 39
    assert analyze_capture(pcap_with_linktype(101, v6))["skipped_non_ipv4"] == 1
    v5 = gen.ip_packet("10.0.0.1", "10.0.0.2", 1, b"abcd", version=5)
    assert "Versión IP distinta de 4" in analyze_capture(pcap_with_linktype(101, v5))["anomalies"][0]["reason"]


def test_trama_cortada_por_snaplen_no_genera_falso_positivo():
    ip = gen.ip_packet("10.0.0.1", "10.0.0.2", 6, b"\x00" * 100)
    recortado = ip[:40]  # la captura guardó solo 40 de 120 bytes
    raw = (struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 40, 101)
           + struct.pack("<IIII", 0, 0, len(recortado), len(ip)) + recortado)
    summary = analyze_capture(raw)
    assert summary["valid"] == 1 and summary["truncated_frames"] == 1 and summary["warnings"]


def test_archivo_cortado_a_mitad_genera_aviso_no_error():
    raw = gen.build_pcap_bytes()[:-10]
    summary = analyze_capture(raw)
    assert summary["frames_total"] == 12 and any("truncado" in w for w in summary["warnings"])


@pytest.mark.parametrize("raw,mensaje", [
    (b"", "demasiado pequeño"),
    (b"esto no es una captura de red", "Formato no reconocido"),
    (b"\xd4\xc3\xb2\xa1" + b"\x00" * 8, "incompleta"),
])
def test_archivos_invalidos(raw, mensaje):
    with pytest.raises(PcapError, match=mensaje):
        read_capture(raw)


def test_registro_con_tamano_absurdo_se_rechaza():
    raw = (struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
           + struct.pack("<IIII", 0, 0, 4_000_000_000, 4_000_000_000))
    with pytest.raises(PcapError, match="corrupto"):
        read_capture(raw)


def test_limite_de_paquetes(monkeypatch):
    with pytest.raises(PcapError, match="máximo"):
        read_capture(gen.build_pcap_bytes(), max_packets=5)
    with pytest.raises(PcapError, match="máximo"):
        read_capture(gen.build_pcapng_bytes(), max_packets=5)


def test_pcapng_corrupto():
    raw = bytearray(gen.build_pcapng_bytes())
    raw[4:8] = b"\x03\x00\x00\x00"  # longitud de bloque no múltiplo de 4
    with pytest.raises(PcapError):
        read_capture(bytes(raw))
