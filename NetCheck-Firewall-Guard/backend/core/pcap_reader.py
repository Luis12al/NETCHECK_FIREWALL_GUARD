"""
Lector de capturas .pcap y .pcapng en Python puro (sin dependencias).

Extrae el paquete IPv4 de cada trama según el tipo de enlace. Lee los bytes tal
como quedaron guardados, de modo que también aparecen paquetes malformados que
el kernel habría descartado antes de que los viera un firewall.
"""
import struct

MAX_PACKETS = 50_000
MAX_FRAME_BYTES = 262_144  # cota razonable por trama; un valor mayor indica archivo corrupto

LINKTYPE_NAMES = {
    0: "BSD loopback", 1: "Ethernet", 12: "Raw IP", 101: "Raw IP",
    108: "OpenBSD loopback", 113: "Linux cooked (SLL)", 276: "Linux cooked v2 (SLL2)",
}

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_VLAN_TYPES = (0x8100, 0x88A8, 0x9100)


class PcapError(ValueError):
    """El archivo no es una captura válida o está corrupto."""


def _extract_ip(linktype: int, data: bytes):
    """Devuelve (bytes_del_paquete_IPv4, None) o (None, motivo_por_el_que_se_omite)."""
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None, "Trama Ethernet demasiado corta"
        ethertype = int.from_bytes(data[12:14], "big")
        offset = 14
        while ethertype in _VLAN_TYPES and len(data) >= offset + 4:  # etiquetas 802.1Q
            ethertype = int.from_bytes(data[offset + 2:offset + 4], "big")
            offset += 4
        if ethertype == 0x0800:
            return data[offset:], None
        names = {0x86DD: "IPv6", 0x0806: "ARP"}
        return None, f"No es IPv4 ({names.get(ethertype, f'ethertype 0x{ethertype:04x}')})"

    if linktype in (12, 101):  # IP crudo: el tipo se deduce del primer nibble
        if not data:
            return None, "Trama vacía"
        if data[0] >> 4 == 6:
            return None, "No es IPv4 (IPv6)"
        return data, None

    if linktype in (0, 108):  # loopback BSD/OpenBSD: 4 bytes con la familia de direcciones
        if len(data) < 4:
            return None, "Trama demasiado corta"
        if data[:4] in (b"\x02\x00\x00\x00", b"\x00\x00\x00\x02"):
            return data[4:], None
        return None, "No es IPv4 (familia distinta de AF_INET)"

    if linktype == 113:  # Linux cooked v1
        if len(data) < 16:
            return None, "Trama demasiado corta"
        if int.from_bytes(data[14:16], "big") == 0x0800:
            return data[16:], None
        return None, "No es IPv4"

    if linktype == 276:  # Linux cooked v2
        if len(data) < 20:
            return None, "Trama demasiado corta"
        if int.from_bytes(data[0:2], "big") == 0x0800:
            return data[20:], None
        return None, "No es IPv4"

    return None, f"Tipo de enlace no soportado ({linktype})"


def _frame(number, timestamp, linktype, data, orig_len):
    ip, skip = _extract_ip(linktype, data)
    return {
        "number": number, "timestamp": timestamp, "ip": ip, "skip_reason": skip,
        "truncated": len(data) < orig_len,  # la captura cortó la trama (snaplen)
        "linktype": linktype, "data": data, "orig_len": orig_len,
    }


def _read_pcap(raw: bytes, max_packets: int):
    endian, divisor = _PCAP_MAGICS[raw[:4]]
    if len(raw) < 24:
        raise PcapError("Cabecera pcap incompleta.")
    network = struct.unpack(endian + "IHHiIII", raw[:24])[6]
    linktype = network & 0x0FFFFFFF
    frames, warnings, pos = [], [], 24
    while pos < len(raw):
        number = len(frames) + 1
        if len(raw) - pos < 16:
            warnings.append("El archivo termina con un registro incompleto; se ignoró.")
            break
        ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", raw[pos:pos + 16])
        pos += 16
        if incl > MAX_FRAME_BYTES:
            raise PcapError(f"Archivo corrupto: la trama {number} declara {incl} bytes.")
        if pos + incl > len(raw):
            warnings.append(f"Archivo truncado en la trama {number}; se ignoró.")
            break
        if number > max_packets:
            raise PcapError(f"La captura supera el máximo de {max_packets} paquetes.")
        frames.append(_frame(number, ts_sec + ts_frac / divisor, linktype, raw[pos:pos + incl], orig))
        pos += incl
    return frames, {"format": "pcap", "linktype": linktype, "warnings": warnings}


def _parse_idb(body: bytes, endian: str) -> dict:
    if len(body) < 8:
        raise PcapError("Bloque de interfaz pcapng corrupto.")
    linktype = struct.unpack(endian + "H", body[:2])[0]
    divisor, off = 1_000_000.0, 8
    while off + 4 <= len(body):  # opciones: solo interesa if_tsresol (código 9)
        code, length = struct.unpack(endian + "HH", body[off:off + 4])
        off += 4
        if code == 0:
            break
        value = body[off:off + length]
        off += (length + 3) // 4 * 4
        if code == 9 and length == 1:
            v = value[0]
            divisor = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** (v & 0x7F))
    return {"linktype": linktype, "divisor": divisor}


def _read_pcapng(raw: bytes, max_packets: int):
    endian, interfaces, frames, warnings, pos = None, [], [], [], 0
    while pos < len(raw):
        if len(raw) - pos < 12:
            warnings.append("El archivo termina con un bloque incompleto; se ignoró.")
            break
        if raw[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":  # nueva sección: define el orden de bytes
            bom = raw[pos + 8:pos + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise PcapError("Cabecera pcapng inválida.")
            interfaces = []
        if endian is None:
            raise PcapError("El archivo pcapng no empieza con un bloque de sección.")
        btype, blen = struct.unpack(endian + "II", raw[pos:pos + 8])
        if blen < 12 or blen % 4:
            raise PcapError("Bloque pcapng corrupto.")
        if pos + blen > len(raw):
            warnings.append("Archivo truncado: se ignoró el último bloque.")
            break
        body = raw[pos + 8:pos + blen - 4]

        if btype == 1:  # Interface Description Block
            interfaces.append(_parse_idb(body, endian))
        elif btype in (6, 3):  # Enhanced Packet Block / Simple Packet Block
            number = len(frames) + 1
            if number > max_packets:
                raise PcapError(f"La captura supera el máximo de {max_packets} paquetes.")
            if btype == 6:
                if len(body) < 20:
                    raise PcapError("Bloque de paquete pcapng corrupto.")
                iface_id, ts_hi, ts_lo, caplen, orig = struct.unpack(endian + "IIIII", body[:20])
                if iface_id >= len(interfaces) or 20 + caplen > len(body) or caplen > MAX_FRAME_BYTES:
                    raise PcapError(f"Bloque de paquete {number} corrupto.")
                iface, data = interfaces[iface_id], body[20:20 + caplen]
                timestamp = ((ts_hi << 32) | ts_lo) / iface["divisor"]
            else:
                if not interfaces or len(body) < 4:
                    raise PcapError(f"Bloque de paquete {number} corrupto.")
                orig = struct.unpack(endian + "I", body[:4])[0]
                iface, data, timestamp = interfaces[0], body[4:4 + min(orig, len(body) - 4)], None
            frames.append(_frame(number, timestamp, iface["linktype"], data, orig))
        pos += blen

    types = sorted({i["linktype"] for i in interfaces})
    return frames, {"format": "pcapng", "linktype": types[0] if len(types) == 1 else types, "warnings": warnings}


def read_capture(raw: bytes, max_packets: int = MAX_PACKETS):
    """Lee un .pcap o .pcapng completo. Devuelve (lista_de_tramas, metadatos)."""
    if len(raw) < 12:
        raise PcapError("El archivo es demasiado pequeño para ser una captura.")
    if raw[:4] == b"\x0a\x0d\x0d\x0a":
        return _read_pcapng(raw, max_packets)
    if raw[:4] in _PCAP_MAGICS:
        return _read_pcap(raw, max_packets)
    raise PcapError("Formato no reconocido: usa un archivo .pcap o .pcapng.")


def linktype_name(linktype) -> str:
    if isinstance(linktype, list):
        return ", ".join(linktype_name(t) for t in linktype)
    return LINKTYPE_NAMES.get(linktype, f"tipo {linktype}")
