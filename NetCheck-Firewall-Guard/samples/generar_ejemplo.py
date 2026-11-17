"""
Genera samples/ejemplo.pcap y samples/ejemplo.pcapng con paquetes conocidos.

Es independiente del backend (implementa su propio checksum), de modo que sirve
como contraste: el inspector debe coincidir con la tabla ESPERADO.
Uso:  python samples/generar_ejemplo.py
"""
import socket
import struct
from pathlib import Path

BASE_TIME = 1_700_000_000
MAC_DST, MAC_SRC = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"


def checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_packet(src, dst, proto, payload=b"", ttl=64, options=b"", version=4,
              ihl=None, total_extra=0, bad_checksum=False):
    header_len = 20 + len(options)
    ihl = header_len // 4 if ihl is None else ihl
    total = header_len + len(payload) + total_extra
    header = bytearray(struct.pack(
        "!BBHHHBBH4s4s", (version << 4) | ihl, 0, total, 0x1000, 0x4000, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst)) + options)
    header[10:12] = checksum(bytes(header)).to_bytes(2, "big")
    if bad_checksum:
        header[10] ^= 0xFF
    return bytes(header) + payload


def ethernet(ethertype: int, payload: bytes) -> bytes:
    frame = MAC_DST + MAC_SRC + ethertype.to_bytes(2, "big") + payload
    return frame.ljust(60, b"\x00")  # Ethernet exige 60 bytes mínimos (relleno)


ICMP, TCP, UDP = 1, 6, 17
NOP4 = b"\x01" * 4


def frames():
    ip = ip_packet
    return [
        ethernet(0x0800, ip("192.168.1.10", "192.168.1.1", ICMP, b"\x08\x00\x00\x00\x00\x01\x00\x01")),   # 1
        ethernet(0x0800, ip("192.168.1.10", "8.8.8.8", UDP, b"\xc3\x50\x00\x35\x00\x08\x00\x00")),         # 2
        ethernet(0x0800, ip("10.0.0.5", "192.168.1.1", TCP, b"\x00" * 20)),                                 # 3
        ethernet(0x0800, ip("203.0.113.7", "192.168.1.1", ICMP, b"\x08\x00\x00\x00", bad_checksum=True)),   # 4
        ethernet(0x0800, ip("192.168.1.10", "192.168.1.1", ICMP, b"\x08\x00\x00\x00", options=NOP4)),       # 5
        ethernet(0x0800, ip("198.51.100.9", "192.168.1.1", ICMP, b"\x08\x00\x00\x00", version=5)),          # 6
        ethernet(0x0800, ip("198.51.100.20", "192.168.1.1", ICMP, b"\x08\x00\x00\x00", ttl=0)),             # 7
        ethernet(0x0800, ip("203.0.113.50", "192.168.1.1", ICMP, b"\x08\x00\x00\x00", total_extra=200)),    # 8
        ethernet(0x0806, b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x00" * 20),                               # 9  ARP
        ethernet(0x86DD, b"\x60" + b"\x00" * 39),                                                           # 10 IPv6
        ethernet(0x0800, ip("203.0.113.99", "192.168.1.1", ICMP, b"\x08\x00\x00\x00", ihl=3)),              # 11
        ethernet(0x0800, ip("203.0.113.77", "192.168.1.1", ICMP, b"\x08\x00\x00\x00", ttl=0, bad_checksum=True)),  # 12
        ethernet(0x0800, ip("192.168.1.10", "192.168.1.1", ICMP, b"\x08\x00\x00\x00")),                     # 13
    ]


# (paquete, resultado, texto que debe contener el motivo)
ESPERADO = [
    (1, "VALID", ""), (2, "VALID", ""), (3, "VALID", ""),
    (4, "INVALID", "Checksum de cabecera incorrecto"),
    (5, "VALID", ""),
    (6, "INVALID", "Versión IP distinta de 4 (5)"),
    (7, "INVALID", "TTL fuera de rango (0)"),
    (8, "INVALID", "mayor que los bytes recibidos"),
    (9, "OMITIDO", "ARP"), (10, "OMITIDO", "IPv6"),
    (11, "INVALID", "Longitud de cabecera fuera de rango (12 bytes)"),
    (12, "INVALID", "TTL fuera de rango (0); Checksum de cabecera incorrecto"),
    (13, "VALID", ""),
]


def build_pcap_bytes(frame_list=None) -> bytes:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, data in enumerate(frame_list or frames()):
        out += struct.pack("<IIII", BASE_TIME + i, 0, len(data), len(data)) + data
    return bytes(out)


def build_pcapng_bytes(frame_list=None) -> bytes:
    def block(btype, body):
        body += b"\x00" * (-len(body) % 4)
        total = 12 + len(body)
        return struct.pack("<II", btype, total) + body + struct.pack("<I", total)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535))
    for i, data in enumerate(frame_list or frames()):
        ticks = (BASE_TIME + i) * 1_000_000
        out += block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF,
                                    len(data), len(data)) + data)
    return out


if __name__ == "__main__":
    folder = Path(__file__).resolve().parent
    (folder / "ejemplo.pcap").write_bytes(build_pcap_bytes())
    (folder / "ejemplo.pcapng").write_bytes(build_pcapng_bytes())
    print("Generados: ejemplo.pcap y ejemplo.pcapng (13 paquetes)")
