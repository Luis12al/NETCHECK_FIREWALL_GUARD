import socket
import struct

from core.packet_inspector import ipv4_checksum


def build_test_packet(src_ip: str, dst_ip: str, header_length: int, checksum: str, issue: str) -> bytes:
    """Construye un paquete IPv4 de prueba a partir de los datos del formulario.
    Sirve para que la simulación pase por el inspector real, igual que pasaría un paquete capturado."""
    options = b"\x01" * (header_length - 20)  # opciones NOP hasta alcanzar el tamaño pedido
    payload = b"NETCHECK-DEMO"
    total_length = header_length + len(payload)

    header = bytearray(struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | (header_length // 4), 0, total_length, 0x1234, 0, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    ) + options)

    if issue == "header":
        header[0] = (5 << 4) | (header[0] & 0x0F)  # versión inválida
    elif issue == "length":
        header[2:4] = (total_length + 100).to_bytes(2, "big")  # longitud mayor que lo recibido

    # Checksum correcto para la cabecera ya modificada; así solo se reporta lo simulado.
    header[10:12] = b"\x00\x00"
    header[10:12] = ipv4_checksum(bytes(header)).to_bytes(2, "big")

    if issue == "checksum" or checksum == "invalid":
        header[10] ^= 0xFF  # corrompe el checksum

    return bytes(header) + payload
