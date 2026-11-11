import socket


def ipv4_checksum(header: bytes) -> int:
    """Suma de comprobación de Internet (RFC 1071) sobre los bytes de la cabecera.
    Si la cabecera incluye su checksum correcto, el resultado es 0."""
    if len(header) % 2:
        header += b"\x00"
    total = sum(int.from_bytes(header[i:i + 2], "big") for i in range(0, len(header), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def inspect_ipv4_packet(packet_bytes: bytes, verify_checksum: bool = True) -> dict:
    """
    Valida la cabecera IPv4 leyendo directamente los bytes crudos.
    Se evita un parser permisivo para no "corregir" sin avisar un paquete malformado.
    """
    try:
        if len(packet_bytes) < 20:
            return {
                "status": "INVALID",
                "reason": f"Paquete demasiado corto ({len(packet_bytes)} bytes)",
                "details": {},
            }

        version = packet_bytes[0] >> 4
        header_length = (packet_bytes[0] & 0x0F) * 4  # IHL en palabras de 32 bits
        total_length = int.from_bytes(packet_bytes[2:4], "big")
        ttl = packet_bytes[8]
        proto = packet_bytes[9]
        src_ip = socket.inet_ntoa(packet_bytes[12:16])
        dst_ip = socket.inet_ntoa(packet_bytes[16:20])
        details = {
            "src_ip": src_ip, "dst_ip": dst_ip, "ttl": ttl,
            "header_length": header_length, "total_length": total_length, "protocol": proto,
        }

        anomalies = []
        if version != 4:
            anomalies.append(f"Versión IP distinta de 4 ({version})")
        if header_length < 20 or header_length > 60:
            anomalies.append(f"Longitud de cabecera fuera de rango ({header_length} bytes)")
        elif len(packet_bytes) < header_length:
            anomalies.append("Cabecera truncada: faltan bytes de opciones")
        elif total_length < header_length:
            anomalies.append("Longitud total menor que la cabecera")
        if total_length > len(packet_bytes):
            anomalies.append(
                f"Longitud total declarada ({total_length}) mayor que los bytes recibidos ({len(packet_bytes)})"
            )
        if ttl == 0:
            anomalies.append("TTL fuera de rango (0)")

        if verify_checksum and 20 <= header_length <= len(packet_bytes):
            if ipv4_checksum(packet_bytes[:header_length]) != 0:
                anomalies.append("Checksum de cabecera incorrecto")

        if anomalies:
            return {"status": "INVALID", "reason": "; ".join(anomalies), "details": details}
        if not verify_checksum:
            return {"status": "UNVERIFIED", "reason": "Checksum no comprobado", "details": details}
        return {"status": "VALID", "reason": "OK", "details": details}

    except Exception as e:
        return {
            "status": "UNVERIFIED",
            "reason": f"Error interno de parseo: {type(e).__name__}",
            "details": {},
        }
