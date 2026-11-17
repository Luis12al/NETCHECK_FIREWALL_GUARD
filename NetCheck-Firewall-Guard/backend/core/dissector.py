"""
Disector de tramas: separa cada capa (enlace, IPv4, TCP/UDP/ICMP) campo por campo.

Cada campo indica su posición (offset) y tamaño dentro de la trama, para que el panel
pueda resaltar en el volcado hexadecimal exactamente los bytes que se leyeron.
Solo describe; quien decide si un paquete es válido es packet_inspector.
"""
import socket

from core.pcap_reader import _extract_ip

IP_PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6-en-IPv4", 47: "GRE",
                50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}
ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q VLAN", 0x88CC: "LLDP"}
ICMP_TYPES = {0: "Echo reply", 3: "Destino inalcanzable", 5: "Redirección", 8: "Echo request",
              11: "Tiempo excedido", 13: "Timestamp", 14: "Timestamp reply"}
WELL_KNOWN = {20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
              68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
              139: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 853: "DNS-TLS",
              1900: "SSDP", 3389: "RDP", 5353: "mDNS", 5355: "LLMNR", 8000: "NetCheck API", 8080: "HTTP-alt"}


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _f(name, value, offset, length, state=None, raw=None):
    field = {"name": name, "value": value, "offset": offset, "length": length}
    if state:
        field["state"] = state  # "ok" | "bad" | "warn" | "info"
    if raw is not None:
        field["raw"] = raw
    return field


def _port(p: int) -> str:
    return f"{p} ({WELL_KNOWN[p]})" if p in WELL_KNOWN else str(p)


def _link_layer(linktype: int, data: bytes, ip_offset: int):
    if linktype == 1 and len(data) >= 14:
        et = int.from_bytes(data[12:14], "big")
        fields = [
            _f("MAC destino", _mac(data[0:6]), 0, 6),
            _f("MAC origen", _mac(data[6:12]), 6, 6),
            _f("EtherType", f"0x{et:04x} ({ETHERTYPES.get(et, 'desconocido')})", 12, 2),
        ]
        if ip_offset and ip_offset > 14:
            fields.append(_f("Etiquetas VLAN", f"{(ip_offset - 14) // 4}", 14, ip_offset - 14))
        return {"name": "Ethernet II", "offset": 0, "length": ip_offset or 14, "fields": fields}
    if linktype in (0, 108) and len(data) >= 4:
        fam = int.from_bytes(data[:4], "little") if data[0] else int.from_bytes(data[:4], "big")
        names = {2: "AF_INET (IPv4)", 23: "AF_INET6 (IPv6)", 24: "AF_INET6", 28: "AF_INET6", 30: "AF_INET6"}
        return {"name": "Loopback (Null/BSD)", "offset": 0, "length": 4,
                "fields": [_f("Familia", names.get(fam, str(fam)), 0, 4)]}
    if linktype in (12, 101):
        return None
    if linktype in (113, 276):
        return {"name": "Linux cooked capture", "offset": 0, "length": ip_offset or 16, "fields": []}
    return None


def _ipv4_layer(ip: bytes, base: int, inspection: dict):
    if len(ip) < 20:
        return None, None
    d = inspection.get("details", {})
    v, ihl = ip[0] >> 4, (ip[0] & 0x0F) * 4
    total = int.from_bytes(ip[2:4], "big")
    ident = int.from_bytes(ip[4:6], "big")
    flags_frag = int.from_bytes(ip[6:8], "big")
    df, mf, frag = bool(flags_frag & 0x4000), bool(flags_frag & 0x2000), (flags_frag & 0x1FFF) * 8
    ttl, proto = ip[8], ip[9]
    stored = int.from_bytes(ip[10:12], "big")
    calc = d.get("checksum_calculated")

    reason = inspection.get("reason", "")
    if d.get("checksum_offload"):
        ck_state, ck_note = "info", "0x0000: lo rellena la tarjeta de red (offload)"
    elif calc is None:
        ck_state, ck_note = "warn", "no se pudo calcular"
    elif stored == calc:
        ck_state, ck_note = "ok", f"correcto (calculado 0x{calc:04x})"
    else:
        ck_state, ck_note = "bad", f"INCORRECTO: el cálculo da 0x{calc:04x}"

    flag_txt = ", ".join(n for n, on in (("DF", df), ("MF", mf)) if on) or "ninguno"
    fields = [
        _f("Versión", str(v), base, 1, "ok" if v == 4 else "bad"),
        _f("IHL (long. cabecera)", f"{ip[0] & 0x0F} × 4 = {ihl} bytes", base, 1,
           "ok" if 20 <= ihl <= 60 else "bad"),
        _f("DSCP / ECN", f"{ip[1] >> 2} / {ip[1] & 3}", base + 1, 1),
        _f("Longitud total", f"{total} bytes" + (" (offload: la rellena la tarjeta)" if d.get("length_offload") else ""),
           base + 2, 2, "bad" if "Longitud total" in reason else "ok"),
        _f("Identificación", f"0x{ident:04x} ({ident})", base + 4, 2),
        _f("Flags", flag_txt, base + 6, 2),
        _f("Desplazamiento de fragmento", f"{frag} bytes", base + 6, 2, "warn" if frag or mf else None),
        _f("TTL", str(ttl), base + 8, 1, "bad" if ttl == 0 else "ok"),
        _f("Protocolo", f"{proto} ({IP_PROTOCOLS.get(proto, 'otro')})", base + 9, 1),
        _f("Checksum de cabecera", f"0x{stored:04x} → {ck_note}", base + 10, 2, ck_state),
        _f("IP origen", socket.inet_ntoa(ip[12:16]), base + 12, 4),
        _f("IP destino", socket.inet_ntoa(ip[16:20]), base + 16, 4),
    ]
    if 20 < ihl <= len(ip):
        fields.append(_f("Opciones", ip[20:ihl].hex(" "), base + 20, ihl - 20))
    return {"name": "IPv4", "offset": base, "length": min(max(ihl, 20), len(ip)), "fields": fields}, (ihl, proto, frag, mf)


def _transport_layer(ip: bytes, base: int, ihl: int, proto: int):
    seg = ip[ihl:]
    off = base + ihl
    if proto == 6 and len(seg) >= 20:
        sp, dp = int.from_bytes(seg[0:2], "big"), int.from_bytes(seg[2:4], "big")
        doff = (seg[12] >> 4) * 4
        flags = seg[13]
        names = [n for bit, n in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"),
                                  (0x08, "PSH"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")) if flags & bit]
        payload = max(0, len(seg) - doff)
        layer = {"name": "TCP", "offset": off, "length": min(doff, len(seg)), "fields": [
            _f("Puerto origen", _port(sp), off, 2), _f("Puerto destino", _port(dp), off + 2, 2),
            _f("Número de secuencia", str(int.from_bytes(seg[4:8], "big")), off + 4, 4),
            _f("Número de ACK", str(int.from_bytes(seg[8:12], "big")), off + 8, 4),
            _f("Long. cabecera TCP", f"{doff} bytes", off + 12, 1, None if 20 <= doff <= 60 else "bad"),
            _f("Flags", " ".join(names) or "ninguno", off + 13, 1,
               "warn" if (flags & 0x03) == 0x03 or flags == 0 else None),
            _f("Ventana", str(int.from_bytes(seg[14:16], "big")), off + 14, 2),
            _f("Checksum TCP", f"0x{int.from_bytes(seg[16:18], 'big'):04x} (no verificado)", off + 16, 2),
        ]}
        info = f"{_port(sp)} → {_port(dp)} [{', '.join(names) or '-'}]" + (f" · {payload} B datos" if payload else "")
        return layer, "TCP", info, sp, dp, payload
    if proto == 17 and len(seg) >= 8:
        sp, dp = int.from_bytes(seg[0:2], "big"), int.from_bytes(seg[2:4], "big")
        ulen = int.from_bytes(seg[4:6], "big")
        layer = {"name": "UDP", "offset": off, "length": 8, "fields": [
            _f("Puerto origen", _port(sp), off, 2), _f("Puerto destino", _port(dp), off + 2, 2),
            _f("Longitud", f"{ulen} bytes", off + 4, 2, None if ulen <= len(seg) else "warn"),
            _f("Checksum UDP", f"0x{int.from_bytes(seg[6:8], 'big'):04x} (no verificado)", off + 6, 2),
        ]}
        app = WELL_KNOWN.get(dp) or WELL_KNOWN.get(sp)
        return layer, app if app in ("DNS", "mDNS", "SSDP", "NTP", "DHCP", "LLMNR", "NetBIOS") else "UDP", \
            f"{_port(sp)} → {_port(dp)} · {max(0, ulen - 8)} B datos", sp, dp, max(0, len(seg) - 8)
    if proto == 1 and len(seg) >= 4:
        t, c = seg[0], seg[1]
        fields = [_f("Tipo", f"{t} ({ICMP_TYPES.get(t, 'otro')})", off, 1), _f("Código", str(c), off + 1, 1),
                  _f("Checksum ICMP", f"0x{int.from_bytes(seg[2:4], 'big'):04x} (no verificado)", off + 2, 2)]
        info = ICMP_TYPES.get(t, f"tipo {t}")
        if t in (0, 8) and len(seg) >= 8:
            ident, seq = int.from_bytes(seg[4:6], "big"), int.from_bytes(seg[6:8], "big")
            fields += [_f("Identificador", str(ident), off + 4, 2), _f("Secuencia", str(seq), off + 6, 2)]
            info += f" id={ident} seq={seq}"
        return {"name": "ICMP", "offset": off, "length": min(8, len(seg)), "fields": fields}, "ICMP", info, None, None, len(seg)
    name = IP_PROTOCOLS.get(proto, f"IP/{proto}")
    return None, name, f"Protocolo {proto} · {len(seg)} B", None, None, len(seg)


def summarize(linktype: int, data: bytes, ip: bytes | None, inspection: dict | None) -> dict:
    """Resumen de una línea (como la lista de paquetes de Wireshark)."""
    return dissect(linktype, data, ip, inspection, summary_only=True)


def dissect(linktype: int, data: bytes, ip: bytes | None = None, inspection: dict | None = None,
            summary_only: bool = False) -> dict:
    if ip is None:
        ip, _ = _extract_ip(linktype, data)
    inspection = inspection or {}
    ip_offset = len(data) - len(ip) if ip is not None else None
    layers = []
    link = _link_layer(linktype, data, ip_offset)
    if link:
        layers.append(link)

    out = {"protocol": "?", "info": "", "src_port": None, "dst_port": None}
    if ip is None:
        if linktype == 1 and len(data) >= 14:
            et = int.from_bytes(data[12:14], "big")
            out["protocol"] = ETHERTYPES.get(et, f"0x{et:04x}")
            if et == 0x0806 and len(data) >= 42:
                op = int.from_bytes(data[20:22], "big")
                spa, tpa = socket.inet_ntoa(data[28:32]), socket.inet_ntoa(data[38:42])
                out["info"] = f"¿Quién tiene {tpa}? Responde a {spa}" if op == 1 else f"{spa} está en {_mac(data[22:28])}"
            elif et == 0x86DD and len(data) >= 54:  # IPv6: solo se muestra, no se inspecciona
                v6 = data[14:]
                out["src_addr"] = socket.inet_ntop(socket.AF_INET6, v6[8:24])
                out["dst_addr"] = socket.inet_ntop(socket.AF_INET6, v6[24:40])
                nh = v6[6]
                pname = {6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(nh, IP_PROTOCOLS.get(nh, f"siguiente cab. {nh}"))
                extra = ""
                if nh in (6, 17) and len(v6) >= 44:
                    extra = f" {_port(int.from_bytes(v6[40:42], 'big'))} → {_port(int.from_bytes(v6[42:44], 'big'))}"
                out["info"] = f"IPv6 / {pname}{extra} · no se inspecciona (solo IPv4)"
                fields = [_f("Versión", str(v6[0] >> 4), 14, 1), _f("Siguiente cabecera", pname, 20, 1),
                          _f("Límite de saltos", str(v6[7]), 21, 1),
                          _f("IP origen", out["src_addr"], 22, 16), _f("IP destino", out["dst_addr"], 38, 16)]
                layers.append({"name": "IPv6 (informativo)", "offset": 14, "length": 40, "fields": fields})
            else:
                out["info"] = "No es IPv4: se cuenta y se omite"
        else:
            out["protocol"], out["info"] = "No IPv4", "Se cuenta y se omite"
    else:
        ip_layer, meta = _ipv4_layer(ip, ip_offset, inspection)
        if ip_layer:
            layers.append(ip_layer)
            ihl, proto, frag, mf = meta
            if frag:  # solo el primer fragmento trae la cabecera de transporte
                out["protocol"], out["info"] = "IPv4", f"Fragmento (offset {frag})"
            elif 20 <= ihl <= len(ip):
                tl, pname, info, sp, dp, _ = _transport_layer(ip, ip_offset, ihl, proto)
                if tl:
                    layers.append(tl)
                out.update(protocol=pname, info=info, src_port=sp, dst_port=dp)
            else:
                out["protocol"], out["info"] = "IPv4", "Cabecera IPv4 inválida"
        else:
            out["protocol"], out["info"] = "IPv4", "Paquete demasiado corto"

    if summary_only:
        return out
    used = max((l["offset"] + l["length"] for l in layers), default=0)
    if used < len(data):
        layers.append({"name": "Datos (payload)", "offset": used, "length": len(data) - used,
                       "fields": [_f("Bytes", f"{len(data) - used} (no se inspecciona el contenido)", used, len(data) - used)]})
    out["layers"] = layers
    out["hex"] = data[:4096].hex()
    out["hex_truncated"] = len(data) > 4096
    return out
