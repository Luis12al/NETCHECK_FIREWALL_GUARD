"""
Procesa tramas (de la red, de un archivo o del laboratorio) con el mismo inspector y
guarda los bytes originales para poder mostrarlos campo por campo y exportarlos.
"""
import struct
import time
from collections import deque
from threading import Lock

from core.decision_engine import decide_action
from core.dissector import summarize
from core.packet_inspector import inspect_ipv4_packet
from core.pcap_reader import _extract_ip


def process_frame(number, timestamp, linktype, data, orig_len=None, local_ips=frozenset()):
    """Inspecciona una trama completa y devuelve el registro con el veredicto."""
    orig_len = len(data) if orig_len is None else orig_len
    ip, skip = _extract_ip(linktype, data)
    record = {
        "no": number, "ts": timestamp if timestamp is not None else time.time(),
        "linktype": linktype, "data": bytes(data), "orig_len": orig_len,
        "ip": ip, "length": orig_len, "direction": None,
    }
    if ip is None:
        record.update(status="SKIPPED", action=None, reason=skip, src=None, dst=None, inspection=None)
    else:
        src = ".".join(map(str, ip[12:16])) if len(ip) >= 16 else "?"
        dst = ".".join(map(str, ip[16:20])) if len(ip) >= 20 else "?"
        outgoing = src in local_ips
        if local_ips:
            record["direction"] = "local" if outgoing and dst in local_ips else (
                "saliente" if outgoing else "entrante" if dst in local_ips else "otro")
        inspection = inspect_ipv4_packet(ip, verify_checksum=True,
                                         capture_truncated=len(data) < orig_len,
                                         local_outgoing=outgoing)
        record.update(status=inspection["status"], action=decide_action(inspection),
                      reason=inspection["reason"], src=src, dst=dst, inspection=inspection)
    summary = summarize(linktype, data, ip, record["inspection"])
    if ip is None:  # IPv6/ARP: direcciones solo para mostrar en la lista
        record["src"], record["dst"] = summary.pop("src_addr", None), summary.pop("dst_addr", None)
    record.update(summary)
    return record


def public_row(r: dict) -> dict:
    """Lo que se envía al panel por cada paquete (sin los bytes)."""
    return {k: r[k] for k in ("no", "ts", "length", "src", "dst", "protocol", "info", "status",
                              "action", "reason", "direction", "src_port", "dst_port")} | {
        "ttl": (r["inspection"] or {}).get("details", {}).get("ttl"),
        "checksum_offload": bool((r["inspection"] or {}).get("details", {}).get("checksum_offload")),
    }


class PacketStore:
    """Búfer circular de los últimos paquetes de una fuente."""

    def __init__(self, maxlen: int):
        self._items = deque(maxlen=maxlen)
        self._by_no = {}
        self._lock = Lock()
        self.label = None
        self.counts = {"total": 0, "ipv4": 0, "valid": 0, "invalid": 0, "unverified": 0, "skipped": 0}

    def clear(self, label=None):
        with self._lock:
            self._items.clear()
            self._by_no.clear()
            self.label = label
            for k in self.counts:
                self.counts[k] = 0

    def add(self, record: dict):
        with self._lock:
            if len(self._items) == self._items.maxlen:
                self._by_no.pop(self._items[0]["no"], None)
            self._items.append(record)
            self._by_no[record["no"]] = record
            c = self.counts
            c["total"] += 1
            if record["status"] == "SKIPPED":
                c["skipped"] += 1
            else:
                c["ipv4"] += 1
                c[{"VALID": "valid", "INVALID": "invalid"}.get(record["status"], "unverified")] += 1

    def get(self, no: int):
        with self._lock:
            return self._by_no.get(no)

    def rows(self, after: int = 0, limit: int = 300, only: str = "all", proto: str = "", ip: str = ""):
        """Paquetes con número mayor que `after` (los más nuevos al final)."""
        with self._lock:
            items = [r for r in self._items if r["no"] > after]
        if only == "anomalies":
            items = [r for r in items if r["status"] in ("INVALID", "UNVERIFIED")]
        elif only == "ipv4":
            items = [r for r in items if r["status"] != "SKIPPED"]
        if proto:
            items = [r for r in items if r["protocol"].lower() == proto.lower()]
        if ip:
            items = [r for r in items if ip in (r["src"], r["dst"])]
        return [public_row(r) for r in items[-limit:]]

    def snapshot(self):
        with self._lock:
            return list(self._items)

    def to_pcapng(self, cut=None) -> bytes:
        """Exporta los paquetes guardados a .pcapng para abrirlos en Wireshark.
        cut(registro) -> número de bytes a conservar de cada trama (p. ej. solo cabeceras);
        la longitud original se mantiene, así Wireshark muestra que la trama fue recortada."""
        items = self.snapshot()
        out = bytearray()
        shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        out += struct.pack("<II", 0x0A0D0D0A, 12 + len(shb)) + shb + struct.pack("<I", 12 + len(shb))
        ifaces = {}
        for r in items:
            if r["linktype"] not in ifaces:
                ifaces[r["linktype"]] = len(ifaces)
                body = struct.pack("<HHI", r["linktype"], 0, 262144)
                out += struct.pack("<II", 1, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))
        for r in items:
            ts = int(r["ts"] * 1_000_000)
            data = r["data"] if cut is None else r["data"][:max(cut(r), 0)]
            pad = (-len(data)) % 4
            body = struct.pack("<IIIII", ifaces[r["linktype"]], ts >> 32, ts & 0xFFFFFFFF,
                               len(data), r["orig_len"]) + data + b"\x00" * pad
            out += struct.pack("<II", 6, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))
        return bytes(out)
