from collections import Counter

from core.packet_store import process_frame
from core.pcap_reader import linktype_name, read_capture


def analyze_capture(raw: bytes, on_packet=None, store=None, max_listed: int = 200) -> dict:
    """
    Pasa cada paquete IPv4 de una captura por el mismo inspector y motor de decisión
    que usan la captura en vivo y el laboratorio. El número de paquete coincide con el
    de Wireshark (frame.number).

    on_packet(numero, src_ip, dst_ip, estado, accion, motivo) se llama por cada paquete IPv4.
    store (PacketStore) recibe todas las tramas para poder verlas campo por campo.
    """
    frames, meta = read_capture(raw)
    summary = {
        "format": meta["format"],
        "linktype": meta["linktype"],
        "linktype_name": linktype_name(meta["linktype"]),
        "frames_total": len(frames),
        "ipv4_analyzed": 0, "skipped_non_ipv4": 0,
        "valid": 0, "invalid": 0, "unverified": 0, "truncated_frames": 0,
        "anomalies": [], "anomalies_truncated": False,
        "warnings": list(meta["warnings"]),
    }
    skipped = Counter()

    for frame in frames:
        record = process_frame(frame["number"], frame["timestamp"], frame["linktype"],
                               frame["data"], frame["orig_len"])
        if store is not None:
            store.add(record)
        if record["status"] == "SKIPPED":
            summary["skipped_non_ipv4"] += 1
            skipped[frame["skip_reason"]] += 1
            continue
        if frame["truncated"]:
            summary["truncated_frames"] += 1

        status, action, reason = record["status"], record["action"], record["reason"]
        src, dst = record["src"], record["dst"]
        summary["ipv4_analyzed"] += 1
        summary[{"VALID": "valid", "INVALID": "invalid"}.get(status, "unverified")] += 1

        if on_packet:
            on_packet(frame["number"], src, dst, status, action, reason)
        if status != "VALID":
            if len(summary["anomalies"]) < max_listed:
                summary["anomalies"].append({
                    "frame": frame["number"], "src": src, "dst": dst,
                    "status": status, "action": action, "reason": reason,
                })
            else:
                summary["anomalies_truncated"] = True

    summary["skipped_reasons"] = dict(skipped)
    if summary["truncated_frames"]:
        summary["warnings"].append(
            f"{summary['truncated_frames']} trama(s) fueron cortadas al capturar (snaplen); "
            "en ellas no se compara la longitud total."
        )
    return summary
