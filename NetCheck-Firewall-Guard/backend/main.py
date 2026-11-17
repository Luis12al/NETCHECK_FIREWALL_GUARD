import functools
import os
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path
from threading import Lock
from typing import Literal
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core.packet_inspector import inspect_ipv4_packet
from core.packet_simulator import build_test_packet
from core.decision_engine import decide_action
from core.dissector import dissect
from core.packet_store import PacketStore, process_frame
from core.pcap_analysis import analyze_capture
from core.pcap_reader import PcapError
from core import live_capture
from audit.audit_logger import log_event, get_recent_logs

PROJECT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_DIR / "frontend"
SAMPLE_PCAP = PROJECT_DIR / "samples" / "ejemplo.pcap"
DEST_IP = "192.168.1.1"
VERSION = "2.0.0"

MAX_UPLOAD_BYTES = 25 * 1024 * 1024   # tamaño máximo del archivo de captura
LOG_LIMIT_PER_CAPTURE = 500           # máximo de líneas de log por captura analizada
LOG_LIMIT_LIVE = 1000                 # máximo de líneas de log por sesión de captura en vivo

# Estadísticas de la sesión (empiezan en 0 y se reinician al reiniciar el servidor).
stats = {"total": 0, "valid": 0, "dropped": 0, "pending": 0}
recent_events = deque(maxlen=50)
_lock = Lock()  # los endpoints, el análisis y la captura corren en hilos distintos
capture_active = False  # NFQUEUE (Linux, opcional)

# Paquetes guardados por fuente, para verlos campo por campo y exportarlos.
stores = {"live": PacketStore(5000), "pcap": PacketStore(50_000), "lab": PacketStore(500)}

# Estado de la captura en vivo (modo monitor con Npcap/libpcap).
live = {"capture": None, "iface": None, "next_no": 0, "logged": 0}
_live_lock = Lock()


def record_packet(src_ip, dst_ip, result, action, reason,
                  source="simulado", manual_conflict=False, interface=None, log=True):
    """Punto único donde se registra un paquete, venga del laboratorio, de un PCAP o de la red."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ip": src_ip,
        "interface": interface,
        "result": result,
        "action": action,
        "reason": reason,
        "manual_conflict": manual_conflict,
        "source": source,
    }
    with _lock:
        stats["total"] += 1
        if result == "VALID":
            stats["valid"] += 1
        else:
            stats["pending"] += 1
        if action == "DROP":
            stats["dropped"] += 1
        # Los paquetes válidos de PCAP o de la red solo se cuentan: guardarlos todos saturaría el panel.
        if source == "simulado" or result != "VALID":
            recent_events.appendleft(event)
        snapshot = dict(stats)

    # Según la Clase 1, solo se auditan los paquetes descartados (sin payload).
    if action == "DROP" and log:
        log_event(src_ip, dst_ip, action, reason)
    return event, snapshot


def _on_live_frame(timestamp, linktype, data, orig_len):
    """Se ejecuta en el hilo de captura por cada trama real que ve la tarjeta de red."""
    iface = live["iface"]
    live["next_no"] += 1
    record = process_frame(live["next_no"], timestamp, linktype, data, orig_len,
                           local_ips=iface["local_ips"])
    stores["live"].add(record)
    if record["status"] == "SKIPPED":
        return
    write_log = record["action"] == "DROP" and live["logged"] < LOG_LIMIT_LIVE
    if write_log:
        live["logged"] += 1
    reason = record["reason"] if record["status"] == "VALID" else \
        f"[vivo #{record['no']} · monitor] {record['reason']}"
    record_packet(record["src"], record["dst"], record["status"], record["action"], reason,
                  source="vivo", interface=iface["description"], log=write_log)


def _stop_live():
    cap = live["capture"]
    if cap:
        cap.stop()
    live["capture"] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """NFQUEUE (Linux + root) es opcional y solo arranca con NETCHECK_CAPTURE=1."""
    global capture_active
    nfq = None
    if os.environ.get("NETCHECK_CAPTURE") == "1":
        from core.nfqueue_capture import start_capture, stop_capture
        nfq = start_capture(
            functools.partial(record_packet, source="real"),
            queue_num=int(os.environ.get("NETCHECK_QUEUE", "1")),
            fail_open=os.environ.get("NETCHECK_FAIL_OPEN", "1") == "1",
        )
        capture_active = True
    yield
    with _live_lock:
        _stop_live()
    if nfq:
        stop_capture(nfq)
        capture_active = False


app = FastAPI(
    title="NetCheck Firewall Guard API",
    version=VERSION,
    description="Inspección de cabeceras IPv4 sobre tráfico real (Npcap/libpcap), archivos PCAP "
                "y paquetes de laboratorio, con auditoría de descartes.",
    lifespan=lifespan,
)


class SimulationRequest(BaseModel):
    interface: Literal["eth0", "wlan0", "lo"]
    ip: IPv4Address
    headerLength: int = Field(ge=20, le=60, multiple_of=4)
    checksum: Literal["valid", "invalid", "unknown"]
    issue: Literal["none", "checksum", "header", "length"]
    action: Literal["DROP", "ALLOW"]


class StartCaptureRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=200)


class ProbeRequest(BaseModel):
    kind: Literal["checksum", "ttl", "version", "length", "ok"]


@app.get("/api/status")
def get_status():
    cap = live["capture"]
    running = bool(cap and cap.running)
    with _lock:
        return {
            "status": "ACTIVA",
            "version": VERSION,
            "mode": "INTERCEPTACION NFQUEUE" if capture_active else
                    ("MONITOR EN VIVO" if running else "EN ESPERA"),
            "capture": capture_active,
            "live": running,
            "stats": dict(stats),
        }


@app.get("/api/statistics")
def get_statistics():
    with _lock:
        return dict(stats)


@app.get("/api/events")
def get_events():
    with _lock:
        return list(recent_events)


@app.get("/api/alerts")
def get_alerts():
    return {"alerts": get_recent_logs(50)}


@app.post("/api/alerts/ack")
def acknowledge_alerts():
    with _lock:
        stats["pending"] = 0
        return dict(stats)


@app.post("/api/reset")
def reset_session():
    """Pone en cero contadores y actividad de la sesión. No borra el registro de auditoría."""
    with _lock:
        for key in stats:
            stats[key] = 0
        recent_events.clear()
        return dict(stats)


# ---------------- Captura en vivo (monitor) ----------------

def _capture_status():
    cap = live["capture"]
    iface = live["iface"]
    running = bool(cap and cap.running)
    return {
        "running": running,
        "interface": {k: iface[k] for k in ("id", "description", "ips", "loopback", "wireless")} if iface else None,
        "linktype": cap.linktype if cap else None,
        "started_at": cap.started_at if cap else None,
        "error": cap.error if cap else None,
        "counts": dict(stores["live"].counts),
        "logged": live["logged"],
        "log_limit": LOG_LIMIT_LIVE,
    }


@app.get("/api/capture/interfaces")
def capture_interfaces():
    info = live_capture.backend_info()
    interfaces, error = [], info["error"]
    if info["available"]:
        try:
            interfaces = live_capture.list_interfaces()
        except live_capture.NpcapUnavailable as e:
            error = str(e)
    return info | {"error": error, "interfaces": interfaces}


@app.get("/api/capture/status")
def capture_status():
    return _capture_status()


@app.post("/api/capture/start")
def capture_start(body: StartCaptureRequest):
    try:
        interfaces = {i["id"]: i for i in live_capture.list_interfaces()}
    except live_capture.NpcapUnavailable as e:
        raise HTTPException(status_code=503, detail=f"Captura no disponible: {e}")
    iface = interfaces.get(body.interface)
    if not iface:  # solo se aceptan nombres que el propio sistema reporta
        raise HTTPException(status_code=400, detail="Interfaz desconocida.")
    with _live_lock:
        _stop_live()
        stores["live"].clear(label=iface["description"])
        live.update(iface=iface | {"local_ips": frozenset(iface["ips"])}, next_no=0, logged=0)
        try:
            live["capture"] = live_capture.LiveCapture(iface["id"], _on_live_frame)
        except live_capture.NpcapUnavailable as e:
            live["iface"] = None
            raise HTTPException(status_code=503, detail=f"No se pudo abrir la interfaz: {e}")
    return _capture_status()


@app.post("/api/capture/stop")
def capture_stop():
    with _live_lock:
        _stop_live()
    return _capture_status()


@app.post("/api/capture/probe")
def capture_probe(body: ProbeRequest):
    """Inyecta un paquete IPv4 real (válido o malformado) en la interfaz de loopback.
    Va de 127.0.0.1 a 127.0.0.1: nunca sale del equipo."""
    cap = live["capture"]
    if not (cap and cap.running and live["iface"]["loopback"]):
        raise HTTPException(status_code=409,
                            detail="Inicia la captura en la interfaz de loopback para inyectar paquetes de prueba.")
    try:
        cap.send(live_capture.build_loopback_probe(body.kind, cap.linktype))
    except live_capture.NpcapUnavailable as e:
        raise HTTPException(status_code=503, detail=f"No se pudo inyectar: {e}")
    return {"sent": body.kind}


# ---------------- Paquetes (vivo, PCAP, laboratorio) ----------------

Source = Literal["live", "pcap", "lab"]


@app.get("/api/packets/{source}")
def list_packets(source: Source, after: int = Query(0, ge=0), limit: int = Query(300, ge=1, le=1000),
                 only: Literal["all", "ipv4", "anomalies"] = "all",
                 proto: str = Query("", max_length=20), ip: str = Query("", max_length=15)):
    store = stores[source]
    return {"label": store.label, "counts": dict(store.counts),
            "rows": store.rows(after=after, limit=limit, only=only, proto=proto, ip=ip)}


@app.get("/api/packets/{source}/export")
def export_packets(source: Source):
    store = stores[source]
    if not store.counts["total"]:
        raise HTTPException(status_code=404, detail="No hay paquetes para exportar.")
    name = f"netcheck-{source}-{time.strftime('%Y%m%d-%H%M%S')}.pcapng"
    return Response(store.to_pcapng(), media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/packets/{source}/{no}")
def packet_detail(source: Source, no: int):
    record = stores[source].get(no)
    if not record:
        raise HTTPException(status_code=404, detail="Paquete no disponible (puede haber salido del búfer).")
    detail = dissect(record["linktype"], record["data"], record["ip"], record["inspection"])
    detail.update({k: record[k] for k in ("no", "ts", "length", "status", "action", "reason",
                                          "src", "dst", "direction")})
    detail["inspection_details"] = (record["inspection"] or {}).get("details", {})
    return detail


# ---------------- Laboratorio (antes "simulación") ----------------

@app.post("/api/simulate")
def simulate_packet(data: SimulationRequest):
    src_ip = str(data.ip)
    packet = build_test_packet(src_ip, DEST_IP, data.headerLength, data.checksum, data.issue)
    inspection = inspect_ipv4_packet(packet, verify_checksum=(data.checksum != "unknown"))

    result = inspection["status"]
    action = decide_action(inspection)
    reason = inspection["reason"]
    manual_conflict = data.action == "ALLOW" and action == "DROP"

    lab = stores["lab"]
    record = process_frame(lab.counts["total"] + 1, None, 101, packet)
    record.update(status=result, action=action, reason=reason, inspection=inspection)
    lab.add(record)

    event, snapshot = record_packet(
        src_ip, DEST_IP, result, action, reason,
        source="simulado", manual_conflict=manual_conflict, interface=data.interface,
    )
    return {
        "result": result, "action": action, "reason": reason,
        "manual_conflict": manual_conflict, "event": event, "stats": snapshot,
        "packet_no": record["no"],
    }


# ---------------- Archivos PCAP ----------------

def _analyze(raw: bytes, label: str, display: str | None = None) -> dict:
    logged = 0

    def on_packet(number, src, dst, status, action, reason):
        nonlocal logged
        write_log = action == "DROP" and logged < LOG_LIMIT_PER_CAPTURE
        if write_log:
            logged += 1
        record_packet(src, dst, status, action, f"[{label} #{number}] {reason}",
                      source="pcap", log=write_log)

    store = stores["pcap"]
    store.clear(label=display or label)
    summary = analyze_capture(raw, on_packet=on_packet, store=store)
    summary["logged"] = logged
    summary["log_limit"] = LOG_LIMIT_PER_CAPTURE
    return summary


@app.post("/api/analyze-pcap")
async def analyze_pcap(request: Request):
    """Recibe el archivo .pcap/.pcapng como cuerpo binario. No se guarda en disco."""
    try:
        declared = int(request.headers.get("content-length", "0"))
    except ValueError:
        raise HTTPException(status_code=400, detail="Cabecera Content-Length inválida.")
    if declared > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Archivo demasiado grande (máximo 25 MB).")

    chunks, size = [], 0
    async for chunk in request.stream():  # se corta apenas se supera el límite
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Archivo demasiado grande (máximo 25 MB).")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw:
        raise HTTPException(status_code=400, detail="No se recibió ningún archivo.")

    display = unquote(request.headers.get("x-filename", ""))[:80] or None  # solo para mostrar
    try:
        return await run_in_threadpool(_analyze, raw, "pcap", display)
    except PcapError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/api/analyze-sample")
async def analyze_sample():
    """Analiza la captura de ejemplo incluida en samples/ (ruta fija, sin entrada del usuario)."""
    if not SAMPLE_PCAP.is_file():
        raise HTTPException(status_code=404, detail="No se encontró samples/ejemplo.pcap.")
    try:
        return await run_in_threadpool(_analyze, SAMPLE_PCAP.read_bytes(), "ejemplo")
    except PcapError as error:
        raise HTTPException(status_code=400, detail=str(error))


# --- Frontend (después de las rutas /api para no taparlas) ---

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
