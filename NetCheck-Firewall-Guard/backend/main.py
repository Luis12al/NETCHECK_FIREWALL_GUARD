from collections import deque
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path
from threading import Lock
from typing import Literal

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core.packet_inspector import inspect_ipv4_packet
from core.packet_simulator import build_test_packet
from core.decision_engine import decide_action
from audit.audit_logger import log_event, get_recent_logs

app = FastAPI(
    title="NetCheck Firewall Guard API",
    version="1.1.0",
    description="Backend API para inspección de paquetes IPv4 y auditoría"
)

# backend/main.py -> sube un nivel -> frontend/
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
DEST_IP = "192.168.1.1"


class SimulationRequest(BaseModel):
    interface: Literal["eth0", "wlan0", "lo"]
    ip: IPv4Address
    headerLength: int = Field(ge=20, le=60, multiple_of=4)
    checksum: Literal["valid", "invalid", "unknown"]
    issue: Literal["none", "checksum", "header", "length"]
    action: Literal["DROP", "ALLOW"]


# Estadísticas reales de la sesión (empiezan en 0 y se reinician al reiniciar el servidor).
stats = {"total": 0, "valid": 0, "dropped": 0, "pending": 0}
recent_events = deque(maxlen=50)
_lock = Lock()  # los endpoints síncronos corren en hilos distintos


@app.get("/api/status")
def get_status():
    with _lock:
        return {"status": "ACTIVA", "mode": "FASTAPI BACKEND", "stats": dict(stats)}


@app.get("/api/statistics")
def get_statistics():
    with _lock:
        return dict(stats)


@app.get("/api/events")
def get_events():
    """Actividad reciente de la sesión (válidos y descartados)."""
    with _lock:
        return list(recent_events)


@app.get("/api/alerts")
def get_alerts():
    """Paquetes descartados leídos del registro de auditoría (netcheck.log)."""
    return {"alerts": get_recent_logs(50)}


@app.post("/api/alerts/ack")
def acknowledge_alerts():
    with _lock:
        stats["pending"] = 0
        return dict(stats)


@app.post("/api/simulate")
def simulate_packet(data: SimulationRequest):
    src_ip = str(data.ip)
    packet = build_test_packet(src_ip, DEST_IP, data.headerLength, data.checksum, data.issue)
    inspection = inspect_ipv4_packet(packet, verify_checksum=(data.checksum != "unknown"))

    result = inspection["status"]            # VALID | INVALID | UNVERIFIED
    action = decide_action(inspection)       # ALLOW | DROP
    reason = inspection["reason"]
    manual_conflict = data.action == "ALLOW" and action == "DROP"

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ip": src_ip,
        "interface": data.interface,
        "result": result,
        "action": action,
        "reason": reason,
        "manual_conflict": manual_conflict,
    }

    with _lock:
        stats["total"] += 1
        if result == "VALID":
            stats["valid"] += 1
        else:
            stats["pending"] += 1
        if action == "DROP":
            stats["dropped"] += 1
        recent_events.appendleft(event)
        snapshot = dict(stats)

    # Según la Clase 1, solo se auditan los paquetes descartados (sin payload).
    if action == "DROP":
        log_event(src_ip, DEST_IP, action, reason)

    return {
        "result": result,
        "action": action,
        "reason": reason,
        "manual_conflict": manual_conflict,
        "event": event,
        "stats": snapshot,
    }


# --- Frontend ---
# Deben ir DESPUÉS de las rutas /api para no taparlas.

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
