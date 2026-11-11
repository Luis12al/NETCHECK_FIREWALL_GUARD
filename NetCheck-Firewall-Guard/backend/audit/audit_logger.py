import logging
import os
import re
import time
from collections import deque
from pathlib import Path

# Carpeta de logs: backend/logs por defecto (no depende de desde dónde ejecutes uvicorn).
# Puedes cambiarla con la variable de entorno NETCHECK_LOG_DIR (p. ej. /var/log en Linux).
LOG_DIR = Path(os.environ.get("NETCHECK_LOG_DIR", Path(__file__).resolve().parents[1] / "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "netcheck.log"

# %(asctime)s usa hora local por defecto; con gmtime el sufijo "UTC" es verdadero.
_formatter = logging.Formatter("%(asctime)s UTC | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
_formatter.converter = time.gmtime

# Logger propio: no depende de logging.basicConfig ni choca con el de uvicorn.
_logger = logging.getLogger("netcheck.audit")
_logger.setLevel(logging.INFO)
_logger.propagate = False
if not _logger.handlers:
    _handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)

_LINE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC \| (?P<level>\w+) \| "
    r"IP_SRC=(?P<ip_src>.*?) \| IP_DST=(?P<ip_dst>.*?) \| "
    r"ACTION=(?P<action>\w+) \| REASON=(?P<reason>.*)$"
)


def _clean(value: object, max_len: int = 200) -> str:
    """Evita inyección de líneas falsas en el log (CWE-117) y mantiene el formato parseable."""
    text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "/")
    return text[:max_len]


def log_event(src_ip: str, dst_ip: str, action: str, reason: str) -> None:
    message = (
        f"IP_SRC={_clean(src_ip)} | IP_DST={_clean(dst_ip)} | "
        f"ACTION={_clean(action)} | REASON={_clean(reason)}"
    )
    if action == "DROP":
        _logger.warning(message)
    else:
        _logger.info(message)


def get_recent_logs(limit: int = 50) -> list[dict]:
    """Devuelve los últimos eventos como diccionarios, del más reciente al más antiguo."""
    if not LOG_FILE.exists():
        return []
    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
        last_lines = deque(f, maxlen=limit)  # solo guarda las últimas N líneas en memoria
    events = []
    for line in reversed(last_lines):
        match = _LINE.match(line.strip())
        if match:
            events.append(match.groupdict())
    return events
