"""
Registro de auditoría con integridad verificable y tamaño acotado.

- Integridad: cada línea termina con MAC=<HMAC-SHA256(clave, MAC_anterior || línea)>.
  Las líneas quedan encadenadas: si alguien modifica, borra o reordena una línea,
  la verificación falla a partir de ese punto. Sin la clave no se pueden recalcular.
- Disponibilidad: el archivo rota al llegar a 2 MB y se conservan 5 archivos
  (máximo ~12 MB), así un flujo de descartes no puede llenar el disco.
- Confidencialidad: nunca se guarda el contenido (payload) de los paquetes; la clave y
  el log se crean con permisos solo para el usuario (en Linux/macOS).
"""
import hashlib
import hmac
import logging
import logging.handlers
import os
import re
import secrets
import threading
import time
from collections import deque
from pathlib import Path

# Carpeta de logs: backend/logs por defecto. Puede cambiarse con NETCHECK_LOG_DIR.
LOG_DIR = Path(os.environ.get("NETCHECK_LOG_DIR", Path(__file__).resolve().parents[1] / "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "netcheck.log"
KEY_FILE = LOG_DIR / ".netcheck.key"
MAX_BYTES = int(os.environ.get("NETCHECK_LOG_MAX_BYTES", 2 * 1024 * 1024))
BACKUPS = 5
GENESIS = "0" * 64


def _restrict(path: Path):
    try:
        os.chmod(path, 0o600)  # en Windows solo afecta el atributo de solo lectura
    except OSError:
        pass


def _load_key() -> bytes:
    env = os.environ.get("NETCHECK_LOG_KEY")
    if env:
        return env.encode()
    if not KEY_FILE.exists():
        KEY_FILE.write_text(secrets.token_hex(32), encoding="ascii")
        _restrict(KEY_FILE)
    return KEY_FILE.read_text(encoding="ascii").strip().encode()


_KEY = _load_key()

_formatter = logging.Formatter("%(asctime)s UTC | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
_formatter.converter = time.gmtime

_logger = logging.getLogger("netcheck.audit")
_logger.setLevel(logging.INFO)
_logger.propagate = False
if not _logger.handlers:
    _handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUPS,
                                                    encoding="utf-8")
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)
    _restrict(LOG_FILE)

_LINE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC \| (?P<level>\w+) \| "
    r"IP_SRC=(?P<ip_src>.*?) \| IP_DST=(?P<ip_dst>.*?) \| "
    r"ACTION=(?P<action>\w+) \| REASON=(?P<reason>.*?)(?: \| MAC=(?P<mac>[0-9a-f]{64}))?$"
)
_MAC_SUFFIX = re.compile(r" \| MAC=([0-9a-f]{64})$")
_chain_lock = threading.Lock()


def _mac(prev: str, body: str) -> str:
    return hmac.new(_KEY, (prev + "\n" + body).encode("utf-8"), hashlib.sha256).hexdigest()


def _log_files() -> list[Path]:
    """Archivos del más antiguo al más reciente (netcheck.log.5 … netcheck.log)."""
    files = [LOG_DIR / f"netcheck.log.{i}" for i in range(BACKUPS, 0, -1)]
    return [f for f in files if f.exists()] + ([LOG_FILE] if LOG_FILE.exists() else [])


def _last_mac() -> str:
    for f in reversed(_log_files()):
        with open(f, "r", encoding="utf-8", errors="replace") as fh:
            tail = deque(fh, maxlen=1)
        if tail:
            m = _MAC_SUFFIX.search(tail[0].rstrip("\n"))
            return m.group(1) if m else GENESIS
    return GENESIS


_prev_mac = _last_mac()


def _clean(value: object, max_len: int = 200) -> str:
    """Evita inyección de líneas falsas en el log (CWE-117) y mantiene el formato parseable."""
    text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "/")
    return text[:max_len]


def log_event(src_ip: str, dst_ip: str, action: str, reason: str) -> None:
    global _prev_mac
    message = (
        f"IP_SRC={_clean(src_ip)} | IP_DST={_clean(dst_ip)} | "
        f"ACTION={_clean(action)} | REASON={_clean(reason)}"
    )
    level = logging.WARNING if action == "DROP" else logging.INFO
    with _chain_lock:  # el encadenamiento exige un solo escritor a la vez
        record = _logger.makeRecord(_logger.name, level, __file__, 0, message, None, None)
        body = _formatter.format(record)
        mac = _mac(_prev_mac, body)
        record.msg = f"{message} | MAC={mac}"
        _logger.handle(record)
        _prev_mac = mac


def log_operator(action: str, detail: str) -> None:
    """Acciones del operador (iniciar/detener captura, reiniciar, inyectar…): trazabilidad."""
    log_event("OPERADOR", "-", action, detail)


def verify_log() -> dict:
    """Recalcula la cadena HMAC de todos los archivos del registro."""
    files = _log_files()
    # Si ya se rotaron más archivos de los que se conservan, la primera línea del más antiguo
    # se encadena con una línea que ya no existe: se acepta como punto de partida.
    oldest_was_pruned = bool(files) and files[0].name == f"netcheck.log.{BACKUPS}"
    prev = None
    total = signed = unsigned = 0

    def broken(f, lineno, why):
        return {"ok": False, "total": total, "signed": signed, "unsigned": unsigned,
                "broken_at": {"file": f.name, "line": lineno},
                "detail": f"Línea {lineno} de {f.name}: {why}", "files": [x.name for x in files]}

    for f in files:
        with open(f, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip("\n")
                if not line:
                    continue
                total += 1
                m = _MAC_SUFFIX.search(line)
                if not m:
                    if prev is not None:  # nada sin firma puede aparecer después de una línea firmada
                        return broken(f, lineno, "línea sin firma insertada en el registro.")
                    unsigned += 1  # líneas de versiones anteriores, antes de existir la firma
                    continue
                body, mac = line[:m.start()], m.group(1)
                if prev is None and oldest_was_pruned and signed == 0:
                    prev, signed = mac, 1
                    continue
                if not hmac.compare_digest(_mac(prev or GENESIS, body), mac):
                    return broken(f, lineno, "fue modificada, o se borró o reordenó una línea anterior.")
                prev = mac
                signed += 1
    with _chain_lock:
        last_written = _prev_mac
    if (prev or GENESIS) != last_written:  # la cadena es correcta pero le faltan las últimas líneas
        return {"ok": False, "total": total, "signed": signed, "unsigned": unsigned, "broken_at": None,
                "detail": "Faltan líneas al final del registro: la última firma no coincide con la "
                          "última que escribió el servidor.", "files": [x.name for x in files]}
    return {"ok": True, "total": total, "signed": signed, "unsigned": unsigned, "broken_at": None,
            "detail": "Cadena íntegra." if signed else "No hay líneas firmadas todavía.",
            "files": [f.name for f in _log_files()],
            "size_bytes": sum(f.stat().st_size for f in _log_files())}


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
            item = match.groupdict()
            item["signed"] = bool(item.pop("mac"))
            events.append(item)
    return events
