"""
Controles de seguridad de la API y del panel (tríada CID).

Confidencialidad
- Token de sesión aleatorio: toda ruta /api exige la cabecera X-NetCheck-Token. Solo el panel
  servido por este mismo servidor lo conoce (va embebido en la página).
- Host permitido: solo 127.0.0.1, localhost o [::1]. Bloquea ataques de "DNS rebinding".
- Origin / Sec-Fetch-Site: una página de otro sitio no puede usar la API (CSRF).
- Cabeceras de seguridad: CSP sin scripts externos ni en línea, sin iframes, nosniff,
  sin Referer y sin caché en las respuestas de la API.

Disponibilidad
- Límite de peticiones por segundo (cubeta de fichas) para que un cliente desbocado
  no deje sin servicio al panel.
"""
import hmac
import os
import secrets
import threading
import time

from fastapi.responses import JSONResponse

TOKEN_HEADER = "X-NetCheck-Token"
API_TOKEN = os.environ.get("NETCHECK_TOKEN") or secrets.token_urlsafe(32)
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"} | {
    h.strip() for h in os.environ.get("NETCHECK_ALLOWED_HOSTS", "").split(",") if h.strip()}
RATE_PER_SECOND = float(os.environ.get("NETCHECK_RATE", "60"))
RATE_BURST = float(os.environ.get("NETCHECK_BURST", "150"))
PUBLIC_PATHS = {"/", "/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect", "/favicon.ico"}
DOCS_PATHS = {"/docs", "/redoc", "/docs/oauth2-redirect"}

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), usb=()",
}

counters = {"rejected_host": 0, "rejected_origin": 0, "rejected_token": 0, "rate_limited": 0}
_bucket = {"tokens": RATE_BURST, "at": time.monotonic()}
_bucket_lock = threading.Lock()


def _take_token() -> bool:
    with _bucket_lock:
        now = time.monotonic()
        _bucket["tokens"] = min(RATE_BURST, _bucket["tokens"] + (now - _bucket["at"]) * RATE_PER_SECOND)
        _bucket["at"] = now
        if _bucket["tokens"] >= 1:
            _bucket["tokens"] -= 1
            return True
        return False


def _hostname(host: str) -> str:
    if host.startswith("["):  # IPv6 con puerto: [::1]:8000
        return host.split("]")[0] + "]"
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _reject(status: int, detail: str, counter: str):
    counters[counter] += 1
    return JSONResponse({"detail": detail}, status_code=status, headers=BASE_HEADERS)


async def security_middleware(request, call_next):
    host = request.headers.get("host", "")
    if _hostname(host) not in ALLOWED_HOSTS:
        return _reject(400, "Host no permitido.", "rejected_host")

    origin = request.headers.get("origin")
    if origin and origin not in (f"http://{host}", f"https://{host}"):
        return _reject(403, "Origen no permitido.", "rejected_origin")
    if request.headers.get("sec-fetch-site") == "cross-site":
        return _reject(403, "Petición desde otro sitio bloqueada.", "rejected_origin")

    path = request.url.path
    if path.startswith("/api/"):
        if not _take_token():
            return _reject(429, "Demasiadas peticiones. Espera un momento.", "rate_limited")
        sent = request.headers.get(TOKEN_HEADER, "")
        if not hmac.compare_digest(sent.encode(), API_TOKEN.encode()):
            return _reject(401, "Falta el token de sesión o no es válido.", "rejected_token")

    response = await call_next(request)
    for name, value in BASE_HEADERS.items():
        response.headers.setdefault(name, value)
    if path not in DOCS_PATHS:  # Swagger UI carga sus archivos desde un CDN
        response.headers.setdefault("Content-Security-Policy", CSP)
    if path.startswith("/api/") or path == "/":
        response.headers["Cache-Control"] = "no-store"
    return response


def status() -> dict:
    return {
        "token_required": True,
        "allowed_hosts": sorted(ALLOWED_HOSTS),
        "rate_limit": {"per_second": RATE_PER_SECOND, "burst": RATE_BURST},
        "headers": sorted(list(BASE_HEADERS) + ["Content-Security-Policy", "Cache-Control"]),
        "rejected": dict(counters),
    }
