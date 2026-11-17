#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
command -v python3 >/dev/null || { echo "No se encontró python3 (3.10 o superior)."; exit 1; }
[ -x .venv/bin/python ] || python3 -m venv .venv
.venv/bin/python -m pip install --quiet --disable-pip-version-check -r requirements.txt
echo "NetCheck Firewall Guard listo en http://127.0.0.1:8000/  (Ctrl+C para detener)"
cd backend
exec ../.venv/bin/python main.py
