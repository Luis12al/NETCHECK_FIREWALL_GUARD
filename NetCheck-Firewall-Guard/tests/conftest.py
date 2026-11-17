import os
import sys
import tempfile
from pathlib import Path

# El log de las pruebas va a una carpeta temporal: no se mezcla con el registro real.
os.environ["NETCHECK_LOG_DIR"] = tempfile.mkdtemp(prefix="netcheck-test-")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "samples"))

# El cliente de pruebas se presenta como "testserver" y usa un token fijo conocido.
os.environ["NETCHECK_ALLOWED_HOSTS"] = "testserver"
os.environ["NETCHECK_TOKEN"] = "token-de-prueba"
os.environ["NETCHECK_RATE"] = "100000"
os.environ["NETCHECK_BURST"] = "100000"
AUTH = {"X-NetCheck-Token": "token-de-prueba"}
