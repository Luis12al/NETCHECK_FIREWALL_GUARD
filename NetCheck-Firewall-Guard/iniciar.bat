@echo off
setlocal
cd /d "%~dp0"
title NetCheck Firewall Guard

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY goto :nopython

if not exist ".venv\Scripts\python.exe" %PY% -m venv .venv
if not exist ".venv\Scripts\python.exe" goto :novenv

echo Instalando dependencias (solo la primera vez tarda)...
".venv\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto :nopip

echo.
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
  echo Npcap detectado: el Monitor en vivo puede capturar el trafico real de este equipo.
) else (
  echo AVISO: Npcap no esta instalado. El Monitor en vivo no estara disponible;
  echo        el analisis de archivos PCAP y el Laboratorio funcionan igual.
  echo        Para activarlo instala Npcap desde https://npcap.com ^(viene con Wireshark^)
  echo        SIN marcar "Restrict Npcap driver's access to Administrators only".
)
echo.
echo NetCheck Firewall Guard listo en http://127.0.0.1:8000/
echo Cierra esta ventana o pulsa Ctrl+C para detenerlo.
start "" /min cmd /c "ping -n 4 127.0.0.1 >nul & start http://127.0.0.1:8000/"
cd backend
"..\.venv\Scripts\python.exe" main.py
goto :end

:nopython
echo No se encontro Python 3.10 o superior.
echo Instalalo desde https://www.python.org/downloads/ y marca la casilla "Add python.exe to PATH".
goto :end

:novenv
echo No se pudo crear el entorno virtual.
goto :end

:nopip
echo Fallo la instalacion de dependencias. Revisa tu conexion a internet y vuelve a intentarlo.

:end
pause
