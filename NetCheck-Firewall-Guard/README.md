# NetCheck Firewall Guard

**Sensor de integridad de cabeceras IPv4 (IDS pasivo) con auditoría.**
Proyecto académico de Seguridad en Redes · Equipo **Arepas.exe** · versión 2.1.0

Integrantes: Luis Alejandro Toloza Mendoza · Nicoll Navarro Simanca · Luz Marina Sanchez Rodriguez

NetCheck lee paquetes **reales** de la tarjeta de red del equipo, o de archivos de captura, y revisa
byte a byte que la cabecera IPv4 esté bien formada. Recalcula el checksum (RFC 1071), decide **ALLOW**
o **DROP** y deja constancia de cada descarte en un registro de auditoría. Todo se ve en un panel web
local que muestra cada paquete campo por campo, con su volcado hexadecimal, al estilo de Wireshark.

> **En una frase:** detecta paquetes IPv4 malformados y lo demuestra con tráfico real, pero **no es un
> firewall completo ni bloquea ataques**. Es una capa más dentro de una defensa en profundidad.

---

## ✅ Lo que SÍ hace

| Capacidad | Detalle |
|---|---|
| **Captura tráfico real del equipo** | Monitor en vivo sobre la Wi‑Fi, la Ethernet o el loopback, usando Npcap (Windows) o libpcap (Linux/macOS), la misma biblioteca que usa Wireshark |
| **Inspecciona la cabecera IPv4** | Versión, IHL (longitud de cabecera), longitud total, TTL y checksum recalculado. Si un paquete tiene varias anomalías, las reporta todas |
| **Muestra cada paquete por dentro** | Ethernet, IPv4, TCP, UDP e ICMP campo por campo. Al pasar el cursor por un campo se resaltan sus bytes exactos en el volcado hexadecimal |
| **Demuestra la detección con paquetes reales** | Inyecta en loopback paquetes malformados reales (checksum alterado, TTL 0, versión 5 y longitud falsa) que nunca salen del equipo |
| **Analiza archivos de captura** | Archivos `.pcap` y `.pcapng` de Wireshark o tcpdump. El número de cada paquete coincide con el de Wireshark |
| **Laboratorio de reglas** | Construye un paquete con el defecto que elijas y comprueba cada regla por separado |
| **Auditoría** | Escribe cada DROP en `backend/logs/netcheck.log` en UTC, sin el contenido del paquete y a prueba de inyección de líneas falsas |
| **Exporta evidencia** | Descarga lo capturado en `.pcapng` para verificarlo en Wireshark, y un reporte en `.txt` |
| **Maneja bien el *checksum offload*** | Los paquetes que salen del propio equipo llevan el checksum en `0x0000` porque lo calcula la tarjeta de red. Solo se acepta ese valor exacto y solo en tráfico saliente, para no dar falsos positivos |
| **Protege sus propios datos (tríada CID)** | Token de sesión, protección anti-CSRF y anti DNS rebinding, contenido de los paquetes oculto por defecto, log firmado con HMAC encadenado, rotación del log, límite de peticiones y reconexión automática de la captura. Detalle en la sección «Tríada CID» |
| **Pruebas automáticas** | 86 pruebas con pytest, 22 de ellas sobre la tríada CID; una hace una captura real en loopback |
| **Funciona sin VM ni administrador** | Si Npcap se instaló sin la opción «solo administradores» |

## ❌ Lo que NO hace

| Limitación | Por qué importa |
|---|---|
| **No bloquea tráfico** | En modo monitor recibe una *copia* de cada paquete. DROP significa «se descartaría»; el paquete llega igual. El bloqueo real (NFQUEUE) es un módulo opcional que solo funciona en Linux con root |
| **No resiste a un atacante** | El checksum detecta errores, **no autentica**. Un atacante recalcula un checksum válido sin esfuerzo, así que un paquete malicioso pero bien formado pasa como ALLOW |
| **No inspecciona el contenido** | No detecta malware, exploits, inyección SQL ni phishing, porque viajan en paquetes con cabeceras válidas |
| **No analiza IPv6** | Lo muestra y lo cuenta, pero no lo inspecciona. En muchas redes domésticas es la mayor parte del tráfico |
| **No sigue el contexto** | Revisa cada paquete por separado. No detecta escaneos de puertos, fuerza bruta, suplantación de IP ni ataques por fragmentación |
| **No resiste inundaciones (DoS)** | Es un prototipo en Python. Con muchos miles de paquetes por segundo empieza a perder paquetes |
| **No verifica checksums de TCP, UDP ni ICMP** | Los muestra, pero el alcance del proyecto es la cabecera IPv4 |
| **No ve lo que el sistema ya descartó** | La tarjeta de red y Windows tiran los paquetes corruptos que llegan de la red antes de que se puedan capturar. Por eso las anomalías se demuestran con la inyección en loopback y con archivos PCAP |
| **No guarda datos de forma permanente** | Contadores y paquetes viven en memoria y se pierden al cerrar el servidor. Solo el log queda en disco |

## ⚠️ Riesgos residuales de la propia herramienta

Lo que la versión 2.1 **no** cubre, aunque aplique la tríada CID:

- **Quien controla el equipo controla la herramienta.** Un programa malicioso que ya corre con tu usuario
  puede leer el token de la página, la clave del log o los archivos. La tríada protege frente a páginas
  web y equipos externos, no frente a un equipo ya comprometido.
- **La firma del log depende de la clave.** `backend/logs/.netcheck.key` está excluida de git; quien la
  obtenga puede recalcular las firmas. Para una auditoría formal, guarda una copia de la última firma
  (o del log completo) fuera del equipo.
- **Borrar el final del log con el servidor apagado** no se puede detectar: la comprobación de las
  últimas líneas compara con la última firma que escribió el servidor en ejecución.
- **Sin HTTPS:** no hace falta mientras el servidor solo escuche en `127.0.0.1`. No lo expongas a la red.

---

## 🚀 Inicio rápido (Windows)

1. Instala **Python 3.10+** desde [python.org](https://www.python.org/downloads/) y marca *Add python.exe to PATH*.
2. Instala **Npcap** desde [npcap.com](https://npcap.com); ya viene si tienes Wireshark o Nmap.
   **No marques** *Restrict Npcap driver's access to Administrators only*.
3. Haz doble clic en **`iniciar.bat`**. Crea el entorno virtual, instala `fastapi` y `uvicorn`, avisa
   si falta Npcap y abre el navegador en http://127.0.0.1:8000/.

En Linux o macOS usa `./iniciar.sh`. En Linux, capturar requiere libpcap y permisos, por ejemplo:
`sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python3)`.

> Sin Npcap el Monitor en vivo no está disponible, pero el análisis de archivos PCAP y el Laboratorio funcionan igual.

## 🔍 Cómo comprobar que el análisis es real (10 minutos)

1. **Tráfico propio.** En *Monitor en vivo*, elige tu Wi‑Fi o Ethernet (aparece con su IP real), pulsa
   **Iniciar captura** y ejecuta `ping -4 8.8.8.8` o abre una página web. Aparecen tus conexiones
   reales. Haz clic en un paquete para ver sus campos y el checksum recalculado.
2. **Detección.** En *Prueba de detección*, pulsa **Checksum alterado**. El panel cambia a loopback,
   inyecta el paquete, lo marca como **DROP** y lo escribe en el log con el prefijo `[vivo #N · monitor]`.
3. **Contraste con Wireshark.** Descarga el **.pcapng** y ábrelo en Wireshark. Los números de paquete,
   IPs y checksums deben coincidir.
4. **Captura de ejemplo.** En *Archivo PCAP*, pulsa **Usar captura de ejemplo**. Resultado esperado:
   13 tramas, 11 IPv4 analizadas, 5 válidas, 6 con anomalías y 2 omitidas (ARP e IPv6).
5. **Pruebas automáticas:**
   ```
   .venv\Scripts\python -m pip install -r requirements-dev.txt
   .venv\Scripts\python -m pytest
   ```

## 🛡️ Tríada CID (confidencialidad, integridad, disponibilidad)

La página **Seguridad (CID)** del panel muestra cada control con su estado en vivo, y la verificación
del log se lanza con un botón. Cada control tiene pruebas automáticas en `tests/test_security.py`.

### 🔒 Confidencialidad: solo quien debe ve los datos

| Control | Contra qué protege | Dónde |
|---|---|---|
| **Token de sesión** aleatorio y obligatorio en toda la API (`X-NetCheck-Token`), comparado en tiempo constante | Otros programas o páginas que intenten leer los paquetes capturados | `security.py` |
| **Lista blanca de Host** (`127.0.0.1`, `localhost`, `[::1]`) | DNS rebinding: una web que apunta su dominio a 127.0.0.1 | `security.py` |
| **Validación de `Origin` y `Sec-Fetch-Site`** | CSRF: una web maliciosa que envía peticiones a tu panel | `security.py` |
| **CSP estricta** (sin scripts en línea ni externos), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `Cache-Control: no-store` | XSS, clickjacking y fugas por caché o por Referer | `security.py`, `frontend/` |
| **Contenido (payload) oculto por defecto** en el panel y en la exportación `.pcapng`; se activa con «Mostrar contenido» | Exponer contraseñas o mensajes que viajan en los paquetes | `main.py` |
| **Captura sin modo promiscuo** | Leer tráfico de otros dispositivos de la red | `live_capture.py` |
| **El log nunca guarda payload**; la clave del log está excluida de git | Fugas a través del registro o del repositorio | `audit_logger.py`, `.gitignore` |
| **Servidor solo en `127.0.0.1`** y sin cabecera `Server` | Acceso desde otros equipos y reconocimiento de versiones | `main.py` |

### 🔏 Integridad: los datos no cambian sin que se note

| Control | Detalle |
|---|---|
| **Log firmado y encadenado** | Cada línea termina en `MAC=HMAC-SHA256(clave, MAC_anterior ‖ línea)`. Modificar, borrar, reordenar o insertar una línea rompe la cadena desde ese punto |
| **Verificación a demanda** | Botón *Verificar log ahora* o `GET /api/audit/verify`: indica el archivo y la línea alterados |
| **Trazabilidad del operador** | Inicio y fin de captura, inyecciones, reinicios, alertas revisadas, exportaciones y verificaciones quedan en el log firmado |
| **Huellas SHA-256** | De cada archivo analizado y de cada exportación (cabecera `X-Content-SHA256`). Compruébala con `Get-FileHash archivo.pcapng` |
| **Integridad de los paquetes** | Checksum IPv4 recalculado según RFC 1071 (detecta corrupción, no autentica) |
| **Entradas validadas** | Pydantic, interfaces aceptadas solo si las reporta el sistema, límites de tamaño |
| **Dependencias con versión fija** | `requirements.txt` con versiones exactas |

### ⚡ Disponibilidad: el servicio sigue en pie ante fallos y abusos

| Control | Detalle |
|---|---|
| **Límite de peticiones** | 60 por segundo con ráfagas de hasta 150 (configurable); por encima responde 429 |
| **Concurrencia acotada** | Máximo 64 conexiones, keep-alive de 5 s y un solo análisis de archivo a la vez |
| **Rotación del log** | 2 MB × 6 archivos (unos 12 MB como máximo) y tope de líneas por captura: una avalancha de descartes no llena el disco. La cadena de firmas sigue verificable entre archivos |
| **Reconexión automática** | Si la Wi‑Fi se cae o cambia de red, la captura reintenta abrir la interfaz hasta 5 veces |
| **Búfer de 8 MB en el driver** y conteo de tramas perdidas | Absorbe ráfagas; las pérdidas se ven en el panel en lugar de pasar inadvertidas |
| **Memoria acotada** | Búferes circulares (5.000, 50.000 y 500 paquetes) y subidas de 25 MB como máximo |
| **Aviso de disco lleno** | El panel avisa cuando quedan menos de 100 MB libres |
| **Un paquete raro no tumba la captura** | Los errores por paquete se cuentan sin detener el hilo; NFQUEUE opcional en modo *fail-open* |

> Para usar `/docs`, copia el **token de sesión** que se muestra en la consola al iniciar y pégalo en el botón *Authorize*.

## ⚙️ Cómo funciona

```
Tarjeta de red ─┐
Archivo .pcap ──┼─► ubicar IPv4 ─► inspector (RFC 1071) ─► motor de decisión ─► panel + log de auditoría
Laboratorio ────┘                   versión, IHL, longitud,   VALID → ALLOW
                                    TTL, checksum             INVALID / UNVERIFIED → DROP
```

Las tres fuentes pasan por **el mismo inspector y el mismo motor de decisión**: una regla probada en el
Laboratorio se comporta igual sobre el tráfico real.

| Estado | Causa | Acción |
|---|---|---|
| VALID | Todas las comprobaciones pasan | ALLOW |
| VALID (offload) | Paquete saliente propio con checksum `0x0000` | ALLOW·NIC |
| INVALID | Una o más anomalías | DROP |
| UNVERIFIED | Checksum no comprobado o error de parseo | DROP (política restrictiva) |
| SKIPPED | No es IPv4 (IPv6, ARP…) | Se cuenta y se omite |

Formato de cada línea del log:

```
2026-11-16 22:58:41 UTC | WARNING | IP_SRC=127.0.0.1 | IP_DST=127.0.0.1 | ACTION=DROP | REASON=[vivo #292 · monitor] Checksum de cabecera incorrecto
```

## 📁 Estructura

```
iniciar.bat / iniciar.sh         Instalación y arranque en un paso
backend/main.py                  API FastAPI y servidor del panel
backend/security.py              Token, Host/Origin, cabeceras de seguridad y límite de peticiones
backend/core/live_capture.py     Captura en vivo con Npcap/libpcap (ctypes) e inyección en loopback
backend/core/packet_store.py     Procesa cada trama, búfer de paquetes y exportación .pcapng
backend/core/dissector.py        Disección por campos con posición de cada byte
backend/core/packet_inspector.py Reglas de la cabecera IPv4 y checksum RFC 1071
backend/core/decision_engine.py  VALID → ALLOW; INVALID/UNVERIFIED → DROP
backend/core/pcap_reader.py      Lector .pcap/.pcapng en Python puro
backend/core/pcap_analysis.py    Análisis de archivos de captura
backend/core/packet_simulator.py Paquetes del Laboratorio
backend/core/nfqueue_capture.py  (Opcional) bloqueo real con NFQUEUE en Linux + root
backend/audit/audit_logger.py    Registro de auditoría firmado (HMAC encadenado) con rotación
frontend/index.html, app.js, app.css  Panel web (sin scripts en línea, compatible con CSP)
samples/                         Capturas de ejemplo y su generador
tests/                           86 pruebas automáticas (pytest)
```

Documentación interactiva de la API: http://127.0.0.1:8000/docs

## 📏 Referencias normativas citadas en los informes

| Control | Referencia |
|---|---|
| Validación de entradas y de cabeceras; Host y Origin | OWASP ASVS V5.1 |
| Token de sesión, CSRF, cabeceras de seguridad y CSP | OWASP ASVS V3 / V14 |
| Log sin datos sensibles, firmado y con trazabilidad | OWASP ASVS V7, NIST SSDF PW.9 |
| Segmentación y exposición mínima (solo `127.0.0.1`, sin modo promiscuo) | ISO/IEC 27033 |
| Límites, rotación y reconexión | ISO/IEC 27001 A.8.6 (gestión de capacidad) |
| Pruebas automáticas de cada control | NIST SSDF PW.8 |

> Confirma la numeración exacta de cada control en las fuentes oficiales antes de entregar el informe.

## 🧭 Uso responsable

- Captura solo redes y equipos propios o con autorización.
- Presenta los resultados como **detección**: en modo monitor nada se bloquea.
- Para proteger de verdad un equipo, combina esta herramienta con el firewall del sistema,
  actualizaciones, contraseñas fuertes con MFA, un antivirus o EDR y, en redes grandes, un IDS completo
  como Suricata o Zeek.

## 📚 Más documentación

- **Manual de instalación**: requisitos, Npcap y solución de problemas.
- **Manual de uso**: cómo operar cada sección del panel, con capturas.
- **Manual de funcionamiento**: arquitectura, reglas, API y controles.
