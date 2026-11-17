"""
Captura en vivo (modo monitor) usando la biblioteca de captura del sistema:
Npcap (wpcap.dll) en Windows o libpcap en Linux/macOS, llamada directamente con ctypes.

Es la misma biblioteca que usa Wireshark. Entrega una COPIA de cada trama que pasa por
la tarjeta de red, por eso el programa puede inspeccionar el tráfico real del equipo
pero NO puede bloquearlo: la decisión DROP se registra como "habría descartado".
Para bloquear de verdad hace falta interceptar (NFQUEUE en Linux, WinDivert en Windows).

En Windows no requiere administrador si Npcap se instaló sin la opción
"Restrict Npcap driver's access to Administrators only" (así viene con Nmap/Wireshark).
"""
import ctypes
import ctypes.util
import os
import socket
import struct
import sys
import threading
import time

ERRBUF = 256
SNAPLEN = 65535


class NpcapUnavailable(RuntimeError):
    """No hay biblioteca de captura instalada o no se puede abrir la interfaz."""


class _sockaddr(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("data", ctypes.c_ubyte * 14)]


class _pcap_addr(ctypes.Structure):
    pass


_pcap_addr._fields_ = [("next", ctypes.POINTER(_pcap_addr)), ("addr", ctypes.POINTER(_sockaddr)),
                       ("netmask", ctypes.POINTER(_sockaddr)), ("broadaddr", ctypes.POINTER(_sockaddr)),
                       ("dstaddr", ctypes.POINTER(_sockaddr))]


class _pcap_if(ctypes.Structure):
    pass


_pcap_if._fields_ = [("next", ctypes.POINTER(_pcap_if)), ("name", ctypes.c_char_p),
                     ("description", ctypes.c_char_p), ("addresses", ctypes.POINTER(_pcap_addr)),
                     ("flags", ctypes.c_uint)]


class _timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _pkthdr(ctypes.Structure):
    _fields_ = [("ts", _timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class _pcap_stat(ctypes.Structure):
    _fields_ = [("ps_recv", ctypes.c_uint), ("ps_drop", ctypes.c_uint), ("ps_ifdrop", ctypes.c_uint)]


MAX_RECONNECTS = 5
RECONNECT_DELAY = 2.0
BUFFER_BYTES = 8 * 1024 * 1024  # búfer del driver: absorbe ráfagas de tráfico sin perder tramas


PCAP_IF_LOOPBACK, PCAP_IF_UP, PCAP_IF_RUNNING, PCAP_IF_WIRELESS = 0x1, 0x2, 0x4, 0x8
PCAP_IF_CONNECTION_STATUS = 0x30
PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x10

_lib = None
_lib_error = None


def _load():
    global _lib, _lib_error
    if _lib or _lib_error:
        return _lib
    try:
        if sys.platform == "win32":
            npcap_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
            if not os.path.isdir(npcap_dir):
                raise OSError("Npcap no está instalado")
            os.add_dll_directory(npcap_dir)
            lib = ctypes.CDLL(os.path.join(npcap_dir, "wpcap.dll"))
        else:
            path = ctypes.util.find_library("pcap")
            if not path:
                raise OSError("libpcap no está instalada")
            lib = ctypes.CDLL(path)
        lib.pcap_lib_version.restype = ctypes.c_char_p
        lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_pcap_if)), ctypes.c_char_p]
        lib.pcap_freealldevs.argtypes = [ctypes.POINTER(_pcap_if)]
        lib.pcap_open_live.restype = ctypes.c_void_p
        lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        lib.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_pkthdr)),
                                     ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
        lib.pcap_datalink.argtypes = [ctypes.c_void_p]
        lib.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
        lib.pcap_close.argtypes = [ctypes.c_void_p]
        lib.pcap_geterr.argtypes = [ctypes.c_void_p]
        lib.pcap_geterr.restype = ctypes.c_char_p
        lib.pcap_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(_pcap_stat)]
        lib.pcap_create.restype = ctypes.c_void_p
        lib.pcap_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        for fn in ("pcap_set_snaplen", "pcap_set_promisc", "pcap_set_timeout", "pcap_set_buffer_size"):
            getattr(lib, fn).argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.pcap_activate.argtypes = [ctypes.c_void_p]
        _lib = lib
    except OSError as error:
        _lib_error = str(error)
    return _lib


def backend_info() -> dict:
    lib = _load()
    if not lib:
        hint = ("Instala Npcap desde https://npcap.com (viene incluido con Wireshark o Nmap) "
                "sin marcar 'Restrict to Administrators only'." if sys.platform == "win32"
                else "Instala libpcap (p. ej. sudo apt install libpcap0.8) y ejecuta con permisos de captura.")
        return {"available": False, "version": None, "error": _lib_error, "hint": hint}
    return {"available": True, "version": lib.pcap_lib_version().decode(errors="replace"),
            "error": None, "hint": None}


def list_interfaces() -> list[dict]:
    lib = _load()
    if not lib:
        raise NpcapUnavailable(_lib_error)
    head = ctypes.POINTER(_pcap_if)()
    err = ctypes.create_string_buffer(ERRBUF)
    if lib.pcap_findalldevs(ctypes.byref(head), err) != 0:
        raise NpcapUnavailable(err.value.decode(errors="replace"))
    result = []
    try:
        node = head
        while node:
            dev = node.contents
            ips = []
            addr = dev.addresses
            while addr:
                a = addr.contents.addr
                if a and a.contents.family == socket.AF_INET:
                    ips.append(socket.inet_ntoa(bytes(a.contents.data[2:6])))
                addr = addr.contents.next
            flags = dev.flags
            name = dev.name.decode(errors="replace")
            loopback = bool(flags & PCAP_IF_LOOPBACK)
            result.append({
                "id": name,
                "description": (dev.description or dev.name).decode(errors="replace"),
                "ips": ips,
                "loopback": loopback,
                "wireless": bool(flags & PCAP_IF_WIRELESS),
                "up": bool(flags & PCAP_IF_UP) and bool(flags & PCAP_IF_RUNNING),
                "connected": loopback or (flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_CONNECTED,
            })
            node = dev.next
    finally:
        lib.pcap_freealldevs(head)
    # Primero las interfaces conectadas con IP real (no 169.254.x.x de enlace local).
    def rank(i):
        real_ip = any(not ip.startswith("169.254.") for ip in i["ips"])
        return (not (i["connected"] and real_ip and not i["loopback"]), not i["loopback"], i["description"])
    return sorted(result, key=rank)


def _open(lib, iface: str):
    """Abre la interfaz sin modo promiscuo (solo tráfico de este equipo: confidencialidad)
    y con un búfer de 8 MB en el driver (disponibilidad ante ráfagas)."""
    err = ctypes.create_string_buffer(ERRBUF)
    handle = lib.pcap_create(iface.encode(), err)
    if not handle:
        raise NpcapUnavailable(err.value.decode(errors="replace") or "No se pudo abrir la interfaz")
    lib.pcap_set_snaplen(handle, SNAPLEN)
    lib.pcap_set_promisc(handle, 0)
    lib.pcap_set_timeout(handle, 200)
    lib.pcap_set_buffer_size(handle, BUFFER_BYTES)
    rc = lib.pcap_activate(handle)
    if rc < 0:  # los valores positivos son advertencias; la interfaz quedó abierta
        msg = (lib.pcap_geterr(handle) or b"").decode(errors="replace")
        lib.pcap_close(handle)
        raise NpcapUnavailable(msg or f"No se pudo activar la interfaz (código {rc})")
    return handle


class LiveCapture:
    """Hilo que lee tramas de una interfaz y llama on_frame(timestamp, linktype, data, orig_len)."""

    def __init__(self, iface: str, on_frame):
        self.lib = _load()
        if not self.lib:
            raise NpcapUnavailable(_lib_error)
        self.iface = iface
        self.on_frame = on_frame
        self.handle = _open(self.lib, iface)
        self.linktype = self.lib.pcap_datalink(self.handle)
        self.stop_event = threading.Event()
        self.error = None
        self.started_at = time.time()
        self.reconnects = 0
        self.packet_errors = 0
        self.last_packet_error = None
        self.stats = {"received": 0, "dropped": 0, "if_dropped": 0}
        self._stats_base = dict(self.stats)
        self.thread = threading.Thread(target=self._run, name="netcheck-live", daemon=True)
        self.thread.start()

    def _read_stats(self):
        st = _pcap_stat()
        if self.lib.pcap_stats(self.handle, ctypes.byref(st)) == 0:
            self.stats = {"received": self._stats_base["received"] + st.ps_recv,
                          "dropped": self._stats_base["dropped"] + st.ps_drop,
                          "if_dropped": self._stats_base["if_dropped"] + st.ps_ifdrop}

    def _run(self):
        """Lee tramas. Si la interfaz falla (Wi-Fi que se cae, cambio de red), reintenta
        abrirla hasta MAX_RECONNECTS veces antes de rendirse: disponibilidad del monitor."""
        hdr = ctypes.POINTER(_pkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        last_stats = 0.0
        while not self.stop_event.is_set():
            rc = self.lib.pcap_next_ex(self.handle, ctypes.byref(hdr), ctypes.byref(data))
            if rc == 1:
                h = hdr.contents
                frame = ctypes.string_at(data, h.caplen)
                try:
                    self.on_frame(h.ts.tv_sec + h.ts.tv_usec / 1e6, self.linktype, frame, h.len)
                except Exception as error:  # un paquete raro no debe tumbar la captura
                    self.packet_errors += 1
                    self.last_packet_error = type(error).__name__
            elif rc < 0:
                self.error = (self.lib.pcap_geterr(self.handle) or b"").decode(errors="replace")
                if not self._reconnect():
                    break
                continue
            now = time.monotonic()
            if now - last_stats > 1:
                self._read_stats()
                last_stats = now
        if self.handle:
            self._read_stats()
            self.lib.pcap_close(self.handle)
            self.handle = None

    def _reconnect(self) -> bool:
        self._read_stats()
        self._stats_base = dict(self.stats)
        self.lib.pcap_close(self.handle)
        self.handle = None
        while self.reconnects < MAX_RECONNECTS and not self.stop_event.wait(RECONNECT_DELAY):
            self.reconnects += 1
            try:
                self.handle = _open(self.lib, self.iface)
                self.error = None
                return True
            except NpcapUnavailable as error:
                self.error = f"Reintento {self.reconnects}/{MAX_RECONNECTS} fallido: {error}"
        return False

    def send(self, frame: bytes) -> None:
        """Inyecta una trama por la misma interfaz con un manejador aparte
        (el de captura lo usa el hilo lector y libpcap no es seguro entre hilos)."""
        if not self.running:
            raise NpcapUnavailable("La captura no está activa")
        handle = _open(self.lib, self.iface)
        try:
            if self.lib.pcap_sendpacket(handle, frame, len(frame)) != 0:
                raise NpcapUnavailable((self.lib.pcap_geterr(handle) or b"").decode(errors="replace"))
        finally:
            self.lib.pcap_close(handle)

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=2)

    @property
    def running(self):
        return self.thread.is_alive()


# --- Paquetes de prueba para inyectar en la interfaz de loopback (no salen del equipo) ---

def build_loopback_probe(kind: str, linktype: int) -> bytes:
    """Trama IPv4/UDP de 127.0.0.1 a 127.0.0.1 (puerto 9, 'discard') con el defecto pedido."""
    from core.packet_inspector import ipv4_checksum

    payload = b"NETCHECK-PRUEBA-" + kind.encode()
    udp = struct.pack("!HHHH", 40000, 9, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ver_ihl, ttl = 0x45, 64
    if kind == "version":
        ver_ihl = 0x55
    if kind == "ttl":
        ttl = 0
    hdr = bytearray(struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, int(time.time()) & 0xFFFF, 0,
                                ttl, 17, 0, socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1")))
    if kind == "length":
        hdr[2:4] = (total + 200).to_bytes(2, "big")
    hdr[10:12] = ipv4_checksum(bytes(hdr)).to_bytes(2, "big")
    if kind == "checksum":
        hdr[10:12] = b"\xde\xad"
    packet = bytes(hdr) + udp
    if linktype == 0:      # DLT_NULL: familia AF_INET en orden del host
        return struct.pack("=I", 2) + packet
    if linktype in (12, 101):
        return packet
    if linktype == 1:      # Ethernet (loopback de Linux)
        return b"\x00" * 12 + b"\x08\x00" + packet
    raise NpcapUnavailable(f"Tipo de enlace {linktype} no soportado para inyección")
