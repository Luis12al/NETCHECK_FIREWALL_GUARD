"""
Captura de tráfico real con NetfilterQueue.
Solo funciona en Linux y necesita permisos de root (CAP_NET_ADMIN).
"""
import logging
import threading

from core.decision_engine import decide_action
from core.packet_inspector import inspect_ipv4_packet

log = logging.getLogger("netcheck.capture")


def start_capture(on_packet, queue_num: int = 1, fail_open: bool = True):
    """
    Arranca la captura en un hilo de fondo y devuelve el objeto NetfilterQueue.

    on_packet(src_ip, dst_ip, result, action, reason) registra el resultado
    (estadísticas, eventos, log). fail_open=True deja pasar el paquete si el
    propio inspector falla, para no cortar la red por un error del programa.
    """
    from netfilterqueue import NetfilterQueue  # import tardío: no existe en Windows

    def callback(pkt):
        drop = not fail_open  # veredicto si algo falla
        try:
            inspection = inspect_ipv4_packet(pkt.get_payload())
            action = decide_action(inspection)
            drop = action == "DROP"
            details = inspection.get("details", {})
            try:
                on_packet(
                    details.get("src_ip", "?"), details.get("dst_ip", "?"),
                    inspection["status"], action, inspection["reason"],
                )
            except Exception:
                log.exception("Fallo al registrar el paquete")  # el veredicto no depende del registro
        except Exception:
            log.exception("Fallo al inspeccionar el paquete")
        finally:
            pkt.drop() if drop else pkt.accept()

    nfq = NetfilterQueue()
    nfq.bind(queue_num, callback)
    threading.Thread(target=nfq.run, name="netcheck-nfqueue", daemon=True).start()
    log.info("Captura NFQUEUE activa en la cola %s", queue_num)
    return nfq


def stop_capture(nfq) -> None:
    try:
        nfq.unbind()
    except Exception:
        log.exception("No se pudo liberar la cola NFQUEUE")
