import queue
import threading
from scapy.all import sniff

class Captura:
    def __init__(self, packet_queue: queue.Queue, iface=None, bpf_filter=None):
        self.packet_queue = packet_queue
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()  # When set, capture is paused
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=2.0)

    def pause(self):
        self.pause_event.set()

    def resume(self):
        self.pause_event.clear()

    def is_paused(self) -> bool:
        """Check if capture is currently paused."""
        return self.pause_event.is_set()

    def _run(self):
        try:
            while not self.stop_event.is_set():
                sniff(
                    iface=self.iface,
                    filter=self.bpf_filter or None,
                    prn=self._packet_callback,
                    stop_filter=lambda _: self.stop_event.is_set(),
                    store=False,
                    timeout=0.5,
                )
        except Exception as e:
            self.packet_queue.put(RuntimeError(f"Captura failed: {e}"))

    def _packet_callback(self, pkt):
        """Callback for each captured packet. Respects pause state."""
        if not self.pause_event.is_set():
            self.packet_queue.put(pkt)
        else:
            # Silently drop packet while paused
            pass