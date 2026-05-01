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

    def pause(self):
        """Pause capture (packets are dropped, but sniff loop continues)."""
        print("[DEBUG] Captura.pause() called")
        self.pause_event.set()
        print(f"[DEBUG] pause_event is now: {self.pause_event.is_set()}")

    def resume(self):
        """Resume capture (packets are queued again)."""
        print("[DEBUG] Captura.resume() called")
        self.pause_event.clear()
        print(f"[DEBUG] pause_event is now: {self.pause_event.is_set()}")

    def is_paused(self) -> bool:
        """Check if capture is currently paused."""
        return self.pause_event.is_set()

    def _run(self):
        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter or None,
                prn=lambda pkt: self._packet_callback(pkt),
                stop_filter=lambda _: self.stop_event.is_set(),
                store=False,
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