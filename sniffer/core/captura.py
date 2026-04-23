import queue
import threading
from scapy.all import sniff

class Captura:
    def __init__(self, packet_queue: queue.Queue, iface=None, bpf_filter=None):
        self.packet_queue = packet_queue
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)


    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def _run(self):
        sniff(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=lambda pkt: self.packet_queue.put(pkt),
            stop_filter=lambda _: self.stop_event.is_set(),
            store=False,
        )