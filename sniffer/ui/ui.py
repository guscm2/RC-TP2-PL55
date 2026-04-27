import queue
from textual.app import App
from ui.screens.main_screen import MainScreen

class SnifferApp(App):
    CSS_PATH = "sniffer.tcss"
    TITLE = "Packet Sniffer"

    def __init__(self, packet_queue: queue.Queue, iface=None, bpf_filter="", **kwargs):
        super().__init__(**kwargs)
        self.packet_queue = packet_queue
        self.iface = iface
        self.bpf_filter = bpf_filter

    def on_mount(self):
        self.push_screen(MainScreen())
