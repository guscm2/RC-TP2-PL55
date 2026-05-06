from __future__ import annotations

import queue
from textual.app import App
from ui.screens.setup_screen import SetupScreen

class SnifferApp(App):
    CSS_PATH = "sniffer.tcss"
    TITLE = "Packet Sniffer"

    def __init__(self, packet_queue: queue.Queue, bpf_filter="", capture_limit: int | None = None, **kwargs):
        super().__init__(**kwargs)
        self.packet_queue = packet_queue
        self.bpf_filter = bpf_filter
        self.capture_mode = "live"
        self.capture_limit: int | None = capture_limit
        self.capture_iface: str | None = None

    def on_mount(self):
        if self.capture_limit is not None or self.bpf_filter:
            from scapy.all import conf as scapy_conf
            self.capture_iface = str(scapy_conf.iface)
            from ui.screens.main_screen import MainScreen
            self.push_screen(MainScreen())
        else:
            self.push_screen(SetupScreen())
