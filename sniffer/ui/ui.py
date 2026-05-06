from __future__ import annotations

import queue
from textual.app import App
from ui.screens.setup_screen import SetupScreen

class SnifferApp(App):
    CSS_PATH = "sniffer.tcss"
    TITLE = "Packet Sniffer"

    def __init__(self, packet_queue: queue.Queue, bpf_filter="", **kwargs):
        super().__init__(**kwargs)
        self.packet_queue = packet_queue
        self.bpf_filter = bpf_filter
        self.capture_mode = "live"
        self.capture_limit: int | None = None
        self.capture_iface: str | None = None

    def on_mount(self):
        self.push_screen(SetupScreen())
