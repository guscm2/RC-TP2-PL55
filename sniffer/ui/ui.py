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
            from ui.widgets.interface_selector import get_interfaces
            ifaces = get_interfaces()
            non_lo = [i for i in ifaces if i != "lo"]
            wireless = [i for i in non_lo if i.startswith("wl")]
            self.capture_iface = (wireless[0] if wireless else
                                  non_lo[0] if non_lo else
                                  ifaces[0] if ifaces else "eth0")
            from ui.screens.main_screen import MainScreen
            self.push_screen(MainScreen())
        else:
            self.push_screen(SetupScreen())
