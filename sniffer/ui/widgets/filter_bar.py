from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Input, Select, Label
from textual.message import Message
from textual.containers import Horizontal

_PROTOCOLS = [("ALL", "ALL"), ("TCP", "TCP"), ("UDP", "UDP"),
              ("ICMP", "ICMP"), ("DNS", "DNS"), ("ARP", "ARP"),
              ("HTTP", "HTTP"), ("OTHER", "OTHER")]

class FilterBar(Widget):
    class FilterChanged(Message):
        def __init__(self, proto: str, ip: str, mac: str):
            super().__init__()
            self.proto = proto
            self.ip = ip
            self.mac = mac

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Label("Proto: ")
            yield Select(_PROTOCOLS, value="ALL", id="proto-select")
            yield Label("  IP: ")
            yield Input(placeholder="filter by IP", id="ip-input")
            yield Label("  MAC: ")
            yield Input(placeholder="filter by MAC", id="mac-input")

    def _post_filter(self) -> None:
        val = self.query_one("#proto-select", Select).value
        proto = "ALL" if val is Select.BLANK else val
        ip = self.query_one("#ip-input", Input).value
        mac = self.query_one("#mac-input", Input).value
        self.post_message(self.FilterChanged(proto, ip, mac))

    def on_select_changed(self, event: Select.Changed) -> None:
        self._post_filter()

    def on_input_changed(self, event: Input.Changed) -> None:
        self._post_filter()
