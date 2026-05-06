from __future__ import annotations

from scapy.all import get_if_list
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Select
from textual.message import Message


def get_interfaces() -> list[str]:
    try:
        return get_if_list() or ["eth0"]
    except Exception:
        return ["eth0"]


class InterfaceSelector(Widget):
    class InterfaceChanged(Message):
        def __init__(self, iface: str):
            super().__init__()
            self.iface = iface

    def compose(self) -> ComposeResult:
        ifaces = get_interfaces()
        options = [(iface, iface) for iface in ifaces]
        yield Select(options, id="iface-select", value=ifaces[0])

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "iface-select" and event.value:
            self.post_message(self.InterfaceChanged(str(event.value)))