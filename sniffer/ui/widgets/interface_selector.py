from __future__ import annotations

import subprocess
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Select
from textual.message import Message


def _get_interfaces() -> list[str]:
    """Devolve lista de interfaces de rede disponíveis no sistema."""
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True
        )
        ifaces = []
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                name = parts[1].strip()
                if name != "lo":  # ignora loopback
                    ifaces.append(name)
        return ifaces if ifaces else ["eth0"]
    except Exception:
        return ["eth0"]


class InterfaceSelector(Widget):
    class InterfaceChanged(Message):
        def __init__(self, iface: str):
            super().__init__()
            self.iface = iface

    def compose(self) -> ComposeResult:
        ifaces = _get_interfaces()
        options = [(iface, iface) for iface in ifaces]
        yield Select(options, id="iface-select", value=ifaces[0])

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "iface-select" and event.value:
            self.post_message(self.InterfaceChanged(str(event.value)))