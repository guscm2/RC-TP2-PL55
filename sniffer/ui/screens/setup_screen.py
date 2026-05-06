from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Select, Input, Button, Label, Static
from textual.containers import Vertical
from ui.widgets.interface_selector import InterfaceSelector, get_interfaces


class SetupScreen(Screen):
    def __init__(self):
        super().__init__()
        ifaces = get_interfaces()
        self._iface: str = ifaces[0] if ifaces else "eth0"

    def compose(self) -> ComposeResult:
        with Vertical(id="setup-box"):
            yield Static("Packet Sniffer", id="setup-title")
            yield Static("Seleciona a interface de rede:", id="setup-iface-label")
            yield InterfaceSelector(id="setup-iface")
            yield Static("Seleciona o modo de captura:", id="setup-subtitle")
            yield Select(
                [("Live capture", "live"), ("Log mode", "log")],
                id="setup-mode",
                value="live",
            )
            yield Input(placeholder="Nº de pacotes", id="setup-pkt-count")
            yield Label("", id="setup-error")
            yield Button("Iniciar Captura", id="setup-start", variant="success")

    def on_mount(self) -> None:
        self.query_one("#setup-pkt-count", Input).display = False
        self.query_one("#setup-error", Label).display = False

    def on_interface_selector_interface_changed(self, event: InterfaceSelector.InterfaceChanged) -> None:
        self._iface = event.iface

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "setup-mode" and event.value:
            is_log = str(event.value) == "log"
            self.query_one("#setup-pkt-count", Input).display = is_log
            self.query_one("#setup-error", Label).display = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "setup-start":
            return
        mode = str(self.query_one("#setup-mode", Select).value)
        packet_limit = None
        if mode == "log":
            raw = self.query_one("#setup-pkt-count", Input).value.strip()
            try:
                packet_limit = int(raw)
                if packet_limit <= 0:
                    raise ValueError
            except ValueError:
                err = self.query_one("#setup-error", Label)
                err.update("Insere um número de pacotes válido (> 0)")
                err.display = True
                return
        self.app.capture_mode = mode
        self.app.capture_limit = packet_limit
        self.app.capture_iface = self._iface
        from ui.screens.main_screen import MainScreen
        self.app.push_screen(MainScreen())
