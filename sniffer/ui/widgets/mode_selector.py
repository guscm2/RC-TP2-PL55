from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Select, Input
from textual.message import Message
from textual.containers import Horizontal


class ModeSelector(Widget):
    class ModeChanged(Message):
        def __init__(self, mode: str, packet_limit: int | None):
            super().__init__()
            self.mode = mode
            self.packet_limit = packet_limit

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._mode = "live"
        self._pkt_count: int | None = None

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Select(
                [("Live capture", "live"), ("Log mode", "log")],
                id="mode-select",
                value="live",
            )
            yield Input(placeholder="Nº de pacotes", id="pkt-count-input")

    def on_mount(self) -> None:
        self.query_one("#pkt-count-input", Input).display = False
        self.post_message(self.ModeChanged("live", None))

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "mode-select" and event.value:
            self._mode = str(event.value)
            self.query_one("#pkt-count-input", Input).display = (self._mode == "log")
            self._post_if_valid()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "pkt-count-input":
            try:
                val = int(event.value.strip())
                if val > 0:
                    self._pkt_count = val
                    self._post_if_valid()
            except ValueError:
                pass

    def _post_if_valid(self) -> None:
        if self._mode == "live":
            self.post_message(self.ModeChanged("live", None))
        elif self._mode == "log" and self._pkt_count is not None:
            self.post_message(self.ModeChanged("log", self._pkt_count))
