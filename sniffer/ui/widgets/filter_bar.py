from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Input, Button, Label
from textual.message import Message
from textual.containers import Horizontal
from ui.widgets.interface_selector import InterfaceSelector


class FilterBar(Widget):
    class FilterChanged(Message):
        def __init__(self, query: str, bpf: str):
            super().__init__()
            self.query = query
            self.bpf   = bpf

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield InterfaceSelector()
            yield Input(placeholder="Filter by protocol, IP or MAC...", id="query-input")
            yield Input(placeholder="BPF expression (e.g. tcp port 80)", id="bpf-input")
            yield Button("Apply BPF", id="bpf-apply", variant="primary")
            yield Label("[green]● LIVE[/green]", id="capture-status")

    def _post_filter(self) -> None:
        query = self.query_one("#query-input", Input).value.strip()
        bpf   = self.query_one("#bpf-input",   Input).value.strip()
        self.post_message(self.FilterChanged(query, bpf))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "query-input":
            self._post_filter()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "bpf-apply":
            self._post_filter()