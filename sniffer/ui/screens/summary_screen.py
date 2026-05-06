from __future__ import annotations

from collections import defaultdict
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Button
from textual.containers import Center


def _fmt(n: int) -> str:
    return f"{n}B" if n < 1024 else f"{n/1024:.1f}KB"


class SummaryScreen(Screen):
    BINDINGS = [("q", "quit_app", "Quit"), ("Q", "quit_app", "Quit")]

    def __init__(self, packets: list[dict], log_filename: str | None = None):
        super().__init__()
        self._packets = packets
        self._log_filename = log_filename

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="summary-body")
        with Center():
            yield Button("Quit", id="quit-btn", variant="error")
        yield Footer()

    def on_mount(self) -> None:
        total = len(self._packets)
        total_bytes = sum(p.get("size_raw", 0) for p in self._packets)

        by_proto: dict[str, dict] = defaultdict(lambda: {"count": 0, "bytes": 0})
        for p in self._packets:
            proto = p.get("proto", "OTHER")
            by_proto[proto]["count"] += 1
            by_proto[proto]["bytes"] += p.get("size_raw", 0)

        sorted_protos = sorted(by_proto.items(), key=lambda x: x[1]["count"], reverse=True)

        lines = [
            "[b]Capture Summary[/b]",
            "═" * 44,
            "",
            f"  Total packets : [b]{total}[/b]",
            f"  Total data    : [b]{_fmt(total_bytes)}[/b]",
            "",
            f"  {'Protocol':<12} {'Packets':>10}   {'Data':>10}",
            "  " + "─" * 40,
        ]

        for proto, stats in sorted_protos:
            pct = (stats["count"] / total * 100) if total else 0
            lines.append(
                f"  {proto:<12} {stats['count']:>6}  ({pct:4.0f}%)   {_fmt(stats['bytes']):>10}"
            )

        if self._log_filename:
            lines += ["", f"  [green]Saved to:[/green] {self._log_filename}"]

        self.query_one("#summary-body", Static).update("\n".join(lines))

    def action_quit_app(self) -> None:
        self.app.exit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit-btn":
            self.app.exit()
