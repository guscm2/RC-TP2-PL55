from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Label, Static
from textual.containers import Horizontal


class DetailPanel(Widget):
    def compose(self) -> ComposeResult:
        yield Label("No packet selected", id="detail-header")
        yield Horizontal(id="detail-scroll")

    def show_packet(self, pkt: dict) -> None:
        self.query_one("#detail-header", Label).update(
            f"#{pkt['index']}  {pkt['proto']}  {pkt['src']} → {pkt['dst']}  {pkt['size']}"
        )
        scroll = self.query_one("#detail-scroll", Horizontal)
        scroll.remove_children()

        for layer in pkt["layers"]:
            lines = [f"[b]{layer['name']}[/b]"]
            for k, v in layer["fields"].items():
                v_str = v if len(v) <= 36 else v[:33] + "..."
                lines.append(f"[dim]{k}[/dim] = {v_str}")
            name_cls = f"layer-{layer['name'].lower()}"
            scroll.mount(Static("\n".join(lines), classes=f"layer-col {name_cls}"))

        raw = pkt["raw_bytes"]
        raw_lines = ["[b]Raw Bytes[/b]"]
        for i in range(0, min(len(raw), 256), 56):
            raw_lines.append(raw[i : i + 56])
        scroll.mount(Static("\n".join(raw_lines), classes="layer-col raw-col"))
