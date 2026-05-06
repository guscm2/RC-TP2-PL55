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

        if pkt.get("is_fragment"):
            offset = pkt.get("fragment_offset", 0)
            is_last = pkt.get("is_last_fragment", False)
            proto = pkt.get("fragment_proto") or pkt.get("proto", "Unknown")
            if offset == 0:
                position = "first"
            elif is_last:
                position = "last"
            else:
                position = "middle"

            siblings = pkt.get("fragment_siblings", [])
            own_idx = pkt["index"]
            other_frames = [f"#{s}" for s in siblings if s != own_idx]

            frag_lines = [f"[b]Fragment Info[/b]"]
            frag_lines.append(f"[dim]protocol[/dim] = {proto}")
            frag_lines.append(f"[dim]position[/dim] = {position}")
            frag_lines.append(f"[dim]offset[/dim] = {offset} bytes")
            if other_frames:
                frag_lines.append(f"[dim]other fragments[/dim] = {', '.join(other_frames)}")
            else:
                frag_lines.append("[dim]other fragments[/dim] = (none seen yet)")
            scroll.mount(Static("\n".join(frag_lines), classes="layer-col layer-fragment"))

        for layer in pkt["layers"]:
            display_name = layer.get("display_name", layer["name"])
            if layer["name"] == "Raw" and pkt.get("is_fragment") and pkt.get("fragment_offset", 0) > 0:
                display_name = f"{pkt.get('fragment_proto') or 'Data'} Fragment Data"
            lines = [f"[b]{display_name}[/b]"]
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
