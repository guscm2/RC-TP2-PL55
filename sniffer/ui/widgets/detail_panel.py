from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Tree, Label
from textual.containers import VerticalScroll

class DetailPanel(Widget):
    def compose(self) -> ComposeResult:
        yield Label("No packet selected", id="detail-header")
        with VerticalScroll():
            yield Tree("Packet", id="detail-tree")

    def show_packet(self, pkt: dict) -> None:
        self.query_one("#detail-header", Label).update(
            f"#{pkt['index']}  {pkt['proto']}  {pkt['src']} → {pkt['dst']}  {pkt['size']}"
        )
        tree = self.query_one("#detail-tree", Tree)
        tree.clear()
        root = tree.root
        root.set_label("Packet")
        root.expand()

        for layer in pkt["layers"]:
            node = root.add(layer["name"], expand=True)
            for k, v in layer["fields"].items():
                node.add_leaf(f"{k} = {v}")

        raw_node = root.add("Raw Bytes")
        raw = pkt["raw_bytes"]
        for i in range(0, min(len(raw), 256), 32):
            raw_node.add_leaf(raw[i : i + 32])
