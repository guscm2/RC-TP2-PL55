from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer
from ui.widgets.filter_bar import FilterBar
from ui.widgets.packet_table import PacketTable
from ui.widgets.detail_panel import DetailPanel

class MainScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield FilterBar()
        yield PacketTable()
        yield DetailPanel()
        yield Footer()

    def on_filter_bar_filter_changed(self, event: FilterBar.FilterChanged) -> None:
        self.query_one(PacketTable).apply_filters(event.proto, event.ip, event.mac)

    def on_packet_table_packet_selected(self, event: PacketTable.PacketSelected) -> None:
        self.query_one(DetailPanel).show_packet(event.packet)
