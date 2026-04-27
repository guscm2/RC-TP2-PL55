import queue
from core.captura import Captura
from core.packet_parser import parse_packet
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

    def on_mount(self) -> None:
        self._packet_index = 0
        self._captura = Captura(self.app.packet_queue,
                               iface=self.app.iface,
                               bpf_filter=self.app.bpf_filter,
                               )
        self._captura.start()
        self.set_interval(0.1, self._poll_queue)
    
    def _poll_queue(self) -> None:
        table = self.query_one(PacketTable)
        try:
            while True:
                raw = self.app.packet_queue.get_nowait()
                table.add_packet(parse_packet(raw, self._packet_index))
                self._packet_index += 1
        except queue.Empty:
            pass

    def on_unmount(self) -> None:
        self._captura.stop()

