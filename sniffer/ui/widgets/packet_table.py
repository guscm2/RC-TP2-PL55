from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable
from textual.message import Message

class PacketTable(Widget):
    class PacketSelected(Message):
        def __init__(self, packet: dict):
            super().__init__()
            self.packet = packet

    _COLS = ("#", "Time", "Proto", "Src", "Dst", "Flags", "Size")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._all: list[dict] = []
        self._proto = "ALL"
        self._ip = ""
        self._mac = ""

    def compose(self) -> ComposeResult:
        yield DataTable(cursor_type="row")

    def on_mount(self) -> None:
        t = self.query_one(DataTable)
        for col in self._COLS:
            t.add_column(col, key=col)

    def add_packet(self, pkt: dict) -> None:
        self._all.append(pkt)
        if self._matches(pkt):
            self._add_row(pkt)

    def apply_filters(self, proto: str, ip: str, mac: str) -> None:
        self._proto, self._ip, self._mac = proto, ip, mac
        t = self.query_one(DataTable)
        t.clear()
        for pkt in self._all:
            if self._matches(pkt):
                self._add_row(pkt)

    def _matches(self, pkt: dict) -> bool:
        if self._proto != "ALL" and pkt["proto"] != self._proto:
            return False
        if self._ip and self._ip not in pkt["src"] and self._ip not in pkt["dst"]:
            return False
        if self._mac:
            m = self._mac.lower()
            src_mac = pkt.get("src_mac", "").lower()
            dst_mac = pkt.get("dst_mac", "").lower()
            if m not in src_mac and m not in dst_mac:
                return False
        return True

    def _add_row(self, pkt: dict) -> None:
        self.query_one(DataTable).add_row(
            str(pkt["index"]), pkt["time"], pkt["proto"],
            pkt["src"], pkt["dst"], pkt["flags"], pkt["size"],
            key=str(pkt["index"]),
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = int(event.row_key.value)
        pkt = next((p for p in self._all if p["index"] == idx), None)
        if pkt:
            self.post_message(self.PacketSelected(pkt))
