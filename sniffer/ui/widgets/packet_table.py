from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable
from textual.message import Message

from core.filter import BpfMatcher


class PacketTable(Widget):
    class PacketSelected(Message):
        def __init__(self, packet: dict):
            super().__init__()
            self.packet = packet

    _COLS = ("#", "Time", "Proto", "Src", "Dst", "Flags", "Size")
    _MAX_DISPLAY = 500

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._all: list[dict] = []
        self._query = ""
        self._bpf = ""
        self._bpf_matcher: BpfMatcher | None = None
        self._filter_timer = None
        self._pending_query = ""
        self._pending_bpf = ""

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

    def apply_filters(self, query: str, bpf: str = "") -> None:
        self._pending_query = query
        self._pending_bpf = bpf
        if self._filter_timer is not None:
            self._filter_timer.stop()
        self._filter_timer = self.set_timer(0.25, self._do_apply_filters)

    def _do_apply_filters(self) -> None:
        self._filter_timer = None
        query = self._pending_query
        bpf = self._pending_bpf
        self._query = query
        # Recompile BPF only when the expression changes
        if bpf != self._bpf:
            self._bpf = bpf
            self._bpf_matcher = BpfMatcher(bpf) if bpf.strip() else None
        matching = [pkt for pkt in self._all if self._matches(pkt)]
        visible = matching[-self._MAX_DISPLAY:]
        t = self.query_one(DataTable)
        t.clear()
        for pkt in visible:
            self._add_row(pkt)

    def _matches(self, pkt: dict) -> bool:
        # --- Query filter (case-insensitive substring across proto/IP/MAC) ---
        if self._query:
            q = self._query.lower()
            if not (
                q in pkt["proto"].lower()
                or q in pkt["src"]
                or q in pkt["dst"]
                or q in pkt.get("src_mac", "").lower()
                or q in pkt.get("dst_mac", "").lower()
            ):
                return False

        # --- BPF expression filter (applied via libpcap offline matching) ---
        if self._bpf_matcher is not None:
            raw_pkt = pkt.get("raw_pkt")
            if raw_pkt is not None:
                try:
                    raw_bytes = bytes(raw_pkt)
                    if not self._bpf_matcher.matches(raw_bytes):
                        return False
                except Exception:
                    pass  # on error, keep the packet visible

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
