import queue
from core.captura import Captura
from core.filter import validate_bpf
from core.packet_parser import parse_packet
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer
from ui.widgets.filter_bar import FilterBar
from ui.widgets.packet_table import PacketTable
from ui.widgets.detail_panel import DetailPanel


class MainScreen(Screen):
    BINDINGS = [
        ("p", "toggle_pause", "Pause/Resume"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield FilterBar()
        yield PacketTable()
        yield DetailPanel()
        yield Footer()

    # ------------------------------------------------------------------
    # Filter handling
    # ------------------------------------------------------------------

    def on_filter_bar_filter_changed(self, event: FilterBar.FilterChanged) -> None:
        table = self.query_one(PacketTable)
        table.apply_filters(event.query, event.bpf)

        # If the BPF expression changed, restart capture with the new kernel filter.
        # This is more efficient: packets that don't match are dropped by the kernel
        # before they even reach Python.
        new_bpf = event.bpf.strip()
        if new_bpf != (self._active_bpf or ""):
            ok, err = validate_bpf(new_bpf)
            if ok:
                self._restart_capture(new_bpf)
            # If invalid, silently ignore (the per-packet matcher in PacketTable
            # will also fail gracefully)

    # ------------------------------------------------------------------
    # Packet selection
    # ------------------------------------------------------------------

    def on_packet_table_packet_selected(self, event: PacketTable.PacketSelected) -> None:
        self.query_one(DetailPanel).show_packet(event.packet)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._packet_index = 0
        self._active_bpf = self.app.bpf_filter or ""
        self._is_paused = False
        self._captura = Captura(
            self.app.packet_queue,
            iface=self.app.iface,
            bpf_filter=self._active_bpf or None,
        )
        self._captura.start()
        self.set_interval(0.1, self._poll_queue)
        self._update_title()

    def on_unmount(self) -> None:
        self._captura.stop()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    _PACKETS_PER_TICK = 50

    def _poll_queue(self) -> None:
        table = self.query_one(PacketTable)
        for _ in range(self._PACKETS_PER_TICK):
            try:
                raw = self.app.packet_queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(raw, RuntimeError):
                self.app.exit(message=str(raw))
                return
            try:
                table.add_packet(parse_packet(raw, self._packet_index))
                self._packet_index += 1
            except Exception as e:
                self.app.log.error(f"parse error: {e}")

    def _restart_capture(self, bpf: str) -> None:
        """Stop the current capture thread and start a new one with *bpf*."""
        self._captura.stop()
        # Drain the old queue so stale packets don't leak into the new session
        while not self.app.packet_queue.empty():
            try:
                self.app.packet_queue.get_nowait()
            except queue.Empty:
                break
        self._active_bpf = bpf
        self._captura = Captura(
            self.app.packet_queue,
            iface=self.app.iface,
            bpf_filter=bpf or None,
        )
        self._captura.start()
    # ------------------------------------------------------------------
    # Pause/Resume controls
    # ------------------------------------------------------------------

    def action_toggle_pause(self) -> None:
        """Toggle between paused and capturing states."""
        print(f"[DEBUG] action_toggle_pause called. Currently paused: {self._is_paused}")
        if self._is_paused:
            print("[DEBUG] Resuming capture")
            self._captura.resume()
            self._is_paused = False
        else:
            print("[DEBUG] Pausing capture")
            self._captura.pause()
            self._is_paused = True
        print(f"[DEBUG] New state - paused: {self._is_paused}, pause_event set: {self._captura.pause_event.is_set()}")
        self._update_title()

    def _update_title(self) -> None:
        """Update app title to show current capture state."""
        status = "PAUSED" if self._is_paused else "CAPTURING"
        self.app.title = f"Packet Sniffer - {status}"