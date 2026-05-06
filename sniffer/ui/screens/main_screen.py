import json
import os
import queue
from datetime import datetime
from core.captura import Captura
from core.filter import validate_bpf
from core.packet_parser import parse_packet
from scapy.all import wrpcap
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Label
from ui.screens.summary_screen import SummaryScreen
from ui.widgets.filter_bar import FilterBar
from ui.widgets.packet_table import PacketTable
from ui.widgets.detail_panel import DetailPanel


class MainScreen(Screen):
    BINDINGS = [
        ("e", "export_pcap", "Export PCAP"),
        ("p", "toggle_pause", "Pause/Resume"),
        ("q", "stop_capture", "Stop"),
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

        new_bpf = event.bpf.strip().lower()
        if new_bpf != (self._active_bpf or ""):
            ok, err = validate_bpf(new_bpf)
            if ok:
                self._restart_capture(new_bpf)

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
        if self._active_bpf:
            from textual.widgets import Input
            self.query_one("#bpf-input", Input).value = self._active_bpf
        self._fragment_groups: dict = {}
        self._stopped = False
        self._limit_reached = False
        self._mode = self.app.capture_mode
        self._packet_limit = self.app.capture_limit
        self._captura = Captura(
            self.app.packet_queue,
            iface=self.app.capture_iface,
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
        if self._stopped or self._limit_reached:
            return
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
                pkt_data = parse_packet(raw, self._packet_index)
                fk = pkt_data.get("fragment_key")
                if fk is not None:
                    group = self._fragment_groups.setdefault(fk, [])
                    group.append(self._packet_index)
                    pkt_data["fragment_siblings"] = group
                table.add_packet(pkt_data)
                self._packet_index += 1
            except Exception as e:
                self.app.log.error(f"parse error: {e}")
                continue
            if self._packet_limit and self._packet_index >= self._packet_limit:
                self._limit_reached = True
                self._captura.pause()
                self._update_title()
                return

    def action_export_pcap(self) -> None:
        packets = self.query_one(PacketTable).get_raw_packets()
        if not packets:
            self.notify("No packets to export")
            return
        os.makedirs("captures", exist_ok=True)
        filename = os.path.join("captures", f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
        wrpcap(filename, packets)
        self.notify(f"Exported {len(packets)} packets to {filename}")

    def action_stop_capture(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        self._captura.stop()
        while not self.app.packet_queue.empty():
            try:
                self.app.packet_queue.get_nowait()
            except queue.Empty:
                break
        packets = self.query_one(PacketTable).get_all_packets()
        log_filename = None
        if self._mode == "log" and packets:
            log_filename = self._save_json(packets)
        self._update_title()
        self.app.push_screen(SummaryScreen(packets, log_filename=log_filename))

    def _save_json(self, packets: list) -> str:
        os.makedirs("captures", exist_ok=True)
        filename = os.path.join("captures", f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        out = []
        for p in packets:
            entry = {k: v for k, v in p.items() if k != "raw_pkt"}
            entry["layers"] = [{"name": l["name"], "fields": l["fields"]} for l in p.get("layers", [])]
            out.append(entry)
        with open(filename, "w") as f:
            json.dump(out, f, indent=2)
        return filename

    def _restart_capture(self, bpf: str) -> None:
        if self._stopped:
            return
        was_paused = self._captura.is_paused()
        self._captura.stop()
        while not self.app.packet_queue.empty():
            try:
                self.app.packet_queue.get_nowait()
            except queue.Empty:
                break
        self._active_bpf = bpf
        self._captura = Captura(
            self.app.packet_queue,
            iface=self.app.capture_iface,
            bpf_filter=bpf or None,
        )
        self._captura.start()
        if was_paused:
            self._captura.pause()

    # ------------------------------------------------------------------
    # Pause/Resume controls
    # ------------------------------------------------------------------

    def action_toggle_pause(self) -> None:
        if self._stopped:
            return
        if self._captura.is_paused():
            self._limit_reached = False
            self._captura.resume()
        else:
            self._captura.pause()
        self._update_title()

    def _update_title(self) -> None:
        if self._stopped:
            self.app.title = "Packet Sniffer - STOPPED"
            try:
                self.query_one("#capture-status", Label).update("[red]■ STOPPED[/red]")
            except Exception:
                pass
            return
        paused = self._captura.is_paused()
        self.app.title = f"Packet Sniffer - {'PAUSED' if paused else 'CAPTURING'}"
        tag = "[yellow]⏸ PAUSED[/yellow]" if paused else "[green]● LIVE[/green]"
        self.query_one("#capture-status", Label).update(tag)
