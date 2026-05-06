# RC TP2 — Packet Sniffer (PL55)

Network packet sniffer built with Python and Scapy for the Computer Networks course (2nd year).

---

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)
- [Textual](https://github.com/Textualize/textual)

```bash
make install
# or manually: pip install scapy textual
```

Root/sudo privileges are required to capture raw packets.

---

## Usage

### With Make (recommended)

| Command | Description |
|---------|-------------|
| `make run` | Run on default interface (`eth0`) |
| `make run IFACE=wlan0` | Run on a specific interface |
| `make run IFACE=eth0 FILTER="tcp port 443"` | Run with a BPF filter |
| `make install` | Install dependencies |
| `make check` | Syntax-check all source files |
| `make clean` | Remove `__pycache__` and `.pyc` files |

### Manually

```bash
sudo python3 sniffer/main.py [options]
```

| Option | Description |
|--------|-------------|
| `-i`, `--iface` | Network interface to listen on (e.g. `eth0`, `wlan0`). Defaults to the system default. |
| `-f`, `--filter` | BPF filter string (e.g. `tcp port 80`, `udp`, `icmp`). |

The sniffer launches an interactive **Textual UI** with a live packet table and per-packet detail panel. Use **Ctrl+C** or **q** to quit.

---

## Current Features

- Interactive Textual TUI with live packet table and per-packet detail panel
- Split layout: filter bar, packet table, detail panel
- Color-coded protocol display: TCP, UDP, ICMP, ARP, DNS, HTTP, IPv4, IPv6
- Protocol detection ordering: ARP > HTTP > DNS > ICMP > TCP > UDP > IPv4/IPv6; non-first IP fragments identified via IP proto field (e.g. fragmented ICMP labelled as `ICMP` instead of `IPv4`)
- Source/destination IP and port; IPv6 src/dst shown correctly
- TCP flag decoding (SYN, ACK, FIN, RST, PSH, URG)
- IP fragmentation detection: first fragment shown as `FRAG-FIRST`, intermediate as `FRAG+<offset>B`, last as `FRAG-LAST+<offset>B` in the Flags column
- DNS query name extraction
- HTTP method, host and path extraction
- Unified single-input filter bar — one field matches protocol, IP, or MAC (case-insensitive substring); separate BPF expression input with an Apply button
- Debounced filter with 250 ms delay so typing stays responsive during live capture
- Display capped at the 500 most recent matching packets
- BPF filter validation at startup via `tcpdump -d`; per-packet BPF matching via libpcap offline filtering (`pcap_offline_filter`)
- BPF filter can be updated at runtime from the UI; capture thread restarts with the new kernel-level filter

---

## Project Structure

```
.
├── Makefile
├── sniffer/
│   ├── main.py
│   ├── core/
│   │   ├── captura.py        # packet capture thread (Scapy)
│   │   ├── filter.py         # BPF filter validation
│   │   └── packet_parser.py  # raw packet → dict
│   └── ui/
│       ├── ui.py             # Textual App entry point
│       ├── sniffer.tcss      # layout and styling
│       ├── screens/
│       │   └── main_screen.py
│       └── widgets/
│           ├── filter_bar.py   # unified filter input (protocol / IP / MAC) + BPF input
│           ├── packet_table.py # live packet list (DataTable)
│           └── detail_panel.py # per-packet layer tree
└── README.md
```