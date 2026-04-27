# RC TP2 — Packet Sniffer (PL55)

Network packet sniffer built with Python and Scapy for the Computer Networks course (2nd year).

> **Status:** work in progress

---

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)

```bash
pip install scapy
```

Root/sudo privileges are required to capture raw packets.

---

## Usage

```bash
sudo python3 sniffer/main.py [options]
```

| Option | Description |
|--------|-------------|
| `-i`, `--iface` | Network interface to listen on (e.g. `eth0`, `wlan0`). Defaults to the system default. |
| `-f`, `--filter` | BPF filter string (e.g. `tcp port 80`, `udp`, `icmp`). |

The sniffer launches an interactive **Textual UI** with a live packet table and per-packet detail panel. Use **Ctrl+C** or **q** to quit.

### Examples

```bash
# Capture all traffic on eth0
sudo python3 sniffer/main.py -i eth0

# Capture only TCP packets on port 443
sudo python3 sniffer/main.py -i eth0 -f "tcp port 443"

# Capture UDP traffic on the default interface
sudo python3 sniffer/main.py -f "udp"
```

---

## Current Features

- Color-coded protocol display: TCP, UDP, ICMP, ARP, DNS, HTTP
- Source/destination IP and port
- TCP flag decoding (SYN, ACK, FIN, RST, PSH, URG)
- DNS query name extraction
- HTTP method, host and path extraction
- Per-protocol packet count bar chart on exit
- BPF filter support via Scapy

---

## Project Structure

```
.
├── sniffer/
│   ├── main.py
│   ├── core/
│   │   ├── captura.py        # packet capture thread (Scapy)
│   │   ├── filter.py         # BPF filter validation
│   │   └── packet_parser.py  # raw packet → dict
│   └── ui/
│       ├── ui.py             # Textual App entry point
│       ├── screens/
│       │   └── main_screen.py
│       └── widgets/
│           ├── filter_bar.py   # protocol / IP / MAC filter inputs
│           ├── packet_table.py # live packet list (DataTable)
│           └── detail_panel.py # per-packet layer tree
└── README.md
```

---

## To-Do

- [ ] **Wire capture to UI** — start `Captura` in `MainScreen.on_mount`, poll `packet_queue` with `set_interval` and call `PacketTable.add_packet()` on each parsed packet
- [ ] **Start/stop controls** — keybinding or button to pause and resume capture without exiting
- [ ] **CSS layout** — style the three panels (filter bar, packet table, detail panel) with a proper split layout using Textual CSS
- [ ] **BPF filter validation** — fix `core/filter.py` to actually compile and validate the filter string before passing it to Scapy
- [ ] **Interface selection** — UI widget to pick the network interface at runtime instead of only via CLI flag
- [ ] **Packet export** — save captured packets to a `.pcap` file (Scapy's `wrpcap`)
- [x] **Update README usage section** — reflect the new `main.py` entry point and Textual UI (`sudo python3 sniffer/main.py -i eth0`)
