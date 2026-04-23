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
sudo python3 sniffer/sniffer.py [options]
```

| Option | Description |
|--------|-------------|
| `-i`, `--iface` | Network interface to listen on (e.g. `eth0`, `wlan0`). Defaults to the system default. |
| `-c`, `--count` | Number of packets to capture. `0` = unlimited (default). |
| `-f`, `--filter` | BPF filter string (e.g. `tcp port 80`, `udp`, `icmp`). |
| `-v`, `--verbose` | Print raw payload (up to 200 bytes) for each packet. |

Press **Ctrl+C** to stop capture and print a summary.

### Examples

```bash
# Capture all traffic on eth0
sudo python3 sniffer/sniffer.py -i eth0

# Capture 100 TCP packets on port 443
sudo python3 sniffer/sniffer.py -i eth0 -c 100 -f "tcp port 443"

# Show raw payload
sudo python3 sniffer/sniffer.py -v
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
│   └── sniffer.py   # main capture and display logic
└── README.md
```
