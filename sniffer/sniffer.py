#!/usr/bin/env python3
"""
Simple Packet Sniffer using Scapy
Usage: sudo python3 packet_sniffer.py [options]
Requires: pip install scapy
"""

import argparse
import signal
import sys
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("Scapy not found. Install it with: pip install scapy")
    sys.exit(1)


# ── Color codes ──────────────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"


# ── Stats ────────────────────────────────────────────────────────────────────
stats = defaultdict(int)
packet_log = []


def protocol_color(proto):
    return {
        "TCP":  C.BLUE,
        "UDP":  C.GREEN,
        "ICMP": C.YELLOW,
        "ARP":  C.CYAN,
        "DNS":  C.RED,
        "HTTP": C.RED,
        "OTHER": C.GRAY,
    }.get(proto, C.GRAY)


def format_size(n):
    return f"{n}B" if n < 1024 else f"{n/1024:.1f}KB"


def get_proto(pkt):
    if pkt.haslayer(DNS):  return "DNS"
    if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse): return "HTTP"
    if pkt.haslayer(TCP):  return "TCP"
    if pkt.haslayer(UDP):  return "UDP"
    if pkt.haslayer(ICMP): return "ICMP"
    if pkt.haslayer(ARP):  return "ARP"
    return "OTHER"


def print_packet(pkt, verbose=False):
    proto = get_proto(pkt)
    color = protocol_color(proto)
    ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    size  = len(pkt)
    stats[proto] += 1
    stats["total"] += 1
    stats["bytes"] += size

    # ── Source / Destination ────────────────────────────────────────────────
    if pkt.haslayer(ARP):
        src = pkt[ARP].psrc
        dst = pkt[ARP].pdst
        sport = dport = ""
    elif pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = f":{pkt.sport}" if hasattr(pkt, "sport") else ""
        dport = f":{pkt.dport}" if hasattr(pkt, "dport") else ""
    else:
        src = dst = "?"
        sport = dport = ""

    # ── Flags (TCP) ─────────────────────────────────────────────────────────
    flags = ""
    if pkt.haslayer(TCP):
        f = pkt[TCP].flags
        flag_map = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
                    "A": "ACK", "U": "URG"}
        flags = " [" + "|".join(v for k, v in flag_map.items() if k in str(f)) + "]"

    # ── DNS info ────────────────────────────────────────────────────────────
    extra = ""
    if pkt.haslayer(DNS) and pkt[DNS].qd:
        try:
            extra = f" → {pkt[DNS].qd.qname.decode().rstrip('.')}"
        except Exception:
            pass

    # ── HTTP info ───────────────────────────────────────────────────────────
    if pkt.haslayer(HTTPRequest):
        try:
            method = pkt[HTTPRequest].Method.decode()
            path   = pkt[HTTPRequest].Path.decode()
            host   = pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else ""
            extra  = f" {method} {host}{path}"
        except Exception:
            pass

    # ── Main line ───────────────────────────────────────────────────────────
    line = (
        f"{C.GRAY}{ts}{C.RESET} "
        f"{color}{C.BOLD}{proto:<5}{C.RESET} "
        f"{C.WHITE}{src}{sport}{C.RESET} "
        f"{C.DIM}→{C.RESET} "
        f"{C.WHITE}{dst}{dport}{C.RESET}"
        f"{C.YELLOW}{flags}{C.RESET}"
        f"{C.CYAN}{extra}{C.RESET} "
        f"{C.GRAY}({format_size(size)}){C.RESET}"
    )
    print(line)

    # ── Verbose: raw payload ─────────────────────────────────────────────────
    if verbose and pkt.haslayer(Raw):
        payload = pkt[Raw].load
        try:
            text = payload[:200].decode("utf-8", errors="replace")
        except Exception:
            text = repr(payload[:200])
        print(f"  {C.DIM}{text}{C.RESET}")


def print_stats():
    print(f"\n{C.BOLD}{'─'*50}{C.RESET}")
    print(f"{C.BOLD}  Capture summary{C.RESET}")
    print(f"{'─'*50}")
    print(f"  Total packets : {C.WHITE}{stats['total']}{C.RESET}")
    print(f"  Total bytes   : {C.WHITE}{format_size(stats['bytes'])}{C.RESET}")
    print()
    for proto in ("TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "OTHER"):
        count = stats[proto]
        if count:
            bar = "█" * min(count, 30)
            print(f"  {protocol_color(proto)}{proto:<6}{C.RESET} {bar} {count}")
    print(f"{'─'*50}\n")


def print_banner(iface, count, bpf):
    print(f"\n{C.BOLD}  Packet Sniffer{C.RESET}{C.DIM}  (Ctrl+C to stop){C.RESET}")
    print(f"  Interface : {C.CYAN}{iface or 'default'}{C.RESET}")
    if bpf:
        print(f"  Filter    : {C.YELLOW}{bpf}{C.RESET}")
    if count:
        print(f"  Limit     : {C.YELLOW}{count} packets{C.RESET}")
    print(f"{'─'*50}\n")


# ── Entry point ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Simple packet sniffer using Scapy"
    )
    parser.add_argument("-i", "--iface",   help="Network interface (e.g. eth0, en0)")
    parser.add_argument("-c", "--count",   type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter",  default="",
                        help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show raw payload")
    args = parser.parse_args()

    print_banner(args.iface, args.count, args.filter)

    def handle_packet(pkt):
        print_packet(pkt, verbose=args.verbose)

    def handle_exit(sig, frame):
        print_stats()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    try:
        sniff(
            iface=args.iface or None,
            filter=args.filter or None,
            count=args.count or 0,
            prn=handle_packet,
            store=False,
        )
    except PermissionError:
        print(f"\n{C.RED}Error: Permission denied.{C.RESET}")
        print("Run with sudo:  sudo python3 packet_sniffer.py\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{C.RED}Error: {e}{C.RESET}\n")
        sys.exit(1)

    print_stats()


if __name__ == "__main__":
    main()