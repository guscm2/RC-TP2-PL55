import argparse
import queue
import sys
from core.filter import validate_bpf
from ui.ui import SnifferApp

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--iface",  help="Network interface")
    parser.add_argument("-f", "--filter", default="", help="BPF filter")
    args = parser.parse_args()

    ok, err = validate_bpf(args.filter)
    if not ok:
        print(f"Invalid BPF filter: {err}", file=sys.stderr)
        sys.exit(1)

    packet_queue = queue.Queue()
    app = SnifferApp(
        packet_queue=packet_queue,
        iface=args.iface,
        bpf_filter=args.filter,
    )
    app.run()

if __name__ == "__main__":
    main()