import argparse
import queue
import sys
from core.filter import validate_bpf
from ui.ui import SnifferApp

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-f", "--filter", default="", help="BPF filter")
    parser.add_argument("-c", "--count", type=int, default=None, metavar="N",
                        help="Número máximo de pacotes a capturar (obrigatório no modo log)")
    args = parser.parse_args()

    if args.count is not None and args.count <= 0:
        print("Erro: -c deve ser um número inteiro positivo.", file=sys.stderr)
        sys.exit(1)

    ok, err = validate_bpf(args.filter)
    if not ok:
        print(f"Invalid BPF filter: {err}", file=sys.stderr)
        sys.exit(1)

    packet_queue = queue.Queue()
    app = SnifferApp(
        packet_queue=packet_queue,
        bpf_filter=args.filter,
        capture_limit=args.count,
    )
    app.run()

if __name__ == "__main__":
    main()
