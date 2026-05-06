from scapy.all import IP, IPv6, TCP, DNS, UDP, ICMP, ARP, Raw, Ether
from scapy.layers.http import HTTPRequest, HTTPResponse
from datetime import datetime

_IP_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

def get_proto(pkt) -> str:
    if pkt.haslayer(ARP): return "ARP"
    if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse): return "HTTP"
    if pkt.haslayer(DNS): return "DNS"
    if pkt.haslayer(ICMP): return "ICMP"
    if pkt.haslayer(TCP): return "TCP"
    if pkt.haslayer(UDP): return "UDP"
    if pkt.haslayer(IP):
        ip = pkt[IP]
        if bool(ip.flags & 0x1) or ip.frag > 0:
            return "IPv4"
        return _IP_PROTO_NAMES.get(ip.proto, "IPv4")
    if pkt.haslayer(IPv6): return "IPv6"
    return "OTHER"

def format_size(n: int) -> str:
    return f"{n}B" if n < 1024 else f"{n/1024:.1f}KB"

def parse_packet(pkt, index: int) -> dict:
    iface = str(getattr(pkt, "sniffed_on", "") or "")
    proto = get_proto(pkt)
    size  = len(pkt)

    if pkt.haslayer(ARP):
        src, dst = pkt[ARP].psrc, pkt[ARP].pdst
        sport = dport = ""
    elif pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
        sport = f":{pkt.sport}" if hasattr(pkt, "sport") else ""
        dport = f":{pkt.dport}" if hasattr(pkt, "dport") else ""
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        sport = f":{pkt.sport}" if hasattr(pkt, "sport") else ""
        dport = f":{pkt.dport}" if hasattr(pkt, "dport") else ""
    else:
        src = dst = "?"
        sport = dport = ""

    flags = ""
    if pkt.haslayer(TCP):
        f = pkt[TCP].flags
        flag_map = {"F":"FIN","S":"SYN","R":"RST","P":"PSH","A":"ACK","U":"URG"}
        flags = "|".join(v for k, v in flag_map.items() if k in str(f))

    fragment_key = None
    is_fragment = False
    fragment_offset = 0
    is_last_fragment = False
    fragment_proto = ""

    if pkt.haslayer(IP):
        ip = pkt[IP]
        mf = bool(ip.flags & 0x1)
        offset = ip.frag
        if mf or offset > 0:
            is_fragment = True
            fragment_offset = offset * 8
            is_last_fragment = not mf
            fragment_key = (ip.src, ip.dst, ip.id, ip.proto)
            fragment_proto = _IP_PROTO_NAMES.get(ip.proto, f"proto={ip.proto}")
            offset_bytes = fragment_offset
            if offset == 0:
                frag_flag = "FRAG-FIRST"
            elif mf:
                frag_flag = f"FRAG+{offset_bytes}B"
            else:
                frag_flag = f"FRAG-LAST+{offset_bytes}B"
            flags = f"{flags}|{frag_flag}" if flags else frag_flag

    extra = ""
    if pkt.haslayer(DNS) and pkt[DNS].qd:
        try:
            extra = pkt[DNS].qd.qname.decode().rstrip(".")
        except Exception:
            pass
    if pkt.haslayer(HTTPRequest):
        try:
            method = pkt[HTTPRequest].Method.decode()
            path   = pkt[HTTPRequest].Path.decode()
            host   = pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else ""
            extra  = f"{method} {host}{path}"
        except Exception:
            pass

    _LAYER_DISPLAY_NAMES = {"IP": "IPv4"}

    layers = []
    current = pkt
    while current:
        layer_name = current.__class__.__name__
        display_name = _LAYER_DISPLAY_NAMES.get(layer_name, layer_name)
        fields = {}
        for k, v in current.fields.items():
            try:
                fields[k] = current.get_field(k).i2repr(current, v)
            except Exception:
                fields[k] = str(v)
        layers.append({"name": layer_name, "display_name": display_name, "fields": fields})
        current = current.payload if current.payload else None
        if isinstance(current, Raw) or current is None:
            break

    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else ""

    raw_bytes = bytes(pkt).hex()

    return {
        "index":           index,
        "time":            datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "proto":           proto,
        "iface":           iface,
        "src":             f"{src}{sport}",
        "dst":             f"{dst}{dport}",
        "flags":           flags,
        "extra":           extra,
        "size":            format_size(size),
        "size_raw":        size,
        "src_mac":         src_mac,
        "dst_mac":         dst_mac,
        "layers":          layers,
        "raw_bytes":       raw_bytes,
        "raw_pkt":         pkt,
        "is_fragment":      is_fragment,
        "fragment_key":     fragment_key,
        "fragment_offset":  fragment_offset,
        "is_last_fragment": is_last_fragment,
        "fragment_proto":   fragment_proto,
        "fragment_siblings": [],  # populated by main_screen after parsing
    }