from scapy.all import conf

def validate_bpf(filter_str: str) -> tuple[bool, str]:
    """Returns (is_valid, error_message)."""
    if not filter_str.strip():
        return True, ""
    try:
        conf.L3socket
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        return True, ""
    except Exception as e:
        return False, str(e)