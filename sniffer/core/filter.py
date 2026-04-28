import ctypes
import subprocess


# ---------------------------------------------------------------------------
# BPF validation (used at startup / by the UI before applying a new filter)
# ---------------------------------------------------------------------------

def validate_bpf(filter_str: str) -> tuple[bool, str]:
    """Returns (is_valid, error_message)."""
    if not filter_str.strip():
        return True, ""
    try:
        result = subprocess.run(
            ["tcpdump", "-d", filter_str],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip() or "Invalid BPF filter"
    except FileNotFoundError:
        return True, ""
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Per-packet BPF matching via libpcap
# ---------------------------------------------------------------------------

class _BpfInsn(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt",   ctypes.c_ubyte),
        ("jf",   ctypes.c_ubyte),
        ("k",    ctypes.c_uint32),
    ]


class _BpfProgram(ctypes.Structure):
    _fields_ = [
        ("bf_len",   ctypes.c_uint),
        ("bf_insns", ctypes.POINTER(_BpfInsn)),
    ]


class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _PcapPkthdr(ctypes.Structure):
    _fields_ = [
        ("ts",     _Timeval),
        ("caplen", ctypes.c_uint32),
        ("len",    ctypes.c_uint32),
    ]


def _load_libpcap():
    for name in ("libpcap.so.0.8", "libpcap.so.1", "libpcap.so"):
        try:
            lib = ctypes.CDLL(name)
            lib.pcap_offline_filter.restype = ctypes.c_int
            return lib
        except OSError:
            continue
    return None


_libpcap = _load_libpcap()


class BpfMatcher:
    """Compiles a BPF expression once and tests individual packets against it."""

    def __init__(self, expression: str):
        self._expression = expression
        self._prog: _BpfProgram | None = None
        self._valid = False
        if _libpcap and expression.strip():
            self._prog = _BpfProgram()
            ret = _libpcap.pcap_compile_nopcap(
                65535,               # snaplen
                1,                   # DLT_EN10MB (Ethernet)
                ctypes.byref(self._prog),
                expression.encode(),
                1,                   # optimize
                0xFFFFFFFF,          # netmask (unknown)
            )
            self._valid = ret == 0

    @property
    def is_valid(self) -> bool:
        return self._valid

    def matches(self, raw_bytes: bytes) -> bool:
        """Return True if *raw_bytes* passes the compiled BPF filter.

        Falls back to True (no filtering) when libpcap is unavailable or the
        expression failed to compile.
        """
        if not self._valid or self._prog is None or _libpcap is None:
            return True
        hdr = _PcapPkthdr()
        hdr.caplen = hdr.len = len(raw_bytes)
        return bool(
            _libpcap.pcap_offline_filter(
                ctypes.byref(self._prog), ctypes.byref(hdr), raw_bytes
            )
        )
