import subprocess


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