import ipaddress
import re

LOG_LINE_RE = re.compile(
    r"from\s+(?P<ip>\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:.]+):\d+.*?email:\s*(?P<email>[^\s]+)",
    re.IGNORECASE,
)


def parse_log_line(line: str) -> tuple[str, str] | None:
    match = LOG_LINE_RE.search(line)
    if not match:
        return None
    raw_ip = match.group("ip")
    ip = raw_ip[1:-1] if raw_ip.startswith("[") and raw_ip.endswith("]") else raw_ip
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    return normalized_ip, match.group("email")
