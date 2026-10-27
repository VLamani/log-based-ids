import re
from datetime import datetime
from ipaddress import ip_address
from typing import Optional

from src.ids.models import Event


ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)'
    r'(?:\s+HTTP/\d(?:\.\d)?)?"\s+'
    r'(?P<status>\d{3})\s+\S+'
)


def parse_access_line(line: str) -> Optional[Event]:
    """Parse one Apache/Nginx combined-format access log line."""

    match = ACCESS_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    try:
        timestamp = datetime.strptime(
            match.group("timestamp"),
            "%d/%b/%Y:%H:%M:%S %z",
        )
        http_status = int(match.group("status"))
        source_ip = str(ip_address(match.group("ip")))
    except (ValueError, OverflowError):
        return None

    return Event(
        timestamp=timestamp,
        source_ip=source_ip,
        username=None,
        event_type="http_request",
        http_status=http_status,
        raw_line=line.rstrip("\r\n"),
    )
