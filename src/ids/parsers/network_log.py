
import re
from datetime import datetime
from ipaddress import ip_address
from typing import Optional

from src.ids.models import Event


NETWORK_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<source_ip>\S+)\s+"
    r"(?P<destination_ip>\S+)\s+"
    r"(?P<destination_port>\d+)$"
)


def parse_network_line(line: str) -> Optional[Event]:
    """Parse a network event formatted as timestamp, source IP, destination IP, destination port."""

    match = NETWORK_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    try:
        timestamp = datetime.fromisoformat(match.group("timestamp"))
        source_ip = str(ip_address(match.group("source_ip")))
        destination_ip = str(ip_address(match.group("destination_ip")))
        destination_port = int(match.group("destination_port"))
    except (ValueError, OverflowError):
        return None

    if not 1 <= destination_port <= 65535:
        return None

    return Event(
        timestamp=timestamp,
        source_ip=source_ip,
        username=None,
        event_type="network_connection",
        http_status=None,
        raw_line=line.rstrip("\r\n"),
        destination_port=destination_port,
        destination_ip=destination_ip,
    )
