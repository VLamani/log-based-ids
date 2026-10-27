import re
from datetime import datetime
from ipaddress import ip_address
from typing import Optional

from src.ids.models import Event


# Classic syslog: "Oct 25 16:19:33 host sshd[2304]: message" (no year, no offset)
AUTH_LOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<message>.*)$"
)

# ISO-8601 syslog, the default on modern Ubuntu/rsyslog:
# "2026-10-25T16:19:33.056507+00:00 host sshd[2304]: message" (year included)
ISO_AUTH_LOG_PATTERN = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<message>.*)$"
)

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<ip>\S+)"
)

SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"Accepted password for (?P<username>\S+) "
    r"from (?P<ip>\S+)"
)


# rsyslog collapses identical consecutive lines into one entry, for example:
# "... sshd[9489]: message repeated 5 times: [ Failed password for dev_user ... ssh2]"
# Each repeat is a real event, so expand the marker into that many copies.
REPEATED_LINE_PATTERN = re.compile(
    r"^(?P<head>.*sshd\[\d+\]:\s+)"
    r"message repeated (?P<count>\d+) times?:\s*\[\s*(?P<message>.*?)\s*\]\s*$"
)

MAX_REPEAT_EXPANSION = 10000


def expand_repeated_auth_line(line: str) -> list[str]:
    """Return the line itself, or copies of it for an rsyslog repeat marker."""

    match = REPEATED_LINE_PATTERN.match(line.strip())
    if not match:
        return [line]

    count = min(int(match.group("count")), MAX_REPEAT_EXPANSION)
    base = f"{match.group('head')}{match.group('message')}"
    return [base] * count


def parse_auth_line(
    line: str,
    year: Optional[int] = None,
) -> Optional[Event]:
    """Parse one SSH authentication log line into an Event."""

    stripped = line.strip()
    iso_match = ISO_AUTH_LOG_PATTERN.match(stripped)
    match = None if iso_match else AUTH_LOG_PATTERN.match(stripped)

    if not iso_match and not match:
        return None

    message = (iso_match or match).group("message")

    failed_match = FAILED_LOGIN_PATTERN.search(message)
    success_match = SUCCESSFUL_LOGIN_PATTERN.search(message)

    if failed_match:
        username = failed_match.group("username")
        source_ip = failed_match.group("ip")
        event_type = "failed_login"

    elif success_match:
        username = success_match.group("username")
        source_ip = success_match.group("ip")
        event_type = "successful_login"

    else:
        return None

    try:
        if iso_match:
            # ISO lines carry their own year and, usually, a UTC offset.
            iso_text = iso_match.group("iso")
            if iso_text.endswith("Z"):
                iso_text = iso_text[:-1] + "+00:00"
            timestamp = datetime.fromisoformat(iso_text)
        else:
            timestamp = datetime.strptime(
                f"{year or datetime.now().year} "
                f"{match.group('month')} "
                f"{match.group('day')} "
                f"{match.group('time')}",
                "%Y %b %d %H:%M:%S",
            )
        source_ip = str(ip_address(source_ip))
    except ValueError:
        return None

    return Event(
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        http_status=None,
        raw_line=line.rstrip("\r\n"),
    )
