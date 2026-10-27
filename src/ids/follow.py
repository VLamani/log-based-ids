"""Live monitoring: read new lines as they are appended to a log file."""

import time
from datetime import timezone
from pathlib import Path

from src.ids.alert_manager import AlertManager
from src.ids.parsers.auth_log import expand_repeated_auth_line


class LogFollower:
    """Return complete lines appended to a file since the last call.

    Partial lines are held back until their newline arrives. If the file is
    truncated or replaced (log rotation), reading restarts from the beginning.
    """

    def __init__(self, path, start_at_end: bool = False):
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"Log file not found: {self.path}")
        stat = self.path.stat()
        self.inode = stat.st_ino
        self.position = stat.st_size if start_at_end else 0
        self._partial = b""

    def read_new_lines(self) -> list[str]:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return []

        if stat.st_ino != self.inode or stat.st_size < self.position:
            self.inode = stat.st_ino
            self.position = 0
            self._partial = b""

        if stat.st_size == self.position:
            return []

        with self.path.open("rb") as handle:
            handle.seek(self.position)
            data = handle.read()
        self.position += len(data)

        chunks = (self._partial + data).split(b"\n")
        self._partial = chunks.pop()
        return [
            chunk.decode("utf-8", errors="replace").rstrip("\r")
            for chunk in chunks
            if chunk.strip()
        ]


def parse_batch(raw_lines, parser, log_type):
    """Parse a batch of lines into UTC-normalized events, sorted by time."""
    events = []
    unparsed = 0
    for raw in raw_lines:
        candidates = expand_repeated_auth_line(raw) if log_type == "auth" else [raw]
        produced = 0
        for candidate in candidates:
            event = parser(candidate)
            if event is None:
                continue
            timestamp = event.timestamp
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                event.timestamp = timestamp.replace(tzinfo=timezone.utc)
            else:
                event.timestamp = timestamp.astimezone(timezone.utc)
            events.append(event)
            produced += 1
        if produced == 0:
            unparsed += 1
    events.sort(key=lambda event: event.timestamp)
    return events, unparsed


def follow_log_file(
    path,
    log_type,
    parser,
    detectors,
    config,
    interval: float = 1.0,
    start_at_end: bool = False,
    on_alert=None,
    max_polls=None,
    sleep=time.sleep,
):
    """Watch a log file and return (alerts, lines_processed, lines_unparsed).

    Runs until Ctrl+C. `max_polls` and `sleep` exist so tests can drive the loop.
    """
    follower = LogFollower(path, start_at_end=start_at_end)
    manager = AlertManager(
        allowlisted_ips=config.get("allowlist", {}).get("ips", []),
        cooldown_seconds=config.get("alert_cooldown_seconds", 300),
    )

    alerts = []
    lines_processed = 0
    lines_unparsed = 0
    polls = 0
    try:
        while True:
            raw_lines = follower.read_new_lines()
            if raw_lines:
                lines_processed += len(raw_lines)
                events, unparsed = parse_batch(raw_lines, parser, log_type)
                lines_unparsed += unparsed
                for event in events:
                    for alert in manager.process_event(event, detectors):
                        alerts.append(alert)
                        if on_alert is not None:
                            on_alert(alert)
            polls += 1
            if max_polls is not None and polls >= max_polls:
                break
            sleep(interval)
    except KeyboardInterrupt:
        pass

    return alerts, lines_processed, lines_unparsed
