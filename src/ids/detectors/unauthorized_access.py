
from collections import defaultdict
from datetime import timedelta
from typing import Optional

from src.ids.detectors.base import BaseDetector
from src.ids.models import Alert, Event


class UnauthorizedAccessDetector(BaseDetector):
    """Detect bursts of HTTP 401 and 403 responses from one source IP."""

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 60,
        severity: str = "High",
    ):
        super().__init__(threshold, window_seconds)
        self.severity = severity
        self.denied_events: dict[str, list[tuple]] = defaultdict(list)


    def process(self, event: Event) -> Optional[Alert]:
        if event.event_type != "http_request":
            return None

        if event.http_status not in (401, 403) or not event.source_ip:
            return None

        ip = event.source_ip
        events = self.denied_events[ip]
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)

        events[:] = [
            (timestamp, status)
            for timestamp, status in events
            if timestamp >= cutoff
        ]

        events.append((event.timestamp, event.http_status))

        if len(events) < self.threshold:
            return None

        return Alert(
            rule_name="unauthorized_access",
            severity=self.severity,
            source_ip=ip,
            start_time=min(timestamp for timestamp, _ in events),
            end_time=event.timestamp,
            event_count=len(events),
            description=(
                f"{len(events)} HTTP 401/403 responses from {ip} "
                f"within {self.window_seconds} seconds"
            ),
        )
