
from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Optional

from src.ids.detectors.base import BaseDetector
from src.ids.models import Alert, Event


class ScanningDetector(BaseDetector):
    """Detect repeated HTTP 404 responses from a single source IP."""

    def __init__(
        self,
        threshold: int = 30,
        window_seconds: int = 60,
        severity: str = "Medium",
    ):
        super().__init__(threshold, window_seconds)
        self.severity = severity
        self.not_found_events: dict[str, Deque] = defaultdict(deque)


    def process(self, event: Event) -> Optional[Alert]:
        if event.event_type != "http_request":
            return None

        if event.http_status != 404 or not event.source_ip:
            return None

        ip = event.source_ip
        timestamps = self.not_found_events[ip]
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)

        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        timestamps.append(event.timestamp)

        if len(timestamps) < self.threshold:
            return None

        return Alert(
            rule_name="scanning",
            severity=self.severity,
            source_ip=ip,
            start_time=timestamps[0],
            end_time=event.timestamp,
            event_count=len(timestamps),
            description=(
                f"{len(timestamps)} HTTP 404 responses from {ip} "
                f"within {self.window_seconds} seconds"
            ),
        )
