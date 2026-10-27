
from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Optional

from src.ids.detectors.base import BaseDetector
from src.ids.models import Alert, Event


class CompromiseDetector(BaseDetector):
    """Flag a successful login after repeated failures from the same IP."""

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 600,
        severity: str = "Critical",
    ):
        super().__init__(threshold, window_seconds)
        self.severity = severity
        self.failures: dict[str, Deque] = defaultdict(deque)

    def process(self, event: Event) -> Optional[Alert]:
        if not event.source_ip:
            return None

        ip = event.source_ip
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
        timestamps = self.failures[ip]

        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        if event.event_type == "failed_login":
            timestamps.append(event.timestamp)
            return None

        if event.event_type != "successful_login":
            return None

        if len(timestamps) < self.threshold:
            return None

        return Alert(
            rule_name="compromise_indicator",
            severity=self.severity,
            source_ip=ip,
            start_time=timestamps[0],
            end_time=event.timestamp,
            event_count=len(timestamps) + 1,
            description=(
                f"Successful SSH login from {ip} after "
                f"{len(timestamps)} failed logins within "
                f"{self.window_seconds} seconds"
            ),
        )
