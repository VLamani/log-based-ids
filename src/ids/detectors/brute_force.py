
from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Optional

from src.ids.detectors.base import BaseDetector
from src.ids.models import Alert, Event


class BruteForceDetector(BaseDetector):
    """Detect repeated failed SSH logins from a single source IP."""

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 300,
        severity: str = "High",
    ):
        super().__init__(threshold, window_seconds)
        self.severity = severity
        self.failures: dict[str, Deque] = defaultdict(deque)


    def process(self, event: Event) -> Optional[Alert]:
        if event.event_type != "failed_login" or not event.source_ip:
            return None

        ip = event.source_ip
        timestamps = self.failures[ip]
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)

        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        timestamps.append(event.timestamp)

        if len(timestamps) < self.threshold:
            return None

        # Repeated alerts for the same IP are suppressed by AlertManager's cooldown.
        return Alert(
            rule_name="brute_force",
            severity=self.severity,
            source_ip=ip,
            start_time=timestamps[0],
            end_time=event.timestamp,
            event_count=len(timestamps),
            description=(
                f"{len(timestamps)} failed SSH logins from {ip} "
                f"within {self.window_seconds} seconds"
            ),
        )
