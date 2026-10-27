
from collections import defaultdict
from datetime import timedelta
from typing import Optional

from src.ids.detectors.base import BaseDetector
from src.ids.models import Alert, Event


class PasswordSprayingDetector(BaseDetector):
    """Detect failed SSH logins targeting multiple usernames from one IP."""

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 600,
        severity: str = "High",
    ):
        super().__init__(threshold, window_seconds)
        self.severity = severity
        self.attempts: dict[str, list[tuple]] = defaultdict(list)


    def process(self, event: Event) -> Optional[Alert]:
        if event.event_type != "failed_login":
            return None

        if not event.source_ip or not event.username:
            return None

        ip = event.source_ip
        attempts = self.attempts[ip]
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)

        attempts[:] = [
            (timestamp, username)
            for timestamp, username in attempts
            if timestamp >= cutoff
        ]

        attempts.append((event.timestamp, event.username))

        distinct_users = {username for _, username in attempts}

        if len(distinct_users) < self.threshold:
            return None

        return Alert(
            rule_name="password_spraying",
            severity=self.severity,
            source_ip=ip,
            start_time=min(timestamp for timestamp, _ in attempts),
            end_time=event.timestamp,
            event_count=len(distinct_users),
            description=(
                f"{len(distinct_users)} distinct usernames received "
                f"failed login attempts from {ip} within "
                f"{self.window_seconds} seconds"
            ),
        )
