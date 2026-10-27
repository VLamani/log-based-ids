from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Iterable

from src.ids.models import Alert, Event


def _comparable_timestamp(value: datetime) -> datetime:
    """Normalize timestamps to UTC; naive log timestamps are assumed to be UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class AlertManager:
    """Apply source-IP allowlisting and per-rule/source alert cooldowns."""

    def __init__(self, allowlisted_ips: Iterable[str] = (), cooldown_seconds: int = 300):
        if isinstance(cooldown_seconds, bool) or not isinstance(cooldown_seconds, int) or cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must be a non-negative integer")

        self.allowlisted_ips = {str(ip_address(ip.strip())) for ip in allowlisted_ips}
        self.cooldown_seconds = cooldown_seconds
        self.last_alerts: dict[tuple[str, str], datetime] = {}

    def is_allowlisted(self, event: Event) -> bool:
        if not event.source_ip:
            return False
        try:
            normalized_ip = str(ip_address(event.source_ip))
        except ValueError:
            return False
        return normalized_ip in self.allowlisted_ips

    def process_event(self, event: Event, detectors) -> list[Alert]:
        """Run eligible events through detectors and return non-cooled-down alerts."""
        if self.is_allowlisted(event):
            return []

        accepted = []
        for detector in detectors:
            alert = detector.process(event)
            if alert is None:
                continue

            key = (alert.rule_name, alert.source_ip)
            previous = self.last_alerts.get(key)
            if previous is not None and self.cooldown_seconds > 0:
                elapsed = (
                    _comparable_timestamp(alert.end_time)
                    - _comparable_timestamp(previous)
                ).total_seconds()

                if 0 <= elapsed < self.cooldown_seconds:
                    continue

            self.last_alerts[key] = alert.end_time
            accepted.append(alert)

        return accepted
