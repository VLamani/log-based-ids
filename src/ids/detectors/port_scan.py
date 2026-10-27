
from collections import defaultdict
from datetime import timedelta
from typing import Optional

from src.ids.detectors.base import BaseDetector
from src.ids.models import Alert, Event


class PortScanDetector(BaseDetector):
    """Detect one source IP contacting many distinct destination ports."""

    def __init__(
        self,
        threshold: int = 15,
        window_seconds: int = 60,
        severity: str = "High",
    ):
        super().__init__(threshold, window_seconds)
        self.severity = severity
        self.port_events: dict[tuple, list[tuple]] = defaultdict(list)


    def process(self, event: Event) -> Optional[Alert]:
        if not event.source_ip or event.destination_port is None:
            return None

        if not 1 <= event.destination_port <= 65535:
            return None

        ip = event.source_ip
        # Key on (source, destination) so one host probing many ports is a scan,
        # while one client touching many different servers is not.
        target = event.destination_ip or "any"
        key = (ip, target)
        events = self.port_events[key]
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)

        events[:] = [
            (timestamp, port)
            for timestamp, port in events
            if timestamp >= cutoff
        ]

        events.append((event.timestamp, event.destination_port))
        distinct_ports = {port for _, port in events}

        if len(distinct_ports) < self.threshold:
            return None

        target_text = "" if target == "any" else f" on {target}"
        return Alert(
            rule_name="port_scan",
            severity=self.severity,
            source_ip=ip,
            start_time=min(timestamp for timestamp, _ in events),
            end_time=event.timestamp,
            event_count=len(distinct_ports),
            description=(
                f"{ip} contacted {len(distinct_ports)} distinct "
                f"destination ports{target_text} within {self.window_seconds} seconds"
            ),
        )
