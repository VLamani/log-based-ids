
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from src.ids.models import Alert


def format_alert(alert: Alert) -> str:
    """Format one security alert as readable text."""

    return "\n".join(
        [
            "=" * 60,
            f"Rule       : {alert.rule_name}",
            f"Severity   : {alert.severity}",
            f"Source IP  : {alert.source_ip}",
            f"Start time : {_format_timestamp(alert.start_time)}",
            f"End time   : {_format_timestamp(alert.end_time)}",
            f"Events     : {alert.event_count}",
            f"Description: {alert.description}",
            "=" * 60,
        ]
    )


def _format_timestamp(timestamp: datetime) -> str:
    """Format a timestamp consistently for reports."""

    return timestamp.isoformat(sep=" ", timespec="seconds")


def report_alerts(alerts: Iterable[Alert]) -> str:
    """Format a collection of alerts into a readable report."""

    alert_list = list(alerts)

    if not alert_list:
        return "No security alerts detected."

    header = [
        "IDS SECURITY ALERT REPORT",
        f"Generated at: {_format_timestamp(datetime.now().astimezone())}",
        f"Total alerts: {len(alert_list)}",
        "",
    ]

    return "\n".join(header + [format_alert(alert) for alert in alert_list])


def print_alerts(alerts: Iterable[Alert]) -> None:
    """Print a formatted alert report to the console."""

    print(report_alerts(alerts))


def write_json_report(
    path: str | Path,
    alerts: Iterable[Alert],
    lines_processed: int,
    lines_unparsed: int,
) -> None:
    """Write alerts and processing counts as a machine-readable JSON file."""

    alert_list = list(alerts)
    document = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "lines_processed": lines_processed,
        "lines_unparsed": lines_unparsed,
        "total_alerts": len(alert_list),
        "alerts": [
            {
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "start_time": alert.start_time.isoformat(),
                "end_time": alert.end_time.isoformat(),
                "event_count": alert.event_count,
                "description": alert.description,
            }
            for alert in alert_list
        ],
    }
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
