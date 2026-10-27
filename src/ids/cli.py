import argparse
from datetime import timezone
from pathlib import Path

from src.ids.alert_manager import AlertManager
from src.ids.config import load_config
from src.ids.detectors.brute_force import BruteForceDetector
from src.ids.detectors.compromise import CompromiseDetector
from src.ids.detectors.port_scan import PortScanDetector
from src.ids.detectors.scanning import ScanningDetector
from src.ids.detectors.spraying import PasswordSprayingDetector
from src.ids.detectors.unauthorized_access import UnauthorizedAccessDetector
from src.ids.parsers.access_log import parse_access_line
from src.ids.parsers.auth_log import expand_repeated_auth_line, parse_auth_line
from src.ids.parsers.network_log import parse_network_line
from src.ids.follow import follow_log_file
from src.ids.reporter import format_alert, print_alerts, write_json_report

BLOCKING_SEVERITIES = {"high", "critical"}


def create_detectors(config=None):
    """Create all detection rules using the loaded configuration."""
    if config is None:
        config = load_config()
    rules = config["detection"]
    return [
        BruteForceDetector(**rules["brute_force"]),
        PasswordSprayingDetector(**rules["password_spraying"]),
        CompromiseDetector(**rules["compromise_indicator"]),
        ScanningDetector(**rules["scanning"]),
        PortScanDetector(**rules["port_scan"]),
        UnauthorizedAccessDetector(**rules["unauthorized_access"]),
    ]


def line_parser_for(log_type: str, year: int | None = None):
    """Return the single-line parser for a log type."""
    parsers = {
        "auth": lambda line: parse_auth_line(line, year=year),
        "http": parse_access_line,
        "network": parse_network_line,
    }
    if log_type not in parsers:
        raise ValueError("log_type must be 'auth', 'http', or 'network'")
    return parsers[log_type]


def process_log_file(
    log_path: str | Path,
    log_type: str,
    detectors=None,
    config=None,
    year: int | None = None,
) -> tuple[list, int, int]:
    """Parse a log file, run detection, and return alerts and line counts.

    `year` is used only for syslog-style auth timestamps, which carry no year.
    When omitted, the current year is assumed.
    """
    parsers = {
        "auth": lambda line: parse_auth_line(line, year=year),
        "http": parse_access_line,
        "network": parse_network_line,
    }
    if log_type not in parsers:
        raise ValueError("log_type must be 'auth', 'http', or 'network'")

    path = Path(log_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    if config is None:
        config = load_config()
    if detectors is None:
        detectors = create_detectors(config)

    allowlisted_ips = config.get("allowlist", {}).get("ips", [])
    manager = AlertManager(
        allowlisted_ips=allowlisted_ips,
        cooldown_seconds=config.get("alert_cooldown_seconds", 300),
    )
    parser = parsers[log_type]
    alerts = []
    lines_processed = 0
    lines_unparsed = 0
    events = []

    # Parse the complete file before detection so detector sliding windows and
    # alert cooldowns always see events in chronological order. Naive timestamps
    # are treated as UTC for ordering; aware timestamps are converted to UTC.
    # This keeps mixed ISO-8601 network timestamps sortable without comparing
    # naive and aware datetime objects directly.
    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            if not line.strip():
                continue
            lines_processed += 1
            candidates = expand_repeated_auth_line(line) if log_type == "auth" else [line]
            produced = 0
            for candidate in candidates:
                event = parser(candidate)
                if event is not None:
                    events.append(event)
                    produced += 1
            if produced == 0:
                lines_unparsed += 1

    def chronological_key(event):
        timestamp = event.timestamp
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = timestamp.astimezone(timezone.utc)
        return timestamp

    events.sort(key=chronological_key)

    # A file can mix ISO-8601 timestamps with and without timezone offsets.
    # If it does, normalize every event to aware UTC datetimes so detector
    # sliding windows never compare naive and aware datetime objects.
    has_naive = any(
        event.timestamp.tzinfo is None or event.timestamp.utcoffset() is None
        for event in events
    )
    has_aware = any(
        event.timestamp.tzinfo is not None and event.timestamp.utcoffset() is not None
        for event in events
    )
    if has_naive and has_aware:
        for event in events:
            event.timestamp = chronological_key(event)

    for event in events:
        alerts.extend(manager.process_event(event, detectors))

    return alerts, lines_processed, lines_unparsed


def _run_follow(argument_parser, args):
    """Live mode: print each alert as it fires, then a summary on Ctrl+C."""
    try:
        config = load_config()
        detectors = create_detectors(config)
        parser = line_parser_for(args.type, args.year)
        print("IDS configuration loaded successfully.")
        print(f"Following {args.type.upper()} log: {args.log_file} (Ctrl+C to stop)")
        if args.interval <= 0:
            raise ValueError("--interval must be greater than zero")

        def show(alert):
            print(format_alert(alert), flush=True)

        alerts, lines_processed, lines_unparsed = follow_log_file(
            args.log_file, args.type, parser, detectors, config,
            interval=args.interval, start_at_end=args.from_end, on_alert=show,
        )
    except (FileNotFoundError, PermissionError, OSError, ValueError) as exc:
        argument_parser.error(str(exc))

    print("\nStopped.")
    print(f"Lines processed: {lines_processed}")
    print(f"Lines not parsed as security events: {lines_unparsed}")
    print(f"Total alerts: {len(alerts)}")
    if args.json_path:
        write_json_report(args.json_path, alerts, lines_processed, lines_unparsed)
        print(f"JSON report written to: {args.json_path}")
    if any(alert.severity.lower() in BLOCKING_SEVERITIES for alert in alerts):
        raise SystemExit(1)


def main():
    """Run the IDS against SSH, HTTP, or network-event logs."""
    argument_parser = argparse.ArgumentParser(
        description="Analyze SSH authentication, HTTP access, or network-event logs."
    )
    argument_parser.add_argument("log_file", help="Path to the log file to analyze")
    argument_parser.add_argument(
        "--type", choices=("auth", "http", "network"), required=True,
        help="Log format: 'auth', 'http', or 'network'",
    )
    argument_parser.add_argument(
        "--year", type=int, default=None,
        help="Year for syslog auth timestamps, which omit it (default: current year)",
    )
    argument_parser.add_argument(
        "--json", dest="json_path", metavar="PATH", default=None,
        help="Also write alerts and counts to a JSON file",
    )
    argument_parser.add_argument(
        "--follow", action="store_true",
        help="Keep watching the file and print alerts as new lines arrive (Ctrl+C to stop)",
    )
    argument_parser.add_argument(
        "--interval", type=float, default=1.0,
        help="Seconds between checks for new lines in --follow mode (default: 1.0)",
    )
    argument_parser.add_argument(
        "--from-end", action="store_true",
        help="In --follow mode, skip existing content and watch only new lines",
    )
    args = argument_parser.parse_args()

    if args.follow:
        _run_follow(argument_parser, args)
        return

    try:
        config = load_config()
        detectors = create_detectors(config)
        print("IDS configuration loaded successfully.")
        print(f"Initialized {len(detectors)} detection rules.")
        print(f"Analyzing {args.type.upper()} log: {args.log_file}")
        alerts, lines_processed, lines_unparsed = process_log_file(
            args.log_file, args.type, detectors, config, year=args.year
        )
        print(f"\nNon-empty lines processed: {lines_processed}")
        print(f"Lines not parsed as security events: {lines_unparsed}")
        print_alerts(alerts)
        if args.json_path:
            write_json_report(args.json_path, alerts, lines_processed, lines_unparsed)
            print(f"JSON report written to: {args.json_path}")
    except (FileNotFoundError, PermissionError, OSError, ValueError) as exc:
        argument_parser.error(str(exc))

    # Exit 1 when any High or Critical alert fired, so scripts and CI can react.
    if any(alert.severity.lower() in BLOCKING_SEVERITIES for alert in alerts):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
