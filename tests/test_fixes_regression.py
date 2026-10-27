import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from src.ids.cli import create_detectors, process_log_file
from src.ids.config import ConfigError, load_config
from src.ids.detectors.port_scan import PortScanDetector
from src.ids.models import Alert, Event
from src.ids.parsers.auth_log import parse_auth_line
from src.ids.parsers.network_log import parse_network_line
from src.ids.reporter import write_json_report


def network_event(ip, dst_ip, port, second):
    return Event(
        timestamp=datetime(2026, 10, 24, 10, 0, 0) + timedelta(seconds=second),
        source_ip=ip,
        username=None,
        event_type="network_connection",
        http_status=None,
        raw_line="",
        destination_port=port,
        destination_ip=dst_ip,
    )


class TestLeapYearAndYearOption(unittest.TestCase):
    def test_feb_29_parses_in_leap_year(self):
        event = parse_auth_line(
            "Feb 29 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2",
            year=2028,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.timestamp.date().isoformat(), "2028-02-29")

    def test_year_option_is_applied_to_file_processing(self):
        line = "Oct 24 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(line, encoding="utf-8")
            config = load_config()
            alerts, processed, unparsed = process_log_file(
                path, "auth", detectors=[], config=config, year=2031
            )
        self.assertEqual((processed, unparsed), (1, 0))


class TestConfigUnknownKeys(unittest.TestCase):
    def test_typo_in_rule_key_is_rejected_with_clear_error(self):
        config = load_config()
        config["detection"]["brute_force"]["treshold"] = 10
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "Unknown key"):
                load_config(path)


class TestPortScanTargets(unittest.TestCase):
    def test_one_host_many_ports_still_alerts(self):
        detector = PortScanDetector(threshold=15, window_seconds=60)
        alerts = [
            a for a in (
                detector.process(network_event("10.0.0.5", "192.168.1.10", port, i))
                for i, port in enumerate(range(1, 16))
            ) if a
        ]
        self.assertEqual(len(alerts), 1)
        self.assertIn("192.168.1.10", alerts[0].description)

    def test_many_hosts_many_ports_does_not_alert(self):
        detector = PortScanDetector(threshold=15, window_seconds=60)
        alerts = [
            a for a in (
                detector.process(network_event("10.0.0.5", f"192.168.1.{h}", 8000 + h, h))
                for h in range(1, 31)
            ) if a
        ]
        self.assertEqual(alerts, [])

    def test_network_parser_stores_destination_ip(self):
        event = parse_network_line("2026-10-24T10:00:00 10.0.0.5 192.168.1.10 22")
        self.assertEqual(event.destination_ip, "192.168.1.10")


class TestJsonReport(unittest.TestCase):
    def test_json_report_contains_counts_and_alerts(self):
        alert = Alert(
            rule_name="brute_force", severity="High", source_ip="192.0.2.1",
            start_time=datetime(2026, 10, 24, 10, 0), end_time=datetime(2026, 10, 24, 10, 1),
            event_count=10, description="test",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.json"
            write_json_report(path, [alert], lines_processed=12, lines_unparsed=2)
            document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["total_alerts"], 1)
        self.assertEqual(document["lines_unparsed"], 2)
        self.assertEqual(document["alerts"][0]["rule_name"], "brute_force")


if __name__ == "__main__":
    unittest.main()


class TestIsoSyslogFormat(unittest.TestCase):
    REAL_FAILED = ("2026-10-25T16:19:33.056507+00:00 lab-host sshd[2304]: "
                   "Failed password for invalid user guest_user from 192.0.2.128 port 60098 ssh2")
    REAL_ACCEPTED = ("2026-10-25T16:20:01.000000+00:00 lab-host sshd[2310]: "
                     "Accepted password for alice from 192.0.2.128 port 60120 ssh2")

    def test_real_ubuntu_failed_line_parses(self):
        event = parse_auth_line(self.REAL_FAILED)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "failed_login")
        self.assertEqual(event.source_ip, "192.0.2.128")
        self.assertEqual(event.username, "guest_user")
        self.assertEqual(event.timestamp.year, 2026)

    def test_real_ubuntu_accepted_line_parses(self):
        event = parse_auth_line(self.REAL_ACCEPTED)
        self.assertEqual(event.event_type, "successful_login")

    def test_iso_line_with_z_suffix_parses(self):
        event = parse_auth_line(
            "2026-10-25T16:19:33Z lab-host sshd[1]: Failed password for root from 192.0.2.9 port 22 ssh2"
        )
        self.assertIsNotNone(event)

    def test_non_sshd_lines_are_ignored(self):
        self.assertIsNone(parse_auth_line(
            "2026-10-25T16:17:01.074718+00:00 lab-host CRON[2287]: session opened"
        ))

    def test_classic_format_still_parses(self):
        self.assertIsNotNone(parse_auth_line(
            "Oct 25 16:19:33 lab-host sshd[2304]: Failed password for root from 192.0.2.9 port 22 ssh2",
            year=2026,
        ))


class TestRepeatedSyslogLines(unittest.TestCase):
    MARKER = ("2026-10-25T16:45:40.364030+00:00 lab-host sshd[9489]: "
              "message repeated 5 times: [ Failed password for dev_user from 192.0.2.128 port 47460 ssh2]")

    def test_repeat_marker_expands_to_count_copies(self):
        from src.ids.parsers.auth_log import expand_repeated_auth_line
        lines = expand_repeated_auth_line(self.MARKER)
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], lines[4])
        self.assertIn("Failed password for dev_user", lines[0])

    def test_ordinary_line_is_not_expanded(self):
        from src.ids.parsers.auth_log import expand_repeated_auth_line
        line = "2026-10-25T16:45:42.381566+00:00 lab-host sshd[9491]: Failed password for dev_user from 192.0.2.128 port 50996 ssh2"
        self.assertEqual(expand_repeated_auth_line(line), [line])

    def test_repeated_failures_reach_compromise_threshold(self):
        import tempfile
        from pathlib import Path
        from src.ids.cli import process_log_file
        from src.ids.config import load_config
        success = ("2026-10-25T16:46:55.384675+00:00 lab-host sshd[9493]: "
                   "Accepted password for dev_user from 192.0.2.128 port 41184 ssh2")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(self.MARKER + "\n" + success + "\n", encoding="utf-8")
            alerts, processed, unparsed = process_log_file(path, "auth", config=load_config())
        self.assertIn("compromise_indicator", [a.rule_name for a in alerts])
        self.assertEqual(processed, 2)
