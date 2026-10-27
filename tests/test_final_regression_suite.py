"""Batch regression tests for configuration, parser, detector, and CLI edge cases."""
import copy
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from src.ids.alert_manager import AlertManager
from src.ids.cli import create_detectors, process_log_file
from src.ids.config import ConfigError, load_config
from src.ids.detectors.brute_force import BruteForceDetector
from src.ids.detectors.compromise import CompromiseDetector
from src.ids.detectors.port_scan import PortScanDetector
from src.ids.detectors.scanning import ScanningDetector
from src.ids.detectors.spraying import PasswordSprayingDetector
from src.ids.detectors.unauthorized_access import UnauthorizedAccessDetector
from src.ids.models import Event
from src.ids.parsers.access_log import parse_access_line
from src.ids.parsers.auth_log import parse_auth_line
from src.ids.parsers.network_log import parse_network_line


class FinalRegressionSuite(unittest.TestCase):
    def setUp(self):
        self.config = copy.deepcopy(load_config())
        self.base = datetime(2026, 10, 24, 10, 0, 0)

    def event(self, seconds=0, *, ip="192.0.2.10", kind="failed_login", username="admin", status=None, port=None):
        return Event(
            timestamp=self.base + timedelta(seconds=seconds),
            source_ip=ip,
            username=username,
            event_type=kind,
            http_status=status,
            raw_line="test",
            destination_port=port,
        )

    def run_file(self, log_type, lines, config=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.log"
            path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            config = config or self.config
            return process_log_file(path, log_type, create_detectors(config), config)

    def test_empty_file_returns_no_alerts_and_zero_counts(self):
        self.assertEqual(self.run_file("auth", []), ([], 0, 0))

    def test_blank_lines_are_ignored_in_line_counts(self):
        alerts, processed, unparsed = self.run_file("auth", ["", "   "])
        self.assertEqual((alerts, processed, unparsed), ([], 0, 0))

    def test_nonempty_unparseable_lines_are_counted(self):
        alerts, processed, unparsed = self.run_file("auth", ["not an ssh log line"])
        self.assertEqual((alerts, processed, unparsed), ([], 1, 1))

    def test_missing_file_raises_file_not_found(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                process_log_file(Path(directory) / "missing.log", "auth", config=self.config)

    def test_all_six_detectors_are_created(self):
        self.assertEqual(len(create_detectors(self.config)), 6)

    def test_allowlist_normalizes_ip_whitespace(self):
        manager = AlertManager([" 192.0.2.10 "])
        self.assertTrue(manager.is_allowlisted(self.event()))

    def test_invalid_allowlist_ip_rejected_by_manager(self):
        with self.assertRaises(ValueError):
            AlertManager(["999.999.999.999"])

    def test_allowlisted_events_do_not_seed_brute_force_state(self):
        detector = BruteForceDetector(threshold=2)
        manager = AlertManager(["192.0.2.10"], cooldown_seconds=0)
        manager.process_event(self.event(0), [detector])
        alerts = manager.process_event(self.event(1, ip="192.0.2.11"), [detector])
        self.assertEqual(alerts, [])

    def test_brute_force_does_not_mix_sources(self):
        detector = BruteForceDetector(threshold=2)
        self.assertIsNone(detector.process(self.event(0, ip="192.0.2.10")))
        self.assertIsNone(detector.process(self.event(1, ip="192.0.2.11")))

    def test_spraying_requires_distinct_usernames(self):
        detector = PasswordSprayingDetector(threshold=3)
        for second in range(5):
            result = detector.process(self.event(second, username="same-user"))
        self.assertIsNone(result)
        result = detector.process(self.event(6, username="second-user"))
        self.assertIsNone(result)

    def test_compromise_rule_requires_success_after_threshold_failures(self):
        detector = CompromiseDetector(threshold=2)
        detector.process(self.event(0))
        detector.process(self.event(1))
        result = detector.process(self.event(2, kind="successful_login"))
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_name, "compromise_indicator")

    def test_compromise_rule_ignores_success_without_enough_failures(self):
        detector = CompromiseDetector(threshold=2)
        detector.process(self.event(0))
        self.assertIsNone(detector.process(self.event(1, kind="successful_login")))

    def test_scanning_detector_ignores_non_404_responses(self):
        detector = ScanningDetector(threshold=1)
        self.assertIsNone(detector.process(self.event(kind="http_request", status=200)))

    def test_unauthorized_access_accepts_401_and_403(self):
        detector = UnauthorizedAccessDetector(threshold=2)
        self.assertIsNone(detector.process(self.event(0, kind="http_request", status=401)))
        result = detector.process(self.event(1, kind="http_request", status=403))
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_name, "unauthorized_access")

    def test_port_scan_counts_distinct_ports_not_repeated_port(self):
        detector = PortScanDetector(threshold=2)
        self.assertIsNone(detector.process(self.event(0, kind="network_connection", port=443)))
        self.assertIsNone(detector.process(self.event(1, kind="network_connection", port=443)))
        result = detector.process(self.event(2, kind="network_connection", port=8443))
        self.assertIsNotNone(result)
        self.assertEqual(result.event_count, 2)

    def test_cooldown_is_separate_per_source_ip(self):
        manager = AlertManager(cooldown_seconds=300)
        detector = BruteForceDetector(threshold=1)
        self.assertEqual(len(manager.process_event(self.event(0), [detector])), 1)
        self.assertEqual(len(manager.process_event(self.event(1, ip="192.0.2.11"), [detector])), 1)

    def test_config_rejects_non_mapping_yaml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.yaml"
            path.write_text("- one\n- two\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_config_rejects_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.yaml"
            path.write_text("detection: [\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_network_parser_rejects_out_of_range_port(self):
        self.assertIsNone(parse_network_line("2026-10-24T10:00:00 192.0.2.1 192.0.2.2 65536"))

    def test_network_parser_rejects_port_zero(self):
        self.assertIsNone(parse_network_line("2026-10-24T10:00:00 192.0.2.1 192.0.2.2 0"))

    def test_network_parser_rejects_invalid_timestamp(self):
        self.assertIsNone(parse_network_line("not-a-date 192.0.2.1 192.0.2.2 443"))

    def test_auth_parser_rejects_invalid_calendar_date(self):
        self.assertIsNone(parse_auth_line("Feb 31 10:00:00 host sshd[1]: Failed password for admin from 192.0.2.1 port 22 ssh2", year=2026))

    def test_auth_parser_rejects_invalid_source_ip(self):
        self.assertIsNone(parse_auth_line("Oct 23 10:00:00 host sshd[1]: Failed password for admin from not-an-ip port 22 ssh2", year=2026))

    def test_auth_parser_normalizes_ipv6_source_ip(self):
        event = parse_auth_line("Oct 23 10:00:00 host sshd[1]: Failed password for admin from 2001:0db8::1 port 22 ssh2", year=2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.source_ip, "2001:db8::1")

    def test_http_parser_rejects_invalid_source_ip(self):
        self.assertIsNone(parse_access_line('not-an-ip - - [24/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 404 123'))

    def test_http_parser_normalizes_ipv6_source_ip(self):
        # Standard access-log client fields use an unbracketed IPv6 address.
        event = parse_access_line('2001:0db8::1 - - [24/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 404 123')
        self.assertIsNotNone(event)
        self.assertEqual(event.source_ip, "2001:db8::1")

    def test_http_parser_rejects_invalid_timestamp(self):
        self.assertIsNone(parse_access_line('192.0.2.1 - - [not-a-date] "GET / HTTP/1.1" 404 123'))

    def test_auth_cli_triggers_password_spraying(self):
        self.config["detection"]["password_spraying"]["threshold"] = 3
        lines = [
            f"Oct 23 10:00:0{i} host sshd[{2000+i}]: Failed password for user{i} from 192.0.2.70 port 5000 ssh2"
            for i in range(3)
        ]
        alerts, processed, unparsed = self.run_file("auth", lines)
        self.assertEqual((processed, unparsed), (3, 0))
        self.assertIn("password_spraying", [alert.rule_name for alert in alerts])

    def test_auth_cli_triggers_compromise_indicator(self):
        self.config["detection"]["compromise_indicator"]["threshold"] = 2
        lines = [
            "Oct 23 10:00:00 host sshd[3000]: Failed password for admin from 192.0.2.71 port 5000 ssh2",
            "Oct 23 10:00:01 host sshd[3001]: Failed password for admin from 192.0.2.71 port 5001 ssh2",
            "Oct 23 10:00:02 host sshd[3002]: Accepted password for admin from 192.0.2.71 port 5002 ssh2",
        ]
        alerts, processed, unparsed = self.run_file("auth", lines)
        self.assertEqual((processed, unparsed), (3, 0))
        self.assertIn("compromise_indicator", [alert.rule_name for alert in alerts])

    def test_http_cli_triggers_unauthorized_access(self):
        self.config["detection"]["unauthorized_access"]["threshold"] = 2
        lines = [
            '192.0.2.72 - - [24/Oct/2026:10:00:00 +0000] "GET /one HTTP/1.1" 401 123',
            '192.0.2.72 - - [24/Oct/2026:10:00:01 +0000] "GET /two HTTP/1.1" 403 123',
        ]
        alerts, processed, unparsed = self.run_file("http", lines)
        self.assertEqual((processed, unparsed), (2, 0))
        self.assertIn("unauthorized_access", [alert.rule_name for alert in alerts])

    def test_http_cli_reports_unparseable_lines_without_crashing(self):
        alerts, processed, unparsed = self.run_file("http", ["garbage", '192.0.2.1 - - [24/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 10'])
        self.assertEqual((processed, unparsed), (2, 1))
        self.assertEqual(alerts, [])

    def test_network_cli_reports_invalid_lines_without_crashing(self):
        alerts, processed, unparsed = self.run_file("network", ["garbage", "2026-10-24T10:00:00 192.0.2.1 192.0.2.2 443"])
        self.assertEqual((processed, unparsed), (2, 1))
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
