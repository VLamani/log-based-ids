import copy
import tempfile
import unittest
from pathlib import Path

from src.ids.cli import create_detectors, process_log_file
from src.ids.config import load_config


class TestFullPipeline(unittest.TestCase):
    def setUp(self):
        self.config = copy.deepcopy(load_config())

    def run_pipeline(self, log_type, lines):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / f"sample.{log_type}.log"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return process_log_file(path, log_type, create_detectors(self.config), self.config)

    def test_http_logs_trigger_scanning_through_cli_pipeline(self):
        self.config["detection"]["scanning"]["threshold"] = 2
        lines = [
            '192.0.2.30 - - [24/Oct/2026:10:00:00 +0000] "GET /one HTTP/1.1" 404 123',
            '192.0.2.30 - - [24/Oct/2026:10:00:10 +0000] "GET /two HTTP/1.1" 404 123',
        ]
        alerts, processed, unparsed = self.run_pipeline("http", lines)
        self.assertEqual((processed, unparsed), (2, 0))
        self.assertIn("scanning", [alert.rule_name for alert in alerts])

    def test_network_logs_trigger_port_scan_through_cli_pipeline(self):
        self.config["detection"]["port_scan"]["threshold"] = 2
        lines = [
            "2026-10-24T10:00:00 192.0.2.40 192.0.2.1 443",
            "2026-10-24T10:00:10 192.0.2.40 192.0.2.1 8443",
        ]
        alerts, processed, unparsed = self.run_pipeline("network", lines)
        self.assertEqual((processed, unparsed), (2, 0))
        self.assertIn("port_scan", [alert.rule_name for alert in alerts])

    def test_auth_pipeline_cooldown_suppresses_repeated_alerts(self):
        self.config["detection"]["brute_force"]["threshold"] = 2
        self.config["alert_cooldown_seconds"] = 300
        lines = [
            "Oct 23 10:00:00 host sshd[1000]: Failed password for admin from 192.0.2.50 port 5000 ssh2",
            "Oct 23 10:00:01 host sshd[1001]: Failed password for admin from 192.0.2.50 port 5001 ssh2",
            "Oct 23 10:01:00 host sshd[1002]: Failed password for admin from 192.0.2.50 port 5002 ssh2",
            "Oct 23 10:01:01 host sshd[1003]: Failed password for admin from 192.0.2.50 port 5003 ssh2",
        ]
        alerts, processed, unparsed = self.run_pipeline("auth", lines)
        self.assertEqual((processed, unparsed), (4, 0))
        brute_force_alerts = [alert for alert in alerts if alert.rule_name == "brute_force"]
        self.assertEqual(len(brute_force_alerts), 1)

    def test_auth_pipeline_allows_alert_after_cooldown_expires(self):
        self.config["detection"]["brute_force"]["threshold"] = 2
        self.config["detection"]["brute_force"]["window_seconds"] = 60
        self.config["alert_cooldown_seconds"] = 30
        lines = [
            "Oct 23 10:00:00 host sshd[1000]: Failed password for admin from 192.0.2.60 port 5000 ssh2",
            "Oct 23 10:00:01 host sshd[1001]: Failed password for admin from 192.0.2.60 port 5001 ssh2",
            "Oct 23 10:00:40 host sshd[1002]: Failed password for admin from 192.0.2.60 port 5002 ssh2",
            "Oct 23 10:00:41 host sshd[1003]: Failed password for admin from 192.0.2.60 port 5003 ssh2",
        ]
        alerts, processed, unparsed = self.run_pipeline("auth", lines)
        self.assertEqual((processed, unparsed), (4, 0))
        brute_force_alerts = [alert for alert in alerts if alert.rule_name == "brute_force"]
        self.assertEqual(len(brute_force_alerts), 2)


if __name__ == "__main__":
    unittest.main()
