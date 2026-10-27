import unittest
from datetime import datetime, timedelta

from src.ids.detectors.brute_force import BruteForceDetector
from src.ids.models import Event


class TestBruteForceDetector(unittest.TestCase):

    def setUp(self):
        self.detector = BruteForceDetector()
        self.start = datetime(2026, 10, 23, 10, 0, 0)

    def make_event(
        self,
        seconds=0,
        event_type="failed_login",
        ip="203.0.113.5",
    ):
        return Event(
            timestamp=self.start + timedelta(seconds=seconds),
            source_ip=ip,
            username="admin",
            event_type=event_type,
            http_status=None,
            raw_line="test log entry",
        )

    def test_alerts_at_threshold(self):
        alert = None

        for i in range(10):
            alert = self.detector.process(self.make_event(seconds=i * 10))

        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_name, "brute_force")
        self.assertEqual(alert.severity, "High")
        self.assertEqual(alert.event_count, 10)

    def test_does_not_alert_below_threshold(self):
        for i in range(9):
            alert = self.detector.process(self.make_event(seconds=i * 10))

        self.assertIsNone(alert)

    def test_ignores_successful_login(self):
        alert = self.detector.process(
            self.make_event(event_type="successful_login")
        )

        self.assertIsNone(alert)

    def test_tracks_ips_separately(self):
        for i in range(9):
            self.detector.process(self.make_event(seconds=i * 10))

        alert = self.detector.process(
            self.make_event(seconds=90, ip="198.51.100.7")
        )

        self.assertIsNone(alert)

class TestPasswordSprayingDetector(unittest.TestCase):

    def setUp(self):
        from src.ids.detectors.spraying import PasswordSprayingDetector

        self.detector = PasswordSprayingDetector()
        self.start = datetime(2026, 10, 23, 10, 0, 0)

    def make_event(self, username, seconds=0, ip="203.0.113.5"):
        return Event(
            timestamp=self.start + timedelta(seconds=seconds),
            source_ip=ip,
            username=username,
            event_type="failed_login",
            http_status=None,
            raw_line="test log entry",
        )

    def test_alerts_for_five_distinct_usernames(self):
        alert = None

        for i, username in enumerate(
            ["alice", "bob", "charlie", "david", "eve"]
        ):
            alert = self.detector.process(
                self.make_event(username, seconds=i * 10)
            )

        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_name, "password_spraying")
        self.assertEqual(alert.event_count, 5)

    def test_repeated_username_does_not_trigger_threshold(self):
        for i in range(5):
            alert = self.detector.process(
                self.make_event("alice", seconds=i * 10)
            )

        self.assertIsNone(alert)

    def test_tracks_ips_separately(self):
        for i, username in enumerate(["alice", "bob", "charlie", "david"]):
            self.detector.process(
                self.make_event(username, seconds=i * 10)
            )

        alert = self.detector.process(
            self.make_event("eve", seconds=50, ip="198.51.100.7")
        )

        self.assertIsNone(alert)


class TestCompromiseDetector(unittest.TestCase):

    def setUp(self):
        from src.ids.detectors.compromise import CompromiseDetector

        self.detector = CompromiseDetector()
        self.start = datetime(2026, 10, 23, 10, 0, 0)

    def make_event(self, event_type, seconds=0):
        return Event(
            timestamp=self.start + timedelta(seconds=seconds),
            source_ip="203.0.113.5",
            username="admin",
            event_type=event_type,
            http_status=None,
            raw_line="test log entry",
        )

    def test_success_after_five_failures_triggers_alert(self):
        for i in range(5):
            self.detector.process(
                self.make_event("failed_login", seconds=i * 10)
            )

        alert = self.detector.process(
            self.make_event("successful_login", seconds=60)
        )

        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "Critical")
        self.assertEqual(alert.rule_name, "compromise_indicator")

    def test_success_without_enough_failures_does_not_alert(self):
        for i in range(4):
            self.detector.process(
                self.make_event("failed_login", seconds=i * 10)
            )

        alert = self.detector.process(
            self.make_event("successful_login", seconds=50)
        )

        self.assertIsNone(alert)

    def test_success_from_different_ip_does_not_alert(self):
        for i in range(5):
            self.detector.process(
                self.make_event("failed_login", seconds=i * 10)
            )

        event = self.make_event("successful_login", seconds=60)
        event.source_ip = "198.51.100.7"

        alert = self.detector.process(event)

        self.assertIsNone(alert)


class TestScanningDetector(unittest.TestCase):

    def setUp(self):
        from src.ids.detectors.scanning import ScanningDetector

        self.detector = ScanningDetector()
        self.start = datetime(2026, 10, 23, 10, 0, 0)

    def make_event(self, status=404, seconds=0, ip="203.0.113.5"):
        return Event(
            timestamp=self.start + timedelta(seconds=seconds),
            source_ip=ip,
            username=None,
            event_type="http_request",
            http_status=status,
            raw_line="test access log",
        )

    def test_alerts_at_thirty_404_responses(self):
        alert = None

        for i in range(30):
            alert = self.detector.process(
                self.make_event(seconds=i)
            )

        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_name, "scanning")
        self.assertEqual(alert.severity, "Medium")
        self.assertEqual(alert.event_count, 30)

    def test_does_not_alert_below_threshold(self):
        for i in range(29):
            alert = self.detector.process(
                self.make_event(seconds=i)
            )

        self.assertIsNone(alert)

    def test_ignores_non_404_responses(self):
        for i in range(35):
            alert = self.detector.process(
                self.make_event(status=200, seconds=i)
            )

        self.assertIsNone(alert)

    def test_tracks_ips_separately(self):
        for i in range(29):
            self.detector.process(self.make_event(seconds=i))

        alert = self.detector.process(
            self.make_event(seconds=29, ip="198.51.100.7")
        )

        self.assertIsNone(alert)


class TestPortScanDetector(unittest.TestCase):

    def setUp(self):
        from src.ids.detectors.port_scan import PortScanDetector

        self.detector = PortScanDetector()
        self.start = datetime(2026, 10, 23, 10, 0, 0)

    def make_event(self, port, seconds=0, ip="203.0.113.5"):
        return Event(
            timestamp=self.start + timedelta(seconds=seconds),
            source_ip=ip,
            username=None,
            event_type="network_connection",
            http_status=None,
            raw_line="test network event",
            destination_port=port,
        )

    def test_alerts_at_distinct_port_threshold(self):
        alert = None

        for port in range(1, 16):
            alert = self.detector.process(
                self.make_event(port, seconds=port)
            )

        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_name, "port_scan")
        self.assertEqual(alert.severity, "High")
        self.assertEqual(alert.event_count, 15)

    def test_repeated_port_does_not_trigger_alert(self):
        for _ in range(20):
            alert = self.detector.process(self.make_event(443))

        self.assertIsNone(alert)

    def test_invalid_port_is_ignored(self):
        self.assertIsNone(self.detector.process(self.make_event(70000)))
        self.assertIsNone(self.detector.process(self.make_event(0)))

    def test_tracks_ips_separately(self):
        for port in range(1, 15):
            self.detector.process(self.make_event(port))

        alert = self.detector.process(
            self.make_event(15, ip="198.51.100.7")
        )

        self.assertIsNone(alert)


class TestUnauthorizedAccessDetector(unittest.TestCase):

    def setUp(self):
        from src.ids.detectors.unauthorized_access import (
            UnauthorizedAccessDetector,
        )

        self.detector = UnauthorizedAccessDetector()
        self.start = datetime(2026, 10, 23, 10, 0, 0)

    def make_event(self, status=401, seconds=0, ip="203.0.113.5"):
        return Event(
            timestamp=self.start + timedelta(seconds=seconds),
            source_ip=ip,
            username=None,
            event_type="http_request",
            http_status=status,
            raw_line="test access log",
        )

    def test_alerts_at_threshold(self):
        alert = None

        for i in range(10):
            status = 401 if i % 2 == 0 else 403
            alert = self.detector.process(
                self.make_event(status=status, seconds=i)
            )

        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_name, "unauthorized_access")
        self.assertEqual(alert.severity, "High")
        self.assertEqual(alert.event_count, 10)

    def test_does_not_alert_below_threshold(self):
        for i in range(9):
            alert = self.detector.process(
                self.make_event(seconds=i)
            )

        self.assertIsNone(alert)

    def test_ignores_successful_responses(self):
        for i in range(15):
            alert = self.detector.process(
                self.make_event(status=200, seconds=i)
            )

        self.assertIsNone(alert)

    def test_tracks_ips_separately(self):
        for i in range(9):
            self.detector.process(self.make_event(seconds=i))

        alert = self.detector.process(
            self.make_event(status=403, seconds=9, ip="198.51.100.7")
        )

        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
