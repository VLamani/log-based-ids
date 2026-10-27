import unittest
from datetime import datetime, timedelta

from src.ids.alert_manager import AlertManager
from src.ids.detectors.brute_force import BruteForceDetector
from src.ids.detectors.compromise import CompromiseDetector
from src.ids.detectors.port_scan import PortScanDetector
from src.ids.detectors.scanning import ScanningDetector
from src.ids.detectors.spraying import PasswordSprayingDetector
from src.ids.detectors.unauthorized_access import UnauthorizedAccessDetector
from src.ids.models import Event


class TestRealDetectorAlertManagerIntegration(unittest.TestCase):
    """Verify real detectors cooperate with shared allowlist/cooldown handling."""

    def setUp(self):
        self.start = datetime(2026, 10, 24, 10, 0, 0)
        self.source_ip = "192.0.2.20"

    def event(
        self,
        seconds,
        event_type="failed_login",
        username="admin",
        status=None,
        port=None,
        source_ip=None,
    ):
        return Event(
            timestamp=self.start + timedelta(seconds=seconds),
            source_ip=source_ip or self.source_ip,
            username=username,
            event_type=event_type,
            http_status=status,
            raw_line="integration test event",
            destination_port=port,
        )

    def assert_rule_triggers_and_cooldown_suppresses_repeat(
        self, detector, first_events, repeat_events, after_cooldown_events, expected_rule
    ):
        manager = AlertManager(cooldown_seconds=300)
        first_alerts = []
        for event in first_events:
            first_alerts.extend(manager.process_event(event, [detector]))

        self.assertEqual(
            [alert.rule_name for alert in first_alerts],
            [expected_rule],
            f"{expected_rule} should trigger through AlertManager",
        )

        repeated_alerts = []
        for event in repeat_events:
            repeated_alerts.extend(manager.process_event(event, [detector]))

        self.assertEqual(
            repeated_alerts,
            [],
            f"{expected_rule} repeat should be suppressed during cooldown",
        )

        after_cooldown_alerts = []
        for event in after_cooldown_events:
            after_cooldown_alerts.extend(manager.process_event(event, [detector]))

        self.assertEqual(
            [alert.rule_name for alert in after_cooldown_alerts],
            [expected_rule],
            f"{expected_rule} should alert again after cooldown expires",
        )

    def test_brute_force_integrates_with_cooldown(self):
        self.assert_rule_triggers_and_cooldown_suppresses_repeat(
            BruteForceDetector(threshold=2, window_seconds=300),
            [self.event(0), self.event(1)],
            [self.event(60), self.event(61)],
            [self.event(400), self.event(401)],
            "brute_force",
        )

    def test_password_spraying_integrates_with_cooldown(self):
        detector = PasswordSprayingDetector(threshold=2, window_seconds=600)
        self.assert_rule_triggers_and_cooldown_suppresses_repeat(
            detector,
            [self.event(0, username="alice"), self.event(1, username="bob")],
            [self.event(60, username="carol"), self.event(61, username="dave")],
            [self.event(400, username="erin"), self.event(401, username="frank")],
            "password_spraying",
        )

    def test_compromise_indicator_integrates_with_cooldown(self):
        detector = CompromiseDetector(threshold=2, window_seconds=600)
        self.assert_rule_triggers_and_cooldown_suppresses_repeat(
            detector,
            [self.event(0), self.event(1), self.event(2, event_type="successful_login")],
            [self.event(60, event_type="successful_login")],
            [self.event(400, event_type="successful_login")],
            "compromise_indicator",
        )

    def test_http_scanning_integrates_with_cooldown(self):
        detector = ScanningDetector(threshold=2, window_seconds=60)
        self.assert_rule_triggers_and_cooldown_suppresses_repeat(
            detector,
            [self.event(0, event_type="http_request", status=404), self.event(1, event_type="http_request", status=404)],
            [self.event(60, event_type="http_request", status=404), self.event(61, event_type="http_request", status=404)],
            [self.event(400, event_type="http_request", status=404), self.event(401, event_type="http_request", status=404)],
            "scanning",
        )

    def test_port_scan_integrates_with_cooldown(self):
        detector = PortScanDetector(threshold=2, window_seconds=60)
        self.assert_rule_triggers_and_cooldown_suppresses_repeat(
            detector,
            [self.event(0, event_type="network_connection", port=5000), self.event(1, event_type="network_connection", port=5001)],
            [self.event(60, event_type="network_connection", port=5002), self.event(61, event_type="network_connection", port=5003)],
            [self.event(400, event_type="network_connection", port=5004), self.event(401, event_type="network_connection", port=5005)],
            "port_scan",
        )

    def test_unauthorized_access_integrates_with_cooldown(self):
        detector = UnauthorizedAccessDetector(threshold=2, window_seconds=60)
        self.assert_rule_triggers_and_cooldown_suppresses_repeat(
            detector,
            [self.event(0, event_type="http_request", status=401), self.event(1, event_type="http_request", status=403)],
            [self.event(60, event_type="http_request", status=401), self.event(61, event_type="http_request", status=403)],
            [self.event(400, event_type="http_request", status=401), self.event(401, event_type="http_request", status=403)],
            "unauthorized_access",
        )

    def test_allowlisted_ip_never_reaches_real_detector(self):
        detector = BruteForceDetector(threshold=2, window_seconds=300)
        manager = AlertManager(
            allowlisted_ips=[self.source_ip],
            cooldown_seconds=300,
        )

        for event in [self.event(0), self.event(1), self.event(2)]:
            self.assertEqual(manager.process_event(event, [detector]), [])

        # Allowlisting happens before detector processing, so the detector's
        # failure history must remain empty for the allowlisted source.
        self.assertNotIn(self.source_ip, detector.failures)


if __name__ == "__main__":
    unittest.main()
