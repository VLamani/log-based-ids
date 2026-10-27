import unittest
from datetime import datetime, timedelta, timezone

from src.ids.alert_manager import AlertManager
from src.ids.models import Alert, Event


class FakeDetector:
    def __init__(self, rule_name="test_rule"):
        self.rule_name = rule_name
        self.calls = 0

    def process(self, event):
        self.calls += 1
        return Alert(
            rule_name=self.rule_name,
            severity="High",
            source_ip=event.source_ip,
            start_time=event.timestamp,
            end_time=event.timestamp,
            event_count=1,
            description="test",
        )


class TestAlertManager(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 10, 24, 10, 0, 0)

    def event(self, seconds=0, ip="192.0.2.10"):
        return Event(
            timestamp=self.start + timedelta(seconds=seconds),
            source_ip=ip,
            username="admin",
            event_type="failed_login",
            http_status=None,
            raw_line="test",
        )

    def test_allowlisted_ip_is_not_sent_to_detectors(self):
        manager = AlertManager(["192.0.2.10"], cooldown_seconds=300)
        detector = FakeDetector()
        self.assertEqual(manager.process_event(self.event(), [detector]), [])
        self.assertEqual(detector.calls, 0)

    def test_non_allowlisted_ip_can_alert(self):
        manager = AlertManager(["192.0.2.11"], cooldown_seconds=300)
        detector = FakeDetector()
        self.assertEqual(len(manager.process_event(self.event(), [detector])), 1)

    def test_cooldown_suppresses_same_rule_and_ip(self):
        manager = AlertManager(cooldown_seconds=300)
        detector = FakeDetector()
        self.assertEqual(len(manager.process_event(self.event(0), [detector])), 1)
        self.assertEqual(manager.process_event(self.event(100), [detector]), [])

    def test_alert_allowed_after_cooldown_expires(self):
        manager = AlertManager(cooldown_seconds=300)
        detector = FakeDetector()
        self.assertEqual(len(manager.process_event(self.event(0), [detector])), 1)
        self.assertEqual(len(manager.process_event(self.event(300), [detector])), 1)

    def test_zero_cooldown_allows_each_alert(self):
        manager = AlertManager(cooldown_seconds=0)
        detector = FakeDetector()
        self.assertEqual(len(manager.process_event(self.event(0), [detector])), 1)
        self.assertEqual(len(manager.process_event(self.event(1), [detector])), 1)

    def test_cooldown_handles_naive_then_aware_timestamps(self):
        manager = AlertManager(cooldown_seconds=300)
        detector = FakeDetector()
        self.assertEqual(len(manager.process_event(self.event(0), [detector])), 1)

        aware_event = Event(
            timestamp=(self.start + timedelta(seconds=60)).replace(tzinfo=timezone.utc),
            source_ip="192.0.2.10",
            username="admin",
            event_type="failed_login",
            http_status=None,
            raw_line="test",
        )
        self.assertEqual(manager.process_event(aware_event, [detector]), [])

    def test_cooldown_compares_equivalent_timezone_instants(self):
        manager = AlertManager(cooldown_seconds=300)
        detector = FakeDetector()
        first = Event(
            timestamp=datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc),
            source_ip="192.0.2.10", username="admin", event_type="failed_login",
            http_status=None, raw_line="first",
        )
        second = Event(
            timestamp=datetime.fromisoformat("2026-10-24T15:01:00+05:00"),
            source_ip="192.0.2.10", username="admin", event_type="failed_login",
            http_status=None, raw_line="second",
        )
        self.assertEqual(len(manager.process_event(first, [detector])), 1)
        self.assertEqual(manager.process_event(second, [detector]), [])

    def test_cooldown_is_separate_per_rule(self):
        manager = AlertManager(cooldown_seconds=300)
        first = FakeDetector("rule_a")
        second = FakeDetector("rule_b")
        self.assertEqual(len(manager.process_event(self.event(), [first, second])), 2)


if __name__ == "__main__":
    unittest.main()
