"""Regression tests for inclusive detection-window boundaries."""
from datetime import datetime, timedelta

from src.ids.detectors.brute_force import BruteForceDetector
from src.ids.detectors.compromise import CompromiseDetector
from src.ids.detectors.port_scan import PortScanDetector
from src.ids.detectors.scanning import ScanningDetector
from src.ids.detectors.spraying import PasswordSprayingDetector
from src.ids.detectors.unauthorized_access import UnauthorizedAccessDetector
from src.ids.models import Event


START = datetime(2026, 10, 24, 10, 0, 0)
IP = "203.0.113.5"


def event(seconds, *, event_type="failed_login", username="admin", status=None, port=None):
    return Event(
        timestamp=START + timedelta(seconds=seconds),
        source_ip=IP,
        username=username,
        event_type=event_type,
        http_status=status,
        raw_line="boundary test event",
        destination_port=port,
    )


def test_brute_force_includes_event_exactly_on_window_boundary():
    detector = BruteForceDetector(threshold=2, window_seconds=300)
    detector.process(event(0))
    assert detector.process(event(300)) is not None


def test_brute_force_excludes_event_just_outside_window():
    detector = BruteForceDetector(threshold=2, window_seconds=300)
    detector.process(event(0))
    assert detector.process(event(300.000001)) is None


def test_password_spraying_includes_event_exactly_on_window_boundary():
    detector = PasswordSprayingDetector(threshold=2, window_seconds=600)
    detector.process(event(0, username="alice"))
    alert = detector.process(event(600, username="bob"))
    assert alert is not None
    assert alert.event_count == 2


def test_password_spraying_excludes_event_just_outside_window():
    detector = PasswordSprayingDetector(threshold=2, window_seconds=600)
    detector.process(event(0, username="alice"))
    assert detector.process(event(600.000001, username="bob")) is None


def test_compromise_includes_failure_exactly_on_window_boundary():
    detector = CompromiseDetector(threshold=1, window_seconds=600)
    detector.process(event(0, event_type="failed_login"))
    alert = detector.process(event(600, event_type="successful_login"))
    assert alert is not None
    assert alert.rule_name == "compromise_indicator"


def test_compromise_excludes_failure_just_outside_window():
    detector = CompromiseDetector(threshold=1, window_seconds=600)
    detector.process(event(0, event_type="failed_login"))
    assert detector.process(event(600.000001, event_type="successful_login")) is None


def test_http_scanning_includes_event_exactly_on_window_boundary():
    detector = ScanningDetector(threshold=2, window_seconds=60)
    detector.process(event(0, event_type="http_request", status=404))
    assert detector.process(event(60, event_type="http_request", status=404)) is not None


def test_http_scanning_excludes_event_just_outside_window():
    detector = ScanningDetector(threshold=2, window_seconds=60)
    detector.process(event(0, event_type="http_request", status=404))
    assert detector.process(event(60.000001, event_type="http_request", status=404)) is None


def test_port_scan_includes_port_exactly_on_window_boundary():
    detector = PortScanDetector(threshold=2, window_seconds=60)
    detector.process(event(0, event_type="network_connection", port=22))
    alert = detector.process(event(60, event_type="network_connection", port=443))
    assert alert is not None
    assert alert.event_count == 2


def test_port_scan_excludes_port_just_outside_window():
    detector = PortScanDetector(threshold=2, window_seconds=60)
    detector.process(event(0, event_type="network_connection", port=22))
    assert detector.process(event(60.000001, event_type="network_connection", port=443)) is None


def test_unauthorized_access_includes_event_exactly_on_window_boundary():
    detector = UnauthorizedAccessDetector(threshold=2, window_seconds=60)
    detector.process(event(0, event_type="http_request", status=401))
    assert detector.process(event(60, event_type="http_request", status=403)) is not None


def test_unauthorized_access_excludes_event_just_outside_window():
    detector = UnauthorizedAccessDetector(threshold=2, window_seconds=60)
    detector.process(event(0, event_type="http_request", status=401))
    assert detector.process(event(60.000001, event_type="http_request", status=403)) is None
