from pathlib import Path

from src.ids.cli import process_log_file
from src.ids.config import load_config


def test_auth_pipeline_sorts_out_of_order_events_before_detection(tmp_path: Path):
    config = load_config()
    lines = [
        f"Oct 23 10:00:{second:02d} host sshd[{1000 + second}]: Failed password for admin from 192.0.2.10 port {5000 + second} ssh2"
        for second in [9, 1, 7, 0, 8, 2, 6, 3, 5, 4]
    ]
    log_path = tmp_path / "auth.log"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    alerts, processed, unparsed = process_log_file(log_path, "auth", config=config)

    assert processed == 10
    assert unparsed == 0
    assert any(alert.rule_name == "brute_force" for alert in alerts)


def test_network_pipeline_sorts_out_of_order_events_before_port_scan(tmp_path: Path):
    config = load_config()
    lines = [
        f"2026-10-24T10:00:{second:02d} 192.0.2.10 192.0.2.20 {port}"
        for second, port in [(14, 1014), (2, 1002), (12, 1012), (0, 1000),
                             (10, 1010), (4, 1004), (8, 1008), (6, 1006),
                             (13, 1013), (1, 1001), (11, 1011), (3, 1003),
                             (9, 1009), (5, 1005), (7, 1007)]
    ]
    log_path = tmp_path / "network.log"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    alerts, processed, unparsed = process_log_file(log_path, "network", config=config)

    assert processed == 15
    assert unparsed == 0
    assert any(alert.rule_name == "port_scan" for alert in alerts)


def test_network_pipeline_sorts_mixed_timezone_timestamps(tmp_path: Path):
    config = load_config()
    lines = [
        "2026-10-24T10:00:14+00:00 192.0.2.70 192.0.2.1 1014",
        "2026-10-24T15:00:02+05:00 192.0.2.70 192.0.2.1 1002",
        "2026-10-24T10:00:12Z 192.0.2.70 192.0.2.1 1012",
        "2026-10-24T10:00:00 192.0.2.70 192.0.2.1 1000",
        "2026-10-24T10:00:10+00:00 192.0.2.70 192.0.2.1 1010",
        "2026-10-24T10:00:04Z 192.0.2.70 192.0.2.1 1004",
        "2026-10-24T10:00:08+00:00 192.0.2.70 192.0.2.1 1008",
        "2026-10-24T10:00:06Z 192.0.2.70 192.0.2.1 1006",
        "2026-10-24T10:00:13+00:00 192.0.2.70 192.0.2.1 1013",
        "2026-10-24T10:00:01Z 192.0.2.70 192.0.2.1 1001",
        "2026-10-24T10:00:11+00:00 192.0.2.70 192.0.2.1 1011",
        "2026-10-24T10:00:03Z 192.0.2.70 192.0.2.1 1003",
        "2026-10-24T10:00:09+00:00 192.0.2.70 192.0.2.1 1009",
        "2026-10-24T10:00:05Z 192.0.2.70 192.0.2.1 1005",
        "2026-10-24T10:00:07+00:00 192.0.2.70 192.0.2.1 1007",
    ]
    log_path = tmp_path / "mixed-timezones.log"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    alerts, processed, unparsed = process_log_file(log_path, "network", config=config)

    assert processed == 15
    assert unparsed == 0
    assert any(alert.rule_name == "port_scan" for alert in alerts)
