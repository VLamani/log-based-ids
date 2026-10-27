"""Generate labeled sample logs with known attacks mixed into normal traffic.

Because the ground truth is written alongside the logs, the detector's output
can be compared against it to measure which attacks were caught (recall) and
which alerts were false (precision).

Usage (from the project root):
    python scripts/simulate_attacks.py --out samples
All IP addresses use documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and the data is synthetic.
"""

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

BASE_TIME = datetime(2026, 10, 24, 10, 0, 0)
SEED = 42


def syslog_time(ts: datetime) -> str:
    return ts.strftime("%b %d %H:%M:%S")


def auth_lines(rng: random.Random):
    """Return (timestamp, line) pairs for SSH auth events."""
    events = []

    def failed(ts, user, ip):
        pid = rng.randint(1000, 9999)
        port = rng.randint(40000, 60000)
        events.append((ts, f"{syslog_time(ts)} ids-lab sshd[{pid}]: "
                           f"Failed password for {user} from {ip} port {port} ssh2"))

    def accepted(ts, user, ip):
        pid = rng.randint(1000, 9999)
        port = rng.randint(40000, 60000)
        events.append((ts, f"{syslog_time(ts)} ids-lab sshd[{pid}]: "
                           f"Accepted password for {user} from {ip} port {port} ssh2"))

    # Benign: alice logs in successfully a few times; bob mistypes once.
    for i in range(5):
        accepted(BASE_TIME + timedelta(minutes=i * 4), "alice", "192.0.2.20")
    failed(BASE_TIME + timedelta(minutes=2, seconds=10), "bob", "192.0.2.21")
    accepted(BASE_TIME + timedelta(minutes=2, seconds=40), "bob", "192.0.2.21")

    # Attack 1: brute force, 12 failures for one user in 3 minutes.
    for i in range(12):
        failed(BASE_TIME + timedelta(minutes=5, seconds=i * 15), "admin", "203.0.113.5")

    # Attack 2: password spraying, 8 distinct users each tried once in 4 minutes.
    users = ["jdoe", "msmith", "root", "test", "guest", "backup", "oracle", "ftp"]
    for i, user in enumerate(users):
        failed(BASE_TIME + timedelta(minutes=12, seconds=i * 30), user, "198.51.100.9")

    # Attack 3: compromise, 6 failures for root then a successful login.
    for i in range(6):
        failed(BASE_TIME + timedelta(minutes=20, seconds=i * 45), "root", "203.0.113.77")
    accepted(BASE_TIME + timedelta(minutes=25), "root", "203.0.113.77")

    return sorted(events, key=lambda pair: pair[0])


def access_lines(rng: random.Random):
    """Return (timestamp, line) pairs for combined-format HTTP access events."""
    events = []

    def request(ts, ip, method, path, status):
        size = rng.randint(200, 5000)
        stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        events.append((ts, f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" '
                           f'{status} {size} "-" "Mozilla/5.0"'))

    # Benign: ordinary page views from several clients, plus one stray 404 each.
    benign_ips = ["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"]
    for i in range(60):
        ts = BASE_TIME + timedelta(seconds=i * 20)
        request(ts, benign_ips[i % len(benign_ips)], "GET", "/index.html", 200)
    request(BASE_TIME + timedelta(minutes=3), "192.0.2.10", "GET", "/old-page", 404)
    request(BASE_TIME + timedelta(minutes=8), "192.0.2.11", "GET", "/missing.png", 404)

    # Attack 4: scanning, 35 distinct 404 probes in 40 seconds.
    probes = [f"/probe-{n}.php" for n in range(35)]
    for i, path in enumerate(probes):
        request(BASE_TIME + timedelta(minutes=15, seconds=i), "198.51.100.23", "GET", path, 404)

    # Attack 5: repeated access denials, 12 x 403 on /admin in 30 seconds.
    for i in range(12):
        request(BASE_TIME + timedelta(minutes=25, seconds=i * 2.5), "203.0.113.44",
                "GET", "/admin", 403)

    return sorted(events, key=lambda pair: pair[0])


def network_lines(rng: random.Random):
    """Return (timestamp, line) pairs for the custom network-event format."""
    events = []

    def connection(ts, src, dst, port):
        events.append((ts, f"{ts.isoformat()} {src} {dst} {port}"))

    # Benign: a workstation repeatedly using HTTPS and HTTP to one server.
    for i in range(20):
        connection(BASE_TIME + timedelta(seconds=i * 30), "192.0.2.30", "192.0.2.1",
                   443 if i % 2 == 0 else 80)

    # Benign trap: one client touches 16 different servers, each on a different
    # port. Many distinct ports in total, but no single target is probed, so it
    # should NOT alert.
    for i in range(16):
        connection(BASE_TIME + timedelta(minutes=10, seconds=i * 2),
                   "192.0.2.60", f"192.168.1.{100 + i}", 8000 + i)

    # Attack 6: port scan of one host, ports 1 to 20 within 20 seconds.
    for port in range(1, 21):
        connection(BASE_TIME + timedelta(minutes=20, seconds=port - 1),
                   "203.0.113.99", "192.168.1.10", port)

    return sorted(events, key=lambda pair: pair[0])


GROUND_TRUTH = {
    "simulated_auth.log": {
        "type": "auth",
        "expected_alerts": [
            {"rule": "brute_force", "source_ip": "203.0.113.5"},
            {"rule": "password_spraying", "source_ip": "198.51.100.9"},
            {"rule": "compromise_indicator", "source_ip": "203.0.113.77"},
        ],
        "expected_no_alert": ["192.0.2.20", "192.0.2.21"],
    },
    "simulated_access.log": {
        "type": "http",
        "expected_alerts": [
            {"rule": "scanning", "source_ip": "198.51.100.23"},
            {"rule": "unauthorized_access", "source_ip": "203.0.113.44"},
        ],
        "expected_no_alert": ["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"],
    },
    "simulated_network.log": {
        "type": "network",
        "expected_alerts": [
            {"rule": "port_scan", "source_ip": "203.0.113.99"},
        ],
        "expected_no_alert": ["192.0.2.30", "192.0.2.60"],
    },
}


def write_log(path: Path, pairs):
    path.write_text("\n".join(line for _, line in pairs) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Generate labeled IDS test logs.")
    parser.add_argument("--out", default="samples", help="Output directory")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)

    write_log(out / "simulated_auth.log", auth_lines(rng))
    write_log(out / "simulated_access.log", access_lines(rng))
    write_log(out / "simulated_network.log", network_lines(rng))

    (out / "ground_truth.json").write_text(
        json.dumps(GROUND_TRUTH, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote simulated logs and ground_truth.json to {out}/")


if __name__ == "__main__":
    main()
