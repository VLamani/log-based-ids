import unittest
from datetime import datetime, timezone

from src.ids.parsers.auth_log import parse_auth_line
from src.ids.parsers.access_log import parse_access_line
from src.ids.parsers.network_log import parse_network_line


class TestAuthLogParser(unittest.TestCase):

    def test_failed_login(self):
        line = (
            "Oct 23 10:15:01 host sshd[1234]: "
            "Failed password for invalid user admin "
            "from 203.0.113.5 port 52122 ssh2"
        )

        event = parse_auth_line(line, year=2026)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "failed_login")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.source_ip, "203.0.113.5")
        self.assertEqual(
            event.timestamp,
            datetime(2026, 10, 23, 10, 15, 1),
        )

    def test_successful_login(self):
        line = (
            "Oct 23 10:15:09 host sshd[1240]: "
            "Accepted password for alice "
            "from 198.51.100.7 port 40022 ssh2"
        )

        event = parse_auth_line(line, year=2026)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "successful_login")
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.source_ip, "198.51.100.7")

    def test_malformed_line(self):
        self.assertIsNone(parse_auth_line("This is not a valid SSH log"))

    def test_unrelated_ssh_message(self):
        line = (
            "Oct 23 10:15:01 host sshd[1234]: "
            "Connection closed by authenticating user alice"
        )
        self.assertIsNone(parse_auth_line(line, year=2026))


class TestAccessLogParser(unittest.TestCase):

    def test_valid_access_log(self):
        line = (
            '203.0.113.5 - - [23/Oct/2026:10:15:01 +0000] '
            '"GET /admin.php HTTP/1.1" 404 209 "-" "Mozilla/5.0"'
        )

        event = parse_access_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "http_request")
        self.assertEqual(event.source_ip, "203.0.113.5")
        self.assertEqual(event.http_status, 404)
        self.assertEqual(
            event.timestamp,
            datetime(2026, 10, 23, 10, 15, 1, tzinfo=timezone.utc),
        )

    def test_successful_http_request(self):
        line = (
            '198.51.100.7 - - [23/Oct/2026:10:16:00 +0000] '
            '"GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        )

        event = parse_access_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.http_status, 200)

    def test_malformed_access_log(self):
        self.assertIsNone(parse_access_line("not a valid access log"))


if __name__ == "__main__":
    unittest.main()


class TestNetworkLogParser(unittest.TestCase):

    def test_valid_network_event(self):
        event = parse_network_line(
            "2026-10-24T10:00:00 192.0.2.10 192.0.2.1 443"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.source_ip, "192.0.2.10")
        self.assertEqual(event.destination_port, 443)
        self.assertEqual(event.event_type, "network_connection")

    def test_invalid_port_is_rejected(self):
        self.assertIsNone(parse_network_line(
            "2026-10-24T10:00:00 192.0.2.10 192.0.2.1 70000"
        ))

    def test_malformed_network_event_is_rejected(self):
        self.assertIsNone(parse_network_line("not a network event"))

    def test_invalid_source_ip_is_rejected(self):
        self.assertIsNone(
            parse_network_line("2026-10-24T10:00:00 not-an-ip 192.0.2.1 443")
        )

    def test_invalid_destination_ip_is_rejected(self):
        self.assertIsNone(
            parse_network_line("2026-10-24T10:00:00 192.0.2.10 not-an-ip 443")
        )

    def test_ipv6_addresses_are_supported(self):
        event = parse_network_line(
            "2026-10-24T10:00:00 2001:db8::10 2001:db8::1 443"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.source_ip, "2001:db8::10")
