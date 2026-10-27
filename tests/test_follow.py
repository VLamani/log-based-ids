import tempfile
import unittest
from pathlib import Path

from src.ids.cli import create_detectors, line_parser_for
from src.ids.config import load_config
from src.ids.follow import LogFollower, follow_log_file


def failed_line(second, ip="192.0.2.50"):
    return (f"2026-10-26T10:00:{second:02d}.000000+00:00 host sshd[1]: "
            f"Failed password for admin from {ip} port 22 ssh2\n")


class TestLogFollower(unittest.TestCase):
    def test_returns_only_new_complete_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("a\n", encoding="utf-8")
            follower = LogFollower(path)
            self.assertEqual(follower.read_new_lines(), ["a"])
            with path.open("a", encoding="utf-8") as handle:
                handle.write("b\nc")  # 'c' has no newline yet
            self.assertEqual(follower.read_new_lines(), ["b"])
            with path.open("a", encoding="utf-8") as handle:
                handle.write("\n")
            self.assertEqual(follower.read_new_lines(), ["c"])
            self.assertEqual(follower.read_new_lines(), [])

    def test_truncation_restarts_from_beginning(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("x\ny\n", encoding="utf-8")
            follower = LogFollower(path)
            self.assertEqual(follower.read_new_lines(), ["x", "y"])
            path.write_text("z\n", encoding="utf-8")
            self.assertEqual(follower.read_new_lines(), ["z"])

    def test_start_at_end_skips_existing_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("old1\nold2\n", encoding="utf-8")
            follower = LogFollower(path, start_at_end=True)
            self.assertEqual(follower.read_new_lines(), [])

    def test_missing_file_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            LogFollower("/nonexistent/path/auth.log")


class TestFollowLogFile(unittest.TestCase):
    def setUp(self):
        self.config = load_config()
        self.detectors = create_detectors(self.config)
        self.parser = line_parser_for("auth")

    def test_alert_fires_on_lines_appended_while_watching(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("".join(failed_line(s) for s in range(4)), encoding="utf-8")
            appended = iter([range(4, 10)])

            def fake_sleep(_):
                # Simulate an attacker's failures arriving while we watch.
                for second in next(appended, []):
                    with path.open("a", encoding="utf-8") as handle:
                        handle.write(failed_line(second))

            seen = []
            alerts, processed, unparsed = follow_log_file(
                path, "auth", self.parser, self.detectors, self.config,
                on_alert=seen.append, max_polls=3, sleep=fake_sleep,
            )
        self.assertEqual([a.rule_name for a in alerts], ["brute_force"])
        self.assertEqual(seen, alerts)
        self.assertEqual(processed, 10)
        self.assertEqual(unparsed, 0)

    def test_start_at_end_ignores_history_and_counts_only_new_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("".join(failed_line(s) for s in range(10)), encoding="utf-8")

            def fake_sleep(_):
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(failed_line(20))

            alerts, processed, _ = follow_log_file(
                path, "auth", self.parser, self.detectors, self.config,
                start_at_end=True, max_polls=2, sleep=fake_sleep,
            )
        self.assertEqual(alerts, [])
        self.assertEqual(processed, 1)


if __name__ == "__main__":
    unittest.main()


class TestJsonFolderCreation(unittest.TestCase):
    def test_json_report_creates_missing_folder(self):
        from src.ids.reporter import write_json_report
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "reports" / "nested" / "alerts.json"
            write_json_report(target, [], lines_processed=0, lines_unparsed=0)
            self.assertTrue(target.is_file())
