import tempfile
import unittest
from pathlib import Path

from src.ids.cli import process_log_file, create_detectors
from src.ids.config import load_config


class TestCliPipeline(unittest.TestCase):
    def setUp(self):
        self.config = load_config()
        self.start_lines = [
            f"Oct 23 10:00:{i:02d} host sshd[{1000+i}]: Failed password for admin from 192.0.2.10 port {5000+i} ssh2"
            for i in range(10)
        ]

    def run_auth(self, lines, config):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return process_log_file(
                path, "auth", create_detectors(config), config
            )

    def test_pipeline_detects_brute_force(self):
        alerts, processed, unparsed = self.run_auth(self.start_lines, self.config)
        self.assertEqual(processed, 10)
        self.assertEqual(unparsed, 0)
        self.assertTrue(any(alert.rule_name == "brute_force" for alert in alerts))

    def test_pipeline_filters_allowlisted_ip(self):
        config = dict(self.config)
        config["allowlist"] = {"ips": ["192.0.2.10"]}
        alerts, processed, unparsed = self.run_auth(self.start_lines, config)
        self.assertEqual(processed, 10)
        self.assertEqual(unparsed, 0)
        self.assertEqual(alerts, [])

    def test_invalid_log_type_is_rejected(self):
        with self.assertRaises(ValueError):
            process_log_file("unused.log", "invalid", detectors=[], config=self.config)


if __name__ == "__main__":
    unittest.main()
