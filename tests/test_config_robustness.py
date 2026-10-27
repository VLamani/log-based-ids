import tempfile
import unittest
from pathlib import Path

import yaml

from src.ids.config import ConfigError, load_config


class TestConfigRobustness(unittest.TestCase):
    def setUp(self):
        self.config = {
            "detection": {
                name: {"threshold": 2, "window_seconds": 60, "severity": "High"}
                for name in (
                    "brute_force",
                    "password_spraying",
                    "compromise_indicator",
                    "scanning",
                    "port_scan",
                    "unauthorized_access",
                )
            },
            "alert_cooldown_seconds": 300,
            "allowlist": {"ips": ["192.0.2.10"]},
        }

    def load_mapping(self, config):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(yaml.safe_dump(config), encoding="utf-8")
            return load_config(path)

    def test_valid_configuration_loads(self):
        self.assertEqual(self.load_mapping(self.config)["alert_cooldown_seconds"], 300)

    def test_invalid_allowlist_ip_is_rejected(self):
        self.config["allowlist"]["ips"] = ["not-an-ip"]
        with self.assertRaises(ConfigError):
            self.load_mapping(self.config)

    def test_negative_cooldown_is_rejected(self):
        self.config["alert_cooldown_seconds"] = -1
        with self.assertRaises(ConfigError):
            self.load_mapping(self.config)

    def test_zero_threshold_is_rejected(self):
        self.config["detection"]["brute_force"]["threshold"] = 0
        with self.assertRaises(ConfigError):
            self.load_mapping(self.config)

    def test_boolean_threshold_is_rejected(self):
        self.config["detection"]["brute_force"]["threshold"] = True
        with self.assertRaises(ConfigError):
            self.load_mapping(self.config)


if __name__ == "__main__":
    unittest.main()
