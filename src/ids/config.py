
from pathlib import Path
from ipaddress import ip_address
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"


class ConfigError(ValueError):
    """Raised when the IDS configuration is missing or invalid."""


def load_config(config_path: str | Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Load and validate the IDS configuration from a YAML file."""

    path = Path(config_path)

    if not path.is_file():
        raise ConfigError(f"Configuration file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as config_file:
            config = yaml.safe_load(config_file)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML configuration: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Unable to read configuration file: {exc}") from exc

    if not isinstance(config, dict):
        raise ConfigError("Configuration must contain a YAML mapping.")

    detection = config.get("detection")
    if not isinstance(detection, dict):
        raise ConfigError("'detection' must be a mapping.")

    required_rules = {
        "brute_force",
        "password_spraying",
        "compromise_indicator",
        "scanning",
        "port_scan",
        "unauthorized_access",
    }

    missing_rules = required_rules - detection.keys()
    if missing_rules:
        raise ConfigError(
            "Missing detection rules: " + ", ".join(sorted(missing_rules))
        )

    for rule_name, rule_config in detection.items():
        if not isinstance(rule_config, dict):
            raise ConfigError(f"Detection rule '{rule_name}' must be a mapping.")

        for key in ("threshold", "window_seconds", "severity"):
            if key not in rule_config:
                raise ConfigError(
                    f"Detection rule '{rule_name}' is missing '{key}'."
                )

        unknown_keys = set(rule_config) - {"threshold", "window_seconds", "severity"}
        if unknown_keys:
            raise ConfigError(
                f"Unknown key(s) for rule '{rule_name}': "
                + ", ".join(sorted(unknown_keys))
            )

        for key in ("threshold", "window_seconds"):
            value = rule_config[key]
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ConfigError(
                    f"'{key}' for rule '{rule_name}' must be a positive integer."
                )

        if not isinstance(rule_config["severity"], str) or not rule_config["severity"].strip():
            raise ConfigError(
                f"'severity' for rule '{rule_name}' must be a non-empty string."
            )

    cooldown = config.get("alert_cooldown_seconds", 300)
    if isinstance(cooldown, bool) or not isinstance(cooldown, int) or cooldown < 0:
        raise ConfigError("'alert_cooldown_seconds' must be a non-negative integer.")

    allowlist = config.get("allowlist", {})
    if not isinstance(allowlist, dict):
        raise ConfigError("'allowlist' must be a mapping.")

    ips = allowlist.get("ips", [])
    if not isinstance(ips, list) or any(not isinstance(ip, str) for ip in ips):
        raise ConfigError("'allowlist.ips' must be a list of IP address strings.")

    for ip in ips:
        try:
            ip_address(ip.strip())
        except ValueError as exc:
            raise ConfigError(f"Invalid IP address in 'allowlist.ips': {ip!r}") from exc

    return config
