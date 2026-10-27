# Changelog

## Unreleased (review fixes)

### Fixed
- SSH auth parser now reads ISO-8601 syslog lines (`2026-10-25T16:19:33+00:00 host sshd[...]`), the default on modern Ubuntu. Previously these real lines were all rejected as unparsed.
- Port-scan rule now groups by source and destination host. A client using many ports across many different servers no longer triggers an alert. Verified against the original code: it alerted on that client.
- Unknown keys in a rule's config (for example `treshold`) now raise a clear `ConfigError` instead of a traceback.
- Syslog auth timestamps can be set with `--year`, so logs from past years parse correctly.

### Added
- `--year` option for the CLI.
- `--json PATH` option that writes alerts and line counts to a JSON file.
- Exit code `1` when any High or Critical alert fires; `2` for usage or input errors.
- `scripts/simulate_attacks.py`, which generates labeled logs and `samples/ground_truth.json`.
- `samples/` with generated logs, ground truth, and a sample report produced by the CLI.
- `requirements-dev.txt` (adds pytest) and `pytest.ini` so `pytest` can import `src`.
- Seven regression tests (`tests/test_fixes_regression.py`).

### Removed
- `src/ids/windows.py` and `tests/test_windows.py`. The class was not used by any detector. Each detector keeps its own window logic.

### Changed
- `.gitignore` now keeps `samples/*.log` in the repository. Lab logs from a personal machine are not included.
- `Event` gained an optional `destination_ip` field.
- The misleading comment in the brute-force detector was corrected.
