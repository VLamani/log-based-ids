# Architecture

## Pipeline

```mermaid
flowchart TB
  subgraph IN["Inputs"]
    L1["SSH auth log"]
    L2["Nginx or Apache access log"]
    L3["Network event file"]
  end

  subgraph ING["Ingestion"]
    BR["Batch reader: whole file"]
    FW["Live follower: --follow"]
  end

  subgraph PARSE["Parsers"]
    P1["auth parser: classic and ISO syslog, repeat expansion"]
    P2["access parser: combined format"]
    P3["network parser: four fields"]
  end

  CFG["config.yaml: thresholds, windows, severities, allowlist, cooldown"]

  subgraph ENG["Detection engine"]
    AL["Allowlist check"]
    subgraph RULES["Six detection rules"]
      R1["brute_force"]
      R2["password_spraying"]
      R3["compromise_indicator"]
      R4["scanning"]
      R5["unauthorized_access"]
      R6["port_scan"]
    end
    CD["Cooldown per rule and source"]
  end

  subgraph OUT["Output"]
    O1["Console report"]
    O2["JSON report"]
    O3["Exit code: 1 if High or Critical"]
  end

  L1 --> BR
  L2 --> BR
  L3 --> BR
  L1 -.-> FW
  L2 -.-> FW
  BR --> P1
  BR --> P2
  BR --> P3
  FW --> P1
  FW --> P2
  FW --> P3
  P1 --> AL
  P2 --> AL
  P3 --> AL
  CFG --> RULES
  AL --> R1
  AL --> R2
  AL --> R3
  AL --> R4
  AL --> R5
  AL --> R6
  R1 --> CD
  R2 --> CD
  R3 --> CD
  R4 --> CD
  R5 --> CD
  R6 --> CD
  CD --> O1
  CD --> O2
  CD --> O3
```

Processing happens in five stages:

1. **Inputs.** Three log types: SSH auth logs, web access logs, and the custom network-event format.
2. **Ingestion.** Batch mode reads the whole file. Live mode (`--follow`) reads only new complete lines.
3. **Parsing.** Each line becomes an event with a UTC timestamp, or is counted as unparsed. Repeat markers from rsyslog are expanded into separate events.
4. **Detection.** Each event passes the allowlist check, then the six rules. The rules read their thresholds and windows from `config.yaml`.
5. **Output.** Alerts are de-duplicated by the cooldown, then written as a console report, a JSON report, and an exit code.

## Components

| Module | Responsibility |
|---|---|
| `parsers/` | Turn one log line into an `Event`, or return nothing. Handles classic and ISO-8601 syslog, and expands rsyslog's repeat markers. |
| `models.py` | `Event` (what was seen) and `Alert` (what was flagged). |
| `alert_manager.py` | Skips allowlisted sources, and suppresses repeat alerts for the same rule and source during the cooldown. |
| `detectors/` | One class per rule. Each keeps its own per-source state and returns an `Alert` when its threshold is met. |
| `follow.py` | Live mode: reads only complete new lines, and restarts after truncation or rotation. |
| `config.py` | Loads `config.yaml` and rejects missing, unknown, or invalid settings before any analysis runs. |
| `reporter.py` | Writes the text summary and the JSON report. |
| `cli.py` | Entry point. Wires the modules together and sets the exit code. |

## Design decisions

- **Parse first, then sort.** Batch analysis reads the whole file, sorts events by time, and only then runs detection. Sliding windows depend on time order, so out-of-order log lines would otherwise miscount.
- **Naive timestamps are treated as UTC.** Classic syslog has no timezone, so timestamps are normalized before comparison. This avoids comparing naive and aware datetimes.
- **Sliding windows per source.** Each detector keeps the timestamps for each source IP (or source and destination pair, for port scans) and drops the ones outside its window. Memory grows with the number of distinct sources, which is listed as a limitation.
- **Thresholds live in config, not code.** Every rule's threshold, window, and severity is set in `config.yaml`, so the rules can be tuned without editing Python.
- **Cooldown lives in the manager, not the rules.** Rules report every threshold crossing, and the alert manager decides which ones to show. This keeps each rule simple and makes the suppression behavior easy to test on its own.
- **Live mode reuses the batch code.** `--follow` uses the same parsers, detectors, and alert manager. Only the input changes, so both modes behave the same way on the same lines.

## Testing

Detector boundaries (exactly at, and just outside, each window), parser edge cases, configuration validation, cooldown and allowlist behavior, out-of-order input, CLI output, and live following are each covered by tests. The suite has 131 tests.
