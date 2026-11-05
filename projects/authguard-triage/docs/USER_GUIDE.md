# AuthGuard User Guide

This guide explains how to install AuthGuard, analyze an authorized Linux authentication log, configure detections, and interpret the resulting report.

## Requirements

- Python 3.11 or newer
- A copied Linux authentication log file readable by your account
- No runtime dependencies beyond the Python standard library

AuthGuard runs on Windows, macOS, and Linux. It analyzes logs exported from Linux hosts; it does not need to run on the host that created the log.

## Install from source

Clone the profile repository and enter the project directory:

```bash
git clone https://github.com/FAHAD-s3do/FAHAD-s3do.git
cd FAHAD-s3do/projects/authguard-triage
python -m venv .venv
```

Activate the virtual environment and install:

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
python -m pip install .
```

```bash
# Linux or macOS
source .venv/bin/activate
python -m pip install .
```

Check the installed command:

```bash
authguard --help
```

## Analyze a log

```bash
authguard /path/to/auth.log \
  --year 2026 \
  --timezone Asia/Karachi \
  --json out/report.json \
  --html out/report.html \
  --redact-ips
```

The output directory is created when needed. JSON and HTML output paths must be different from each other and from the input log.

### Timestamp handling

AuthGuard accepts common syslog records with month/day/time, ISO timestamps with an explicit UTC offset, and ISO timestamps without an offset. For classic syslog records that omit a year, `--year` supplies the year. For timestamps without an offset, `--timezone` supplies an IANA timezone such as `UTC` or `Asia/Karachi`. The defaults are the current year and UTC.

Use the timezone of the system or logging pipeline that produced the file. A wrong year or timezone can shift event times and affect time-window detections.

### Try the included fixture

```bash
authguard examples/auth.log \
  --year 2026 \
  --timezone Asia/Karachi \
  --json out/report.json \
  --html out/report.html \
  --redact-ips
```

This synthetic fixture contains reserved documentation IP addresses and demonstrates six findings. Compare your generated files with [sample JSON](../examples/report.json) and [sample HTML](../examples/report.html).

## Detection rules

| Rule | Default behavior | Finding severity |
|---|---|---|
| SSH failure burst | At least five failures from one source and host within a ten-minute window | High |
| SSH multi-account pattern | Failures targeting at least five distinct, non-allowlisted usernames from one source and host within a ten-minute window | High |
| Login after failures | At least five failures followed by a successful login from the same source and host within ten minutes | High |
| Direct root SSH login | A successful SSH login as root | Critical |
| Local account creation | A `useradd` account creation event | High |

The SSH failure window starts with the first failure in a group. A later event outside the window starts a new group. Findings are deterministic summaries of parsed evidence, not a verdict about intent or compromise. `sudo` events are counted for context and are not independently flagged.

## Configuration

Use `--config config/example.json` to load strict JSON settings. Unknown or duplicate keys, malformed IP addresses, and invalid value types are rejected.

```json
{
  "ssh_failure_threshold": 5,
  "ssh_distinct_user_threshold": 5,
  "window_minutes": 10,
  "allowlisted_ips": ["192.0.2.10"],
  "allowlisted_users": ["backup"]
}
```

| Key | Type | Default | Valid range / effect |
|---|---|---:|---|
| `ssh_failure_threshold` | integer | 5 | 2–1000 failures for burst and success-after-failures findings |
| `ssh_distinct_user_threshold` | integer | 5 | 2–1000 distinct usernames for the multi-account finding |
| `window_minutes` | integer | 10 | 1–1440 minutes for SSH grouping |
| `allowlisted_ips` | string array | `[]` | Excludes these source addresses from SSH failure and login-after-failure findings |
| `allowlisted_users` | string array | `[]` | Excludes these usernames from multi-account counts, root login, and account creation findings |

Use allowlists only for known, reviewed exceptions. An allowlisted address or username can hide relevant findings from the corresponding rules.

## Command options

| Option | Purpose |
|---|---|
| `--json PATH` | Write a JSON report |
| `--html PATH` | Write a standalone HTML report |
| `--config PATH` | Load thresholds and allowlists from JSON |
| `--year YYYY` | Set year for classic syslog timestamps |
| `--timezone ZONE` | Set timezone for timestamps without offsets |
| `--redact-ips` | Replace source addresses in reports with `<redacted>` |
| `--fail-on LEVEL` | Exit with code 1 if a finding meets `low`, `medium`, `high`, or `critical`; `none` disables this behavior |

When no report path is given, the JSON report is printed to standard output. Exit code 2 indicates an input, configuration, or output error.

## Understanding reports

Each finding includes a stable finding ID, rule ID, severity, summary, host, time range, source where applicable, event count, original line numbers, and recommended review steps. Use line numbers to inspect the source log in context. Reports do not include raw log lines, sudo command text, or the complete input path.

`--redact-ips` is useful for examples and sharing, but hostnames, usernames, timestamps, and other context may still identify an environment. Review a report before publishing it.

## Supported events and known limits

The parser recognizes common `sshd`, `sudo`, and `useradd` records. Unsupported programs or message patterns are counted as ignored; malformed relevant timestamps are counted separately as invalid. This visibility helps identify input that was not analyzed.

AuthGuard is not a full SIEM parser or a forensic collection tool. Log rotation gaps, missing records, clock skew, NAT, shared addresses, unusual distribution formats, and account naming conventions can affect findings. Confirm important events against source systems and other evidence.

## Troubleshooting

| Problem | What to check |
|---|---|
| `authguard` command is not found | Activate the virtual environment or run `python -m authguard` from the project directory |
| No events are parsed | Confirm the file is a supported Linux auth log and inspect ignored/invalid counts |
| Event times look shifted | Set the source log's actual year and timezone |
| Too many or too few findings | Review the threshold, time window, and allowlists; inspect the cited source lines |
| HTML report appears blank or malformed | Open the standalone file in a current browser and check that output creation completed successfully |

## Safe handling

Analyze only logs you own or are authorized to review. Protect source logs and unredacted reports as sensitive operational data. AuthGuard is read-only with respect to the analyzed host and makes no outbound requests.
