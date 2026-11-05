# AuthGuard Triage

[![CI](https://github.com/FAHAD-s3do/FAHAD-s3do/actions/workflows/authguard-triage.yml/badge.svg?branch=main)](https://github.com/FAHAD-s3do/FAHAD-s3do/actions/workflows/authguard-triage.yml)

**Offline Linux authentication-log triage with explainable findings and shareable reports.**

AuthGuard reads a copied **auth.log** or ISO-timestamped syslog file, groups useful security events, and highlights a small set of high-signal patterns. It runs locally, makes no network requests, and never changes the source host.

## What it detects

| Rule | Default severity | Evidence |
|---|---|---|
| Repeated SSH authentication failures from one source within a time window | High | Source IP, event count, first/last time, and original line numbers |
| SSH failures targeting multiple usernames from one source in a time window | High | Targeted account count and original line numbers |
| Successful SSH login shortly after repeated failures | High | Failed attempts and the later successful login |
| Successful SSH login directly as root | Critical | Login event and source IP |
| Local user account creation | High | Account name and source line |

Thresholds and allowlists can be set in a strict JSON config. Findings are investigation leads, not proof of compromise. Routine sudo activity is counted but not labeled suspicious by itself.

## Install

Python 3.11 or newer is required. AuthGuard uses only the Python standard library at runtime.

~~~bash
python -m venv .venv
~~~

Activate the environment, then install from the repository root:

~~~bash
python -m pip install .
~~~

On Windows, activate with **.venv\Scripts\Activate.ps1**; on Linux or macOS, use **source .venv/bin/activate**.

## Run against a log

Classic syslog timestamps omit the year and timezone. Supply both explicitly when they differ from the defaults:

~~~bash
authguard /path/to/auth.log \
  --year 2026 \
  --timezone Asia/Karachi \
  --config config/example.json \
  --json out/report.json \
  --html out/report.html
~~~

Try the included synthetic fixture:

~~~bash
authguard examples/auth.log --year 2026 --json out/report.json --html out/report.html --redact-ips
~~~

The fixture produces six findings: two SSH failure bursts, a multi-account spray pattern, a success after failures, a direct root login, and a new account. All sample addresses come from documentation-only IP ranges.

See the [sample JSON report](examples/report.json) and [sample HTML report](examples/report.html) for redacted output.

Use **python -m authguard --help** for all options. **--fail-on high** returns exit code 1 when a high or critical finding is present, which can be used as a CI gate.

## Reports and privacy

- JSON and standalone HTML reports contain summaries, line-number evidence, explanations, and suggested review steps.
- Raw log lines, sudo command text, and full local paths are not copied into reports.
- **--redact-ips** replaces source IPs with **<redacted>** in report findings.
- Report files are written atomically. Output paths cannot overwrite the input log or each other.
- Treat source logs and unredacted reports as sensitive operational data. Store them with appropriate access controls and delete them according to your organization's retention policy.

## Detection behavior

Defaults: five failed SSH attempts from one IP and host within ten minutes. The window begins at the first event in a burst; separate bursts are emitted when the next event falls outside that window. Allowlisted IPs are excluded from SSH failure detections and allowlisted usernames are excluded from direct-root-login and new-account findings.

The parser supports common month/day/time syslog records, ISO timestamps with offsets, and ISO timestamps without offsets. For classic syslog, **--year** and **--timezone** are applied. Unsupported or malformed lines are counted instead of silently disappearing.

## Validation

Run the unit and CLI checks:

~~~bash
python -m unittest discover -s tests -v
authguard examples/auth.log --year 2026 --json out/report.json --html out/report.html --redact-ips
~~~

GitHub Actions runs the same checks on pushes and pull requests.

## Scope and limitations

AuthGuard is a local triage aid, not an endpoint agent, SIEM, forensic acquisition system, or automated response tool. It does not block IPs, kill processes, query hosts, fetch threat intelligence, or decide whether an event is malicious. Log format differences, missing records, clock skew, NAT, and shared accounts can affect results. Review the original log around each cited line before taking action.

Security testing is limited to systems and data you own or are authorized to assess. Never publish real authentication logs or reports containing operational identifiers without authorization.

## License

MIT. See [LICENSE](LICENSE).
