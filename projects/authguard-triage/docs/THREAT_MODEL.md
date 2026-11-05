# Threat model and data handling

## Assets

- Authentication events in the input log
- Generated triage findings and source IPs
- The analyst's local report files

## Trust boundaries

- Input files are untrusted text and may contain malformed timestamps or attacker-controlled names.
- Configuration files are untrusted JSON and are validated strictly.
- HTML reports render event-derived text and must escape it before display.
- Output paths are user-selected and must not overwrite the input log.

## Design controls

- Analysis is offline; there are no outbound requests, host probes, or response actions.
- Parser records normalized event fields and source line numbers, not raw messages or sudo commands.
- JSON and HTML output omit the full input path and raw log lines.
- HTML text is escaped; the report is static and includes a restrictive content security policy.
- Optional IP redaction supports safer report sharing.
- Report writes use a temporary file and atomic replacement.
- Malformed or unsupported lines are counted for visibility.

## Out of scope

- Authenticity of the log file, trusted timestamps, source-host integrity, or complete event collection
- Detection of all brute-force, password-spray, persistence, or account-abuse behavior
- Automated blocking, account disablement, or any other remediation
- Protection of a report after it leaves the analyst's machine

## Analyst responsibilities

Use authorized data only. Confirm findings against source logs and independent evidence. Protect and retain reports according to local policy; use IP redaction before sharing when exact addresses are not necessary.
