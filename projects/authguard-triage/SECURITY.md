# Security policy

## Safe use

AuthGuard is designed for offline analysis of authentication logs you own or are authorized to review. It does not make network requests or perform response actions.

Treat input logs and unredacted reports as sensitive. Reports omit raw lines and command text by design; the source IP can still be identifying unless **--redact-ips** is enabled.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository if enabled. Do not include real credentials, customer logs, or exploitable details in a public issue.

## Limitations

Detection results are heuristics for triage. They do not establish compromise, actor identity, or system security. Confirm findings against the source system and other evidence.
