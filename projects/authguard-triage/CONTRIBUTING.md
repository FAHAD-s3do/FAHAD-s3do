# Contributing

Thanks for your interest in improving AuthGuard. Changes should keep the tool offline, read-only, privacy-conscious, and clear about the limits of heuristic detections.

## Development setup

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --no-deps -e .
python -m unittest discover -s tests -v
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

## Proposing a change

1. Describe the user or analyst problem the change solves.
2. Keep parsing and detection behavior explainable, with evidence tied to original line numbers.
3. Add or update tests for changed behavior and include synthetic fixtures only.
4. Update the user guide when command options, configuration, supported formats, or detection behavior changes.
5. Do not add network lookups, automatic response actions, real authentication logs, secrets, or environment-specific identifiers.

Before submitting, run the unit suite and the synthetic fixture command shown in the README. Report any known limitations or compatibility changes in the pull request description.

## Security reports

Do not publish real credentials, customer logs, or exploitable details in an issue. Follow [SECURITY.md](SECURITY.md) for responsible reporting guidance.
