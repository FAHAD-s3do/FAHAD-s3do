"""Privacy-aware JSON and standalone HTML report rendering."""

from __future__ import annotations

import html
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding, ParseSummary


def build_report(
    *,
    source_name: str,
    summary: ParseSummary,
    findings: tuple[Finding, ...],
    redact_ips: bool,
    source_names: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    display_sources = [Path(name).name for name in (source_names or (source_name,))]
    return {
        "schema_version": 2,
        "tool": "AuthGuard",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_file": display_sources[0] if len(display_sources) == 1 else f"{len(display_sources)} input files",
        "source_files": display_sources,
        "privacy": {"raw_log_lines_included": False, "source_ips_redacted": redact_ips},
        "summary": summary.to_dict(),
        "finding_count": len(findings),
        "findings": [finding.to_dict(redact_ips=redact_ips) for finding in findings],
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_html(report: dict[str, Any]) -> str:
    summary = report["summary"]
    cells = "".join(
        f"<tr><td>{html.escape(str(f['severity']).upper())}</td>"
        f"<td>{html.escape(f['title'])}</td><td>{html.escape(f['host'])}</td>"
        f"<td>{html.escape(str(f.get('source_ip') or '—'))}</td>"
        f"<td>{html.escape(', '.join(f'{name}:{line}' for name, line in zip(f.get('evidence_files', []), f['evidence_lines']))) or html.escape(', '.join(map(str, f['evidence_lines'])))}</td>"
        f"<td>{html.escape(f['summary'])}<ul>"
        f"{''.join('<li>' + html.escape(item) + '</li>' for item in f['recommendations'])}</ul></td></tr>"
        for f in report["findings"]
    )
    if not cells:
        cells = '<tr><td colspan="6">No findings matched the configured rules.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>AuthGuard Triage report</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033;background:#f5f7fb}}
h1{{color:#12304a}}.summary{{display:flex;gap:1rem;flex-wrap:wrap}}.card{{background:white;border:1px solid #d7dfeb;border-radius:10px;padding:1rem;min-width:130px}}
table{{width:100%;border-collapse:collapse;background:white;margin-top:1rem}}th,td{{padding:.7rem;border:1px solid #d7dfeb;text-align:left;vertical-align:top}}th{{background:#e8eef6}}
.note{{color:#53657c;font-size:.9rem}}code{{overflow-wrap:anywhere}}
</style></head><body>
<h1>AuthGuard Triage</h1>
<p>Offline authentication-log triage · Source: <code>{html.escape(report["source_file"])}</code> · Generated {html.escape(report["generated_at"])}</p>
<div class="summary">
<div class="card"><strong>Parsed events</strong><br>{summary["parsed_events"]}</div>
<div class="card"><strong>Findings</strong><br>{report["finding_count"]}</div>
<div class="card"><strong>Ignored lines</strong><br>{summary["ignored_lines"]}</div>
<div class="card"><strong>Invalid lines</strong><br>{summary["invalid_lines"]}</div>
</div>
<p class="note">Findings are triage leads, not proof of compromise. Raw log lines are not included in this report.</p>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Host</th><th>Source</th><th>Evidence file and line</th><th>Why it matched</th></tr></thead>
<tbody>{cells}</tbody></table>
</body></html>
"""


def write_atomic(path: Path, content: str) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as stream:
            temporary = stream.name
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
