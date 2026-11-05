"""Command-line entry point."""

from __future__ import annotations

import argparse
import gzip
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from .config import load_config
from .models import ParseSummary
from .parsers import parse_auth_log
from .report import build_report, render_html, render_json, write_atomic
from .rules import RuleConfig, analyze_events

_EXIT_SEVERITY = {"none": None, "low": 3, "medium": 2, "high": 1, "critical": 0}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authguard",
        description="Analyze Linux authentication logs offline and create explainable triage reports.",
    )
    parser.add_argument("input", type=Path, nargs="+", help="one or more auth.log, syslog, or .gz files")
    parser.add_argument("--json", dest="json_path", type=Path, help="write a JSON report")
    parser.add_argument("--html", dest="html_path", type=Path, help="write a standalone HTML report")
    parser.add_argument("--config", type=Path, help="optional strict JSON rule configuration")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="year for classic syslog timestamps")
    parser.add_argument("--timezone", default="UTC", help="IANA timezone for timestamps without offsets (default: UTC)")
    parser.add_argument("--redact-ips", action="store_true", help="hide source IPs in generated reports")
    parser.add_argument("--fail-on", choices=_EXIT_SEVERITY, default="none", help="exit 1 if findings meet this severity")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        input_paths: list[Path] = args.input
        resolved_inputs = [path.resolve() for path in input_paths]
        if len(resolved_inputs) != len(set(resolved_inputs)):
            raise ValueError("the same input file was provided more than once")
        for path in input_paths:
            if not path.is_file():
                raise ValueError(f"input file does not exist or is not a regular file: {path}")
        output_paths = [path.resolve() for path in (args.json_path, args.html_path) if path is not None]
        if len(output_paths) != len(set(output_paths)):
            raise ValueError("JSON and HTML report paths must be different")
        if set(resolved_inputs) & set(output_paths):
            raise ValueError("a report path cannot overwrite an input log")
        config = load_config(args.config) if args.config else RuleConfig()
        labels: list[str] = []
        label_counts: Counter[str] = Counter()
        all_events = []
        total_lines = parsed_events = ignored_lines = invalid_lines = 0
        event_counts: Counter[str] = Counter()
        for path in input_paths:
            base_label = path.name
            label_counts[base_label] += 1
            label = base_label if label_counts[base_label] == 1 else f"{path.stem} ({label_counts[base_label]}){path.suffix}"
            labels.append(label)
            opener = gzip.open if path.suffix.lower() == ".gz" else open
            with opener(path, "rt", encoding="utf-8-sig", errors="strict") as stream:
                parsed = parse_auth_log(stream, year=args.year, timezone_name=args.timezone, source_label=label)
            all_events.extend(parsed.events)
            total_lines += parsed.summary.total_lines
            parsed_events += parsed.summary.parsed_events
            ignored_lines += parsed.summary.ignored_lines
            invalid_lines += parsed.summary.invalid_lines
            event_counts.update(parsed.summary.event_counts)
        summary = ParseSummary(total_lines, parsed_events, ignored_lines, invalid_lines, dict(sorted(event_counts.items())))
        findings = analyze_events(all_events, config)
        report = build_report(
            source_name=labels[0], source_names=tuple(labels), summary=summary,
            findings=findings, redact_ips=args.redact_ips,
        )
        json_text = render_json(report)
        if args.json_path:
            write_atomic(args.json_path, json_text)
        if args.html_path:
            write_atomic(args.html_path, render_html(report))
        if not args.json_path and not args.html_path:
            sys.stdout.write(json_text)
        print(
            f"AuthGuard: {parsed_events} events from {len(input_paths)} file(s), {len(findings)} findings, "
            f"{ignored_lines} ignored lines, {invalid_lines} invalid lines.",
            file=sys.stderr,
        )
        threshold = _EXIT_SEVERITY[args.fail_on]
        if threshold is not None and any(_SEVERITY_ORDER[item.severity] <= threshold for item in findings):
            return 1
        return 0
    except (OSError, EOFError, UnicodeError, ValueError) as exc:
        print(f"authguard: error: {exc}", file=sys.stderr)
        return 2
