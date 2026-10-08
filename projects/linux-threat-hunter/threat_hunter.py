#!/usr/bin/env python3
"""Read-only, heuristic Linux triage. No third-party Python dependencies."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

VERSION = '1.0.0'
LIMIT = 1024 * 1024
TEMP_PATH = re.compile(r'(?:^|[\s=;\"\x27])/(?:tmp|var/tmp|dev/shm)/')


def coverage(status, records=0, note=''):
    return dict(status=status, records=records, note=note)


def finding(rule, severity, subject, evidence, recommendation):
    return dict(rule=rule, severity=severity, subject=subject,
                evidence=evidence, recommendation=recommendation)


def process_findings(records):
    out = []
    for item in records:
        exe = item['exe']
        if exe.endswith(' (deleted)'):
            out.append(finding('PROC_DELETED', 'medium', f"PID {item['pid']}",
                exe, 'Check package upgrades and process provenance before escalation.'))
        if TEMP_PATH.search(exe):
            out.append(finding('PROC_TEMP', 'medium', f"PID {item['pid']}",
                exe, 'Verify the executable owner, origin and expected application behavior.'))
    return out


def collect_processes():
    records, skipped = [], 0
    try:
        paths = sorted(p for p in Path('/proc').iterdir() if p.name.isdigit())[:10000]
    except OSError as exc:
        return [], coverage('unavailable', note=type(exc).__name__)
    for path in paths:
        try:
            records.append(dict(pid=int(path.name), exe=os.readlink(path / 'exe')))
        except OSError:
            skipped += 1  # Kernel threads, exited processes and permission boundaries.
    return records, coverage('partial' if skipped or len(paths) == 10000 else 'ok',
        len(records), f'{skipped} executable links unreadable; kernel threads and process races are normal. Cap: 10000 PIDs.')


def parse_listeners(text):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ('tcp', 'udp'):
            continue
        rows.append(dict(protocol=fields[0], state=fields[1], local=fields[4]))
    return rows


def listener_findings(rows):
    return [finding('NET_WILDCARD', 'info', row['local'], row['protocol'],
        'Confirm bind scope and firewall policy. A wildcard bind alone does not establish external reachability.')
        for row in rows if row['local'].rsplit(':', 1)[0] in ('*', '0.0.0.0', '[::]', '::')]


def collect_listeners():
    tool = shutil.which('ss')
    if not tool:
        return [], coverage('unavailable', note='ss is missing; install your distribution iproute2 package for socket inventory.')
    try:
        result = subprocess.run([tool, '-H', '-lntu'], capture_output=True, text=True,
                                timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], coverage('unavailable', note=type(exc).__name__)
    if result.returncode:
        return [], coverage('unavailable', note=f'ss exited {result.returncode}')
    rows = parse_listeners(result.stdout[:LIMIT])
    return rows, coverage('partial' if len(result.stdout) > LIMIT else 'ok', len(rows),
                         'Listening TCP and bound UDP endpoints in the current network namespace; output capped at 1 MiB.')


def inspect_config(path, text):
    active = '\n'.join(line for line in text.splitlines()
                       if not line.lstrip().startswith(('#', ';')))
    if TEMP_PATH.search(active):
        return [finding('PERSIST_TEMP_REFERENCE', 'medium', str(path),
            'Active configuration references /tmp, /var/tmp or /dev/shm. Raw content withheld.',
            'Review the full configuration locally. This reference may be benign and is not proof of execution.')]
    return []


def collect_persistence():
    roots = [Path('/etc/crontab'), Path('/etc/cron.d'), Path('/etc/cron.hourly'),
             Path('/etc/cron.daily'), Path('/etc/cron.weekly'), Path('/etc/cron.monthly'),
             Path('/var/spool/cron'), Path('/etc/systemd/system'),
             Path('/usr/lib/systemd/system'), Path('/lib/systemd/system')]
    rows, findings, errors, seen = [], [], 0, set()
    for root in roots:
        if len(rows) >= 2000:
            break
        try:
            if not root.exists():
                continue
            paths = [root] if root.is_file() else root.rglob('*')
            for path in paths:
                if len(rows) >= 2000:
                    break
                # Symlinked units and drop-in directories are not followed.
                if path.is_symlink() or not path.is_file():
                    continue
                if 'systemd' in root.parts and path.suffix not in ('.service', '.timer', '.conf'):
                    continue
                stat = path.stat()
                identity = (stat.st_dev, stat.st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                if stat.st_size > LIMIT:
                    errors += 1
                    continue
                data = path.read_bytes()[:LIMIT]
                rows.append(dict(path=str(path), sha256=hashlib.sha256(data).hexdigest()))
                findings.extend(inspect_config(path, data.decode('utf-8', errors='replace')))
        except OSError:
            errors += 1
    note = (f'{errors} read errors/oversized files. Max 2000 files, 1 MiB each. '
            'System configuration inventory only: symlinks, user units, login scripts and some crontabs may be omitted. '
            'Configuration presence does not mean enabled or running.')
    return rows, findings, coverage('partial', len(rows), note)


def ssh_summary(text, threshold):
    counts = Counter()
    for line in text.splitlines():
        if not re.search(r'sshd(?:\[\d+\])?:', line):
            continue
        match = re.search(r'Failed password for (?:invalid user )?\S+ from (\S+) port \d+', line)
        if match:
            try:
                address = str(ipaddress.ip_address(match.group(1)))
            except ValueError:
                continue
            counts[address] += 1
    findings = [finding('SSH_REPEATED_FAILURE', 'medium', address,
        f'{count} failed-password messages in the inspected sample (no time-window calculation).',
        'Correlate with successful logins and account activity; retries or automation may explain failures.')
        for address, count in sorted(counts.items()) if count >= threshold]
    return dict(failed_password_messages=sum(counts.values()), sources=dict(sorted(counts.items()))), findings


def collect_ssh(log_path, threshold):
    paths = [Path(log_path)] if log_path else [Path('/var/log/auth.log'), Path('/var/log/secure')]
    for path in paths:
        try:
            with path.open('rb') as handle:
                size = handle.seek(0, 2)
                handle.seek(max(0, size - LIMIT))
                if size > LIMIT:
                    handle.readline()  # Discard possibly truncated initial line.
                text = handle.read(LIMIT).decode('utf-8', errors='replace')
        except OSError:
            continue
        summary, findings = ssh_summary(text, threshold)
        return summary, findings, coverage('partial', summary['failed_password_messages'],
            f'Tail sample of {path}; at most 1 MiB. Failed-password sshd messages only; rotated logs and journald not collected.')
    return {}, [], coverage('unavailable', note='No readable SSH text log. Use --auth-log with a local exported log. Journald is not queried.')


def demo():
    processes = [dict(pid=4242, exe='/tmp/demo-agent'), dict(pid=4243, exe='/usr/bin/demo-old (deleted)')]
    listeners = parse_listeners('tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\nudp UNCONN 0 0 127.0.0.1:5353 0.0.0.0:*')
    auth = '\n'.join(f'Jan 1 00:00:{i:02d} demo sshd[10]: Failed password for invalid user demo from 192.0.2.10 port 40000 ssh2' for i in range(5))
    ssh, failures = ssh_summary(auth, 5)
    findings = process_findings(processes) + listener_findings(listeners) + failures
    findings += inspect_config('/etc/cron.d/demo', '* * * * * demo /tmp/example-task')
    return dict(mode='synthetic-demo', coverage={k: coverage('synthetic', note='Fabricated fixture; no host collection.')
        for k in ('processes', 'listeners', 'persistence', 'ssh')},
        inventory=dict(processes=processes, listeners=listeners, persistence=[], ssh=ssh), findings=findings)


def scan(log_path=None, threshold=5):
    processes, pc = collect_processes()
    listeners, nc = collect_listeners()
    persistence, pf, fc = collect_persistence()
    ssh, sf, sc = collect_ssh(log_path, threshold)
    return dict(mode='live-read-only', coverage=dict(processes=pc, listeners=nc, persistence=fc, ssh=sc),
        inventory=dict(processes=processes, listeners=listeners, persistence=persistence, ssh=ssh),
        findings=process_findings(processes) + listener_findings(listeners) + pf + sf)


def render_html(report):
    esc = lambda value: html.escape(str(value), quote=True)
    items = ''.join('<tr>' + ''.join(f'<td>{esc(f[key])}</td>' for key in
        ('rule', 'severity', 'subject', 'evidence', 'recommendation')) + '</tr>' for f in report['findings'])
    cov = ''.join(f'<li><b>{esc(k)}: {esc(v["status"])}</b> — {esc(v["note"])}</li>' for k, v in report['coverage'].items())
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Linux Threat Hunter</title>
<style>body{{font:16px system-ui;background:#0b1220;color:#dbeafe;margin:3rem auto;padding:0 1rem;max-width:1200px}}h1{{color:#67e8f9}}td,th{{border-bottom:1px solid #334155;padding:12px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}table{{border-collapse:collapse;width:100%}}.scroll{{overflow:auto}}li{{margin:12px 0}}</style>
<h1>Linux Threat Hunter</h1><p>Mode: <strong>{esc(report['mode'])}</strong> · {esc(report['generated_at'])}</p>
<p>Heuristic investigation leads, not confirmed threats. No findings does not prove a clean host.</p><h2>Collection coverage</h2><ul>{cov}</ul><h2>Findings ({len(report['findings'])})</h2><div class="scroll"><table><thead><tr><th>Rule</th><th>Priority</th><th>Subject</th><th>Evidence</th><th>Next action</th></tr></thead><tbody>{items}</tbody></table></div></html>'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--demo', action='store_true', help='Synthetic fixtures; no live host inspection')
    parser.add_argument('--auth-log', help='SSH text log to inspect (last 1 MiB)')
    parser.add_argument('--ssh-threshold', type=int, default=5, help='Failures per IP in sampled log, not a rate (default 5)')
    parser.add_argument('--output', type=Path, default=Path('reports'), help='New directory for JSON/HTML; must not exist')
    args = parser.parse_args(argv)
    if args.ssh_threshold < 1:
        parser.error('--ssh-threshold must be positive')
    if not args.demo and sys.platform != 'linux':
        parser.error('Live collection requires Linux; --demo works on other platforms')
    # Never overwrite previous evidence or follow an existing output-directory symlink.
    try:
        args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    except OSError as exc:
        parser.error(f'Cannot create a new output directory: {exc}')
    report = demo() if args.demo else scan(args.auth_log, args.ssh_threshold)
    report.update(version=VERSION, generated_at=datetime.now(timezone.utc).isoformat())
    for filename, body in [('report.json', json.dumps(report, indent=2)), ('report.html', render_html(report))]:
        path = args.output / filename
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(body)
    print(f'{len(report["findings"])} investigation leads. Reports: {args.output}')
    print('Review coverage before interpreting findings. No remediation was performed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
