"""Parsers for common Linux auth.log and ISO-timestamped syslog records."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .models import AuthEvent, ParseSummary, ParsedLog

_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<message>.*)$"
)
_ISO_PREFIX = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ][^\s]+)\s+(?P<rest>.+)$")
_PROGRAM = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)(?:\[\d+\])?:")
_FAILED = re.compile(
    r"Failed\s+(?:password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?:(?:invalid|authenticating)\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)",
    re.IGNORECASE,
)
_ACCEPTED = re.compile(
    r"Accepted\s+(?:password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)",
    re.IGNORECASE,
)
_SUDO = re.compile(r"\bsudo(?:\[\d+\])?:\s*(?P<user>[A-Za-z0-9_.-]+)\s*:", re.IGNORECASE)
_NEW_USER = re.compile(r"\bnew user:\s*name=(?P<user>[A-Za-z0-9_.-]+)", re.IGNORECASE)


def _timestamp(value: str, local_zone: ZoneInfo) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=local_zone)
    return parsed.astimezone(timezone.utc)


def parse_auth_log(
    lines: Iterable[str],
    *,
    year: int,
    timezone_name: str = "UTC",
    source_label: str = "auth.log",
) -> ParsedLog:
    """Parse supported events without retaining raw log messages or commands.

    Classic syslog records have no year or timezone; callers must select the
    year and local timezone used to interpret them. ISO timestamps keep their
    explicit offset, or use timezone_name if no offset is present.
    """
    try:
        local_zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown timezone: {timezone_name}") from exc
    if not 1970 <= year <= 9999:
        raise ValueError("year must be between 1970 and 9999")

    events: list[AuthEvent] = []
    ignored = 0
    invalid = 0
    total_lines = 0
    counts: Counter[str] = Counter()

    for line_number, raw in enumerate(lines, start=1):
        total_lines = line_number
        line = raw.strip()
        if not line:
            ignored += 1
            continue
        try:
            iso = _ISO_PREFIX.match(line)
            if iso:
                timestamp = _timestamp(iso.group("timestamp"), local_zone)
                rest = iso.group("rest")
                host, separator, message = rest.partition(" ")
                if not separator:
                    ignored += 1
                    continue
            else:
                syslog = _SYSLOG_PREFIX.match(line)
                if not syslog:
                    ignored += 1
                    continue
                naive = datetime.strptime(
                    f"{year} {syslog.group('month')} {syslog.group('day')} {syslog.group('clock')}",
                    "%Y %b %d %H:%M:%S",
                )
                timestamp = naive.replace(tzinfo=local_zone).astimezone(timezone.utc)
                host = syslog.group("host")
                message = syslog.group("message")
        except (ValueError, OverflowError):
            invalid += 1
            continue

        kind: str | None = None
        source_ip: str | None = None
        user: str | None = None
        program_match = _PROGRAM.match(message)
        program = program_match.group("name").lower() if program_match else ""
        failed = _FAILED.search(message) if program == "sshd" else None
        accepted = _ACCEPTED.search(message) if program == "sshd" else None
        new_user = _NEW_USER.search(message) if program == "useradd" else None
        sudo = _SUDO.search(message) if program == "sudo" else None
        if failed:
            kind, source_ip, user = "ssh_failed", failed.group("ip"), failed.group("user")
        elif accepted:
            user, source_ip = accepted.group("user"), accepted.group("ip")
            kind = "ssh_root_login" if user == "root" else "ssh_success"
        elif new_user:
            kind, user = "user_created", new_user.group("user")
        elif sudo:
            kind, user = "sudo_activity", sudo.group("user")
        else:
            ignored += 1
            continue

        if source_ip:
            try:
                source_ip = ipaddress.ip_address(source_ip).compressed
            except ValueError:
                invalid += 1
                continue

        identity = hashlib.sha256(f"{source_label}\0{line_number}\0{raw}".encode("utf-8", "replace")).hexdigest()[:16]
        events.append(AuthEvent(identity, timestamp, host, kind, line_number, source_ip, user, source_label))
        counts[kind] += 1

    events.sort(key=lambda event: (event.timestamp, event.line_number))
    return ParsedLog(
        tuple(events),
        ParseSummary(total_lines, len(events), ignored, invalid, dict(sorted(counts.items()))),
    )
