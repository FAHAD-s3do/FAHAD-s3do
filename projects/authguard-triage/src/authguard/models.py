"""Typed data structures shared by parsers, detection rules, and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class AuthEvent:
    event_id: str
    timestamp: datetime
    host: str
    kind: str
    line_number: int
    source_ip: str | None = None
    user: str | None = None

    def to_dict(self, redact_ips: bool = False) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if redact_ips and data["source_ip"]:
            data["source_ip"] = "<redacted>"
        return data


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    rule_id: str
    severity: str
    title: str
    summary: str
    host: str
    first_seen: datetime
    last_seen: datetime
    evidence_lines: tuple[int, ...]
    event_count: int
    source_ip: str | None = None
    user: str | None = None
    recommendations: tuple[str, ...] = ()

    def to_dict(self, redact_ips: bool = False) -> dict[str, Any]:
        data = asdict(self)
        for key in ("first_seen", "last_seen"):
            data[key] = getattr(self, key).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        data["evidence_lines"] = list(self.evidence_lines)
        data["recommendations"] = list(self.recommendations)
        if redact_ips and data["source_ip"]:
            data["source_ip"] = "<redacted>"
        return data


@dataclass(frozen=True, slots=True)
class ParseSummary:
    total_lines: int
    parsed_events: int
    ignored_lines: int
    invalid_lines: int
    event_counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ParsedLog:
    events: tuple[AuthEvent, ...]
    summary: ParseSummary
