"""Strict JSON configuration loading."""

from __future__ import annotations

import json
import ipaddress
from pathlib import Path
from typing import Any

from .rules import RuleConfig


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate configuration key: {key}")
        result[key] = value
    return result


def load_config(path: Path) -> RuleConfig:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read configuration: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("configuration must be a JSON object")
    allowed = {
        "ssh_failure_threshold",
        "ssh_distinct_user_threshold",
        "window_minutes",
        "allowlisted_ips",
        "allowlisted_users",
    }
    unknown = set(data) - allowed
    if unknown:
        raise ValueError("unknown configuration keys: " + ", ".join(sorted(unknown)))
    for name in ("ssh_failure_threshold", "ssh_distinct_user_threshold", "window_minutes"):
        if name in data and (not isinstance(data[name], int) or isinstance(data[name], bool)):
            raise ValueError(f"{name} must be an integer")
    for name in ("allowlisted_ips", "allowlisted_users"):
        if name in data and (
            not isinstance(data[name], list)
            or any(not isinstance(item, str) or not item.strip() for item in data[name])
        ):
            raise ValueError(f"{name} must be a list of non-empty strings")
    normalized_ips: set[str] = set()
    for value in data.get("allowlisted_ips", []):
        try:
            normalized_ips.add(ipaddress.ip_address(value).compressed)
        except ValueError as exc:
            raise ValueError(f"allowlisted IP is invalid: {value}") from exc
    return RuleConfig(
        ssh_failure_threshold=data.get("ssh_failure_threshold", 5),
        ssh_distinct_user_threshold=data.get("ssh_distinct_user_threshold", 5),
        window_minutes=data.get("window_minutes", 10),
        allowlisted_ips=frozenset(normalized_ips),
        allowlisted_users=frozenset(data.get("allowlisted_users", [])),
    )
