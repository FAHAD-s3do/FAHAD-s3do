"""Explainable, deterministic detections for Linux authentication events."""

from __future__ import annotations

import hashlib
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from .models import AuthEvent, Finding


@dataclass(frozen=True, slots=True)
class RuleConfig:
    ssh_failure_threshold: int = 5
    ssh_distinct_user_threshold: int = 5
    window_minutes: int = 10
    allowlisted_ips: frozenset[str] = frozenset()
    allowlisted_users: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not 2 <= self.ssh_failure_threshold <= 1000:
            raise ValueError("ssh_failure_threshold must be between 2 and 1000")
        if not 2 <= self.ssh_distinct_user_threshold <= 1000:
            raise ValueError("ssh_distinct_user_threshold must be between 2 and 1000")
        if not 1 <= self.window_minutes <= 1440:
            raise ValueError("window_minutes must be between 1 and 1440")


_SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _finding_id(rule_id: str, host: str, key: str, first: AuthEvent) -> str:
    seed = f"{rule_id}\0{host}\0{key}\0{first.event_id}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]


def analyze_events(events: Iterable[AuthEvent], config: RuleConfig) -> tuple[Finding, ...]:
    ordered = tuple(sorted(events, key=lambda event: (event.timestamp, event.line_number)))
    findings: list[Finding] = []
    failures: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    successes: list[AuthEvent] = []

    for event in ordered:
        if event.kind == "ssh_failed" and event.source_ip not in config.allowlisted_ips:
            failures[(event.host, event.source_ip or "unknown")].append(event)
        elif event.kind in {"ssh_success", "ssh_root_login"}:
            successes.append(event)

        if event.kind == "ssh_root_login" and event.user not in config.allowlisted_users:
            findings.append(
                Finding(
                    _finding_id("root-ssh-login", event.host, event.user or "root", event),
                    "root-ssh-login",
                    "critical",
                    "Successful SSH login as root",
                    "A direct SSH session authenticated as root.",
                    event.host,
                    event.timestamp,
                    event.timestamp,
                    (event.line_number,),
                    1,
                    event.source_ip,
                    event.user,
                    ("Verify the activity with the account owner.", "Prefer named accounts with audited privilege elevation."),
                )
            )
        elif event.kind == "user_created" and event.user not in config.allowlisted_users:
            findings.append(
                Finding(
                    _finding_id("account-created", event.host, event.user or "unknown", event),
                    "account-created",
                    "high",
                    "Local account created",
                    "The authentication log records creation of a local user account.",
                    event.host,
                    event.timestamp,
                    event.timestamp,
                    (event.line_number,),
                    1,
                    None,
                    event.user,
                    ("Confirm the account request and provisioning change.", "Review the account's groups and authentication settings."),
                )
            )

    window = timedelta(minutes=config.window_minutes)
    failure_times = {
        key: [event.timestamp for event in items]
        for key, items in failures.items()
    }
    for (host, source_ip), items in sorted(failures.items()):
        cluster: list[AuthEvent] = []
        for event in items:
            if cluster and event.timestamp - cluster[0].timestamp > window:
                findings.extend(_cluster_findings(host, source_ip, cluster, config))
                cluster = []
            cluster.append(event)
        findings.extend(_cluster_findings(host, source_ip, cluster, config))

    for success in successes:
        if not success.source_ip or success.source_ip in config.allowlisted_ips:
            continue
        key = (success.host, success.source_ip)
        candidates = failures.get(key, [])
        timestamps = failure_times.get(key, [])
        left = bisect_left(timestamps, success.timestamp - window)
        right = bisect_right(timestamps, success.timestamp)
        prior = candidates[left:right]
        if len(prior) < config.ssh_failure_threshold:
            continue
        evidence = (*prior, success)
        findings.append(
            Finding(
                _finding_id("ssh-success-after-failures", success.host, success.source_ip, prior[0]),
                "ssh-success-after-failures",
                "high",
                "SSH login succeeded after repeated failures",
                f"{len(prior)} failed attempts were followed by a successful SSH login within {config.window_minutes} minutes.",
                success.host,
                prior[0].timestamp,
                success.timestamp,
                tuple(event.line_number for event in evidence),
                len(evidence),
                success.source_ip,
                success.user,
                ("Verify the login with the account owner.", "Review nearby authentication and privilege-elevation events."),
            )
        )

    findings.sort(key=lambda item: (_SEVERITY[item.severity], item.first_seen, item.host, item.rule_id))
    return tuple(findings)


def _failure_finding(host: str, source_ip: str, cluster: list[AuthEvent], config: RuleConfig) -> Finding:
    first, last = cluster[0], cluster[-1]
    return Finding(
        _finding_id("ssh-failure-burst", host, source_ip, first),
        "ssh-failure-burst",
        "high",
        "Repeated SSH authentication failures",
        f"{len(cluster)} failed attempts from one source occurred within {config.window_minutes} minutes.",
        host,
        first.timestamp,
        last.timestamp,
        tuple(event.line_number for event in cluster),
        len(cluster),
        source_ip,
        None,
        ("Check whether the source is expected.", "Review firewall, rate-limit, and SSH authentication controls."),
    )


def _cluster_findings(host: str, source_ip: str, cluster: list[AuthEvent], config: RuleConfig) -> list[Finding]:
    findings: list[Finding] = []
    if len(cluster) >= config.ssh_failure_threshold:
        findings.append(_failure_finding(host, source_ip, cluster, config))
    targeted_users = {
        event.user for event in cluster
        if event.user and event.user not in config.allowlisted_users
    }
    if len(targeted_users) >= config.ssh_distinct_user_threshold:
        first, last = cluster[0], cluster[-1]
        findings.append(
            Finding(
                _finding_id("ssh-user-spray", host, source_ip, first),
                "ssh-user-spray",
                "high",
                "SSH failures targeted multiple accounts",
                f"{len(targeted_users)} distinct usernames were targeted from one source within {config.window_minutes} minutes.",
                host,
                first.timestamp,
                last.timestamp,
                tuple(event.line_number for event in cluster),
                len(cluster),
                source_ip,
                None,
                ("Check whether the source is an approved identity or vulnerability scanner.", "Review authentication outcomes for the targeted accounts."),
            )
        )
    return findings
