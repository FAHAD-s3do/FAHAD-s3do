from __future__ import annotations

import unittest

from authguard.parsers import parse_auth_log
from authguard.rules import RuleConfig, analyze_events


def events(*lines: str):
    return parse_auth_log(list(lines), year=2026).events


class RuleTests(unittest.TestCase):
    def test_detects_brute_force_burst_with_evidence_lines(self) -> None:
        source = [
            f"Oct 31 09:0{i}:00 edge-01 sshd[{i}]: Failed password for admin from 203.0.113.44 port {i} ssh2"
            for i in range(5)
        ]
        findings = analyze_events(events(*source), RuleConfig())
        burst = [finding for finding in findings if finding.rule_id == "ssh-failure-burst"]
        self.assertEqual(len(burst), 1)
        self.assertEqual(burst[0].severity, "high")
        self.assertEqual(burst[0].evidence_lines, (1, 2, 3, 4, 5))

    def test_does_not_alert_below_threshold_or_across_separate_windows(self) -> None:
        source = [
            "Oct 31 09:00:00 edge-01 sshd[1]: Failed password for admin from 203.0.113.44 port 1 ssh2",
            "Oct 31 09:01:00 edge-01 sshd[2]: Failed password for admin from 203.0.113.44 port 2 ssh2",
            "Oct 31 09:02:00 edge-01 sshd[3]: Failed password for admin from 203.0.113.44 port 3 ssh2",
            "Oct 31 09:30:00 edge-01 sshd[4]: Failed password for admin from 203.0.113.44 port 4 ssh2",
            "Oct 31 09:31:00 edge-01 sshd[5]: Failed password for admin from 203.0.113.44 port 5 ssh2",
        ]
        self.assertEqual(analyze_events(events(*source), RuleConfig()), ())

    def test_detects_success_after_failures(self) -> None:
        lines = [
            f"Oct 31 09:0{i}:00 edge-01 sshd[{i}]: Failed password for deploy from 203.0.113.9 port {i} ssh2"
            for i in range(5)
        ]
        lines.append("Oct 31 09:06:00 edge-01 sshd[9]: Accepted password for deploy from 203.0.113.9 port 9 ssh2")
        findings = analyze_events(events(*lines), RuleConfig())
        self.assertIn("ssh-success-after-failures", {finding.rule_id for finding in findings})

    def test_detects_many_distinct_target_usernames(self) -> None:
        source = [
            f"Oct 31 09:0{i}:00 edge-01 sshd[{i}]: Failed password for user{i} from 203.0.113.77 port {i} ssh2"
            for i in range(5)
        ]
        config = RuleConfig(ssh_failure_threshold=10, ssh_distinct_user_threshold=4)
        findings = analyze_events(events(*source), config)
        self.assertEqual([f.rule_id for f in findings], ["ssh-user-spray"])

    def test_allowlisted_ip_is_excluded_from_ssh_findings(self) -> None:
        lines = [
            f"Oct 31 09:0{i}:00 edge-01 sshd[{i}]: Failed password for backup from 192.0.2.10 port {i} ssh2"
            for i in range(5)
        ]
        findings = analyze_events(events(*lines), RuleConfig(allowlisted_ips=frozenset({"192.0.2.10"})))
        self.assertEqual(findings, ())

    def test_detects_root_login_and_new_user_creation(self) -> None:
        parsed = events(
            "Oct 31 09:00:00 edge-01 sshd[1]: Accepted password for root from 198.51.100.9 port 1 ssh2",
            "Oct 31 09:01:00 edge-01 useradd[2]: new user: name=temp, UID=1004",
        )
        findings = analyze_events(parsed, RuleConfig())
        self.assertEqual({finding.rule_id for finding in findings}, {"root-ssh-login", "account-created"})
        root = next(f for f in findings if f.rule_id == "root-ssh-login")
        self.assertEqual(root.severity, "critical")

    def test_rule_configuration_bounds_are_checked(self) -> None:
        with self.assertRaises(ValueError):
            RuleConfig(ssh_failure_threshold=1)
        with self.assertRaises(ValueError):
            RuleConfig(window_minutes=0)
        with self.assertRaises(ValueError):
            RuleConfig(ssh_distinct_user_threshold=1)


if __name__ == "__main__":
    unittest.main()
