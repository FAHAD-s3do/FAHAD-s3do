from __future__ import annotations

import unittest

from authguard.parsers import parse_auth_log


class ParserTests(unittest.TestCase):
    def test_parses_failed_and_successful_ssh(self) -> None:
        lines = [
            "Oct 31 09:00:00 edge-01 sshd[1]: Failed password for invalid user admin from 203.0.113.44 port 1 ssh2",
            "Oct 31 09:01:00 edge-01 sshd[2]: Accepted publickey for deploy from 203.0.113.44 port 2 ssh2",
        ]
        parsed = parse_auth_log(lines, year=2026)
        self.assertEqual([event.kind for event in parsed.events], ["ssh_failed", "ssh_success"])
        self.assertEqual(parsed.events[0].user, "admin")
        self.assertEqual(parsed.events[1].source_ip, "203.0.113.44")
        self.assertEqual(parsed.summary.parsed_events, 2)

    def test_parses_root_login_account_creation_and_sudo_without_command_text(self) -> None:
        lines = [
            "Oct 31 09:00:00 edge-01 sshd[1]: Accepted password for root from 198.51.100.8 port 2 ssh2",
            "Oct 31 09:01:00 edge-01 useradd[2]: new user: name=temp, UID=1004",
            "Oct 31 09:02:00 edge-01 sudo: fahad : TTY=pts/0 ; COMMAND=/usr/bin/id",
        ]
        events = parse_auth_log(lines, year=2026).events
        self.assertEqual([event.kind for event in events], ["ssh_root_login", "user_created", "sudo_activity"])
        self.assertEqual(events[-1].user, "fahad")
        self.assertNotIn("/usr/bin/id", repr(events[-1]))

    def test_iso_timestamp_preserves_offset_as_utc(self) -> None:
        line = "2026-10-31T12:00:00+05:00 host-a sshd[1]: Failed password for admin from 203.0.113.8 port 1 ssh2"
        event = parse_auth_log([line], year=2026).events[0]
        self.assertEqual(event.timestamp.isoformat(), "2026-10-31T07:00:00+00:00")

    def test_normalizes_ipv6_address(self) -> None:
        line = "Oct 31 09:00:00 edge-01 sshd[1]: Failed password for admin from 2001:0DB8:0:0:0:0:0:1 port 22 ssh2"
        event = parse_auth_log([line], year=2026).events[0]
        self.assertEqual(event.source_ip, "2001:db8::1")

    def test_invalid_timestamp_is_counted_separately_from_irrelevant_lines(self) -> None:
        lines = [
            "Feb 30 09:00:00 edge-01 sshd[1]: Failed password for admin from 203.0.113.8 port 1 ssh2",
            "Oct 31 09:00:00 edge-01 CRON[1]: routine task",
            "not a syslog record",
        ]
        parsed = parse_auth_log(lines, year=2026)
        self.assertEqual(parsed.summary.invalid_lines, 1)
        self.assertEqual(parsed.summary.ignored_lines, 2)

    def test_ignores_authentication_like_text_from_unrelated_programs(self) -> None:
        line = "Oct 31 09:00:00 edge-01 app[1]: Failed password for admin from 203.0.113.8"
        parsed = parse_auth_log([line], year=2026)
        self.assertEqual(parsed.events, ())
        self.assertEqual(parsed.summary.ignored_lines, 1)

    def test_invalid_timezone_and_year_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_auth_log([], year=2026, timezone_name="No/Such_Zone")
        with self.assertRaises(ValueError):
            parse_auth_log([], year=1000)


if __name__ == "__main__":
    unittest.main()
