from __future__ import annotations

import unittest

from authguard.parsers import parse_auth_log
from authguard.report import build_report, render_html, render_json
from authguard.rules import RuleConfig, analyze_events


class ReportTests(unittest.TestCase):
    def make_report(self, redact: bool = False):
        parsed = parse_auth_log(
            [
                "Oct 31 09:00:00 edge-01 sshd[1]: Accepted password for root from 198.51.100.9 port 1 ssh2"
            ],
            year=2026,
        )
        findings = analyze_events(parsed.events, RuleConfig())
        return build_report(source_name="/private/path/auth.log", summary=parsed.summary, findings=findings, redact_ips=redact)

    def test_json_report_omits_raw_log_and_can_redact_source_ip(self) -> None:
        report = self.make_report(redact=True)
        rendered = render_json(report)
        self.assertNotIn("Accepted password", rendered)
        self.assertNotIn("/private/path", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertTrue(report["privacy"]["source_ips_redacted"])

    def test_html_escapes_untrusted_text_and_has_no_script(self) -> None:
        report = self.make_report()
        report["findings"][0]["title"] = "<script>alert(1)</script>"
        rendered = render_html(report)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("Content-Security-Policy", rendered)


if __name__ == "__main__":
    unittest.main()
