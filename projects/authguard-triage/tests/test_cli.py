from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from authguard.cli import main


class CliTests(unittest.TestCase):
    def test_writes_json_and_html_and_redacts_addresses(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            root = Path(directory)
            source = root / "auth.log"
            source.write_text(
                "Oct 31 09:00:00 edge-01 sshd[1]: Accepted password for root from 198.51.100.9 port 1 ssh2\n",
                encoding="utf-8",
            )
            json_path, html_path = root / "report.json", root / "report.html"
            with contextlib.redirect_stderr(io.StringIO()):
                result = main([str(source), "--year", "2026", "--json", str(json_path), "--html", str(html_path), "--redact-ips"])
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(result, 0)
            self.assertEqual(report["findings"][0]["source_ip"], "<redacted>")
            self.assertTrue(html_path.is_file())
            self.assertNotIn("198.51.100.9", html_path.read_text(encoding="utf-8"))

    def test_prevents_report_from_overwriting_source_log(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            source = Path(directory) / "auth.log"
            original = "Oct 31 09:00:00 edge-01 sshd[1]: Accepted password for root from 198.51.100.9 port 1 ssh2\n"
            source.write_text(original, encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                result = main([str(source), "--year", "2026", "--json", str(source)])
            self.assertEqual(result, 2)
            self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_fail_on_threshold_returns_one_for_matching_finding(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            source = Path(directory) / "auth.log"
            source.write_text(
                "Oct 31 09:00:00 edge-01 sshd[1]: Accepted password for root from 198.51.100.9 port 1 ssh2\n",
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = main([str(source), "--year", "2026", "--fail-on", "high"])
            self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
