from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from authguard.config import load_config


class ConfigTests(unittest.TestCase):
    def test_loads_configuration(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / "rules.json"
            path.write_text('{"ssh_failure_threshold": 4, "window_minutes": 8, "allowlisted_ips": ["192.0.2.1"]}', encoding="utf-8")
            config = load_config(path)
        self.assertEqual(config.ssh_failure_threshold, 4)
        self.assertIn("192.0.2.1", config.allowlisted_ips)
        self.assertEqual(config.ssh_distinct_user_threshold, 5)

    def test_rejects_duplicate_keys_unknown_fields_and_boolean_threshold(self) -> None:
        invalid = [
            '{"window_minutes": 5, "window_minutes": 9}',
            '{"unknown": true}',
            '{"ssh_failure_threshold": true}',
        ]
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / "rules.json"
            for content in invalid:
                path.write_text(content, encoding="utf-8")
                with self.subTest(content=content), self.assertRaises(ValueError):
                    load_config(path)


if __name__ == "__main__":
    unittest.main()
