"""Task 23.7.5.12C.3 editorial-policy checks for declared public surfaces."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools import compat_public_policy as policy


class PublicEditorialTests(unittest.TestCase):
    def _scan(self, text: str, audience: str = "product", exceptions=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs" / "fixture.md").write_text(text, encoding="utf-8")
            surface = policy.Surface("docs/fixture.md", "VERIFIED", "RETAIN_PRODUCT", audience)
            return policy.scan_editorial(root, [surface], exceptions or {"privacy": {}, "editorial": {}})

    def test_product_prose_rejects_each_internal_category(self) -> None:
        fixtures = {
            "internal-task": "Task 12C is planned.\n",
            "internal-status": "The state is CLOSED / APPROVED.\n",
            "evidence-route": "Read the evidence route.\n",
            "private-path": "Read /home/alice/log.\n",
            "internal-host": "The nls1 host is unavailable.\n",
            "internal-profile": "The lab-profile is not public.\n",
            "process-narrative": "CI testing completed the certification process.\n",
        }
        for expected_rule, text in fixtures.items():
            with self.subTest(rule=expected_rule):
                self.assertEqual({finding.rule for finding in self._scan(text)}, {expected_rule})

    def test_clean_product_prose_passes(self) -> None:
        self.assertEqual(self._scan("WatchdogVPN provides documented setup and recovery controls.\n"), [])

    def test_technical_reference_can_include_needed_public_detail(self) -> None:
        self.assertEqual(
            self._scan(
                "Task 12C is PENDING; CI testing records certification process details.\n",
                audience="technical_reference",
            ),
            [],
        )

    def test_privacy_exception_cannot_suppress_editorial(self) -> None:
        exceptions = {
            "privacy": {("docs/fixture.md", "internal-task"): {"Task 12C"}},
            "editorial": {},
        }
        self.assertEqual(
            [finding.rule for finding in self._scan("Task 12C is PENDING.\n", exceptions=exceptions)],
            ["internal-task", "internal-status"],
        )


if __name__ == "__main__":
    unittest.main()
