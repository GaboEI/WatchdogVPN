"""Task 23.7.5.12C.2 public-output privacy checks."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools import compat_public_policy as policy


class PublicPrivacyTests(unittest.TestCase):
    def _registry_with_review_date(self, review_date: str) -> Path:
        document = json.loads(policy.REGISTRY_PATH.read_text(encoding="utf-8"))
        document["policy"]["privacy_exceptions"][0]["review_date"] = review_date
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "registry.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def _scan(self, text: str, exceptions: dict[str, dict[tuple[str, str], set[str]]] | None = None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs" / "fixture.md").write_text(text, encoding="utf-8")
            surface = policy.Surface("docs/fixture.md", "VERIFIED", "RETAIN_PRODUCT", "technical_reference")
            return policy.scan_privacy(root, [surface], exceptions or {"privacy": {}, "editorial": {}})

    def test_seeded_sensitive_values_fail_with_precise_categories(self) -> None:
        findings = self._scan(
            "path /home/alice/evidence\nhost nls1\nprivate 192.168.10.5\n"
            "loopback 127.0.0.1\nlink-local 169.254.1.5\n"
            "ipv6-loopback ::1\nipv6-link-local fe80::1\nipv6-ula fd12:3456::9\n"
            "password=secret-value\nhttps://user:pass@example.test\n"
            "Authorization: Bearer confidential-token\n"
        )
        self.assertEqual(
            {finding.rule for finding in findings},
            {
                "private-path",
                "private-host",
                "private-ipv4",
                "private-ipv6",
                "credential",
                "credential-uri",
                "authorization-credential",
            },
        )
        self.assertTrue(all(finding.path == "docs/fixture.md" and finding.line > 0 for finding in findings))
        diagnostics = "\n".join(finding.message() for finding in findings)
        self.assertNotIn("secret-value", diagnostics)
        self.assertNotIn("confidential-token", diagnostics)

    def test_clean_public_output_passes(self) -> None:
        self.assertEqual(
            self._scan(
                "Use the documented backup command with an environment variable. "
                "The public example address is 203.0.113.7; Authorization is documented without a value.\n"
            ),
            [],
        )

    def test_explicit_exception_is_honored(self) -> None:
        exceptions = {
            "privacy": {("docs/fixture.md", "private-path"): {"/home/example/fixture"}},
            "editorial": {},
        }
        self.assertEqual(self._scan("Example: /home/example/fixture\n", exceptions), [])

    def test_editorial_exception_cannot_suppress_privacy(self) -> None:
        exceptions = {
            "privacy": {},
            "editorial": {("docs/fixture.md", "private-path"): {"/home/example/fixture"}},
        }
        self.assertEqual(
            [finding.rule for finding in self._scan("Example: /home/example/fixture\n", exceptions)],
            ["private-path"],
        )

    def test_exception_review_date_accepts_strict_iso_date(self) -> None:
        surfaces, exceptions = policy.load_registry(self._registry_with_review_date("2026-09-23"))
        self.assertTrue(surfaces)
        self.assertIn("privacy", exceptions)

    def test_exception_review_date_rejects_invalid_value(self) -> None:
        with self.assertRaisesRegex(policy.PolicyError, "review_date must be ISO YYYY-MM-DD"):
            policy.load_registry(self._registry_with_review_date("not-a-date"))

    def test_public_compatibility_artifacts_expose_no_private_data(self) -> None:
        # Scans the real tracked artifacts (compat/*.json), not a fixture.
        findings = policy.scan_compatibility_artifacts(policy.ROOT)
        self.assertEqual(
            [(finding.path, finding.rule, finding.value) for finding in findings],
            [],
            "public compatibility artifacts must not expose private paths or hosts",
        )

    def test_compatibility_artifact_scan_detects_seeded_private_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "compat").mkdir()
            (root / "compat" / "compatibility.json").write_text(
                '{"x": "host nls1 path /home/alice/evidence"}', encoding="utf-8"
            )
            self.assertEqual(
                {finding.rule for finding in policy.scan_compatibility_artifacts(root)},
                {"private-host", "private-path"},
            )


if __name__ == "__main__":
    unittest.main()
