"""Guard the public certification count against drifting from the manifest.

The public README/ROADMAP state how many Linux distributions are
field-certified. That number must equal the count of distinct distributions
carrying a current qualifying 12/12 physical-field certification in
``compat/compatibility.json`` (a distribution may have more than one
certification record -- Kali has two -- but still counts once).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from compat import detection
from tools import compat_read

ROOT = Path(__file__).resolve().parents[1]


def qualifying_certification_ids(manifest):
    return [
        cert_id
        for cert_id in manifest["certifications"]
        if compat_read.certification_qualifies_for_support(manifest, cert_id)
    ]


def qualifying_distributions(manifest):
    return {
        manifest["certifications"][cert_id]["distribution"]
        for cert_id in qualifying_certification_ids(manifest)
    }


class PublicCertificationCountTests(unittest.TestCase):
    def test_manifest_qualifying_shape(self) -> None:
        manifest = detection.load_product_manifest()
        records = qualifying_certification_ids(manifest)
        distros = qualifying_distributions(manifest)
        self.assertEqual(len(distros), 13)
        self.assertEqual(len(records), 14)
        self.assertIn("manjaro", distros)
        for cert_id in records:
            self.assertEqual(len(manifest["certifications"][cert_id]["protocol_results"]), 12)

    def test_readme_count_matches_manifest(self) -> None:
        manifest = detection.load_product_manifest()
        expected = len(qualifying_distributions(manifest))
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        match = re.search(r"(\d+)\s+distributions field-certified", readme)
        if match is None:
            self.fail("README must state the field-certified count")
        self.assertEqual(int(match.group(1)), expected)

    def test_roadmap_count_matches_manifest(self) -> None:
        manifest = detection.load_product_manifest()
        expected = len(qualifying_distributions(manifest))
        roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
        match = re.search(r"field-certified WatchdogVPN across (\d+) Linux distributions", roadmap)
        if match is None:
            self.fail("ROADMAP must state the field-certified count")
        self.assertEqual(int(match.group(1)), expected)


if __name__ == "__main__":
    unittest.main()
