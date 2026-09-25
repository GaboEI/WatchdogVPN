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
        # Every declared certification must qualify for support and carry the
        # full 12-protocol physical-field profile. The public count is derived
        # from the manifest, never hardcoded here.
        self.assertEqual(set(records), set(manifest["certifications"]))
        for cert_id in records:
            self.assertEqual(len(manifest["certifications"][cert_id]["protocol_results"]), 12)
        self.assertEqual(
            len(distros),
            len({manifest["certifications"][cert_id]["distribution"] for cert_id in records}),
        )
        self.assertIn("manjaro", distros)
        self.assertIn("centos_stream", distros)
        self.assertTrue(
            compat_read.certification_qualifies_for_support(manifest, "cert_centos_stream_rolling")
        )

    def test_readme_count_matches_manifest(self) -> None:
        manifest = detection.load_product_manifest()
        expected = len(qualifying_distributions(manifest))
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        match = re.search(r"certified on (\d+) distributions", readme)
        if match is None:
            self.fail("README must state the certified distribution count")
        self.assertEqual(int(match.group(1)), expected)

    def test_roadmap_count_matches_manifest(self) -> None:
        manifest = detection.load_product_manifest()
        expected = len(qualifying_distributions(manifest))
        roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
        match = re.search(r"certified across (\d+)\s+Linux\s+distributions", roadmap)
        if match is None:
            self.fail("ROADMAP must state the certified distribution count")
        self.assertEqual(int(match.group(1)), expected)


if __name__ == "__main__":
    unittest.main()
