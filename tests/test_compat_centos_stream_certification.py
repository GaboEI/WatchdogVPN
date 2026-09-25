"""Focused tests for the CentOS Stream rolling certification (23.7.5.11F C7).

Non-mutating: they only read the shipped manifest, build in-memory os-release
fixtures and exercise the pure detection, support-model and manifest-validation
layers with injected inputs. No container, package manager, network or host
access is performed.
"""

from __future__ import annotations

import json
import re
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from compat import detection
from compat.support_model import (
    RollingFacts,
    SupportClassification,
    classify_support_rolling,
)
from tools import compat_read

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 20)
CENTOS_OS_RELEASE = 'ID=centos\nVERSION_ID=9\nPRETTY_NAME="CentOS Stream 9"\n'
RHEL_OS_RELEASE = "ID=rhel\nVERSION_ID=9\n"

EXPECTED_PROTOCOLS = {
    "vless",
    "trojan",
    "hysteria2",
    "amneziawg",
    "openvpn_cloak",
    "wireguard",
    "tuic",
    "http",
    "shadowsocks",
    "vmess",
    "socks",
    "openvpn",
}

FORBIDDEN_PUBLIC_PATTERNS = (
    r"\bC[0-9]\b",  # task/gate labels
    r"\b11[A-Z]\b",
    r"23\.7\.5",
    r"\bMAN-E\d",
    r"\bCENT-[A-Z]",
    r"\bJudge-Tester\b",
    r"\bnls1\b",
    r"\bF-C\d",
    r"\bD-C\d",
    r"\bL2 run\b",
)


def manifest():
    return detection.load_product_manifest()


def facts(manifest_data, text):
    return detection.distro_facts_from_os_release(
        detection.parse_os_release_text(text.strip() + "\n"),
        manifest_data,
        kernel_release="5.14.0-745.el9",
        machine_architecture="x86_64",
    )


def support(manifest_data, distro):
    return detection._support_classification(manifest_data, distro, now=NOW).value


def rolling_facts(manifest_data, distro_id="centos_stream"):
    data = compat_read._rolling_facts(manifest_data, distro_id)
    facts_in = dict(data["facts"])
    if facts_in["last_validated"]:
        facts_in["last_validated"] = datetime.strptime(
            facts_in["last_validated"], "%Y-%m-%dT%H:%M:%S"
        )
    return data, RollingFacts(**facts_in)


class CentosStreamCertificationTests(unittest.TestCase):
    def test_id_centos_resolves_exactly_to_centos_stream(self) -> None:
        m = manifest()
        d = facts(m, CENTOS_OS_RELEASE)

        self.assertEqual(d.resolved_distribution, "centos_stream")
        self.assertEqual(d.resolution_status, "resolved")
        self.assertEqual(d.technical_family, "redhat_dnf")
        self.assertEqual(d.release_model, "rolling")
        self.assertTrue(d.is_derivative)
        self.assertIsNone(d.resolved_release)
        # Never resolved as RHEL or as another Red Hat-family member.
        self.assertNotEqual(d.resolved_distribution, "rhel")
        self.assertNotEqual(d.resolved_distribution, "rocky")
        self.assertNotEqual(d.resolved_distribution, "almalinux")

    def test_centos_stream_is_certified_from_its_own_evidence(self) -> None:
        m = manifest()
        d = facts(m, CENTOS_OS_RELEASE)

        self.assertEqual(support(m, d), "certified")

        entry = m["distributions"]["centos_stream"]
        self.assertTrue(entry["lineage"]["has_own_evidence"])
        self.assertTrue(entry["lineage"]["is_derivative"])
        self.assertFalse(entry["policy"]["inherits_family_support"])

        self.assertTrue(
            compat_read.certification_qualifies_for_support(m, "cert_centos_stream_rolling")
        )
        self.assertEqual(
            m["certifications"]["cert_centos_stream_rolling"]["distribution"], "centos_stream"
        )
        self.assertEqual(
            m["certifications"]["cert_centos_stream_rolling"]["scope"],
            "physical_field_certification",
        )
        self.assertIs(m["certifications"]["cert_centos_stream_rolling"]["current"], True)

    def test_rolling_policy_and_validation_metadata_reference_the_certification(self) -> None:
        m = manifest()
        rolling = m["distributions"]["centos_stream"]["policy"]["rolling"]
        self.assertIsNotNone(rolling["last_validated"])

        policy = m["validation_metadata"]["rolling_policies"]["centos_stream"]
        self.assertEqual(policy["evidence_refs"], ["cert_centos_stream_rolling"])
        self.assertEqual(policy["last_validated"], rolling["last_validated"])
        self.assertEqual(policy["expiry_seconds"], rolling["evidence_expiry_seconds"])

        data, rf = rolling_facts(m)
        self.assertTrue(rf.has_valid_field_certification)
        self.assertTrue(rf.has_own_evidence)
        rf_validated = rf
        self.assertIsNotNone(data["facts"]["last_validated"])
        result = classify_support_rolling(
            rf_validated,
            expiry=timedelta(seconds=data["expiry_seconds"]),
            now=NOW,
        )
        self.assertIs(result, SupportClassification.CERTIFIED)

    def test_exact_twelve_key_protocol_declaration_all_green(self) -> None:
        m = manifest()
        cert = m["certifications"]["cert_centos_stream_rolling"]
        results = cert["protocol_results"]

        self.assertEqual(set(results.keys()), EXPECTED_PROTOCOLS)
        self.assertEqual(set(results.keys()), set(m["protocols"].keys()))
        self.assertEqual(len(results), len(m["protocols"]))
        for protocol_id, result in results.items():
            self.assertEqual(result["disposition"], "green", protocol_id)
            self.assertTrue(result["evidence"].strip(), protocol_id)

    def test_rhel_stays_family_inferred_and_is_never_certified_by_centos(self) -> None:
        m = manifest()
        d = facts(m, RHEL_OS_RELEASE)

        self.assertEqual(d.resolved_distribution, "rhel")
        self.assertEqual(support(m, d), "family_inferred")
        self.assertEqual(m["releases"]["rhel_9"]["distribution"], "rhel")
        self.assertNotIn("cert_rhel_9", m["certifications"])

    def test_certification_evidence_is_privacy_safe_and_traceable(self) -> None:
        m = manifest()
        cert = m["certifications"]["cert_centos_stream_rolling"]
        blobs = [cert["evidence"], cert["snapshot"]]
        blobs.extend(result["evidence"] for result in cert["protocol_results"].values())
        blob = "\n".join(blobs)

        for pattern in FORBIDDEN_PUBLIC_PATTERNS:
            self.assertIsNone(
                re.search(pattern, blob),
                "certification evidence must not contain %s" % pattern,
            )
        self.assertIn("does not certify RHEL", cert["evidence"])

    def test_public_certification_count_derives_from_the_manifest(self) -> None:
        m = manifest()
        qualifying = [
            cert_id
            for cert_id in m["certifications"]
            if compat_read.certification_qualifies_for_support(m, cert_id)
        ]
        distros = {m["certifications"][cert_id]["distribution"] for cert_id in qualifying}
        self.assertIn("centos_stream", distros)
        # CentOS Stream carries exactly one certification record and counts once.
        centos_records = [
            cert_id
            for cert_id in qualifying
            if m["certifications"][cert_id]["distribution"] == "centos_stream"
        ]
        self.assertEqual(centos_records, ["cert_centos_stream_rolling"])

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        match = re.search(r"certified on (\d+) distributions", readme)
        if match is None:
            self.fail("README must state the certified distribution count")
        self.assertEqual(int(match.group(1)), len(distros))

    def test_centos_without_own_evidence_fails_closed(self) -> None:
        m = manifest()
        mutated = json.loads(json.dumps(m))
        mutated["certifications"]["cert_centos_stream_rolling"]["current"] = False
        mutated["distributions"]["centos_stream"]["lineage"]["has_own_evidence"] = False
        mutated["validation_metadata"]["rolling_policies"]["centos_stream"]["last_validated"] = None
        mutated["distributions"]["centos_stream"]["policy"]["rolling"]["last_validated"] = None
        data, rf = rolling_facts(mutated)

        self.assertFalse(rf.has_valid_field_certification)
        self.assertFalse(rf.has_own_evidence)
        result = classify_support_rolling(
            rf,
            expiry=timedelta(seconds=data["expiry_seconds"]),
            now=NOW,
        )
        self.assertIs(result, SupportClassification.FAMILY_INFERRED)

    def test_manifest_validation_accepts_the_product_manifest(self) -> None:
        compat_read.validate_manifest(manifest())


if __name__ == "__main__":
    unittest.main()
