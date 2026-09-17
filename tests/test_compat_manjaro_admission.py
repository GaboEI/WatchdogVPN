"""Focused tests for 23.7.5.11H M1: explicit Manjaro admission (no Arch inheritance).

These tests are non-mutating. They only read the shipped manifest, build
in-memory os-release fixtures and exercise the pure detection, support-model
and dependency-resolution layers with injected inputs. No container, package
manager, network, or host access is performed.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from compat import dependency_resolution as resolver
from compat import detection
from compat.support_model import (
    RollingFacts,
    SupportClassification,
    classify_support_rolling,
)
from tools import compat_read

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 17)
MANJARO_OS_RELEASE = "ID=manjaro\nID_LIKE=arch\nBUILD_ID=rolling\n"


def manifest():
    return detection.load_product_manifest()


def facts(manifest_data, text):
    return detection.distro_facts_from_os_release(
        detection.parse_os_release_text(text.strip() + "\n"),
        manifest_data,
        kernel_release="6.1.187-2-MANJARO",
        machine_architecture="x86_64",
    )


def support(manifest_data, distro):
    return detection._support_classification(manifest_data, distro, now=NOW).value


def requirement_caps(manifest_data):
    return tuple(
        detection.CapabilityResult(cap_id, "absent", "provisionable", "fixture", "fixture", "fixture")
        for cap_id in sorted(
            {item["capability_id"] for item in manifest_data["dependency_requirements"].values()}
        )
    )


def decision_for(report, dependency_id):
    return next(item for item in report.decisions if item.dependency_id == dependency_id)


def candidate_for(manifest_data, decision):
    return next(
        candidate
        for candidate in manifest_data["dependency_requirements"][decision.dependency_id]["method_chain"]
        if candidate["id"] == decision.selected_method_id
    )


class ManjaroAdmissionTests(unittest.TestCase):
    def test_id_manjaro_resolves_exactly_to_manjaro(self) -> None:
        m = manifest()
        d = facts(m, MANJARO_OS_RELEASE)

        self.assertEqual(d.resolved_distribution, "manjaro")
        self.assertEqual(d.resolution_status, "resolved")
        self.assertEqual(d.mapping_evidence, "manjaro_lineage")
        self.assertNotEqual(d.mapping_evidence, "id_like:arch")
        self.assertEqual(d.technical_family, "arch_pacman")
        self.assertEqual(d.adapter, "arch")
        self.assertEqual(d.package_manager, "pacman")
        self.assertEqual(d.release_model, "rolling")
        self.assertTrue(d.is_derivative)
        self.assertEqual(d.lineage_distribution, "arch")
        self.assertIsNone(d.resolved_release)

    def test_id_like_arch_does_not_resolve_or_inherit_arch(self) -> None:
        m = manifest()
        d = facts(m, MANJARO_OS_RELEASE)

        self.assertNotEqual(d.resolved_distribution, "arch")
        self.assertIsNone(d.resolved_release)
        self.assertEqual(support(m, d), "experimental")
        self.assertNotIn(support(m, d), {"certified", "family_inferred", "supported"})

        entry = m["distributions"]["manjaro"]
        self.assertTrue(entry["lineage"]["is_derivative"])
        self.assertFalse(entry["lineage"]["has_own_evidence"])
        self.assertFalse(entry["lineage"]["family_inference_allowed"])
        self.assertFalse(entry["policy"]["inherits_family_support"])

        # No Manjaro release and no Manjaro certification exist, and the
        # arch/cachyos certifications stay attached to their own distributions.
        self.assertFalse(any(rel["distribution"] == "manjaro" for rel in m["releases"].values()))
        self.assertFalse(
            any(cert.get("distribution") == "manjaro" for cert in m["certifications"].values())
        )
        for cert_id in ("cert_arch_rolling", "cert_cachyos_rolling"):
            if cert_id in m["certifications"]:
                self.assertNotEqual(m["certifications"][cert_id].get("distribution"), "manjaro")

    def test_rolling_facts_remain_experimental_without_manjaro_evidence(self) -> None:
        m = manifest()
        data = compat_read._rolling_facts(m, "manjaro")

        self.assertEqual(data["model"], "rolling")
        self.assertIsNone(data["facts"]["last_validated"])
        self.assertFalse(data["facts"]["has_valid_field_certification"])
        self.assertFalse(data["facts"]["has_own_evidence"])
        self.assertFalse(data["facts"]["family_inference_allowed"])
        # The arch family does have a certified anchor; Manjaro must not inherit it.
        self.assertTrue(data["facts"]["family_has_certified_anchor"])

        result = classify_support_rolling(
            RollingFacts(**data["facts"]),
            expiry=timedelta(seconds=data["expiry_seconds"]),
            now=NOW,
        )
        self.assertIs(result, SupportClassification.EXPERIMENTAL)

    def test_missing_or_malformed_manjaro_policy_fails_closed(self) -> None:
        m = manifest()

        # (a) Removing the explicit admission must not silently become Arch support.
        mutated = json.loads(json.dumps(m))
        del mutated["distributions"]["manjaro"]
        del mutated["derivatives"]["manjaro_lineage"]
        d = facts(mutated, MANJARO_OS_RELEASE)
        self.assertIsNone(d.resolved_distribution)
        self.assertEqual(d.resolution_status, "family_recognized_by_id_like")
        self.assertEqual(d.technical_family, "arch_pacman")
        self.assertEqual(support(mutated, d), "unsupported")

        # (b) A malformed rolling policy is rejected by manifest validation.
        malformed = json.loads(json.dumps(m))
        del malformed["distributions"]["manjaro"]["policy"]["rolling"]["meets_technical_floor"]
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(malformed)

        # (c) A non-derivative Manjaro without own evidence is rejected.
        malformed2 = json.loads(json.dumps(m))
        malformed2["distributions"]["manjaro"]["lineage"]["is_derivative"] = False
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(malformed2)

        # (d) Declaring family-support inheritance is rejected.
        malformed3 = json.loads(json.dumps(m))
        malformed3["distributions"]["manjaro"]["policy"]["inherits_family_support"] = True
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(malformed3)

    def test_dependency_path_is_arch_pacman_and_invalid_targets_fail_closed(self) -> None:
        m = manifest()
        d = facts(m, MANJARO_OS_RELEASE)
        s = support(m, d)
        provider = resolver.StaticAvailabilityProvider.all_available()
        caps = requirement_caps(m)

        report = resolver.resolve_all(m, d, s, caps, availability=provider)
        self.assertEqual(report.technical_family, "arch_pacman")
        self.assertFalse(
            [item for item in report.decisions if item.resolution_status == "internal_error"]
        )

        py = decision_for(report, "dep_python_runtime")
        self.assertEqual(py.selected_method_id, "python_runtime_pacman_rolling")
        self.assertEqual(candidate_for(m, py)["runtime_python"]["executable"], "python")

        sb = decision_for(report, "dep_sing_box_runtime")
        self.assertEqual(sb.selected_method_id, "sing_box_official_artifact_rolling")

        # (a) Not explicitly targeted: fail closed, never fall back to another path.
        not_targeted = json.loads(json.dumps(m))
        for candidate in not_targeted["dependency_requirements"]["dep_python_runtime"]["method_chain"]:
            if candidate["id"] == "python_runtime_pacman_rolling":
                candidate["target_scope"]["rolling_distributions"].remove("manjaro")
        report2 = resolver.resolve_all(not_targeted, d, s, caps, availability=provider)
        py2 = decision_for(report2, "dep_python_runtime")
        self.assertIsNone(py2.selected_method_id)
        self.assertFalse(py2.execution_ready)
        self.assertEqual(py2.resolution_status, "no_safe_route")
        self.assertTrue(
            any(
                rejection.reason == "rolling_distribution_not_explicitly_targeted"
                for rejection in py2.rejected_candidates
            )
        )

        # (b) Selected candidate unavailable: fail closed.
        unavailable = resolver.StaticAvailabilityProvider(
            {}, default_status="unavailable", authoritative=True
        )
        report3 = resolver.resolve_all(m, d, s, caps, availability=unavailable)
        py3 = decision_for(report3, "dep_python_runtime")
        self.assertIsNone(py3.selected_method_id)
        self.assertFalse(py3.execution_ready)

    def test_no_regression_for_existing_arch_family_and_rolling_distributions(self) -> None:
        m = manifest()
        expected = {
            "ID=arch\nID_LIKE=arch\n": ("arch", "python", "certified"),
            "ID=cachyos\nID_LIKE=arch\n": ("cachyos", "python", "certified"),
            "ID=kali\nID_LIKE=debian\nVERSION_ID=2026.2\n": ("kali", "python3", "certified"),
            "ID=opensuse-tumbleweed\nID_LIKE=opensuse\n": (
                "opensuse_tumbleweed",
                "python3.13",
                "certified",
            ),
        }
        provider = resolver.StaticAvailabilityProvider.all_available()
        for text, (distro_id, executable, expected_support) in expected.items():
            with self.subTest(distro=distro_id):
                d = facts(m, text)
                self.assertEqual(d.resolved_distribution, distro_id)
                self.assertEqual(support(m, d), expected_support)
                caps = requirement_caps(m)
                report = resolver.resolve_all(m, d, support(m, d), caps, availability=provider)
                py = decision_for(report, "dep_python_runtime")
                self.assertEqual(candidate_for(m, py)["runtime_python"]["executable"], executable)

        compat_read.validate_manifest(m)

    def test_manjaro_amneziawg_guidance_matches_resolved_identity(self) -> None:
        m = manifest()
        d = facts(m, MANJARO_OS_RELEASE)
        self.assertEqual(d.technical_family, "arch_pacman")
        self.assertEqual(d.adapter, "arch")

        with tempfile.TemporaryDirectory() as tmp:
            os_release = Path(tmp) / "os-release"
            os_release.write_text("ID=manjaro\nID_LIKE=arch\nNAME=Manjaro\n", encoding="utf-8")
            script = (
                'source "$1/lib/common.sh"; '
                'source "$1/lib/distro.sh"; '
                'OS_RELEASE_FILE="$2"; detect_distro; '
                'adapter="$(distro_adapter_path "$1")"; source "$adapter"; '
                'source "$1/lib/amneziawg.sh"; amneziawg_import_guidance_json'
            )
            result = subprocess.run(
                ["bash", "-c", script, "test", str(ROOT), str(os_release)],
                text=True,
                capture_output=True,
                check=True,
            )

        guidance = json.loads(result.stdout)
        self.assertEqual(guidance["distro"], "manjaro")
        self.assertEqual(guidance["distro_adapter"], d.adapter)
        self.assertIn("amneziawg-dkms", "\n".join(guidance["commands"]))


if __name__ == "__main__":
    unittest.main()
