"""Focused non-mutating L1 dependency-resolution matrix checks.

These tests exercise the per-release resolver matrix with an injected
availability provider. They deliberately do not start containers, run package
managers, add repositories or access the network.
"""

from __future__ import annotations

import unittest
from datetime import datetime

from compat import dependency_resolution as resolver
from compat import detection


def manifest():
    return detection.load_product_manifest()


def distro(manifest_data, text: str) -> detection.DistroFacts:
    return detection.distro_facts_from_os_release(
        detection.parse_os_release_text(text.strip() + "\n"),
        manifest_data,
        kernel_release="6.8.0-test",
        machine_architecture="x86_64",
    )


def capability_result(manifest_data, capability_id: str) -> detection.CapabilityResult:
    observed = "partial" if capability_id in manifest_data["capabilities"]["core_host_capabilities"] else "absent"
    return detection.CapabilityResult(capability_id, observed, "provisionable", "fixture", "fixture", "fixture")


def capability_results_for_all_requirements(manifest_data):
    return tuple(
        capability_result(manifest_data, cap_id)
        for cap_id in sorted({item["capability_id"] for item in manifest_data["dependency_requirements"].values()})
    )


def ready_core(manifest_data, facts):
    return tuple(
        detection.CapabilityResult(cap_id, "present", "present", "fixture", "fixture", "fixture")
        for cap_id in manifest_data["technical_families"][facts.technical_family]["core_capabilities"]
    )


def present_protocols(manifest_data):
    return tuple(
        detection.CapabilityResult(cap_id, "present", "present", "fixture", "fixture", "fixture")
        for cap_id in sorted(manifest_data["capabilities"]["protocol_capabilities"])
    )


def support(manifest_data, facts):
    return detection.evaluate(
        manifest_data,
        facts,
        ready_core(manifest_data, facts),
        present_protocols(manifest_data),
        now=datetime(2026, 7, 26),
    ).support_classification


def selected_candidate(manifest_data, decision):
    if not decision.selected_method_id:
        return None
    for candidate in manifest_data["dependency_requirements"][decision.dependency_id]["method_chain"]:
        if candidate["id"] == decision.selected_method_id:
            return candidate
    raise AssertionError("selected candidate missing from manifest")


class FocusedDependencyMatrixContractTests(unittest.TestCase):
    CASES = {
        "ubuntu_24_04": {
            "os_release": "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n",
            "support": "certified",
            "release_model": "stable",
            "resolved_release": "ubuntu_24_04",
            "python": "python3",
        },
        "ubuntu_26_04": {
            "os_release": "ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n",
            "support": "experimental",
            "release_model": "stable",
            "resolved_release": "ubuntu_26_04",
            "python": "python3",
        },
        "debian_13": {
            "os_release": "ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n",
            "support": "certified",
            "release_model": "stable",
            "resolved_release": "debian_13",
            "python": "python3",
        },
        "fedora_44": {
            "os_release": "ID=fedora\nVERSION_ID=44\n",
            "support": "certified",
            "release_model": "stable",
            "resolved_release": "fedora_44",
            "python": "python3",
            "openvpn": "openvpn_dnf_fedora_official",
        },
        "rocky_9": {
            "os_release": "ID=rocky\nVERSION_ID=9.6\n",
            "support": "certified",
            "release_model": "stable",
            "resolved_release": "rocky_9",
            "python": "python3.11",
            "openvpn": "openvpn_epel_rhel9_exact",
        },
        "almalinux_9": {
            "os_release": "ID=almalinux\nVERSION_ID=9.6\n",
            "support": "family_inferred",
            "release_model": "stable",
            "resolved_release": "almalinux_9",
            "python": "python3.11",
            "openvpn": "openvpn_epel_rhel9_exact",
        },
        "rhel_9": {
            "os_release": "ID=rhel\nVERSION_ID=9\n",
            "support": "family_inferred",
            "release_model": "stable",
            "resolved_release": "rhel_9",
            "python": "python3.11",
            "openvpn": "openvpn_epel_rhel9_exact",
        },
        "centos_stream_9": {
            "os_release": "ID=centos\nVERSION_ID=9\nPRETTY_NAME=\"CentOS Stream 9\"\n",
            "support": "family_inferred",
            "release_model": "stable",
            "resolved_release": "centos_stream_9",
            "python": "python3.11",
            "openvpn": "openvpn_epel_rhel9_exact",
        },
        "opensuse_leap_15_6": {
            "os_release": "ID=opensuse-leap\nVERSION_ID=15.6\n",
            "support": "certified",
            "release_model": "stable",
            "resolved_release": "opensuse_leap_15_6",
            "python": "python3.11",
        },
        "opensuse_tumbleweed": {
            "os_release": "ID=opensuse-tumbleweed\nID_LIKE=opensuse\n",
            "support": "family_inferred",
            "release_model": "rolling",
            "resolved_release": None,
            "python": "python3.11",
        },
        "arch": {
            "os_release": "ID=arch\nID_LIKE=arch\n",
            "support": "certified",
            "release_model": "rolling",
            "resolved_release": None,
            "python": "python",
        },
        "cachyos": {
            "os_release": "ID=cachyos\nID_LIKE=arch\n",
            "support": "certified",
            "release_model": "rolling",
            "resolved_release": None,
            "python": "python",
        },
        "linuxmint_22_3": {
            "os_release": "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=22.3\nVERSION_CODENAME=zena\nUBUNTU_CODENAME=noble\n",
            "support": "certified",
            "release_model": "stable",
            "resolved_release": "linuxmint_22_3",
            "python": "python3",
            "mapped_base_release": "ubuntu_24_04",
        },
        "kali": {
            "os_release": "ID=kali\nID_LIKE=debian\nVERSION_ID=2026.2\n",
            "support": "experimental",
            "release_model": "rolling",
            "resolved_release": None,
            "python": "python3",
        },
    }

    def test_full_productive_matrix_resolves_all_requirements_without_internal_errors(self) -> None:
        m = manifest()
        provider = resolver.StaticAvailabilityProvider.all_available()
        caps = capability_results_for_all_requirements(m)
        for name, case in self.CASES.items():
            with self.subTest(name=name):
                facts = distro(m, case["os_release"])
                self.assertEqual(facts.release_model, case["release_model"])
                self.assertEqual(facts.resolved_release, case["resolved_release"])
                self.assertEqual(facts.mapped_base_release, case.get("mapped_base_release"))
                derived_support = support(m, facts)
                self.assertEqual(derived_support, case["support"])
                report = resolver.resolve_all(m, facts, derived_support, caps, availability=provider)
                self.assertEqual(report.release_model, case["release_model"])
                self.assertFalse(
                    [decision for decision in report.decisions if decision.resolution_status == "internal_error"]
                )
                python_decision = next(item for item in report.decisions if item.dependency_id == "dep_python_runtime")
                python_candidate = selected_candidate(m, python_decision)
                self.assertIsNotNone(python_candidate)
                self.assertEqual(python_candidate["runtime_python"]["executable"], case["python"])
                openvpn_expected = case.get("openvpn")
                if openvpn_expected:
                    openvpn_decision = next(item for item in report.decisions if item.dependency_id == "dep_openvpn_runtime")
                    self.assertEqual(openvpn_decision.selected_method_id, openvpn_expected)
                for decision in report.decisions:
                    candidate = selected_candidate(m, decision)
                    if not candidate:
                        continue
                    hashes = candidate.get("integrity", {})
                    for value in hashes.values():
                        if isinstance(value, str) and len(value) == 64:
                            self.assertNotEqual(value, "0" * 64)
                            self.assertNotEqual(value, "1" * 64)

    def test_external_series_absence_is_controlled_not_silent_fallback(self) -> None:
        m = manifest()
        provider = resolver.StaticAvailabilityProvider.all_available()
        cases = (
            ("debian_13", "ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n", "amneziawg_debian_legacy_focal_ppa"),
            ("ubuntu_26", "ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n", "amneziawg_ubuntu_ppa_exact"),
        )
        for name, os_release, method_id in cases:
            with self.subTest(name=name):
                facts = distro(m, os_release)
                decision = resolver.resolve_dependency(
                    m,
                    facts,
                    support(m, facts),
                    (capability_result(m, "proto_amneziawg_runtime"),),
                    "dep_amneziawg_runtime",
                    availability=provider,
                )
                rejection = [item for item in decision.rejected_candidates if item.method_id == method_id][0]
                self.assertEqual(rejection.reason, "target_release_not_explicitly_compatible")


if __name__ == "__main__":
    unittest.main()
