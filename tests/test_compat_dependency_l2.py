"""Focused non-mutating L2-style dependency-resolution checks.

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


def cap(capability_id: str) -> detection.CapabilityResult:
    return detection.CapabilityResult(capability_id, "absent", "provisionable", "fixture", "fixture", "fixture")


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


class FocusedDependencyL2ContractTests(unittest.TestCase):
    CASES = {
        "ubuntu_24": ("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "dep_openvpn_runtime", "openvpn_apt_official"),
        "ubuntu_26": ("ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n", "dep_sing_box_runtime", "sing_box_official_artifact"),
        "debian_13": ("ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n", "dep_openvpn_runtime", "openvpn_apt_official"),
        "fedora_44": ("ID=fedora\nVERSION_ID=44\n", "dep_openvpn_runtime", "openvpn_rpm_official"),
        "opensuse_leap": ("ID=opensuse-leap\nVERSION_ID=15.6\n", "dep_openvpn_runtime", "openvpn_zypper_official"),
        "arch_rolling": ("ID=arch\nID_LIKE=arch\n", "dep_openvpn_runtime", "openvpn_pacman_official"),
    }

    def test_focused_matrix_selects_exact_declared_methods(self) -> None:
        m = manifest()
        provider = resolver.StaticAvailabilityProvider.all_available()
        for name, (os_release, dependency_id, expected_method) in self.CASES.items():
            with self.subTest(name=name):
                facts = distro(m, os_release)
                decision = resolver.resolve_dependency(
                    m,
                    facts,
                    support(m, facts),
                    (cap(m["dependency_requirements"][dependency_id]["capability_id"]),),
                    dependency_id,
                    availability=provider,
                )
                self.assertEqual(decision.selected_method_id, expected_method)
                self.assertFalse(decision.execution_ready)

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
                    (cap("proto_amneziawg_runtime"),),
                    "dep_amneziawg_runtime",
                    availability=provider,
                )
                rejection = [item for item in decision.rejected_candidates if item.method_id == method_id][0]
                self.assertEqual(rejection.reason, "target_release_not_explicitly_compatible")


if __name__ == "__main__":
    unittest.main()
