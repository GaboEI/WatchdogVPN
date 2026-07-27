"""L1 tests for Phase 23.7.5.5 dependency-method resolution."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from compat import dependency_resolution as resolver
from compat import detection
from tools import compat_read


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "compat_resolve.py"


def manifest():
    return detection.load_product_manifest()


def osr(text: str) -> detection.OsReleaseData:
    return detection.parse_os_release_text(text.strip() + "\n")


def facts(manifest_data, text: str, *, arch: str = "x86_64") -> detection.DistroFacts:
    return detection.distro_facts_from_os_release(
        osr(text),
        manifest_data,
        kernel_release="6.8.0-test",
        machine_architecture=arch,
    )


def cap(capability_id: str, status: str = "provisionable") -> detection.CapabilityResult:
    observed = "present" if status == "present" else "absent"
    return detection.CapabilityResult(capability_id, observed, status, "fixture", "fixture", "fixture")


def ready_core(manifest_data, distro: detection.DistroFacts):
    return tuple(
        cap(cap_id, "present")
        for cap_id in manifest_data["technical_families"][distro.technical_family]["core_capabilities"]
    )


def present_protocols(manifest_data):
    return tuple(
        cap(cap_id, "present")
        for cap_id in sorted(manifest_data["capabilities"]["protocol_capabilities"])
    )


def support(manifest_data, distro: detection.DistroFacts) -> str:
    report = detection.evaluate(
        manifest_data,
        distro,
        ready_core(manifest_data, distro),
        present_protocols(manifest_data),
        now=datetime(2026, 7, 26),
    )
    return report.support_classification


def resolve(manifest_data, distro, dependency_id, *caps, provider=None):
    return resolver.resolve_dependency(
        manifest_data,
        distro,
        support(manifest_data, distro),
        caps,
        dependency_id,
        availability=provider or resolver.StaticAvailabilityProvider.all_available(),
    )


def shell_default(path: str, name: str) -> str:
    text = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(r'%s="\$\{%s:-([^}]+)\}"' % (re.escape(name), re.escape(name)), text)
    if not match:
        raise AssertionError("missing shell default %s in %s" % (name, path))
    return match.group(1)


def shell_scalar(path: str, name: str) -> str:
    text = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(r'^%s="([^"]+)"' % re.escape(name), text, re.MULTILINE)
    if not match:
        raise AssertionError("missing shell scalar %s in %s" % (name, path))
    return match.group(1)


def shell_array(path: str, name: str) -> list[str]:
    text = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(r'^%s=\(\n(.*?)\n\)' % re.escape(name), text, re.MULTILINE | re.DOTALL)
    if match:
        lines = match.group(1).splitlines()
    else:
        inline = re.search(r'^%s=\(([^)]*)\)' % re.escape(name), text, re.MULTILINE)
        if not inline:
            raise AssertionError("missing shell array %s in %s" % (name, path))
        lines = [inline.group(1)]
    body = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            body.extend(item.strip("'\"") for item in line.split())
    return body


def packages_for_candidate(manifest_data, dependency_id: str, method_id: str) -> list[str]:
    for candidate in manifest_data["dependency_requirements"][dependency_id]["method_chain"]:
        if candidate["id"] == method_id:
            return list(candidate.get("package_names", ()))
    raise AssertionError("missing candidate %s" % method_id)


class DependencyResolverTests(unittest.TestCase):
    def test_dependency_already_present_does_not_select_method(self) -> None:
        m = manifest()
        distro = facts(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        decision = resolve(m, distro, "dep_openvpn_runtime", cap("proto_openvpn_runtime", "present"))
        self.assertEqual(decision.resolution_status, "already_present")
        self.assertTrue(decision.execution_ready)
        self.assertIsNone(decision.selected_method_id)

    def test_official_package_exact_is_selected_without_being_execution_ready_yet(self) -> None:
        m = manifest()
        distro = facts(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        decision = resolve(m, distro, "dep_openvpn_runtime", cap("proto_openvpn_runtime"))
        self.assertEqual(decision.selected_method_id, "openvpn_apt_stable_official")
        self.assertEqual(decision.selected_method_kind, "official_package_exact")
        self.assertEqual(decision.resolution_status, "recipe_not_implemented")
        self.assertFalse(decision.execution_ready)

    def test_official_artifact_pinned_is_selected_for_sing_box(self) -> None:
        m = manifest()
        distro = facts(m, "ID=fedora\nVERSION_ID=44\n")
        decision = resolve(m, distro, "dep_sing_box_runtime", cap("proto_sing_box_runtime"))
        self.assertEqual(decision.selected_method_id, "sing_box_official_artifact_stable")
        self.assertEqual(decision.selected_method_kind, "official_artifact_pinned")
        self.assertIn("lib/singbox.sh", " ".join(decision.evidence))

    def test_candidate_rejections_are_recorded_before_next_candidate_is_selected(self) -> None:
        m = manifest()
        distro = facts(
            m,
            "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=22.3\nVERSION_CODENAME=zena\nUBUNTU_CODENAME=noble\n",
        )
        decision = resolve(m, distro, "dep_amneziawg_runtime", cap("proto_amneziawg_runtime"))
        self.assertEqual(decision.selected_method_id, "amneziawg_mint_base_ppa_exact")
        self.assertEqual(decision.selected_method_kind, "external_repo_exact")
        self.assertEqual(distro.resolved_release, "linuxmint_22_3")
        self.assertEqual(distro.mapped_base_release, "ubuntu_24_04")
        self.assertEqual(decision.rejected_candidates[0].reason, "stable_release_not_explicitly_targeted")

    def test_debian_13_rejects_legacy_focal_without_exact_compatibility(self) -> None:
        m = manifest()
        distro = facts(m, "ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n")
        decision = resolve(m, distro, "dep_amneziawg_runtime", cap("proto_amneziawg_runtime"))
        focal = [item for item in decision.rejected_candidates if item.method_id == "amneziawg_debian_legacy_focal_ppa"][0]
        self.assertEqual(focal.reason, "target_release_not_explicitly_compatible")
        self.assertIn("focal", decision.candidate_chain[2])
        self.assertEqual(decision.resolution_status, "no_safe_route")
        self.assertFalse(decision.execution_ready)

    def test_ubuntu_26_rejects_nearby_series_and_remains_experimental(self) -> None:
        m = manifest()
        distro = facts(m, "ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n")
        self.assertEqual(support(m, distro), "experimental")
        decision = resolve(m, distro, "dep_amneziawg_runtime", cap("proto_amneziawg_runtime"))
        self.assertEqual(decision.support_classification, "experimental")
        self.assertEqual(decision.rejected_candidates[0].reason, "target_release_not_explicitly_compatible")
        self.assertEqual(decision.resolution_status, "no_safe_route")
        self.assertFalse(any("noble" in item.evidence and item.reason == "method_selected" for item in decision.rejected_candidates))

        artifact = resolve(m, distro, "dep_sing_box_runtime", cap("proto_sing_box_runtime"))
        self.assertEqual(artifact.support_classification, "experimental")
        self.assertEqual(artifact.selected_method_id, "sing_box_official_artifact_stable")
        self.assertNotEqual(artifact.support_classification, "supported")

    def test_kali_and_cachyos_do_not_borrow_parent_stable_versions(self) -> None:
        m = manifest()
        kali = facts(m, "ID=kali\nID_LIKE=debian\nVERSION_ID=13\n")
        self.assertEqual(kali.release_model, "rolling")
        self.assertIsNone(kali.resolved_release)
        kali_decision = resolve(m, kali, "dep_amneziawg_runtime", cap("proto_amneziawg_runtime"))
        self.assertEqual(kali_decision.resolution_status, "no_safe_route")
        focal = [item for item in kali_decision.rejected_candidates if item.method_id == "amneziawg_debian_legacy_focal_ppa"][0]
        self.assertEqual(focal.reason, "rolling_target_requires_rolling_identity")

        cachy = facts(m, "ID=cachyos\nID_LIKE=arch\nVERSION_ID=999\n")
        self.assertEqual(cachy.release_model, "rolling")
        self.assertIsNone(cachy.resolved_release)
        sing = resolve(m, cachy, "dep_sing_box_runtime", cap("proto_sing_box_runtime"))
        self.assertEqual(sing.selected_method_id, "sing_box_official_artifact_rolling")

    def test_release_unknown_and_unsupported_targets_are_controlled(self) -> None:
        m = manifest()
        unknown_release = facts(m, "ID=ubuntu\nVERSION_ID=25.04\nVERSION_CODENAME=plucky\n")
        decision = resolve(m, unknown_release, "dep_openvpn_runtime", cap("proto_openvpn_runtime"))
        self.assertEqual(decision.resolution_status, "no_safe_route")
        self.assertEqual(decision.rejected_candidates[0].reason, "release_unknown")

        unknown_distro = facts(m, "ID=unknownos\nID_LIKE=unknown\nVERSION_ID=1\n")
        decision = resolver.resolve_dependency(
            m,
            unknown_distro,
            "unsupported",
            (cap("proto_openvpn_runtime"),),
            "dep_openvpn_runtime",
            availability=resolver.StaticAvailabilityProvider.all_available(),
        )
        self.assertEqual(decision.resolution_status, "out_of_contract")

    def test_availability_unknown_is_not_package_absence(self) -> None:
        m = manifest()
        distro = facts(m, "ID=fedora\nVERSION_ID=44\n")
        decision = resolve(
            m,
            distro,
            "dep_openvpn_runtime",
            cap("proto_openvpn_runtime"),
            provider=resolver.AvailabilityProvider(),
        )
        self.assertEqual(decision.resolution_status, "availability_unknown")
        self.assertIn("availability provider has no package evidence", {item.reason for item in decision.rejected_candidates})

    def test_architecture_incompatible_rejects_every_candidate(self) -> None:
        m = manifest()
        distro = facts(m, "ID=fedora\nVERSION_ID=44\n", arch="mips")
        decision = resolve(m, distro, "dep_openvpn_runtime", cap("proto_openvpn_runtime"))
        self.assertEqual(decision.resolution_status, "no_safe_route")
        rpm = [item for item in decision.rejected_candidates if item.method_id == "openvpn_dnf_fedora_official"][0]
        self.assertEqual(rpm.reason, "architecture_not_supported")

    def test_source_without_pin_and_artifact_without_integrity_are_not_executable(self) -> None:
        m = manifest()
        distro = facts(m, "ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n")
        decision = resolve(m, distro, "dep_amneziawg_runtime", cap("proto_amneziawg_runtime"))
        source = [item for item in decision.rejected_candidates if item.method_id == "amneziawg_pinned_source_build_apt_stable_future"][0]
        self.assertEqual(source.reason, "pin_metadata_incomplete")

        broken = json.loads(json.dumps(m))
        del broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]["integrity"]["x86_64"]
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

    def test_artifact_pins_match_legacy_constants_and_assets(self) -> None:
        m = manifest()
        sing = m["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]
        cloak = m["dependency_requirements"]["dep_ck_client_runtime"]["method_chain"][0]
        self.assertEqual(sing["version"], shell_default("lib/singbox.sh", "SINGBOX_VERSION"))
        self.assertEqual(cloak["version"], shell_default("lib/cloak.sh", "CLOAK_VERSION"))
        self.assertEqual(sing["integrity"]["x86_64"], shell_default("lib/singbox.sh", "SINGBOX_SHA256_LINUX_AMD64"))
        self.assertEqual(sing["integrity"]["aarch64"], shell_default("lib/singbox.sh", "SINGBOX_SHA256_LINUX_ARM64"))
        self.assertEqual(cloak["integrity"]["x86_64"], shell_default("lib/cloak.sh", "CLOAK_SHA256_LINUX_AMD64"))
        self.assertEqual(cloak["integrity"]["aarch64"], shell_default("lib/cloak.sh", "CLOAK_SHA256_LINUX_ARM64"))
        self.assertEqual(
            {asset["asset_name"] for asset in sing["assets"]},
            {
                "sing-box-1.13.14-linux-amd64-glibc.tar.gz",
                "sing-box-1.13.14-linux-arm64.tar.gz",
            },
        )
        self.assertEqual(
            {asset["asset_name"] for asset in cloak["assets"]},
            {
                "ck-client-linux-amd64-v2.12.0",
                "ck-client-linux-arm64-v2.12.0",
            },
        )
        self.assertEqual({asset["expected_executable"] for asset in sing["assets"]}, {"sing-box"})
        self.assertEqual({asset["expected_executable"] for asset in cloak["assets"]}, {"ck-client"})

    def test_manifest_rejects_artifact_placeholders_and_unsafe_expected_files(self) -> None:
        m = manifest()
        broken = json.loads(json.dumps(m))
        candidate = broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]
        candidate["integrity"]["x86_64"] = "0" * 64
        candidate["assets"][0]["sha256"] = "0" * 64
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_ck_client_runtime"]["method_chain"][0]["expected_files"][0] = "../ck-client"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_ck_client_runtime"]["method_chain"][0]["assets"] = broken["dependency_requirements"]["dep_ck_client_runtime"]["method_chain"][0]["assets"][:1]
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][1]["version"] = "9.9.9"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

    def test_unknown_availability_blocks_lower_available_fallback(self) -> None:
        m = manifest()
        distro = facts(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        provider = resolver.StaticAvailabilityProvider(
            {
                ("package_exists", "openvpn_apt_stable_official", "ubuntu_24_04", "openvpn"): resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.TIMEOUT.value,
                    reason="official package lookup timed out",
                    error_kind="timeout",
                ),
            },
            default_status=resolver.AvailabilityStatus.AVAILABLE.value,
        )
        decision = resolver.resolve_dependency(
            m,
            distro,
            support(m, distro),
            (cap("proto_openvpn_runtime"),),
            "dep_openvpn_runtime",
            availability=provider,
        )
        self.assertEqual(decision.resolution_status, "availability_unknown")
        self.assertIsNone(decision.selected_method_id)
        self.assertIn(
            "not_evaluated_due_to_higher_priority_unknown",
            {item.reason for item in decision.rejected_candidates},
        )

    def test_static_metadata_rejection_happens_before_provider(self) -> None:
        m = manifest()
        distro = facts(m, "ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n")

        class SpyProvider(resolver.StaticAvailabilityProvider):
            def __init__(self):
                super().__init__(default_status=resolver.AvailabilityStatus.TIMEOUT.value)
                self.calls = []

            def source_revision_available(self, candidate, target_id):
                self.calls.append((candidate.method_id, target_id))
                return resolver.AvailabilityObservation(resolver.AvailabilityStatus.TIMEOUT.value, reason="should not be called")

        provider = SpyProvider()
        decision = resolver.resolve_dependency(
            m,
            distro,
            support(m, distro),
            (cap("proto_amneziawg_runtime"),),
            "dep_amneziawg_runtime",
            availability=provider,
        )
        self.assertEqual(provider.calls, [])
        self.assertIn("pin_metadata_incomplete", {item.reason for item in decision.rejected_candidates})
        self.assertEqual(decision.resolution_status, "no_safe_route")

    def test_amneziawg_source_build_is_componentized_and_family_specific(self) -> None:
        m = manifest()
        source_candidates = [
            candidate
            for candidate in m["dependency_requirements"]["dep_amneziawg_runtime"]["method_chain"]
            if candidate["kind"] == "pinned_source_build"
        ]
        self.assertGreaterEqual(len(source_candidates), 4)
        for candidate in source_candidates:
            with self.subTest(candidate=candidate["id"]):
                components = {component["component_id"]: component for component in candidate["components"]}
                self.assertEqual(set(components), {"amneziawg_tools", "amneziawg_transport"})
                self.assertIn("awg", components["amneziawg_tools"]["expected_outputs"])
                self.assertIn("awg-quick", components["amneziawg_tools"]["expected_outputs"])
                self.assertIn("amneziawg-go", components["amneziawg_transport"]["expected_outputs"])
                self.assertEqual(components["amneziawg_tools"]["repository"], "https://github.com/amnezia-vpn/amneziawg-tools")
                self.assertEqual(components["amneziawg_transport"]["repository"], "https://github.com/amnezia-vpn/amneziawg-go")
                self.assertEqual(components["amneziawg_tools"]["revision"], "unresolved")
                self.assertEqual(components["amneziawg_transport"]["revision"], "unresolved")
        by_id = {candidate["id"]: candidate for candidate in source_candidates}
        self.assertIn("golang-go", by_id["amneziawg_pinned_source_build_apt_stable_future"]["build_dependencies"])
        self.assertIn("golang", by_id["amneziawg_pinned_source_build_dnf_stable_future"]["build_dependencies"])
        self.assertIn("go", by_id["amneziawg_pinned_source_build_zypper_stable_future"]["build_dependencies"])
        self.assertIn("go", by_id["amneziawg_pinned_source_build_pacman_rolling_future"]["build_dependencies"])

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_amneziawg_runtime"]["method_chain"][3]["components"][1]["component_id"] = "amneziawg_go"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_amneziawg_runtime"]["method_chain"][3]["components"][0]["expected_outputs"] = ["awg-quick"]
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_amneziawg_runtime"]["method_chain"][3]["components"][1]["postcondition"] = "arbitrary_runtime"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

    def test_provider_validates_package_target_and_bad_provider_results(self) -> None:
        m = manifest()
        distro = facts(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        provider = resolver.StaticAvailabilityProvider(
            {
                ("package_exists", "base_runtime_apt_stable", "ubuntu_24_04", "bash"): resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.AVAILABLE.value,
                    evidence="bash exists",
                ),
                ("package_exists", "base_runtime_apt_stable", "ubuntu_24_04", "git"): resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.UNAVAILABLE.value,
                    reason="git absent",
                ),
            },
            default_status=resolver.AvailabilityStatus.AVAILABLE.value,
        )
        decision = resolver.resolve_dependency(
            m,
            distro,
            support(m, distro),
            (cap("cap_base_runtime_commands"),),
            "dep_base_runtime_commands",
            availability=provider,
        )
        self.assertEqual(decision.resolution_status, "no_safe_route")
        self.assertIn("git absent", {item.reason for item in decision.rejected_candidates})

        class BadProvider(resolver.AvailabilityProvider):
            def package_exists(self, candidate, exact_target, package_name):
                return object()

        bad = resolver.resolve_dependency(
            m,
            distro,
            support(m, distro),
            (cap("cap_base_runtime_commands"),),
            "dep_base_runtime_commands",
            availability=BadProvider(),
        )
        self.assertEqual(bad.resolution_status, "availability_unknown")
        self.assertEqual(bad.error_kind, "provider_error")

        class RaisingProvider(resolver.AvailabilityProvider):
            def package_exists(self, candidate, exact_target, package_name):
                raise RuntimeError("provider exploded")

        raised = resolver.resolve_dependency(
            m,
            distro,
            support(m, distro),
            (cap("cap_base_runtime_commands"),),
            "dep_base_runtime_commands",
            availability=RaisingProvider(),
        )
        self.assertEqual(raised.resolution_status, "availability_unknown")
        self.assertEqual(raised.error_kind, "provider_error")

    def test_provider_evidence_is_preserved_by_package(self) -> None:
        m = manifest()
        distro = facts(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        provider = resolver.StaticAvailabilityProvider.all_available()
        decision = resolver.resolve_dependency(
            m,
            distro,
            support(m, distro),
            (cap("cap_base_runtime_commands"),),
            "dep_base_runtime_commands",
            availability=provider,
        )
        package_records = [item for item in decision.availability_observations if item["operation"] == "package_exists"]
        self.assertGreater(len(package_records), 2)
        self.assertIn("package_name", package_records[0])
        self.assertEqual(decision.provider_type, "static_fixture")
        self.assertFalse(decision.provider_authoritative)

    def test_fedora_and_rhel_family_epel_are_separated(self) -> None:
        m = manifest()
        fedora = facts(m, "ID=fedora\nVERSION_ID=44\n")
        rocky = facts(m, "ID=rocky\nVERSION_ID=9\n")
        fedora_decision = resolve(m, fedora, "dep_openvpn_runtime", cap("proto_openvpn_runtime"))
        self.assertEqual(fedora_decision.selected_method_id, "openvpn_dnf_fedora_official")
        rocky_decision = resolve(m, rocky, "dep_openvpn_runtime", cap("proto_openvpn_runtime"))
        self.assertEqual(rocky_decision.selected_method_id, "openvpn_epel_rhel9_exact")
        self.assertNotEqual(rocky_decision.selected_method_id, "openvpn_dnf_fedora_official")

        provider = resolver.StaticAvailabilityProvider(
            {
                ("repository_supports_exact_target", "openvpn_epel_rhel9_exact", "rocky_9", None): resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.UNKNOWN.value,
                    reason="EPEL availability unknown",
                )
            },
            default_status=resolver.AvailabilityStatus.AVAILABLE.value,
        )
        unknown = resolver.resolve_dependency(
            m,
            rocky,
            support(m, rocky),
            (cap("proto_openvpn_runtime"),),
            "dep_openvpn_runtime",
            availability=provider,
        )
        self.assertEqual(unknown.resolution_status, "availability_unknown")

    def test_rhel_base_runtime_requires_official_packages_and_epel_together(self) -> None:
        m = manifest()
        rocky = facts(m, "ID=rocky\nVERSION_ID=9\n")
        candidate_id = "base_runtime_dnf_rhel9_with_epel_exact"
        full = resolve(m, rocky, "dep_base_runtime_commands", cap("cap_base_runtime_commands"))
        self.assertEqual(full.selected_method_id, candidate_id)
        self.assertIn("openvpn", packages_for_candidate(m, "dep_base_runtime_commands", candidate_id))
        origins = {
            item["package_name"]: item["package_origin"]
            for item in full.availability_observations
            if item["operation"] in ("repository_package_available", "package_exists")
        }
        self.assertEqual(origins["openvpn"], "external_repository:epel_9")
        self.assertEqual(origins["bash"], "base_repository")
        self.assertEqual(origins["epel-release"], "base_repository")

        provider = resolver.StaticAvailabilityProvider(
            {
                ("repository_supports_exact_target", candidate_id, "rocky_9", None): resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.UNKNOWN.value,
                    reason="EPEL unknown",
                )
            },
            default_status=resolver.AvailabilityStatus.AVAILABLE.value,
        )
        unknown = resolve(m, rocky, "dep_base_runtime_commands", cap("cap_base_runtime_commands"), provider=provider)
        self.assertEqual(unknown.resolution_status, "availability_unknown")

        provider = resolver.StaticAvailabilityProvider(
            {
                ("repository_supports_exact_target", candidate_id, "rocky_9", None): resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.UNAVAILABLE.value,
                    reason="EPEL unavailable",
                )
            },
            default_status=resolver.AvailabilityStatus.AVAILABLE.value,
        )
        unavailable = resolve(m, rocky, "dep_base_runtime_commands", cap("cap_base_runtime_commands"), provider=provider)
        self.assertEqual(unavailable.resolution_status, "no_safe_route")
        self.assertTrue(unavailable.all_availability_observations)

        provider = resolver.StaticAvailabilityProvider(
            {
                ("package_exists", candidate_id, "rocky_9", "bash"): resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.UNAVAILABLE.value,
                    reason="official package missing",
                )
            },
            default_status=resolver.AvailabilityStatus.AVAILABLE.value,
        )
        missing_official = resolve(m, rocky, "dep_base_runtime_commands", cap("cap_base_runtime_commands"), provider=provider)
        self.assertEqual(missing_official.resolution_status, "no_safe_route")

        provider = resolver.StaticAvailabilityProvider(
            {
                ("package_exists", candidate_id, "rocky_9", "openvpn"): resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.UNAVAILABLE.value,
                    reason="EPEL OpenVPN missing",
                )
            },
            default_status=resolver.AvailabilityStatus.AVAILABLE.value,
        )
        missing_epel_package = resolve(m, rocky, "dep_base_runtime_commands", cap("cap_base_runtime_commands"), provider=provider)
        self.assertEqual(missing_epel_package.resolution_status, "no_safe_route")
        self.assertTrue(missing_epel_package.all_availability_observations)

        broken = json.loads(json.dumps(m))
        candidate = next(
            item
            for item in broken["dependency_requirements"]["dep_base_runtime_commands"]["method_chain"]
            if item["id"] == candidate_id
        )
        candidate["exposed_package_names"] = []
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        candidate = next(
            item
            for item in broken["dependency_requirements"]["dep_base_runtime_commands"]["method_chain"]
            if item["id"] == candidate_id
        )
        candidate["exposed_package_names"] = ["not-in-package-list"]
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        candidate = next(
            item
            for item in broken["dependency_requirements"]["dep_base_runtime_commands"]["method_chain"]
            if item["id"] == candidate_id
        )
        del candidate["repository_package"]
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        candidate = next(
            item
            for item in broken["dependency_requirements"]["dep_base_runtime_commands"]["method_chain"]
            if item["id"] == candidate_id
        )
        candidate["package_names"].remove("openvpn")
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        candidate = next(
            item
            for item in broken["dependency_requirements"]["dep_base_runtime_commands"]["method_chain"]
            if item["id"] == candidate_id
        )
        partial = dict(candidate)
        partial["id"] = "base_runtime_dnf_rhel9_partial_regression"
        partial["priority"] = 99
        partial["package_names"] = ["openvpn"]
        broken["dependency_requirements"]["dep_base_runtime_commands"]["method_chain"].append(partial)
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

    def test_artifact_provider_receives_selected_asset_for_current_architecture(self) -> None:
        m = manifest()
        ubuntu_x86 = facts(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", arch="x86_64")
        decision = resolve(m, ubuntu_x86, "dep_sing_box_runtime", cap("proto_sing_box_runtime"))
        self.assertEqual(decision.selected_asset.architecture, "x86_64")
        self.assertEqual(decision.selected_asset.asset_name, "sing-box-1.13.14-linux-amd64-glibc.tar.gz")
        self.assertTrue(decision.all_availability_observations[0]["asset"]["asset_name"].endswith("amd64-glibc.tar.gz"))

        ubuntu_arm = facts(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", arch="aarch64")
        decision = resolve(m, ubuntu_arm, "dep_sing_box_runtime", cap("proto_sing_box_runtime"))
        self.assertEqual(decision.selected_asset.architecture, "aarch64")
        self.assertEqual(decision.selected_asset.asset_name, "sing-box-1.13.14-linux-arm64.tar.gz")

        class ArtifactProvider(resolver.StaticAvailabilityProvider):
            def __init__(self, **overrides):
                super().__init__(default_status=resolver.AvailabilityStatus.AVAILABLE.value)
                self.overrides = overrides

            def artifact_exists(self, candidate, target_id, selected_asset):
                values = {
                    "target_id": target_id,
                    "architecture": selected_asset.architecture,
                    "asset_name": selected_asset.asset_name,
                    "official_download_base": selected_asset.official_download_base,
                    "sha256": selected_asset.sha256,
                    "expected_executable": selected_asset.expected_executable,
                }
                values.update(self.overrides)
                return resolver.ArtifactAvailabilityObservation(
                    resolver.AvailabilityStatus.AVAILABLE.value,
                    evidence="asset_name=%s" % selected_asset.asset_name,
                    **values,
                )

            def artifact_integrity_metadata_available(self, candidate, target_id, selected_asset):
                return self.artifact_exists(candidate, target_id, selected_asset)

        exact = resolve(m, ubuntu_x86, "dep_sing_box_runtime", cap("proto_sing_box_runtime"), provider=ArtifactProvider())
        self.assertEqual(exact.selected_method_id, "sing_box_official_artifact_stable")

        for field, value in (
            ("target_id", "debian_13"),
            ("architecture", "aarch64"),
            ("asset_name", "sing-box-1.13.14-linux-arm64.tar.gz"),
            ("sha256", "0" * 64),
            ("official_download_base", "https://downloads.example.invalid/"),
            ("expected_executable", "other-binary"),
        ):
            with self.subTest(field=field):
                mismatched = resolve(
                    m,
                    ubuntu_x86,
                    "dep_sing_box_runtime",
                    cap("proto_sing_box_runtime"),
                    provider=ArtifactProvider(**{field: value}),
                )
                self.assertEqual(mismatched.resolution_status, "availability_unknown")
                self.assertEqual(mismatched.error_kind, "artifact_subject_mismatch")

        class MissingIdentityProvider(resolver.StaticAvailabilityProvider):
            def artifact_exists(self, candidate, target_id, selected_asset):
                return resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.AVAILABLE.value,
                    evidence="convincing text includes %s" % selected_asset.asset_name,
                )

        missing_identity = resolve(
            m,
            ubuntu_x86,
            "dep_sing_box_runtime",
            cap("proto_sing_box_runtime"),
            provider=MissingIdentityProvider(default_status=resolver.AvailabilityStatus.AVAILABLE.value),
        )
        self.assertEqual(missing_identity.resolution_status, "availability_unknown")
        self.assertEqual(missing_identity.error_kind, "artifact_subject_mismatch")

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]["assets"] = [
            asset
            for asset in broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]["assets"]
            if asset["architecture"] != "x86_64"
        ]
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        asset = dict(broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]["assets"][0])
        broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]["assets"].append(asset)
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

    def test_all_availability_observations_accumulate_across_chain(self) -> None:
        m = manifest()
        distro = facts(m, "ID=rocky\nVERSION_ID=9\n")
        mutated = json.loads(json.dumps(m))
        first = mutated["dependency_requirements"]["dep_openvpn_runtime"]["method_chain"][0]
        first["id"] = "openvpn_rocky_official_fixture"
        first["target_scope"]["stable_releases"] = ["rocky_9"]
        first["target_scope"]["technical_families"] = ["redhat_dnf"]
        first["package_manager"] = "dnf"
        provider = resolver.StaticAvailabilityProvider(
            {
                ("package_exists", "openvpn_rocky_official_fixture", "rocky_9", "openvpn"): resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.UNAVAILABLE.value,
                    reason="official unavailable",
                ),
                ("repository_supports_exact_target", "openvpn_epel_rhel9_exact", "rocky_9", None): resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.UNAVAILABLE.value,
                    reason="repo unavailable",
                ),
            },
            default_status=resolver.AvailabilityStatus.AVAILABLE.value,
        )
        # Use a temporary lower artifact candidate to prove selected decisions keep earlier observations.
        artifact = dict(mutated["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0])
        artifact["id"] = "openvpn_fixture_artifact"
        artifact["priority"] = 99
        artifact["postcondition"] = "proto_openvpn_runtime"
        artifact["method_ref"] = "official_artifact_pinned"
        artifact["kind"] = "official_artifact_pinned"
        mutated["dependency_requirements"]["dep_openvpn_runtime"]["method_chain"].append(artifact)
        compat_read.validate_manifest(mutated)
        decision = resolver.resolve_dependency(
            mutated,
            distro,
            support(mutated, distro),
            (cap("proto_openvpn_runtime"),),
            "dep_openvpn_runtime",
            availability=provider,
        )
        self.assertEqual(decision.selected_method_id, "openvpn_fixture_artifact")
        self.assertGreaterEqual(len(decision.all_availability_observations), 3)
        self.assertEqual(decision.all_availability_observations[0]["method_id"], "openvpn_rocky_official_fixture")
        self.assertEqual(decision.all_availability_observations[-1]["operation"], "artifact_integrity_metadata_available")

    def test_manifest_validates_runtime_python_policy_exactness(self) -> None:
        m = manifest()
        broken = json.loads(json.dumps(m))
        candidate = broken["dependency_requirements"]["dep_python_runtime"]["method_chain"][0]
        candidate["package_names"] = ["python3-other"]
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_python_cryptography"]["method_chain"][0]["runtime_python"]["cryptography_package"] = "python3-other"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        duplicate = dict(broken["dependency_requirements"]["dep_python_runtime"]["method_chain"][0])
        duplicate["id"] = "python_runtime_duplicate"
        duplicate["priority"] = 99
        broken["dependency_requirements"]["dep_python_runtime"]["method_chain"].append(duplicate)
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        reordered = json.loads(json.dumps(m))
        reordered["dependency_requirements"]["dep_python_runtime"]["method_chain"].reverse()
        compat_read.validate_manifest(reordered)
        distro = facts(reordered, "ID=rocky\nVERSION_ID=9\n")
        self.assertEqual(detection._runtime_python_executable(reordered, distro), "python3.11")

    def test_capability_observation_and_support_inputs_are_strict(self) -> None:
        m = manifest()
        distro = facts(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        missing = resolver.resolve_dependency(
            m,
            distro,
            support(m, distro),
            (),
            "dep_openvpn_runtime",
            availability=resolver.StaticAvailabilityProvider.all_available(),
        )
        self.assertEqual(missing.resolution_status, "capability_observation_missing")

        with self.assertRaises(resolver.DependencyResolutionError):
            resolver.resolve_dependency(
                m,
                distro,
                support(m, distro),
                (cap("proto_openvpn_runtime"), cap("proto_openvpn_runtime")),
                "dep_openvpn_runtime",
                availability=resolver.StaticAvailabilityProvider.all_available(),
            )
        impossible = resolver.resolve_dependency(
            m,
            distro,
            support(m, distro),
            (cap("proto_openvpn_runtime", "impossible"),),
            "dep_openvpn_runtime",
            availability=resolver.StaticAvailabilityProvider.all_available(),
        )
        self.assertEqual(impossible.resolution_status, "no_safe_route")
        with self.assertRaises(resolver.DependencyResolutionError):
            resolver.resolve_dependency(
                m,
                distro,
                "invented",
                (cap("proto_openvpn_runtime"),),
                "dep_openvpn_runtime",
                availability=resolver.StaticAvailabilityProvider.all_available(),
            )

    def test_capability_status_must_match_core_or_protocol_enum(self) -> None:
        m = manifest()
        distro = facts(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        with self.assertRaises(resolver.DependencyResolutionError):
            resolver.resolve_dependency(
                m,
                distro,
                support(m, distro),
                (detection.CapabilityResult("cap_nftables", "absent", "absent", "fixture", "fixture", "fixture"),),
                "dep_nftables",
                availability=resolver.StaticAvailabilityProvider.all_available(),
            )
        with self.assertRaises(resolver.DependencyResolutionError):
            resolver.resolve_dependency(
                m,
                distro,
                support(m, distro),
                (detection.CapabilityResult("cap_nftables", "present", "operable", "fixture", "fixture", "fixture"),),
                "dep_nftables",
                availability=resolver.StaticAvailabilityProvider.all_available(),
            )
        with self.assertRaises(resolver.DependencyResolutionError):
            resolver.resolve_dependency(
                m,
                distro,
                support(m, distro),
                (
                    detection.CapabilityResult(
                        "proto_openvpn_runtime",
                        "absent",
                        "preparation_failed",
                        "fixture",
                        "fixture",
                        "fixture",
                    ),
                ),
                "dep_openvpn_runtime",
                availability=resolver.StaticAvailabilityProvider.all_available(),
            )

    def test_manifest_rejects_empty_chain_duplicate_priority_and_unknown_method(self) -> None:
        m = manifest()
        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_openvpn_runtime"]["method_chain"] = []
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        chain = broken["dependency_requirements"]["dep_openvpn_runtime"]["method_chain"]
        chain[1]["priority"] = chain[0]["priority"]
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_openvpn_runtime"]["method_chain"][0]["method_ref"] = "not_real"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

    def test_manifest_rejects_target_identity_and_repository_series_mismatches(self) -> None:
        m = manifest()
        broken = json.loads(json.dumps(m))
        candidate = broken["dependency_requirements"]["dep_openvpn_runtime"]["method_chain"][0]
        candidate["target_identity"] = "rolling_distribution"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        candidate = broken["dependency_requirements"]["dep_openvpn_runtime"]["method_chain"][-1]
        candidate["target_identity"] = "resolved_release"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        candidate = broken["dependency_requirements"]["dep_amneziawg_runtime"]["method_chain"][0]
        candidate["compatible_targets"][0]["series"] = "focal"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        candidate = broken["dependency_requirements"]["dep_amneziawg_runtime"]["method_chain"][0]
        candidate["compatible_targets"][0]["target_id"] = "ubuntu_26_04"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        candidate = broken["dependency_requirements"]["dep_amneziawg_runtime"]["method_chain"][1]
        candidate["compatible_targets"][0]["target_id"] = "ubuntu_26_04"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

    def test_manifest_rejects_security_metadata_and_unsafe_data(self) -> None:
        m = manifest()
        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_openvpn_runtime"]["method_chain"][0]["package_names"][0] = "openvpn;rm"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]["integrity"]["x86_64"] = "abc"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]["official_provenance"] = "http://example.com/file"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]["official_provenance"] = "https://user@example.com/file"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_amneziawg_runtime"]["method_chain"][-1]["revision"] = "not-a-commit"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

        broken = json.loads(json.dumps(m))
        broken["dependency_requirements"]["dep_openvpn_runtime"]["method_chain"][0]["postcondition"] = "cap_nftables"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(broken)

    def test_dependency_catalog_covers_legacy_inventory_surface(self) -> None:
        m = manifest()
        expected_capabilities = {
            "cap_python310",
            "cap_python_cryptography",
            "cap_polkit",
            "cap_dns_runtime_package",
            "cap_network_manager",
            "cap_nftables",
            "proto_openvpn_runtime",
            "proto_sing_box_runtime",
            "proto_ck_client_runtime",
            "proto_amneziawg_runtime",
            "cap_base_runtime_commands",
        }
        self.assertEqual(
            expected_capabilities,
            {requirement["capability_id"] for requirement in m["dependency_requirements"].values()},
        )
        apt_base = shell_array("distros/ubuntu.sh", "DISTRO_BASE_PACKAGES")
        self.assertEqual(packages_for_candidate(m, "dep_base_runtime_commands", "base_runtime_apt_stable"), apt_base)
        self.assertEqual(packages_for_candidate(m, "dep_base_runtime_commands", "base_runtime_apt_kali_rolling"), apt_base)
        self.assertEqual(
            packages_for_candidate(m, "dep_python_cryptography", "python_cryptography_apt_stable"),
            [shell_scalar("distros/ubuntu.sh", "DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE")],
        )
        self.assertEqual(packages_for_candidate(m, "dep_polkit_runtime", "polkit_apt_stable"), [shell_scalar("distros/ubuntu.sh", "DISTRO_POLKIT_PACKAGE")])
        self.assertEqual(packages_for_candidate(m, "dep_dns_runtime_package", "dns_runtime_apt_stable"), shell_array("distros/ubuntu.sh", "DISTRO_DNS_PACKAGES"))

        fedora_base = shell_array("distros/fedora.sh", "DISTRO_BASE_PACKAGES")
        self.assertEqual(packages_for_candidate(m, "dep_base_runtime_commands", "base_runtime_dnf_fedora_official"), fedora_base)
        rhel_base = fedora_base + ["python3.11"]
        self.assertEqual(packages_for_candidate(m, "dep_base_runtime_commands", "base_runtime_dnf_rhel9_with_epel_exact"), rhel_base)
        self.assertEqual(packages_for_candidate(m, "dep_python_cryptography", "python_cryptography_dnf_fedora_official"), ["python3-cryptography"])
        self.assertEqual(packages_for_candidate(m, "dep_python_cryptography", "python_cryptography_dnf_rhel9_official"), ["python3.11-cryptography"])

        suse_base = shell_array("distros/opensuse.sh", "DISTRO_BASE_PACKAGES")
        self.assertEqual(packages_for_candidate(m, "dep_base_runtime_commands", "base_runtime_zypper_stable"), suse_base)
        self.assertEqual(packages_for_candidate(m, "dep_base_runtime_commands", "base_runtime_zypper_tumbleweed_rolling"), suse_base)
        self.assertEqual(packages_for_candidate(m, "dep_python_cryptography", "python_cryptography_zypper_stable"), [shell_scalar("distros/opensuse.sh", "DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE")])
        self.assertEqual(packages_for_candidate(m, "dep_dns_runtime_package", "dns_runtime_zypper_stable"), shell_array("distros/opensuse.sh", "DISTRO_DNS_PACKAGES"))

        arch_base = shell_array("distros/arch.sh", "DISTRO_BASE_PACKAGES")
        self.assertEqual(packages_for_candidate(m, "dep_base_runtime_commands", "base_runtime_pacman_rolling"), arch_base)
        self.assertEqual(packages_for_candidate(m, "dep_python_cryptography", "python_cryptography_pacman_rolling"), [shell_scalar("distros/arch.sh", "DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE")])
        self.assertEqual(packages_for_candidate(m, "dep_dns_runtime_package", "dns_runtime_pacman_rolling"), shell_array("distros/arch.sh", "DISTRO_DNS_PACKAGES"))

    def test_cli_operations_emit_json_and_unknown_dependency_is_exit_2(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            handle.write("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
            handle.flush()
            commands = (
                ["dependency", "dep_openvpn_runtime"],
                ["all"],
                ["explain", "dep_openvpn_runtime"],
                ["matrix"],
            )
            for command in commands:
                with self.subTest(command=command):
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(TOOL),
                            "--os-release",
                            handle.name,
                            "--fixture-host",
                            "--availability",
                            "available",
                            "--missing-capability",
                            "proto_openvpn_runtime",
                        ] + command,
                        cwd=str(ROOT),
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    payload = json.loads(result.stdout)
                    self.assertEqual(payload["provider"]["type"], "static_fixture")
                    self.assertFalse(payload["provider"]["authoritative"])
                    self.assertNotIn("Traceback", result.stderr)

            normal = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--os-release",
                    handle.name,
                    "--fixture-host",
                    "--missing-capability",
                    "proto_openvpn_runtime",
                    "dependency",
                    "dep_openvpn_runtime",
                ],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(normal.returncode, 0, normal.stderr)
            payload = json.loads(normal.stdout)
            self.assertEqual(payload["provider"]["type"], "static_fixture")
            self.assertEqual(payload["decision"]["resolution_status"], "availability_unknown")

            for invalid in (
                ["--availability", "available", "dependency", "dep_openvpn_runtime"],
                ["--missing-capability", "proto_openvpn_runtime", "dependency", "dep_openvpn_runtime"],
            ):
                with self.subTest(invalid=invalid):
                    result = subprocess.run(
                        [sys.executable, str(TOOL), "--os-release", handle.name] + invalid,
                        cwd=str(ROOT),
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn("Traceback", result.stderr)

            result = subprocess.run(
                [sys.executable, str(TOOL), "--os-release", handle.name, "--fixture-host", "dependency", "dep_missing"],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("unknown dependency", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_resolver_source_has_no_subprocess_or_mutating_commands(self) -> None:
        source = (ROOT / "compat" / "dependency_resolution.py").read_text(encoding="utf-8")
        forbidden = ("subprocess", "shell=True", "os.system", "sudo", "apt ", "dnf ", "zypper ", "pacman ")
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
