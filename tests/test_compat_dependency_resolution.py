"""L1 tests for Phase 23.7.5.5 dependency-method resolution."""

from __future__ import annotations

import json
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
        rpm = [item for item in decision.rejected_candidates if item.method_id == "openvpn_rpm_official"][0]
        self.assertEqual(rpm.reason, "architecture_not_supported")

    def test_source_without_pin_and_artifact_without_integrity_are_not_executable(self) -> None:
        m = manifest()
        distro = facts(m, "ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n")
        decision = resolve(m, distro, "dep_amneziawg_runtime", cap("proto_amneziawg_runtime"))
        source = [item for item in decision.rejected_candidates if item.method_id == "amneziawg_pinned_source_build_stable_future"][0]
        self.assertEqual(source.reason, "pin_metadata_incomplete")

        broken = json.loads(json.dumps(m))
        del broken["dependency_requirements"]["dep_sing_box_runtime"]["method_chain"][0]["integrity"]["x86_64"]
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
        expected = {
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
            expected,
            {requirement["capability_id"] for requirement in m["dependency_requirements"].values()},
        )
        package_union = {
            package
            for requirement in m["dependency_requirements"].values()
            for candidate in requirement["method_chain"]
            for package in candidate.get("package_names", ())
        }
        frozen_legacy_subset = {
            "bash",
            "git",
            "curl",
            "python3-cryptography",
            "python-cryptography",
            "python311-cryptography",
            "polkitd",
            "polkit",
            "dnsutils",
            "bind-utils",
            "bind",
            "network-manager",
            "NetworkManager",
            "networkmanager",
            "nftables",
            "openvpn",
            "amneziawg",
        }
        self.assertTrue(frozen_legacy_subset.issubset(package_union))

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
