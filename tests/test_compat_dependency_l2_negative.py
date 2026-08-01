"""Deterministic L2 negative tests for dependency resolution.

These tests exercise the resolver against the real product manifest using a
static availability provider. They do not start containers, access the
network, or mutate the host.
"""

from __future__ import annotations

import unittest
from datetime import datetime

from compat import dependency_resolution as resolver
from compat import detection
from compat.support_model import StableReleaseFacts, classify_support_stable


def manifest():
    return detection.load_product_manifest()


def distro(manifest_data, text: str) -> detection.DistroFacts:
    return detection.distro_facts_from_os_release(
        detection.parse_os_release_text(text.strip() + "\n"),
        manifest_data,
        kernel_release="6.8.0-test",
        machine_architecture="x86_64",
    )


def core_capability_result(capability_id: str) -> detection.CapabilityResult:
    return detection.CapabilityResult(capability_id, "partial", "provisionable", "fixture", "fixture", "fixture")


def protocol_capability_result(capability_id: str) -> detection.CapabilityResult:
    return detection.CapabilityResult(capability_id, "absent", "provisionable", "fixture", "fixture", "fixture")


def core_capabilities(manifest_data, facts):
    if facts.technical_family is None:
        family_caps = manifest_data["capabilities"]["core_host_capabilities"]
    else:
        family_caps = manifest_data["technical_families"][facts.technical_family]["core_capabilities"]
    return tuple(
        core_capability_result(cap_id)
        for cap_id in sorted(family_caps)
    )


def protocol_capabilities(manifest_data):
    return tuple(
        protocol_capability_result(cap_id)
        for cap_id in sorted(manifest_data["capabilities"]["protocol_capabilities"])
    )


def all_capability_results(manifest_data, facts):
    return core_capabilities(manifest_data, facts) + protocol_capabilities(manifest_data)


def support(manifest_data, facts):
    return detection.evaluate(
        manifest_data,
        facts,
        core_capabilities(manifest_data, facts),
        protocol_capabilities(manifest_data),
        now=datetime(2026, 7, 26),
    ).support_classification


def resolve_dependency(manifest_data, facts, dep_id, provider=None):
    return resolver.resolve_dependency(
        manifest_data,
        facts,
        support(manifest_data, facts),
        all_capability_results(manifest_data, facts),
        dep_id,
        availability=provider,
    )


def static_unknown():
    return resolver.AvailabilityProvider()


def static_unavailable():
    return resolver.StaticAvailabilityProvider({}, default_status=resolver.AvailabilityStatus.UNAVAILABLE.value)


class NegativeTargetSeriesTests(unittest.TestCase):
    def test_amneziawg_ppa_rejected_for_ubuntu_26_04(self) -> None:
        m = manifest()
        facts = distro(m, "ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n")
        decision = resolve_dependency(m, facts, "dep_amneziawg_runtime", resolver.StaticAvailabilityProvider.all_available())
        self.assertIn(
            "target_release_not_explicitly_compatible",
            [r.reason for r in decision.rejected_candidates if r.method_id == "amneziawg_ubuntu_ppa_exact"],
        )

    def test_amneziawg_legacy_focal_rejected_for_debian_13(self) -> None:
        m = manifest()
        facts = distro(m, "ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n")
        decision = resolve_dependency(m, facts, "dep_amneziawg_runtime", resolver.StaticAvailabilityProvider.all_available())
        rejection = next(
            (r for r in decision.rejected_candidates if r.method_id == "amneziawg_debian_legacy_focal_ppa"),
            None,
        )
        self.assertIsNotNone(rejection)
        self.assertEqual(rejection.reason, "target_release_not_explicitly_compatible")


class NegativeAvailabilityTests(unittest.TestCase):
    def test_unknown_availability_blocks_lower_priority_candidates(self) -> None:
        m = manifest()
        facts = distro(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        decision = resolve_dependency(m, facts, "dep_amneziawg_runtime", static_unknown())
        self.assertEqual(decision.resolution_status, "availability_unknown")
        self.assertTrue(
            any(
                r.reason == "not_evaluated_due_to_higher_priority_unknown"
                for r in decision.rejected_candidates
            )
        )

    def test_unavailable_higher_priority_allows_lower_priority_evaluation(self) -> None:
        m = manifest()
        facts = distro(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        provider = resolver.StaticAvailabilityProvider(
            {
                ("repository_supports_exact_target", "amneziawg_ubuntu_ppa_exact", "ubuntu_24_04", None):
                    resolver.AvailabilityStatus.UNAVAILABLE.value,
            },
            default_status=resolver.AvailabilityStatus.AVAILABLE.value,
        )
        decision = resolve_dependency(m, facts, "dep_amneziawg_runtime", provider)
        self.assertEqual(decision.resolution_status, "method_selected")
        self.assertEqual(decision.selected_method_id, "amneziawg_pinned_source_build_apt_stable_future")
        self.assertTrue(decision.execution_ready)

    def test_all_candidates_unavailable_yields_no_safe_route(self) -> None:
        m = manifest()
        facts = distro(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        decision = resolve_dependency(m, facts, "dep_amneziawg_runtime", static_unavailable())
        self.assertEqual(decision.resolution_status, "no_safe_route")


class NegativeManifestDataTests(unittest.TestCase):
    # These are data-regression checks, not exercises of the manifest validator
    # (validator rejection tests live in tests.test_compat_manifest.py).

    def test_manifest_data_has_no_placeholder_sha256_hashes(self) -> None:
        m = manifest()
        for dep_id, req in m["dependency_requirements"].items():
            for candidate in req["method_chain"]:
                integrity = candidate.get("integrity", {})
                if integrity.get("type") == "sha256":
                    for arch in candidate.get("architectures", ()):
                        value = integrity.get(arch, "")
                        self.assertNotEqual(value, "0" * 64, "placeholder sha256 in %s" % candidate["id"])
                        self.assertNotEqual(value, "1" * 64, "placeholder sha256 in %s" % candidate["id"])

    def test_manifest_source_builds_have_commit_revisions(self) -> None:
        m = manifest()
        for dep_id, req in m["dependency_requirements"].items():
            for candidate in req["method_chain"]:
                if candidate["kind"] == "pinned_source_build":
                    components = candidate.get("components", ())
                    if components:
                        for component in components:
                            self.assertEqual(component.get("revision_type"), "commit")
                            self.assertRegex(component.get("revision", ""), r"^[0-9a-f]{40}$")
                            self.assertTrue(component.get("tag"))
                    else:
                        self.assertEqual(candidate.get("revision_type"), "commit")
                        self.assertRegex(candidate.get("revision", ""), r"^[0-9a-f]{40}$")


class NegativeUnsupportedTests(unittest.TestCase):
    def test_unknown_distribution_is_out_of_contract(self) -> None:
        m = manifest()
        facts = distro(m, "ID=unknownos\nVERSION_ID=1\n")
        decision = resolve_dependency(m, facts, "dep_python_runtime", resolver.StaticAvailabilityProvider.all_available())
        self.assertEqual(decision.resolution_status, "out_of_contract")

    def test_eol_release_is_unsupported(self) -> None:
        # The support model, not the resolver, decides that an EOL/withdrawn
        # release is unsupported. This exercises that precedence directly.
        facts = StableReleaseFacts(
            has_adapter=True,
            meets_technical_floor=True,
            admitted=False,
            expressly_excluded=False,
            future_or_unevaluated=False,
            eol_or_withdrawn=True,
            vendor_maintained=True,
            ci_green=True,
            is_derivative=False,
            has_own_evidence=True,
            family_inference_allowed=False,
            has_valid_field_certification=False,
            family_has_certified_anchor=True,
        )
        self.assertEqual(classify_support_stable(facts).value, "unsupported")


class NegativeArchitectureTests(unittest.TestCase):
    def test_unsupported_architecture_yields_no_safe_route(self) -> None:
        m = manifest()
        os_release = detection.parse_os_release_text("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        facts = detection.distro_facts_from_os_release(
            os_release,
            m,
            kernel_release="6.8.0-test",
            machine_architecture="riscv64",
        )
        self.assertEqual(facts.machine_architecture, "riscv64")
        decision = resolve_dependency(m, facts, "dep_python_runtime", resolver.StaticAvailabilityProvider.all_available())
        self.assertEqual(decision.resolution_status, "no_safe_route")
        self.assertTrue(
            any(r.reason == "architecture_not_supported" for r in decision.rejected_candidates),
            "expected architecture_not_supported rejection among %s" % [r.reason for r in decision.rejected_candidates],
        )


class NegativeAggregateTests(unittest.TestCase):
    def test_one_unavailable_package_fails_aggregate(self) -> None:
        from tests import test_compat_dependency_l2_real as l2
        statuses = [{"status": "available"}, {"status": "unavailable"}]
        self.assertEqual(l2.aggregate_package_status(statuses), "unavailable")


class NegativeRecipeStatusTests(unittest.TestCase):
    def test_unimplemented_official_package_is_recipe_not_implemented(self) -> None:
        m = manifest()
        facts = distro(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        provider = resolver.StaticAvailabilityProvider.all_available()
        decision = resolve_dependency(m, facts, "dep_base_runtime_commands", provider)
        self.assertEqual(decision.resolution_status, "recipe_not_implemented")
        self.assertFalse(decision.execution_ready)
        self.assertEqual(decision.selected_method_kind, "official_package_exact")

    def test_implemented_source_build_is_method_selected(self) -> None:
        m = manifest()
        facts = distro(m, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
        provider = resolver.StaticAvailabilityProvider(
            {
                ("repository_supports_exact_target", "amneziawg_ubuntu_ppa_exact", "ubuntu_24_04", None):
                    resolver.AvailabilityStatus.UNAVAILABLE.value,
            },
            default_status=resolver.AvailabilityStatus.AVAILABLE.value,
        )
        decision = resolve_dependency(m, facts, "dep_amneziawg_runtime", provider)
        # The source-build candidate is implemented and should be selected once PPA candidates are rejected.
        self.assertEqual(decision.resolution_status, "method_selected")
        self.assertTrue(decision.execution_ready)
        self.assertEqual(decision.selected_method_kind, "pinned_source_build")


if __name__ == "__main__":
    unittest.main()
