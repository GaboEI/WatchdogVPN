"""L1 tests for the Phase 23.7.5.3 compatibility manifest and bootstrap reader."""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

from compat import (
    RollingFacts,
    StableReleaseFacts,
    SupportClassification,
    classify_support_rolling,
    classify_support_stable,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "compat_read.py"
PRODUCT_MANIFEST = ROOT / "compat" / "compatibility.json"

spec = importlib.util.spec_from_file_location("compat_read_bootstrap", TOOL)
compat_read = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(compat_read)


def load_product() -> dict:
    return compat_read.load_manifest_file(str(PRODUCT_MANIFEST), product_path=True)


def write_json_tmp(value) -> str:
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    with handle:
        json.dump(value, handle, sort_keys=True)
    return handle.name


def write_text_tmp(text: str, mode: str = "w") -> str:
    kwargs = {} if "b" in mode else {"encoding": "utf-8"}
    handle = tempfile.NamedTemporaryFile(mode, delete=False, **kwargs)
    with handle:
        handle.write(text)
    return handle.name


def minimal_manifest() -> dict:
    return {
        "schema_version": "1.0.0",
        "technical_families": {
            "mini_apt": {
                "adapter": "mini",
                "package_manager": "apt",
                "common_features": ["systemd"],
                "core_capabilities": ["cap_systemd"],
                "provisioning_methods": ["apt_official_package"],
            }
        },
        "distributions": {
            "mini": {
                "id": "mini",
                "lineage": {
                    "is_derivative": False,
                    "has_own_evidence": True,
                    "family_inference_allowed": False,
                },
                "technical_family": "mini_apt",
                "release_model": "stable",
                "policy": {
                    "inherits_family_support": False,
                    "stable": {
                        "admitted_releases": ["mini_1"],
                        "pending_releases": ["mini_2"],
                        "excluded_releases": [],
                    },
                },
            },
            "miniroll": {
                "id": "miniroll",
                "lineage": {
                    "is_derivative": False,
                    "has_own_evidence": True,
                    "family_inference_allowed": False,
                },
                "technical_family": "mini_apt",
                "release_model": "rolling",
                "policy": {
                    "inherits_family_support": False,
                    "rolling": {
                        "meets_technical_floor": True,
                        "expressly_excluded": False,
                        "eol_or_withdrawn": False,
                        "last_validated": "2026-07-26T00:00:00Z",
                        "evidence_expiry_seconds": 2592000,
                    },
                },
            },
        },
        "releases": {
            "mini_1": {
                "distribution": "mini",
                "version": "1",
                "os_release_version_ids": ["1"],
                "policy_state": "admitted",
                "evidence_refs": ["cert_mini_1"],
                "meets_technical_floor": True,
                "vendor_maintained": True,
                "eol_or_withdrawn": False,
            },
            "mini_2": {
                "distribution": "mini",
                "version": "2",
                "os_release_version_ids": ["2"],
                "policy_state": "pending_evaluation",
                "evidence_refs": [],
                "meets_technical_floor": True,
                "vendor_maintained": True,
                "eol_or_withdrawn": False,
            },
        },
        "derivatives": {},
        "capabilities": {
            "core_host_capabilities": {
                "cap_systemd": {"type": "required", "description": "systemd"},
                "cap_architecture": {
                    "type": "required",
                    "description": "architecture",
                    "supported_values": ["x86_64"],
                },
            },
            "protocol_capabilities": {
                "proto_runtime": {"type": "provisionable", "description": "runtime"}
            },
        },
        "dependency_requirements": {
            "dep_runtime": {
                "capability_id": "proto_runtime",
                "description": "fixture runtime",
                "method_chain": [
                    {
                        "id": "runtime_apt_official",
                        "priority": 10,
                        "kind": "official_package_exact",
                        "method_ref": "apt_official_package",
                        "target_identity": "resolved_release",
                        "target_scope": {
                            "technical_families": ["mini_apt"],
                            "stable_releases": ["mini_1", "mini_2"],
                            "rolling_distributions": ["miniroll"],
                        },
                        "architectures": ["x86_64"],
                        "package_manager": "apt",
                        "package_names": ["mini-runtime"],
                        "implementation_status": "not_implemented",
                        "postcondition": "proto_runtime",
                        "evidence": ["fixture package catalog"],
                    }
                ],
            }
        },
        "provisioning_methods": {
            "apt_official_package": {
                "kind": "official_package_exact",
                "exact_release_required": True,
                "mutates_system": True,
                "provenance": "official apt",
            }
        },
        "protocols": {
            "mini_proto": {
                "category": "resilient",
                "required_protocol_capabilities": ["proto_runtime"],
                "evidence_policy": "real traffic",
            }
        },
        "certifications": {
            "cert_mini_1": {
                "distribution": "mini",
                "release": "mini_1",
                "date": "2026-07-26T00:00:00Z",
                "scope": "physical_field_certification",
                "evidence": "private evidence",
                "protocol_results": {
                    "mini_proto": {
                        "disposition": "green",
                        "evidence": "real traffic",
                    }
                },
                "current": True,
            },
            "cert_miniroll": {
                "distribution": "miniroll",
                "snapshot": "miniroll-2026-07-26",
                "date": "2026-07-26T00:00:00Z",
                "scope": "physical_field_certification",
                "evidence": "private rolling evidence",
                "protocol_results": {
                    "mini_proto": {
                        "disposition": "green",
                        "evidence": "real traffic",
                    }
                },
                "current": True,
            }
        },
        "validation_metadata": {
            "rolling_policies": {
                "default": {"expiry_seconds": 2592000, "evidence_refs": []},
                "miniroll": {
                    "expiry_seconds": 2592000,
                    "last_validated": "2026-07-26T00:00:00Z",
                    "evidence_refs": ["cert_miniroll"],
                },
            },
            "repository_ci": {
                "latest_known_green": True,
                "scope": "general repo CI",
                "evidence": "test fixture",
            },
            "per_release_ci": {
                "mini_1": {"status": "not_run", "l1_l2_green": False, "evidence": None},
                "mini_2": {"status": "not_run", "l1_l2_green": False, "evidence": None},
            },
            "doc_generation": {
                "public_claims_generated": False,
                "reason": "fixture",
            },
        },
    }


def stable_facts(**overrides) -> dict:
    facts = {
        "has_adapter": True,
        "meets_technical_floor": True,
        "admitted": False,
        "expressly_excluded": False,
        "future_or_unevaluated": False,
        "eol_or_withdrawn": False,
        "vendor_maintained": True,
        "ci_green": True,
        "is_derivative_without_own_evidence": False,
        "has_valid_field_certification": False,
        "family_has_certified_anchor": True,
    }
    facts.update(overrides)
    return facts


class ManifestValidCasesTests(unittest.TestCase):
    def test_minimal_manifest_validates(self) -> None:
        manifest = minimal_manifest()
        self.assertTrue(compat_read.validate_manifest(manifest))

    def test_product_manifest_validates_and_has_required_sections(self) -> None:
        manifest = load_product()
        self.assertTrue(compat_read.validate_manifest(manifest))
        for key in (
            "schema_version",
            "technical_families",
            "distributions",
            "releases",
            "derivatives",
            "capabilities",
            "dependency_requirements",
            "provisioning_methods",
            "protocols",
            "certifications",
            "validation_metadata",
        ):
            self.assertIn(key, manifest)

    def test_product_has_valid_cross_references_and_expected_examples(self) -> None:
        manifest = load_product()
        self.assertIn("ubuntu_24_04", manifest["distributions"]["ubuntu"]["policy"]["stable"]["admitted_releases"])
        self.assertIn("ubuntu_26_04", manifest["distributions"]["ubuntu"]["policy"]["stable"]["pending_releases"])
        self.assertEqual(
            manifest["derivatives"]["linuxmint_ubuntu_codename"]["mapping_source"],
            "ubuntu_codename",
        )
        self.assertEqual(
            manifest["derivatives"]["linuxmint_ubuntu_codename"]["codename_map"]["noble"],
            "ubuntu_24_04",
        )
        self.assertEqual(manifest["releases"]["ubuntu_24_04"]["os_release_version_ids"], ["24.04"])
        self.assertEqual(manifest["releases"]["debian_13"]["os_release_version_ids"], ["13"])
        self.assertEqual(manifest["releases"]["linuxmint_22_3"]["os_release_version_ids"], ["22.3"])
        self.assertIn("cap_firewalld", manifest["technical_families"]["redhat_dnf"]["core_capabilities"])
        self.assertIn("cap_firewalld", manifest["technical_families"]["suse_zypper"]["core_capabilities"])
        self.assertIn("cap_apparmor", manifest["technical_families"]["debian_apt"]["core_capabilities"])
        self.assertIn("cap_apparmor", manifest["technical_families"]["ubuntu_apt"]["core_capabilities"])
        self.assertIn("cap_apparmor", manifest["technical_families"]["suse_zypper"]["core_capabilities"])
        self.assertNotIn("cap_firewalld", manifest["technical_families"]["ubuntu_apt"]["core_capabilities"])
        self.assertFalse(manifest["derivatives"]["kali_lineage"]["base_version_gating"])
        self.assertEqual(manifest["distributions"]["arch"]["release_model"], "rolling")
        self.assertTrue(manifest["certifications"]["cert_rocky_9"]["current"])

    def test_capabilities_are_separated(self) -> None:
        capabilities = load_product()["capabilities"]
        self.assertIn("cap_tun", capabilities["core_host_capabilities"])
        self.assertIn("proto_sing_box_runtime", capabilities["protocol_capabilities"])
        self.assertNotIn("proto_sing_box_runtime", capabilities["core_host_capabilities"])

    def test_support_model_facts_can_be_constructed_without_stored_classification(self) -> None:
        manifest = load_product()
        for release_id in ("ubuntu_24_04", "ubuntu_26_04", "almalinux_9"):
            facts = StableReleaseFacts(**compat_read._stable_facts(manifest, release_id)["facts"])
            result = classify_support_stable(facts)
            self.assertIsInstance(result, SupportClassification)
        ubuntu = StableReleaseFacts(**compat_read._stable_facts(manifest, "ubuntu_24_04")["facts"])
        ubuntu_26 = StableReleaseFacts(**compat_read._stable_facts(manifest, "ubuntu_26_04")["facts"])
        alma = StableReleaseFacts(**compat_read._stable_facts(manifest, "almalinux_9")["facts"])
        self.assertIs(classify_support_stable(ubuntu), SupportClassification.CERTIFIED)
        self.assertIs(classify_support_stable(ubuntu_26), SupportClassification.EXPERIMENTAL)
        self.assertIs(classify_support_stable(alma), SupportClassification.FAMILY_INFERRED)

    def test_rolling_facts_can_be_constructed_with_utc_normalization(self) -> None:
        manifest = load_product()
        data = compat_read._rolling_facts(manifest, "arch")
        normalized = data["facts"]["last_validated"]
        data["facts"]["last_validated"] = datetime.fromisoformat(normalized)
        facts = RollingFacts(**data["facts"])
        result = classify_support_rolling(
            facts,
            expiry=timedelta(seconds=data["expiry_seconds"]),
            now=datetime(2026, 7, 26, 0, 0, 0),
        )
        self.assertIs(result, SupportClassification.CERTIFIED)
        self.assertEqual(normalized, "2026-07-22T00:00:00")

    def test_product_classification_examples_are_derived(self) -> None:
        manifest = load_product()
        cases = {
            "kali": SupportClassification.EXPERIMENTAL,
            "arch": SupportClassification.CERTIFIED,
            "cachyos": SupportClassification.CERTIFIED,
            "opensuse_tumbleweed": SupportClassification.FAMILY_INFERRED,
        }
        for distro_id, expected in cases.items():
            data = compat_read._rolling_facts(manifest, distro_id)
            if data["facts"]["last_validated"] is not None:
                data["facts"]["last_validated"] = datetime.fromisoformat(data["facts"]["last_validated"])
            result = classify_support_rolling(
                RollingFacts(**data["facts"]),
                expiry=timedelta(seconds=data["expiry_seconds"]),
                now=datetime(2026, 7, 26, 0, 0, 0),
            )
            self.assertIs(result, expected, distro_id)
        alma = StableReleaseFacts(**compat_read._stable_facts(manifest, "almalinux_9")["facts"])
        self.assertIs(classify_support_stable(alma), SupportClassification.FAMILY_INFERRED)
        ubuntu_26 = StableReleaseFacts(**compat_read._stable_facts(manifest, "ubuntu_26_04")["facts"])
        self.assertIs(classify_support_stable(ubuntu_26), SupportClassification.EXPERIMENTAL)

    def test_product_certifications_all_qualify_with_exact_protocol_profile(self) -> None:
        manifest = load_product()
        self.assertEqual(len(manifest["certifications"]), 8)
        for cert_id, cert in manifest["certifications"].items():
            with self.subTest(cert_id=cert_id):
                self.assertTrue(compat_read.certification_qualifies_for_support(manifest, cert_id))
                counts = {}
                for result in cert["protocol_results"].values():
                    counts[result["disposition"]] = counts.get(result["disposition"], 0) + 1
                self.assertEqual(counts, {"green": 9, "formal_non_green": 3})
                self.assertEqual(
                    {
                        protocol_id
                        for protocol_id, result in cert["protocol_results"].items()
                        if result["disposition"] == "formal_non_green"
                    },
                    {"wireguard", "shadowsocks", "openvpn"},
                )

    def test_validated_manifest_can_emit_all_facts(self) -> None:
        manifest = load_product()
        compat_read.validate_manifest(manifest)
        for release_id in manifest["releases"]:
            data = compat_read._stable_facts(manifest, release_id)
            self.assertEqual(data["model"], "stable")
        for distro_id, distro in manifest["distributions"].items():
            if distro["release_model"] == "rolling":
                data = compat_read._rolling_facts(manifest, distro_id)
                self.assertEqual(data["model"], "rolling")

    def test_cli_validate_get_list_facts_are_deterministic_json(self) -> None:
        validate = subprocess.run(
            [sys.executable, str(TOOL), "validate"],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(validate.returncode, 0, validate.stderr)
        self.assertEqual(json.loads(validate.stdout), {"ok": True, "schema_version": "1.0.0"})

        listed = subprocess.run(
            [sys.executable, str(TOOL), "list", "technical_families"],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(json.loads(listed.stdout), sorted(json.loads(listed.stdout)))

        got = subprocess.run(
            [sys.executable, str(TOOL), "get", "releases.ubuntu_24_04.version"],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(json.loads(got.stdout), "24.04.4")

        facts = subprocess.run(
            [sys.executable, str(TOOL), "facts", "stable-release", "ubuntu_24_04"],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(facts.returncode, 0, facts.stderr)
        self.assertEqual(json.loads(facts.stdout)["model"], "stable")


class ManifestInvalidCasesTests(unittest.TestCase):
    def assert_invalid(self, manifest_or_text, fragment: str | None = None) -> None:
        if isinstance(manifest_or_text, str):
            with self.assertRaises(compat_read.ManifestError) as ctx:
                compat_read._load_json_text(manifest_or_text)
        else:
            with self.assertRaises(compat_read.ManifestError) as ctx:
                compat_read.validate_manifest(manifest_or_text)
        if fragment is not None:
            self.assertIn(fragment, str(ctx.exception))

    def product_copy(self) -> dict:
        return copy.deepcopy(load_product())

    def assert_cli_invalid(self, manifest: dict, fragment: str | None = None) -> None:
        path = write_json_tmp(manifest)
        try:
            result = subprocess.run(
                [sys.executable, str(TOOL), "--manifest", path, "validate"],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        finally:
            os.unlink(path)
        self.assertEqual(result.returncode, compat_read.EXIT_INVALID_MANIFEST, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("compatibility manifest invalid:", result.stderr)
        if fragment is not None:
            self.assertIn(fragment, result.stderr)

    def test_invalid_json_malformed_duplicate_trailing_nonfinite_and_top_type(self) -> None:
        self.assert_invalid("{", "invalid JSON")
        self.assert_invalid('{"schema_version":"1.0.0","schema_version":"1.0.1"}', "duplicate JSON key")
        self.assert_invalid('{"schema_version":"1.0.0"} trailing', "invalid JSON")
        self.assert_invalid('{"schema_version":NaN}', "non-finite")
        self.assert_invalid("[]", "top level")

    def test_unknown_schema_major_and_missing_section(self) -> None:
        manifest = self.product_copy()
        manifest["schema_version"] = "2.0.0"
        self.assert_invalid(manifest, "unsupported schema major")
        manifest = self.product_copy()
        del manifest["technical_families"]
        self.assert_invalid(manifest, "missing required")

    def test_documentation_schema_matches_reader_top_level(self) -> None:
        manifest = self.product_copy()
        schema_path = ROOT / "compat" / "compatibility.schema.json"
        schema = compat_read.load_manifest_file(str(schema_path))
        self.assertEqual(set(schema["properties"]), set(compat_read._TOP_LEVEL_SCHEMA_PROPERTIES))
        self.assertEqual(set(schema["required"]), set(compat_read._REQUIRED_TOP_LEVEL))
        manifest["unexpected"] = {}
        self.assert_invalid(manifest, "unknown top-level")

    def test_strict_boolean_and_integer_types(self) -> None:
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["vendor_maintained"] = "true"
        self.assert_invalid(manifest, "boolean")
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["vendor_maintained"] = 1
        self.assert_invalid(manifest, "boolean")
        manifest = self.product_copy()
        manifest["validation_metadata"]["rolling_policies"]["default"]["expiry_seconds"] = True
        self.assert_invalid(manifest, "integer")

    def test_empty_or_invalid_id_and_duplicate_entity_id(self) -> None:
        manifest = self.product_copy()
        manifest["provisioning_methods"][""] = copy.deepcopy(manifest["provisioning_methods"]["apt_official_package"])
        self.assert_invalid(manifest, "must not be empty")
        manifest = self.product_copy()
        manifest["protocols"]["ubuntu"] = manifest["protocols"].pop("vless")
        self.assert_invalid(manifest, "reused")

    def test_references_and_release_ownership_are_strict(self) -> None:
        manifest = self.product_copy()
        manifest["distributions"]["ubuntu"]["technical_family"] = "missing"
        self.assert_invalid(manifest, "unknown technical family")
        manifest = self.product_copy()
        manifest["distributions"]["ubuntu"]["policy"]["stable"]["admitted_releases"] = ["debian_13"]
        self.assert_invalid(manifest, "owned by debian")
        manifest = self.product_copy()
        manifest["certifications"]["cert_ubuntu_24_04"]["release"] = "debian_13"
        self.assert_invalid(manifest, "does not belong")
        manifest = self.product_copy()
        manifest["protocols"]["vless"]["required_protocol_capabilities"] = ["missing_cap"]
        self.assert_invalid(manifest, "unknown protocol capability")

    def test_structural_corruption_is_manifest_error_and_cli_exit_2(self) -> None:
        mutations = [
            ("release_distribution", lambda m: m["releases"]["ubuntu_24_04"].pop("distribution"), "distribution"),
            ("release_policy_state", lambda m: m["releases"]["ubuntu_24_04"].pop("policy_state"), "policy_state"),
            ("release_floor", lambda m: m["releases"]["ubuntu_24_04"].pop("meets_technical_floor"), "meets_technical_floor"),
            ("distribution_release_model", lambda m: m["distributions"]["ubuntu"].pop("release_model"), "release_model"),
            ("protocol_category", lambda m: m["protocols"]["vless"].pop("category"), "category"),
            ("cert_distribution", lambda m: m["certifications"]["cert_ubuntu_24_04"].pop("distribution"), "distribution"),
            ("cert_release", lambda m: m["certifications"]["cert_ubuntu_24_04"].pop("release"), "exactly one"),
            ("cert_protocol_results", lambda m: m["certifications"]["cert_ubuntu_24_04"].pop("protocol_results"), "protocol_results"),
            ("release_distribution_wrong_type", lambda m: m["releases"]["ubuntu_24_04"].__setitem__("distribution", []), "string"),
            ("protocol_category_wrong_type", lambda m: m["protocols"]["vless"].__setitem__("category", True), "string"),
        ]
        for label, mutate, fragment in mutations:
            with self.subTest(label=label):
                manifest = self.product_copy()
                mutate(manifest)
                with self.assertRaises(compat_read.ManifestError):
                    compat_read.validate_manifest(manifest)
                self.assert_cli_invalid(manifest, fragment)

    def test_policy_and_derived_fact_contradictions_are_rejected(self) -> None:
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["policy_state"] = "pending_evaluation"
        self.assert_invalid(manifest, "not admitted")
        manifest = self.product_copy()
        manifest["distributions"]["ubuntu"]["policy"]["stable"]["admitted_releases"].remove("ubuntu_24_04")
        manifest["distributions"]["ubuntu"]["policy"]["stable"]["pending_releases"].append("ubuntu_24_04")
        self.assert_invalid(manifest, "not in admitted_releases")
        manifest = self.product_copy()
        manifest["validation_metadata"]["per_release_ci"]["ubuntu_24_04"]["status"] = "green"
        manifest["validation_metadata"]["per_release_ci"]["ubuntu_24_04"]["l1_l2_green"] = False
        self.assert_invalid(manifest, "green status requires")

    def test_certification_evidence_must_match_facts_and_release_refs(self) -> None:
        manifest = self.product_copy()
        manifest["certifications"]["cert_ubuntu_24_04"]["current"] = False
        self.assert_invalid(manifest, "evidence_refs must equal current certifications")
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["evidence_refs"] = []
        self.assert_invalid(manifest, "evidence_refs must equal current certifications")
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_26_04"]["evidence_refs"] = ["cert_ubuntu_24_04"]
        self.assert_invalid(manifest, "evidence_refs must equal current certifications")

    def test_stable_certification_requires_eligible_release_policy(self) -> None:
        manifest = self.product_copy()
        cert = copy.deepcopy(manifest["certifications"]["cert_ubuntu_24_04"])
        cert["release"] = "ubuntu_26_04"
        manifest["certifications"]["cert_ubuntu_26_04"] = cert
        manifest["releases"]["ubuntu_26_04"]["evidence_refs"] = ["cert_ubuntu_26_04"]
        self.assert_invalid(manifest, "not admitted")

        manifest = self.product_copy()
        release = manifest["releases"]["ubuntu_24_04"]
        release["policy_state"] = "excluded"
        distro_policy = manifest["distributions"]["ubuntu"]["policy"]["stable"]
        distro_policy["admitted_releases"].remove("ubuntu_24_04")
        distro_policy["excluded_releases"].append("ubuntu_24_04")
        self.assert_invalid(manifest, "not admitted")

        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["eol_or_withdrawn"] = True
        self.assert_invalid(manifest, "EOL or withdrawn")

        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["vendor_maintained"] = False
        self.assert_invalid(manifest, "not vendor maintained")

        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["meets_technical_floor"] = False
        self.assert_invalid(manifest, "below the technical floor")

    def test_rolling_certification_requires_eligible_distribution_policy(self) -> None:
        manifest = self.product_copy()
        manifest["distributions"]["arch"]["policy"]["rolling"]["expressly_excluded"] = True
        self.assert_invalid(manifest, "expressly excluded")

        manifest = self.product_copy()
        manifest["distributions"]["arch"]["policy"]["rolling"]["eol_or_withdrawn"] = True
        self.assert_invalid(manifest, "EOL or withdrawn")

        manifest = self.product_copy()
        manifest["distributions"]["arch"]["policy"]["rolling"]["meets_technical_floor"] = False
        self.assert_invalid(manifest, "below the technical floor")

    def test_family_anchor_requires_current_family_certification(self) -> None:
        manifest = self.product_copy()
        for cert_id, cert in manifest["certifications"].items():
            if manifest["distributions"][cert["distribution"]]["technical_family"] == "redhat_dnf":
                cert["current"] = False
        facts = compat_read._stable_facts(manifest, "almalinux_9")["facts"]
        self.assertFalse(facts["family_has_certified_anchor"])
        self.assertIs(
            classify_support_stable(StableReleaseFacts(**facts)),
            SupportClassification.EXPERIMENTAL,
        )

    def test_family_inference_requires_qualifying_anchor(self) -> None:
        manifest = self.product_copy()
        alma = StableReleaseFacts(**compat_read._stable_facts(manifest, "almalinux_9")["facts"])
        self.assertIs(classify_support_stable(alma), SupportClassification.FAMILY_INFERRED)
        tumbleweed_data = compat_read._rolling_facts(manifest, "opensuse_tumbleweed")
        tumbleweed = RollingFacts(**tumbleweed_data["facts"])
        self.assertIs(
            classify_support_rolling(
                tumbleweed,
                expiry=timedelta(seconds=tumbleweed_data["expiry_seconds"]),
                now=datetime(2026, 7, 26, 0, 0, 0),
            ),
            SupportClassification.FAMILY_INFERRED,
        )

        for cert in manifest["certifications"].values():
            if manifest["distributions"][cert["distribution"]]["technical_family"] == "redhat_dnf":
                cert["current"] = False
        alma = StableReleaseFacts(**compat_read._stable_facts(manifest, "almalinux_9")["facts"])
        self.assertIs(classify_support_stable(alma), SupportClassification.EXPERIMENTAL)

        manifest = self.product_copy()
        manifest["certifications"]["cert_opensuse_leap_15_6"]["protocol_results"]["vless"]["disposition"] = "failed"
        with self.assertRaises(compat_read.ManifestError):
            compat_read.validate_manifest(manifest)

        manifest = self.product_copy()
        manifest["certifications"]["cert_opensuse_leap_15_6"]["current"] = False
        manifest["releases"]["opensuse_leap_15_6"]["evidence_refs"] = []
        tumbleweed_data = compat_read._rolling_facts(manifest, "opensuse_tumbleweed")
        tumbleweed = RollingFacts(**tumbleweed_data["facts"])
        self.assertFalse(tumbleweed.family_has_certified_anchor)
        self.assertIs(
            classify_support_rolling(
                tumbleweed,
                expiry=timedelta(seconds=tumbleweed_data["expiry_seconds"]),
                now=datetime(2026, 7, 26, 0, 0, 0),
            ),
            SupportClassification.EXPERIMENTAL,
        )

    def test_derivative_cycles_and_ambiguous_or_borrowed_mapping_rejected(self) -> None:
        manifest = self.product_copy()
        manifest["derivatives"]["opensuse_tumbleweed_lineage"]["lineage_distribution"] = "opensuse_tumbleweed"
        self.assert_invalid(manifest, "cycle")
        manifest = self.product_copy()
        manifest["derivatives"]["linuxmint_ubuntu_codename"]["codename_map"]["noble"] = "debian_13"
        self.assert_invalid(manifest, "outside lineage")
        manifest = self.product_copy()
        manifest["derivatives"]["kali_lineage"]["base_version"] = "13"
        self.assert_invalid(manifest, "unknown key base_version")
        manifest = self.product_copy()
        del manifest["derivatives"]["linuxmint_ubuntu_codename"]["mapping_source"]
        self.assert_invalid(manifest, "mapping_source")
        manifest = self.product_copy()
        manifest["derivatives"]["linuxmint_ubuntu_codename"]["mapping_source"] = "pretty_name"
        self.assert_invalid(manifest, "mapping_source")

    def test_stable_and_rolling_policy_errors(self) -> None:
        manifest = self.product_copy()
        del manifest["distributions"]["ubuntu"]["policy"]["stable"]
        self.assert_invalid(manifest, "policy.stable")
        manifest = self.product_copy()
        manifest["distributions"]["ubuntu"]["policy"]["stable"]["minimum_version"] = "22.04"
        self.assert_invalid(manifest, "unknown key minimum_version")
        manifest = self.product_copy()
        manifest["distributions"]["arch"]["policy"]["rolling"]["minimum_version"] = "1"
        self.assert_invalid(manifest, "unknown key minimum_version")
        manifest = self.product_copy()
        del manifest["distributions"]["arch"]["policy"]["rolling"]["meets_technical_floor"]
        self.assert_invalid(manifest, "meets_technical_floor")
        manifest = self.product_copy()
        manifest["validation_metadata"]["rolling_policies"]["default"]["expiry_seconds"] = None
        self.assert_invalid(manifest, "integer")
        manifest = self.product_copy()
        manifest["validation_metadata"]["rolling_policies"]["rocky"] = {"expiry_seconds": 10, "evidence_refs": []}
        self.assert_invalid(manifest, "rolling distribution")
        manifest = self.product_copy()
        manifest["validation_metadata"]["rolling_policies"]["arch"]["expiry_seconds"] = 60
        self.assert_invalid(manifest, "expiry diverges")
        manifest = self.product_copy()
        manifest["validation_metadata"]["rolling_policies"]["arch"]["last_validated"] = None
        self.assert_invalid(manifest, "diverges")

    def test_timestamp_and_expiry_errors(self) -> None:
        manifest = self.product_copy()
        manifest["validation_metadata"]["rolling_policies"]["arch"]["last_validated"] = "2026-07-22T00:00:00+00:00"
        self.assert_invalid(manifest, "trailing Z")
        manifest = self.product_copy()
        manifest["validation_metadata"]["rolling_policies"]["arch"]["last_validated"] = "2026-02-31T00:00:00Z"
        self.assert_invalid(manifest, "not a real")
        manifest = self.product_copy()
        manifest["validation_metadata"]["rolling_policies"]["default"]["expiry_seconds"] = 0
        self.assert_invalid(manifest, "positive")
        manifest = self.product_copy()
        manifest["validation_metadata"]["rolling_policies"]["default"]["expiry_seconds"] = -1
        self.assert_invalid(manifest, "positive")

    def test_protocol_certification_and_calculated_state_errors(self) -> None:
        manifest = self.product_copy()
        manifest["protocols"]["vless"]["required_protocol_capabilities"] = []
        self.assert_invalid(manifest, "must not be empty")
        manifest = self.product_copy()
        manifest["certifications"]["cert_ubuntu_24_04"]["evidence"] = ""
        self.assert_invalid(manifest, "must not be empty")
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["support_classification"] = "unsupported"
        self.assert_invalid(manifest, "calculated state")
        manifest = self.product_copy()
        manifest["certifications"]["cert_ubuntu_24_04"]["release"] = "ubuntu_24_04"
        manifest["certifications"]["cert_ubuntu_24_04"]["snapshot"] = "bad"
        self.assert_invalid(manifest, "exactly one")
        manifest = self.product_copy()
        del manifest["certifications"]["cert_ubuntu_24_04"]["release"]
        manifest["certifications"]["cert_ubuntu_24_04"]["snapshot"] = "bad"
        self.assert_invalid(manifest, "stable distribution")
        manifest = self.product_copy()
        del manifest["certifications"]["cert_arch_rolling"]["snapshot"]
        manifest["certifications"]["cert_arch_rolling"]["release"] = "ubuntu_24_04"
        self.assert_invalid(manifest, "rolling distribution")
        manifest = self.product_copy()
        manifest["certifications"]["cert_ubuntu_24_04"]["protocol_results"]["vless"]["disposition"] = "maybe"
        self.assert_invalid(manifest, "must be one of")
        manifest = self.product_copy()
        cert = manifest["certifications"]["cert_ubuntu_24_04"]
        for result in cert["protocol_results"].values():
            result["disposition"] = "green"
        self.assert_invalid(manifest, "disposition green does not match required formal_non_green")
        manifest = self.product_copy()
        cert = manifest["certifications"]["cert_ubuntu_24_04"]
        cert["protocols_included"] = list(manifest["protocols"])
        self.assert_invalid(manifest, "unknown key protocols_included")

    def test_physical_certification_must_match_qualifying_profile(self) -> None:
        manifest = self.product_copy()
        cert = manifest["certifications"]["cert_ubuntu_24_04"]
        cert["protocol_results"] = {
            "vless": cert["protocol_results"]["vless"],
        }
        self.assert_invalid(manifest, "exactly all manifest protocols")

        manifest = self.product_copy()
        manifest["certifications"]["cert_ubuntu_24_04"]["protocol_results"]["vless"]["disposition"] = "failed"
        self.assert_invalid(manifest, "does not match required green")

        manifest = self.product_copy()
        manifest["certifications"]["cert_ubuntu_24_04"]["protocol_results"]["vless"]["disposition"] = "not_run"
        self.assert_invalid(manifest, "does not match required green")

        manifest = self.product_copy()
        manifest["certifications"]["cert_ubuntu_24_04"]["protocol_results"]["wireguard"]["disposition"] = "green"
        self.assert_invalid(manifest, "does not match required formal_non_green")

        manifest = self.product_copy()
        del manifest["certifications"]["cert_ubuntu_24_04"]["protocol_results"]["vless"]
        self.assert_invalid(manifest, "exactly all manifest protocols")

        manifest = self.product_copy()
        manifest["certifications"]["cert_ubuntu_24_04"]["scope"] = "partial_field_certification"
        self.assert_invalid(manifest, "must be one of")

        manifest = self.product_copy()
        manifest["certifications"]["cert_ubuntu_24_04"]["current"] = False
        self.assertFalse(compat_read.certification_qualifies_for_support(manifest, "cert_ubuntu_24_04"))
        self.assert_invalid(manifest, "evidence_refs must equal current certifications")

    def test_rolling_evidence_uses_only_qualifying_current_certifications(self) -> None:
        manifest = self.product_copy()
        self.assertTrue(compat_read.certification_qualifies_for_support(manifest, "cert_arch_rolling"))
        data = compat_read._rolling_facts(manifest, "arch")
        self.assertTrue(data["facts"]["has_valid_field_certification"])
        self.assertIs(
            classify_support_rolling(
                RollingFacts(**{**data["facts"], "last_validated": datetime.fromisoformat(data["facts"]["last_validated"])}),
                expiry=timedelta(seconds=data["expiry_seconds"]),
                now=datetime(2026, 7, 26, 0, 0, 0),
            ),
            SupportClassification.CERTIFIED,
        )

        manifest = self.product_copy()
        manifest["certifications"]["cert_arch_rolling"]["current"] = False
        self.assert_invalid(manifest, "non-qualifying certification")

        manifest = self.product_copy()
        manifest["certifications"]["cert_arch_rolling"]["protocol_results"]["vless"]["disposition"] = "failed"
        self.assert_invalid(manifest, "does not match required green")

        manifest = self.product_copy()
        del manifest["certifications"]["cert_arch_rolling"]["protocol_results"]["vless"]
        self.assert_invalid(manifest, "exactly all manifest protocols")

        manifest = self.product_copy()
        manifest["validation_metadata"]["rolling_policies"]["arch"]["last_validated"] = "2026-07-23T00:00:00Z"
        manifest["distributions"]["arch"]["policy"]["rolling"]["last_validated"] = "2026-07-23T00:00:00Z"
        self.assert_invalid(manifest, "latest qualifying certification date")

        manifest = self.product_copy()
        manifest["certifications"]["cert_arch_rolling"]["current"] = False
        manifest["validation_metadata"]["rolling_policies"]["arch"]["evidence_refs"] = []
        manifest["validation_metadata"]["rolling_policies"]["arch"]["last_validated"] = "2026-07-22T00:00:00Z"
        manifest["distributions"]["arch"]["policy"]["rolling"]["last_validated"] = "2026-07-22T00:00:00Z"
        self.assert_invalid(manifest, "without qualifying certification")

    def test_unknown_keys_inside_each_entity_type_are_rejected(self) -> None:
        mutations = [
            ("technical_families", "ubuntu_apt"),
            ("distributions", "ubuntu"),
            ("releases", "ubuntu_24_04"),
            ("derivatives", "linuxmint_ubuntu_codename"),
            ("provisioning_methods", "apt_official_package"),
            ("protocols", "vless"),
            ("certifications", "cert_ubuntu_24_04"),
        ]
        for section, entity_id in mutations:
            with self.subTest(section=section):
                manifest = self.product_copy()
                manifest[section][entity_id]["unexpected"] = True
                self.assert_invalid(manifest, "unknown key")
        manifest = self.product_copy()
        manifest["capabilities"]["core_host_capabilities"]["cap_tun"]["unexpected"] = True
        self.assert_invalid(manifest, "unknown key")
        manifest = self.product_copy()
        manifest["validation_metadata"]["repository_ci"]["unexpected"] = True
        self.assert_invalid(manifest, "unknown key")

    def test_architecture_supported_values_are_required_and_strict(self) -> None:
        manifest = self.product_copy()
        self.assertEqual(
            manifest["capabilities"]["core_host_capabilities"]["cap_architecture"]["supported_values"],
            ["x86_64", "aarch64"],
        )
        manifest = self.product_copy()
        manifest["capabilities"]["core_host_capabilities"]["cap_architecture"]["supported_values"] = []
        self.assert_invalid(manifest, "must not be empty")
        manifest = self.product_copy()
        manifest["capabilities"]["core_host_capabilities"]["cap_architecture"]["supported_values"] = "x86_64"
        self.assert_invalid(manifest, "must be a list")
        manifest = self.product_copy()
        manifest["capabilities"]["core_host_capabilities"]["cap_tun"]["supported_values"] = ["x86_64"]
        self.assert_invalid(manifest, "only valid for cap_architecture")

    def test_release_os_release_version_ids_are_required_exact_and_unique(self) -> None:
        manifest = self.product_copy()
        del manifest["releases"]["ubuntu_24_04"]["os_release_version_ids"]
        self.assert_invalid(manifest, "os_release_version_ids")
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["os_release_version_ids"] = []
        self.assert_invalid(manifest, "must not be empty")
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["os_release_version_ids"] = ["24.04", "24.04"]
        self.assert_invalid(manifest, "duplicate")
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_26_04"]["os_release_version_ids"] = ["24.04"]
        self.assert_invalid(manifest, "also used by release")

    def test_release_codenames_are_valid_and_unique_within_distribution(self) -> None:
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_26_04"]["codename"] = "noble"
        self.assert_invalid(manifest, "codename")
        manifest = self.product_copy()
        manifest["releases"]["linuxmint_22_3"]["codename"] = "noble"
        compat_read.validate_manifest(manifest)
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["codename"] = ""
        self.assert_invalid(manifest, "codename")
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["codename"] = 24
        self.assert_invalid(manifest, "codename")

    def test_file_size_limit_utf8_and_symlink_product_path(self) -> None:
        too_large = tempfile.NamedTemporaryFile(delete=False)
        try:
            too_large.write(b" " * (compat_read.MAX_MANIFEST_BYTES + 1))
            too_large.close()
            with self.assertRaises(compat_read.ManifestError):
                compat_read.load_manifest_file(too_large.name)
        finally:
            os.unlink(too_large.name)

        invalid_utf8 = write_text_tmp(b"\xff", mode="wb")
        try:
            with self.assertRaises(compat_read.ManifestError):
                compat_read.load_manifest_file(invalid_utf8)
        finally:
            os.unlink(invalid_utf8)

        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = pathlib.Path(tmp) / "compatibility.json"
            link.symlink_to(target)
            with self.assertRaises(compat_read.ManifestError):
                compat_read.load_manifest_file(str(link), product_path=True)

    def test_missing_query_has_distinct_exit_code(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "get", "releases.nope"],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, compat_read.EXIT_NOT_FOUND)
        self.assertIn("query not found", result.stderr)


class BootstrapCompatibilityTests(unittest.TestCase):
    def test_bootstrap_reader_does_not_import_modern_compat_package(self) -> None:
        tree = ast.parse(TOOL.read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        self.assertNotIn("compat", imported)
        self.assertNotIn("compat.support_model", imported)

    def test_bootstrap_reader_parses_as_python_36(self) -> None:
        reader_text = TOOL.read_text(encoding="utf-8")
        ast.parse(reader_text, filename=str(TOOL), feature_version=(3, 6))


if __name__ == "__main__":
    unittest.main()
