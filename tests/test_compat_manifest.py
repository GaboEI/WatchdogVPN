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
                "technical_family": "mini_apt",
                "release_model": "rolling",
                "policy": {
                    "inherits_family_support": False,
                    "rolling": {
                        "meets_technical_floor": True,
                        "expressly_excluded": False,
                        "eol_or_withdrawn": False,
                        "is_derivative_without_own_evidence": False,
                        "has_valid_field_certification": False,
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
                "policy_state": "admitted",
                "evidence_refs": ["cert_mini_1"],
                "stable_facts": stable_facts(admitted=True, has_valid_field_certification=True),
            },
            "mini_2": {
                "distribution": "mini",
                "version": "2",
                "policy_state": "pending_evaluation",
                "evidence_refs": [],
                "stable_facts": stable_facts(future_or_unevaluated=True),
            },
        },
        "derivatives": {},
        "capabilities": {
            "core_host_capabilities": {
                "cap_systemd": {"type": "required", "description": "systemd"}
            },
            "protocol_capabilities": {
                "proto_runtime": {"type": "provisionable", "description": "runtime"}
            },
        },
        "provisioning_methods": {
            "apt_official_package": {
                "kind": "official_package",
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
                "protocols_included": ["mini_proto"],
                "current": True,
            }
        },
        "validation_metadata": {
            "rolling_policies": {
                "default": {"expiry_seconds": 2592000, "evidence_refs": []},
                "miniroll": {
                    "expiry_seconds": 2592000,
                    "last_validated": "2026-07-26T00:00:00Z",
                    "evidence_refs": [],
                },
            },
            "ci_status": {"mini_1": True},
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
            manifest["derivatives"]["linuxmint_ubuntu_codename"]["codename_map"]["zena"],
            "ubuntu_24_04",
        )
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
            release = manifest["releases"][release_id]
            facts = StableReleaseFacts(**release["stable_facts"])
            result = classify_support_stable(facts)
            self.assertIsInstance(result, SupportClassification)
        ubuntu = StableReleaseFacts(**manifest["releases"]["ubuntu_24_04"]["stable_facts"])
        ubuntu_26 = StableReleaseFacts(**manifest["releases"]["ubuntu_26_04"]["stable_facts"])
        alma = StableReleaseFacts(**manifest["releases"]["almalinux_9"]["stable_facts"])
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

    def test_strict_boolean_and_integer_types(self) -> None:
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["stable_facts"]["admitted"] = "true"
        self.assert_invalid(manifest, "boolean")
        manifest = self.product_copy()
        manifest["releases"]["ubuntu_24_04"]["stable_facts"]["admitted"] = 1
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

    def test_derivative_cycles_and_ambiguous_or_borrowed_mapping_rejected(self) -> None:
        manifest = self.product_copy()
        manifest["derivatives"]["opensuse_tumbleweed_lineage"]["lineage_distribution"] = "opensuse_tumbleweed"
        self.assert_invalid(manifest, "cycle")
        manifest = self.product_copy()
        manifest["derivatives"]["linuxmint_ubuntu_codename"]["codename_map"]["zena"] = "debian_13"
        self.assert_invalid(manifest, "outside lineage")
        manifest = self.product_copy()
        manifest["derivatives"]["kali_lineage"]["base_version"] = "13"
        self.assert_invalid(manifest, "must not borrow")

    def test_stable_and_rolling_policy_errors(self) -> None:
        manifest = self.product_copy()
        del manifest["distributions"]["ubuntu"]["policy"]["stable"]
        self.assert_invalid(manifest, "policy.stable")
        manifest = self.product_copy()
        manifest["distributions"]["ubuntu"]["policy"]["stable"]["minimum_version"] = "22.04"
        self.assert_invalid(manifest, "continuous range")
        manifest = self.product_copy()
        manifest["distributions"]["arch"]["policy"]["rolling"]["minimum_version"] = "1"
        self.assert_invalid(manifest, "numeric minimum")

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
        source = TOOL.read_text(encoding="utf-8")
        ast.parse(source, filename=str(TOOL), feature_version=(3, 6))


if __name__ == "__main__":
    unittest.main()
