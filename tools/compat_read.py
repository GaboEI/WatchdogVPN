#!/usr/bin/env python3
"""Bootstrap reader and strict validator for the compatibility manifest.

This script is intentionally stdlib-only. Python 3.6 syntax target: verified.
Python 3.6 runtime execution: not yet independently verified. It must not import
``compat`` or any product module that may require the final runtime Python floor;
installers need this reader before that runtime is prepared.
"""

from __future__ import print_function

import argparse
import json
import os
import re
import sys
from datetime import datetime


SUPPORTED_SCHEMA_MAJOR = 1
BOOTSTRAP_PYTHON_MIN = "3.6"
MAX_MANIFEST_BYTES = 1024 * 1024

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MANIFEST_PATH = os.path.join(ROOT, "compat", "compatibility.json")

EXIT_USAGE = 1
EXIT_INVALID_MANIFEST = 2
EXIT_NOT_FOUND = 3

_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(?:-[a-z0-9_]+)*$")
_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:-]*$")
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_GIT_COMMIT_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
_HTTPS_URL_RE = re.compile(r"^https://[^/@\s]+(?:[/:?#][^\s]*)?$")
_SAFE_RELATIVE_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+:-]*$")
_KEYID_SUBSTRING_RE = re.compile(r"\bkeyid\s+[A-Fa-f0-9]{8,40}\b")
_FINGERPRINT_SUBSTRING_RE = re.compile(r"\bfingerprint\s+([A-Fa-f0-9][A-Fa-f0-9 ]{38,}[A-Fa-f0-9])\b")
_SIGNING_KEY_SOURCE_RE = re.compile(r"\b(?:fedoraproject\.org/security|keyserver\.ubuntu\.com)\b")
_VERSION_RE = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)$")
_RFC3339_UTC_RE = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})Z$"
)

_REQUIRED_TOP_LEVEL = (
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
)
_OPTIONAL_TOP_LEVEL = ("metadata",)

_CALCULATED_STATE_KEYS = (
    "support_classification",
    "host_readiness",
    "protocol_readiness",
)

_STABLE_FACT_KEYS = (
    "has_adapter",
    "meets_technical_floor",
    "admitted",
    "expressly_excluded",
    "future_or_unevaluated",
    "eol_or_withdrawn",
    "vendor_maintained",
    "ci_green",
    "is_derivative",
    "has_own_evidence",
    "family_inference_allowed",
    "has_valid_field_certification",
    "family_has_certified_anchor",
)

_ROLLING_FACT_KEYS = (
    "has_adapter",
    "meets_technical_floor",
    "expressly_excluded",
    "eol_or_withdrawn",
    "is_derivative",
    "has_own_evidence",
    "family_inference_allowed",
    "has_valid_field_certification",
    "family_has_certified_anchor",
)

_TOP_LEVEL_SCHEMA_PROPERTIES = tuple(sorted(_REQUIRED_TOP_LEVEL + _OPTIONAL_TOP_LEVEL))
_PROTOCOL_DISPOSITIONS = ("green", "formal_non_green", "failed", "not_run", "not_applicable")
_RELEASE_POLICY_STATES = ("admitted", "pending_evaluation", "excluded")
_PER_RELEASE_CI_STATUSES = ("not_run", "green", "failed")
_CERTIFICATION_SCOPES = ("physical_field_certification",)

_ENTITY_KEYS = {
    "metadata": (
        "bootstrap_python_min",
        "bootstrap_python_runtime_note",
        "bootstrap_python_runtime_verified",
        "bootstrap_python_syntax_verified",
        "max_manifest_bytes",
        "source_authority",
    ),
    "technical_family": ("adapter", "common_features", "core_capabilities", "package_manager", "provisioning_methods"),
    "distribution": ("id", "lineage", "os_release_ids", "policy", "release_model", "technical_family"),
    "lineage": ("family_inference_allowed", "has_own_evidence", "is_derivative"),
    "stable_policy": ("admitted_releases", "excluded_releases", "pending_releases"),
    "rolling_policy": (
        "eol_or_withdrawn",
        "evidence_expiry_seconds",
        "expressly_excluded",
        "last_validated",
        "meets_technical_floor",
    ),
    "release": (
        "codename",
        "distribution",
        "eol_or_withdrawn",
        "evidence_refs",
        "meets_technical_floor",
        "os_release_version_ids",
        "policy_state",
        "vendor_maintained",
        "version",
    ),
    "derivative": (
        "base_version_gating",
        "codename_map",
        "distribution",
        "lineage_distribution",
        "mapping_source",
        "mapping_type",
    ),
    "capability": ("description", "dns_backend_policy", "supported_values", "type"),
    "provisioning_method": ("exact_release_required", "kind", "mutates_system", "provenance"),
    "dependency_requirement": ("capability_id", "description", "method_chain"),
    "method_candidate": (
        "architectures",
        "assets",
        "build_dependencies",
        "compatible_targets",
        "evidence",
        "expected_executable",
        "expected_files",
        "expected_outputs",
        "id",
        "implementation_status",
        "integrity",
        "kind",
        "method_ref",
        "official_provenance",
        "package_manager",
        "package_names",
        "postcondition",
        "priority",
        "provider",
        "repository",
        "repository_package",
        "runtime_python",
        "signing_key_provenance",
        "exposed_package_names",
        "official_download_base",
        "components",
        "target_identity",
        "target_scope",
        "version",
    ),
    "artifact_asset": (
        "architecture",
        "archive_or_binary_kind",
        "asset_name",
        "expected_executable",
        "official_download_base",
        "sha256",
    ),
    "runtime_python": ("cryptography_package", "executable", "package"),
    "source_component": (
        "build_dependencies",
        "component_id",
        "expected_outputs",
        "postcondition",
        "repository",
        "revision",
        "revision_type",
        "tag",
    ),
    "dns_backend_policy_entry": ("helper_requirement",),
    "compatible_target": ("own_release", "series", "target_id"),
    "repository": ("id", "series", "url"),
    "target_scope": ("rolling_distributions", "stable_releases", "technical_families"),
    "protocol": ("category", "evidence_policy", "required_protocol_capabilities"),
    "certification": (
        "current",
        "date",
        "distribution",
        "evidence",
        "protocol_results",
        "release",
        "scope",
        "snapshot",
    ),
    "protocol_result": ("disposition", "evidence"),
    "rolling_policy_metadata": ("evidence_refs", "expiry_seconds", "last_validated"),
    "repository_ci": ("evidence", "latest_known_green", "scope"),
    "per_release_ci": ("evidence", "l1_l2_green", "status"),
    "doc_generation": ("public_claims_generated", "reason"),
    "certification_review_policy": ("review_due_seconds", "review_overdue_seconds"),
}


class ManifestError(ValueError):
    """Raised when the manifest is invalid."""


class QueryError(KeyError):
    """Raised when a valid manifest cannot satisfy a query."""


def _fail_duplicate_object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("duplicate JSON key: %s" % key)
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ManifestError("non-finite JSON number is not allowed: %s" % value)


def _load_json_text(text):
    try:
        loaded = json.loads(
            text,
            object_pairs_hook=_fail_duplicate_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except ManifestError:
        raise
    except ValueError as exc:
        raise ManifestError("invalid JSON: %s" % exc)
    if type(loaded) is not dict:
        raise ManifestError("manifest top level must be a JSON object")
    return loaded


def load_manifest_file(path, product_path=False):
    abspath = os.path.abspath(path)
    if product_path and os.path.islink(abspath):
        raise ManifestError("product manifest path must not be a symlink: %s" % abspath)
    try:
        stat_result = os.stat(abspath)
    except OSError as exc:
        raise ManifestError("cannot stat manifest: %s" % exc)
    if stat_result.st_size > MAX_MANIFEST_BYTES:
        raise ManifestError(
            "manifest exceeds %d byte limit: %d" % (MAX_MANIFEST_BYTES, stat_result.st_size)
        )
    try:
        with open(abspath, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise ManifestError("cannot read manifest: %s" % exc)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestError("manifest must be valid UTF-8: %s" % exc)
    return _load_json_text(text)


def _path_join(parent, child):
    if parent:
        return "%s.%s" % (parent, child)
    return child


def _require_obj(value, path):
    if type(value) is not dict:
        raise ManifestError("%s must be an object" % path)
    return value


def _require_list(value, path):
    if type(value) is not list:
        raise ManifestError("%s must be a list" % path)
    return value


def _require_str(value, path):
    if type(value) is not str:
        raise ManifestError("%s must be a string" % path)
    if value == "":
        raise ManifestError("%s must not be empty" % path)
    return value


def _require_bool(value, path):
    if type(value) is not bool:
        raise ManifestError("%s must be a boolean true/false" % path)
    return value


def _require_positive_int(value, path):
    if type(value) is not int:
        raise ManifestError("%s must be an integer" % path)
    if value <= 0:
        raise ManifestError("%s must be a positive integer" % path)
    return value


def _require_id(value, path):
    text = _require_str(value, path)
    if not _ID_RE.match(text):
        raise ManifestError("%s is not a valid id: %r" % (path, text))
    return text


def _require_enum(value, allowed, path):
    text = _require_str(value, path)
    if text not in allowed:
        raise ManifestError("%s must be one of %s" % (path, ", ".join(allowed)))
    return text


def _require_string_list(value, path, allow_empty=False):
    values = _require_list(value, path)
    if not allow_empty and not values:
        raise ManifestError("%s must not be empty" % path)
    seen = set()
    for index, item in enumerate(values):
        item_path = "%s[%d]" % (path, index)
        text = _require_str(item, item_path)
        if text in seen:
            raise ManifestError("%s contains duplicate item %r" % (path, text))
        seen.add(text)
    return values


def _require_id_list(value, path, allow_empty=False):
    values = _require_list(value, path)
    if not allow_empty and not values:
        raise ManifestError("%s must not be empty" % path)
    seen = set()
    for index, item in enumerate(values):
        item_path = "%s[%d]" % (path, index)
        text = _require_id(item, item_path)
        if text in seen:
            raise ManifestError("%s contains duplicate id %r" % (path, text))
        seen.add(text)
    return values


def _require_package_name(value, path):
    text = _require_str(value, path)
    if not _PACKAGE_NAME_RE.match(text):
        raise ManifestError("%s is not a safe package name: %r" % (path, text))
    return text


def _require_package_list(value, path):
    values = _require_list(value, path)
    if not values:
        raise ManifestError("%s must not be empty" % path)
    seen = set()
    for index, item in enumerate(values):
        text = _require_package_name(item, "%s[%d]" % (path, index))
        if text in seen:
            raise ManifestError("%s contains duplicate package %r" % (path, text))
        seen.add(text)
    return values


def _require_https_url(value, path):
    text = _require_str(value, path)
    if not _HTTPS_URL_RE.match(text):
        raise ManifestError("%s must be an absolute HTTPS URL without credentials" % path)
    return text


def _require_sha256(value, path):
    text = _require_str(value, path)
    if not _SHA256_RE.match(text):
        raise ManifestError("%s must be a 64-character hexadecimal SHA-256" % path)
    if len(set(text.lower())) == 1:
        raise ManifestError("%s must not be a repeated-character placeholder hash" % path)
    return text


def _is_git_commit(value):
    return type(value) is str and _GIT_COMMIT_RE.match(value)


def _require_safe_expected_path(value, path):
    text = _require_str(value, path)
    if text.startswith("/") or ".." in text.split("/"):
        raise ManifestError("%s must be a safe relative file name/path" % path)
    if not _SAFE_RELATIVE_PATH_RE.match(text):
        raise ManifestError("%s contains unsafe characters" % path)
    return text


def _has_signing_key_fingerprint(text):
    for match in _FINGERPRINT_SUBSTRING_RE.finditer(text):
        compact = match.group(1).replace(" ", "")
        if len(compact) == 40 and re.match(r"^[A-Fa-f0-9]{40}$", compact):
            return True
    return False


def _require_signing_key_provenance(value, path, repository_package):
    text = _require_str(value, path)
    # This is the only _require_* helper that intentionally searches within
    # prose: signing_key_provenance is free-form provenance text, not a single
    # identifier field that can be matched as a whole value.
    has_explicit_key = bool(_KEYID_SUBSTRING_RE.search(text)) or _has_signing_key_fingerprint(text)
    has_key_source = bool(_SIGNING_KEY_SOURCE_RE.search(text))
    has_bootstrap_trust = (
        repository_package is not None
        and repository_package in text
        and "repository GPG key" in text
        and (
            "already-trusted base repositories" in text
            or "trusted base repositories" in text
        )
    )
    if not ((has_explicit_key and has_key_source) or has_bootstrap_trust):
        raise ManifestError(
            "%s must identify a signing key with a verifiable source or a trusted base-repository bootstrap package"
            % path
        )
    return text


def _require_safe_expected_paths(value, path):
    values = _require_list(value, path)
    if not values:
        raise ManifestError("%s must not be empty" % path)
    seen = set()
    for index, item in enumerate(values):
        text = _require_safe_expected_path(item, "%s[%d]" % (path, index))
        if text in seen:
            raise ManifestError("%s contains duplicate expected path %r" % (path, text))
        seen.add(text)
    return values


def _require_object_ids(obj, path):
    _require_obj(obj, path)
    for key in obj:
        _require_id(key, "%s key" % path)


def _reject_unknown_keys(obj, allowed, path):
    _require_obj(obj, path)
    allowed_set = set(allowed)
    for key in obj:
        if key not in allowed_set:
            raise ManifestError("%s has unknown key %s" % (path, key))


def _require_rfc3339_utc(value, path):
    text = _require_str(value, path)
    match = _RFC3339_UTC_RE.match(text)
    if not match:
        raise ManifestError("%s must be RFC 3339 UTC with trailing Z" % path)
    try:
        datetime(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            int(match.group(4)),
            int(match.group(5)),
            int(match.group(6)),
        )
    except ValueError as exc:
        raise ManifestError("%s is not a real UTC timestamp: %s" % (path, exc))
    return text


def _normalize_rfc3339_utc_to_naive(value):
    match = _RFC3339_UTC_RE.match(value)
    return "%s-%s-%sT%s:%s:%s" % (
        match.group(1),
        match.group(2),
        match.group(3),
        match.group(4),
        match.group(5),
        match.group(6),
    )


def _walk_no_calculated_states(value, path):
    if type(value) is dict:
        for key, child in value.items():
            if key in _CALCULATED_STATE_KEYS:
                raise ManifestError(
                    "%s stores calculated state %r; derive it from facts instead" % (path, key)
                )
            _walk_no_calculated_states(child, _path_join(path, key))
    elif type(value) is list:
        for index, child in enumerate(value):
            _walk_no_calculated_states(child, "%s[%d]" % (path, index))


def _schema_major(version):
    text = _require_str(version, "schema_version")
    match = _VERSION_RE.match(text)
    if not match:
        raise ManifestError("schema_version must be semantic major.minor.patch")
    return int(match.group(1))


def _check_required_top_level(manifest):
    for key in _REQUIRED_TOP_LEVEL:
        if key not in manifest:
            raise ManifestError("missing required top-level section: %s" % key)
    for key in manifest:
        if key not in _REQUIRED_TOP_LEVEL and key not in _OPTIONAL_TOP_LEVEL:
            raise ManifestError("unknown top-level section: %s" % key)


def _validate_documentation_schema(manifest):
    schema = load_manifest_file(os.path.join(ROOT, "compat", "compatibility.schema.json"))
    _require_obj(schema, "compatibility.schema.json")
    if schema.get("additionalProperties") is not False:
        raise ManifestError("schema must set additionalProperties:false at top level")
    properties = _require_obj(schema.get("properties"), "schema.properties")
    schema_props = set(properties.keys())
    reader_props = set(_TOP_LEVEL_SCHEMA_PROPERTIES)
    if schema_props != reader_props:
        raise ManifestError(
            "schema top-level properties diverge from reader: schema=%s reader=%s"
            % (sorted(schema_props), sorted(reader_props))
        )
    required = set(_require_string_list(schema.get("required"), "schema.required"))
    if required != set(_REQUIRED_TOP_LEVEL):
        raise ManifestError("schema.required diverges from reader required sections")
    for key in manifest:
        if key not in schema_props:
            raise ManifestError("manifest top-level key %s is not declared by schema" % key)


def _check_unique_entity_ids(manifest):
    owners = {}
    sections = (
        "technical_families",
        "distributions",
        "releases",
        "derivatives",
        "dependency_requirements",
        "provisioning_methods",
        "protocols",
        "certifications",
    )
    for section in sections:
        for entity_id in manifest[section]:
            previous = owners.get(entity_id)
            if previous is not None:
                raise ManifestError(
                    "id %r is reused in both %s and %s" % (entity_id, previous, section)
                )
            owners[entity_id] = section
    capabilities = manifest["capabilities"]
    for subsection in ("core_host_capabilities", "protocol_capabilities"):
        for entity_id in capabilities[subsection]:
            previous = owners.get(entity_id)
            if previous is not None:
                raise ManifestError(
                    "id %r is reused in both %s and capabilities.%s"
                    % (entity_id, previous, subsection)
                )
            owners[entity_id] = "capabilities.%s" % subsection


def _validate_metadata(manifest):
    metadata = manifest.get("metadata", {})
    _require_obj(metadata, "metadata")
    _reject_unknown_keys(metadata, _ENTITY_KEYS["metadata"], "metadata")
    if "bootstrap_python_min" in metadata:
        if _require_str(metadata["bootstrap_python_min"], "metadata.bootstrap_python_min") != BOOTSTRAP_PYTHON_MIN:
            raise ManifestError("metadata.bootstrap_python_min must be %s" % BOOTSTRAP_PYTHON_MIN)
    if "max_manifest_bytes" in metadata:
        limit = _require_positive_int(metadata["max_manifest_bytes"], "metadata.max_manifest_bytes")
        if limit != MAX_MANIFEST_BYTES:
            raise ManifestError("metadata.max_manifest_bytes must be %d" % MAX_MANIFEST_BYTES)
    if "bootstrap_python_syntax_verified" in metadata:
        _require_bool(
            metadata["bootstrap_python_syntax_verified"],
            "metadata.bootstrap_python_syntax_verified",
        )
    if "bootstrap_python_runtime_verified" in metadata:
        _require_bool(
            metadata["bootstrap_python_runtime_verified"],
            "metadata.bootstrap_python_runtime_verified",
        )
    if "bootstrap_python_runtime_note" in metadata:
        _require_str(
            metadata["bootstrap_python_runtime_note"],
            "metadata.bootstrap_python_runtime_note",
        )


def _validate_technical_families(manifest):
    families = manifest["technical_families"]
    methods = manifest["provisioning_methods"]
    caps = manifest["capabilities"]["core_host_capabilities"]
    _require_object_ids(families, "technical_families")
    for family_id, family in families.items():
        path = "technical_families.%s" % family_id
        _require_obj(family, path)
        _reject_unknown_keys(family, _ENTITY_KEYS["technical_family"], path)
        _require_str(family.get("adapter"), path + ".adapter")
        _require_enum(family.get("package_manager"), ("apt", "dnf", "zypper", "pacman"), path + ".package_manager")
        for cap_id in _require_id_list(family.get("core_capabilities"), path + ".core_capabilities"):
            if cap_id not in caps:
                raise ManifestError("%s references unknown core capability %r" % (path, cap_id))
        for method_id in _require_id_list(
            family.get("provisioning_methods"), path + ".provisioning_methods", allow_empty=True
        ):
            if method_id not in methods:
                raise ManifestError("%s references unknown provisioning method %r" % (path, method_id))
        _require_string_list(family.get("common_features", []), path + ".common_features", allow_empty=True)


def _validate_capabilities(manifest):
    capabilities = _require_obj(manifest["capabilities"], "capabilities")
    for subsection in ("core_host_capabilities", "protocol_capabilities"):
        if subsection not in capabilities:
            raise ManifestError("missing capabilities.%s" % subsection)
        _require_object_ids(capabilities[subsection], "capabilities.%s" % subsection)
    for cap_id, cap in capabilities["core_host_capabilities"].items():
        path = "capabilities.core_host_capabilities.%s" % cap_id
        _require_obj(cap, path)
        _reject_unknown_keys(cap, _ENTITY_KEYS["capability"], path)
        _require_enum(
            cap.get("type"),
            ("required", "alternative", "optional", "provisionable", "incompatible", "diagnostic_only"),
            path + ".type",
        )
        _require_str(cap.get("description"), path + ".description")
        if cap_id == "cap_architecture":
            _require_id_list(cap.get("supported_values"), path + ".supported_values")
        elif "supported_values" in cap:
            raise ManifestError("%s.supported_values is only valid for cap_architecture" % path)
        if cap_id == "cap_dns_runtime_package":
            _validate_dns_backend_policy(cap.get("dns_backend_policy"), path + ".dns_backend_policy")
        elif "dns_backend_policy" in cap:
            raise ManifestError("%s.dns_backend_policy is only valid for cap_dns_runtime_package" % path)
    for cap_id, cap in capabilities["protocol_capabilities"].items():
        path = "capabilities.protocol_capabilities.%s" % cap_id
        _require_obj(cap, path)
        _reject_unknown_keys(cap, _ENTITY_KEYS["capability"], path)
        _require_enum(cap.get("type"), ("provisionable", "required", "optional"), path + ".type")
        _require_str(cap.get("description"), path + ".description")


def _validate_dns_backend_policy(policy, path):
    policy = _require_obj(policy, path)
    required = {"systemd_resolved", "networkmanager", "static_resolv_conf", "unknown"}
    if set(policy) != required:
        raise ManifestError("%s must define exactly %s" % (path, sorted(required)))
    for backend, entry in policy.items():
        entry_path = "%s.%s" % (path, backend)
        _require_obj(entry, entry_path)
        _reject_unknown_keys(entry, _ENTITY_KEYS["dns_backend_policy_entry"], entry_path)
        _require_enum(
            entry.get("helper_requirement"),
            ("satisfied_by_backend", "optional", "required_package", "unknown"),
            entry_path + ".helper_requirement",
        )


def _validate_provisioning_methods(manifest):
    methods = manifest["provisioning_methods"]
    _require_object_ids(methods, "provisioning_methods")
    for method_id, method in methods.items():
        path = "provisioning_methods.%s" % method_id
        _require_obj(method, path)
        _reject_unknown_keys(method, _ENTITY_KEYS["provisioning_method"], path)
        _require_enum(
            method.get("kind"),
            ("official_package_exact", "external_repo_exact", "official_artifact_pinned", "pinned_source_build", "diagnostic_only"),
            path + ".kind",
        )
        _require_bool(method.get("exact_release_required"), path + ".exact_release_required")
        _require_bool(method.get("mutates_system"), path + ".mutates_system")
        _require_str(method.get("provenance"), path + ".provenance")


def _validate_dependency_requirements(manifest):
    requirements = manifest["dependency_requirements"]
    core_caps = manifest["capabilities"]["core_host_capabilities"]
    protocol_caps = manifest["capabilities"]["protocol_capabilities"]
    all_caps = set(core_caps) | set(protocol_caps)
    methods = manifest["provisioning_methods"]
    releases = manifest["releases"]
    distributions = manifest["distributions"]
    families = manifest["technical_families"]
    supported_arches = set(core_caps["cap_architecture"]["supported_values"])
    allowed_statuses = ("implemented", "not_implemented", "future_task")
    global_candidate_ids = {}
    artifact_versions = {}
    _require_object_ids(requirements, "dependency_requirements")
    for requirement_id, requirement in requirements.items():
        path = "dependency_requirements.%s" % requirement_id
        _require_obj(requirement, path)
        _reject_unknown_keys(requirement, _ENTITY_KEYS["dependency_requirement"], path)
        cap_id = _require_id(requirement.get("capability_id"), path + ".capability_id")
        if cap_id not in all_caps:
            raise ManifestError("%s references unknown capability %r" % (path, cap_id))
        _require_str(requirement.get("description"), path + ".description")
        chain = _require_list(requirement.get("method_chain"), path + ".method_chain")
        if not chain:
            raise ManifestError("%s.method_chain must not be empty" % path)
        seen_priorities = set()
        seen_candidate_ids = set()
        for index, candidate in enumerate(chain):
            cand_path = "%s.method_chain[%d]" % (path, index)
            _require_obj(candidate, cand_path)
            _reject_unknown_keys(candidate, _ENTITY_KEYS["method_candidate"], cand_path)
            candidate_id = _require_id(candidate.get("id"), cand_path + ".id")
            previous_owner = global_candidate_ids.get(candidate_id)
            if previous_owner is not None:
                raise ManifestError(
                    "%s candidate id %r is also used by %s"
                    % (cand_path, candidate_id, previous_owner)
                )
            global_candidate_ids[candidate_id] = path
            if candidate_id in seen_candidate_ids:
                raise ManifestError("%s has duplicate candidate id %r" % (path, candidate_id))
            seen_candidate_ids.add(candidate_id)
            priority = _require_positive_int(candidate.get("priority"), cand_path + ".priority")
            if priority in seen_priorities:
                raise ManifestError("%s has duplicate method priority %d" % (path, priority))
            seen_priorities.add(priority)
            method_ref = _require_id(candidate.get("method_ref"), cand_path + ".method_ref")
            if method_ref not in methods:
                raise ManifestError("%s references unknown provisioning method %r" % (cand_path, method_ref))
            kind = _require_enum(
                candidate.get("kind"),
                ("official_package_exact", "external_repo_exact", "official_artifact_pinned", "pinned_source_build"),
                cand_path + ".kind",
            )
            if methods[method_ref]["kind"] != kind:
                raise ManifestError("%s kind diverges from provisioning method %s" % (cand_path, method_ref))
            _require_enum(candidate.get("implementation_status"), allowed_statuses, cand_path + ".implementation_status")
            _require_enum(
                candidate.get("target_identity"),
                ("resolved_release", "rolling_distribution", "mapped_base_release"),
                cand_path + ".target_identity",
            )
            target_identity = candidate["target_identity"]
            scope = _require_obj(candidate.get("target_scope"), cand_path + ".target_scope")
            _reject_unknown_keys(scope, _ENTITY_KEYS["target_scope"], cand_path + ".target_scope")
            for family_id in _require_id_list(scope.get("technical_families"), cand_path + ".target_scope.technical_families"):
                if family_id not in families:
                    raise ManifestError("%s targets unknown family %r" % (cand_path, family_id))
            for release_id in _require_id_list(
                scope.get("stable_releases", []),
                cand_path + ".target_scope.stable_releases",
                allow_empty=True,
            ):
                if release_id not in releases:
                    raise ManifestError("%s targets unknown stable release %r" % (cand_path, release_id))
                if distributions[releases[release_id]["distribution"]]["release_model"] != "stable":
                    raise ManifestError("%s stable release target %r is not stable" % (cand_path, release_id))
                if releases[release_id]["distribution"] not in distributions:
                    raise ManifestError("%s stable release target %r has unknown owner" % (cand_path, release_id))
                owner_family = distributions[releases[release_id]["distribution"]]["technical_family"]
                if owner_family not in scope["technical_families"]:
                    raise ManifestError("%s stable target %r belongs to family %s outside scope" % (cand_path, release_id, owner_family))
            for distro_id in _require_id_list(
                scope.get("rolling_distributions", []),
                cand_path + ".target_scope.rolling_distributions",
                allow_empty=True,
            ):
                if distro_id not in distributions:
                    raise ManifestError("%s targets unknown rolling distribution %r" % (cand_path, distro_id))
                if distributions[distro_id]["release_model"] != "rolling":
                    raise ManifestError("%s rolling target %r is not rolling" % (cand_path, distro_id))
                if distributions[distro_id]["technical_family"] not in scope["technical_families"]:
                    raise ManifestError("%s rolling target %r belongs to family outside scope" % (cand_path, distro_id))
            stable_targets = scope.get("stable_releases", [])
            rolling_targets = scope.get("rolling_distributions", [])
            if target_identity == "resolved_release":
                if not stable_targets:
                    raise ManifestError("%s resolved_release requires stable_releases" % cand_path)
                if rolling_targets:
                    raise ManifestError("%s resolved_release must not target rolling distributions" % cand_path)
            elif target_identity == "rolling_distribution":
                if not rolling_targets:
                    raise ManifestError("%s rolling_distribution requires rolling_distributions" % cand_path)
                if stable_targets:
                    raise ManifestError("%s rolling_distribution must not target stable releases" % cand_path)
            elif target_identity == "mapped_base_release":
                if not stable_targets:
                    raise ManifestError("%s mapped_base_release requires derivative stable_releases" % cand_path)
                if rolling_targets:
                    raise ManifestError("%s mapped_base_release must not target rolling distributions" % cand_path)
                for release_id in stable_targets:
                    owner = distributions[releases[release_id]["distribution"]]
                    if owner["lineage"]["is_derivative"] is not True:
                        raise ManifestError("%s mapped_base_release target %r is not derivative" % (cand_path, release_id))
            arches = _require_id_list(candidate.get("architectures"), cand_path + ".architectures")
            for arch in arches:
                if arch not in supported_arches:
                    raise ManifestError("%s architecture %r is not admitted by cap_architecture" % (cand_path, arch))
            evidence = _require_string_list(candidate.get("evidence"), cand_path + ".evidence")
            if any((";" in item or "&&" in item or "|" in item) for item in evidence):
                raise ManifestError("%s evidence must be references, not commands" % cand_path)
            postcondition = _require_id(candidate.get("postcondition"), cand_path + ".postcondition")
            if postcondition not in all_caps:
                raise ManifestError("%s.postcondition references unknown capability" % cand_path)
            if postcondition != cap_id:
                raise ManifestError("%s.postcondition must equal requirement capability_id" % cand_path)
            if "runtime_python" in candidate:
                runtime_python = _require_obj(candidate.get("runtime_python"), cand_path + ".runtime_python")
                _reject_unknown_keys(runtime_python, _ENTITY_KEYS["runtime_python"], cand_path + ".runtime_python")
                _require_package_name(runtime_python.get("executable"), cand_path + ".runtime_python.executable")
                _require_package_name(runtime_python.get("package"), cand_path + ".runtime_python.package")
                _require_package_name(runtime_python.get("cryptography_package"), cand_path + ".runtime_python.cryptography_package")
            if kind in ("official_package_exact", "external_repo_exact"):
                pm = _require_enum(candidate.get("package_manager"), ("apt", "dnf", "zypper", "pacman"), cand_path + ".package_manager")
                for family_id in scope["technical_families"]:
                    if families[family_id]["package_manager"] != pm:
                        raise ManifestError("%s package_manager diverges from family %s" % (cand_path, family_id))
                _require_package_list(candidate.get("package_names"), cand_path + ".package_names")
            elif "package_manager" in candidate or "package_names" in candidate:
                raise ManifestError("%s package fields are only valid for package/repo methods" % cand_path)
            if kind == "external_repo_exact":
                _require_str(candidate.get("provider"), cand_path + ".provider")
                repository = _require_obj(candidate.get("repository"), cand_path + ".repository")
                _reject_unknown_keys(repository, _ENTITY_KEYS["repository"], cand_path + ".repository")
                _require_id(repository.get("id"), cand_path + ".repository.id")
                _require_https_url(repository.get("url"), cand_path + ".repository.url")
                repo_series = _require_id(repository.get("series"), cand_path + ".repository.series")
                compatible_targets = _require_list(candidate.get("compatible_targets"), cand_path + ".compatible_targets")
                seen_compatible = set()
                for target_index, target in enumerate(compatible_targets):
                    target_path = "%s.compatible_targets[%d]" % (cand_path, target_index)
                    _require_obj(target, target_path)
                    _reject_unknown_keys(target, _ENTITY_KEYS["compatible_target"], target_path)
                    target_id = _require_id(target.get("target_id"), target_path + ".target_id")
                    series = _require_id(target.get("series"), target_path + ".series")
                    if series != repo_series:
                        raise ManifestError("%s.series must equal repository.series" % target_path)
                    own_release = None
                    if "own_release" in target:
                        own_release = _require_id(target.get("own_release"), target_path + ".own_release")
                    key = (own_release, target_id, series)
                    if key in seen_compatible:
                        raise ManifestError("%s contains duplicate compatible target" % target_path)
                    seen_compatible.add(key)
                    if target_id not in releases:
                        raise ManifestError("%s targets unknown release %r" % (target_path, target_id))
                    if distributions[releases[target_id]["distribution"]]["release_model"] != "stable":
                        raise ManifestError("%s target_id must be a stable release" % target_path)
                    if releases[target_id].get("codename") and releases[target_id].get("codename") != series:
                        raise ManifestError("%s series must match target release codename" % target_path)
                    if target_identity == "mapped_base_release":
                        if own_release is None:
                            raise ManifestError("%s mapped_base_release requires own_release" % target_path)
                        if own_release not in stable_targets:
                            raise ManifestError("%s own_release must be in candidate stable scope" % target_path)
                        _validate_mapped_base_target(manifest, own_release, target_id, series, target_path)
                    else:
                        if own_release is not None:
                            raise ManifestError("%s own_release is only valid for mapped_base_release" % target_path)
                        if target_id not in stable_targets:
                            raise ManifestError("%s target_id must be in candidate stable scope" % target_path)
            elif "provider" in candidate or "repository" in candidate or "compatible_targets" in candidate:
                raise ManifestError("%s repository fields are only valid for external_repo_exact" % cand_path)
            if kind == "external_repo_exact":
                if "repository_package" in candidate:
                    _require_package_name(candidate.get("repository_package"), cand_path + ".repository_package")
                _require_signing_key_provenance(
                    candidate.get("signing_key_provenance"),
                    cand_path + ".signing_key_provenance",
                    candidate.get("repository_package"),
                )
                if "exposed_package_names" in candidate:
                    exposed = _require_package_list(candidate.get("exposed_package_names"), cand_path + ".exposed_package_names")
                    if not exposed:
                        raise ManifestError("%s.exposed_package_names must not be empty" % cand_path)
                    package_names = candidate.get("package_names", [])
                    if any(package not in package_names for package in exposed):
                        raise ManifestError("%s.exposed_package_names must be a subset of package_names" % cand_path)
            elif "repository_package" in candidate or "signing_key_provenance" in candidate or "exposed_package_names" in candidate:
                raise ManifestError("%s repository prerequisite fields are only valid for external_repo_exact" % cand_path)
            if kind == "official_artifact_pinned":
                _require_https_url(candidate.get("official_provenance"), cand_path + ".official_provenance")
                version = _require_str(candidate.get("version"), cand_path + ".version")
                _require_https_url(candidate.get("official_download_base"), cand_path + ".official_download_base")
                executable = _require_safe_expected_path(candidate.get("expected_executable"), cand_path + ".expected_executable")
                version_key = (requirement_id, executable)
                previous_version = artifact_versions.get(version_key)
                if previous_version is not None and previous_version != version:
                    raise ManifestError("%s artifact version diverges from sibling candidate" % cand_path)
                artifact_versions[version_key] = version
                integrity = _require_obj(candidate.get("integrity"), cand_path + ".integrity")
                _require_enum(integrity.get("type"), ("sha256", "signature"), cand_path + ".integrity.type")
                if integrity["type"] == "sha256":
                    for arch in arches:
                        if arch not in integrity:
                            raise ManifestError("%s.integrity missing architecture %s" % (cand_path, arch))
                        _require_sha256(integrity[arch], cand_path + ".integrity." + arch)
                else:
                    for field in ("signature", "key_fingerprint", "key_provenance", "verification_policy"):
                        _require_str(integrity.get(field), cand_path + ".integrity." + field)
                _require_safe_expected_paths(candidate.get("expected_files"), cand_path + ".expected_files")
                _validate_artifact_assets(candidate, arches, cand_path)
            elif "version" in candidate or "integrity" in candidate or "expected_files" in candidate or "assets" in candidate or "official_download_base" in candidate or "expected_executable" in candidate:
                raise ManifestError("%s artifact fields are only valid for official_artifact_pinned" % cand_path)
            if kind == "pinned_source_build":
                _require_https_url(candidate.get("official_provenance"), cand_path + ".official_provenance")
                if "components" not in candidate:
                    _require_enum(candidate.get("revision_type"), ("tag", "commit"), cand_path + ".revision_type")
                    revision = _require_str(candidate.get("revision"), cand_path + ".revision")
                    if revision != "unresolved" and candidate["revision_type"] == "commit" and not _is_git_commit(revision):
                        raise ManifestError("%s.revision must be an immutable Git commit" % cand_path)
                elif "revision" in candidate or "revision_type" in candidate:
                    raise ManifestError("%s aggregate source build must pin component revisions, not top-level revision" % cand_path)
                _require_package_list(candidate.get("build_dependencies"), cand_path + ".build_dependencies")
                _require_safe_expected_paths(candidate.get("expected_outputs"), cand_path + ".expected_outputs")
                if "components" in candidate:
                    _validate_source_components(candidate, cand_path)
            elif "revision_type" in candidate or "revision" in candidate or "build_dependencies" in candidate or "expected_outputs" in candidate or "components" in candidate:
                raise ManifestError("%s source-build fields are only valid for pinned_source_build" % cand_path)
    _validate_rhel_base_runtime_composite(manifest)
    _validate_runtime_python_policies(manifest)


def _stable_scope(candidate):
    return set(candidate.get("target_scope", {}).get("stable_releases", ()))


def _validate_rhel_base_runtime_composite(manifest):
    requirements = manifest["dependency_requirements"]
    if "dep_base_runtime_commands" not in requirements:
        return
    rhel_targets = {"rocky_9", "almalinux_9", "rhel_9", "centos_stream_9"}
    if not (rhel_targets & set(manifest.get("releases", {}))):
        return
    matching = []
    for index, candidate in enumerate(requirements["dep_base_runtime_commands"]["method_chain"]):
        scope = _stable_scope(candidate)
        if scope & rhel_targets:
            matching.append((index, candidate))
    if len(matching) != 1:
        raise ManifestError("RHEL-family base runtime must use exactly one composite candidate")
    index, candidate = matching[0]
    path = "dependency_requirements.dep_base_runtime_commands.method_chain[%d]" % index
    if candidate["id"] != "base_runtime_dnf_rhel9_with_epel_exact":
        raise ManifestError("%s must be the RHEL-family composite candidate" % path)
    if candidate["kind"] != "external_repo_exact":
        raise ManifestError("%s must be external_repo_exact" % path)
    if candidate.get("repository_package") is None:
        raise ManifestError("%s.repository_package is required" % path)
    package_names = set(candidate.get("package_names", ()))
    exposed = set(candidate.get("exposed_package_names", ()))
    if not exposed or not exposed <= package_names:
        raise ManifestError("%s.exposed_package_names must be a non-empty subset of package_names" % path)
    if "openvpn" not in exposed:
        raise ManifestError("%s.exposed_package_names must include openvpn" % path)
    required = {
        "bash",
        "git",
        "coreutils",
        "findutils",
        "grep",
        "gawk",
        "sed",
        "glibc-common",
        "shadow-utils",
        "systemd",
        "sudo",
        "kmod",
        "ca-certificates",
        "nftables",
        "iptables-nft",
        "iputils",
        "procps-ng",
        "NetworkManager",
        "polkit",
        "firewalld",
        "systemd-resolved",
        "python3.11",
        "openvpn",
    }
    missing = sorted(required - package_names)
    if missing:
        raise ManifestError("%s missing required RHEL-family base packages %s" % (path, missing))


def _target_keys_for_candidate(candidate):
    identity = candidate["target_identity"]
    scope = candidate["target_scope"]
    if identity == "resolved_release":
        return {("stable", release_id) for release_id in scope["stable_releases"]}
    if identity == "rolling_distribution":
        return {("rolling", distro_id) for distro_id in scope["rolling_distributions"]}
    return set()


def _validate_runtime_python_policies(manifest):
    requirements = manifest["dependency_requirements"]
    if "dep_python_runtime" not in requirements or "dep_python_cryptography" not in requirements:
        if "dep_python_runtime" not in requirements and "dep_python_cryptography" not in requirements:
            return
        raise ManifestError("Python runtime and cryptography requirements must both exist")
    runtime_by_target = {}
    for index, candidate in enumerate(requirements["dep_python_runtime"]["method_chain"]):
        path = "dependency_requirements.dep_python_runtime.method_chain[%d]" % index
        runtime = candidate.get("runtime_python")
        if runtime is None:
            raise ManifestError("%s.runtime_python is required" % path)
        if runtime["package"] not in candidate["package_names"]:
            raise ManifestError("%s.runtime_python.package must be included in package_names" % path)
        for target in _target_keys_for_candidate(candidate):
            if target in runtime_by_target:
                raise ManifestError("%s overlaps Python runtime policy for %s" % (path, target[1]))
            runtime_by_target[target] = runtime
    crypto_by_target = {}
    for index, candidate in enumerate(requirements["dep_python_cryptography"]["method_chain"]):
        path = "dependency_requirements.dep_python_cryptography.method_chain[%d]" % index
        runtime = candidate.get("runtime_python")
        if runtime is None:
            raise ManifestError("%s.runtime_python is required" % path)
        if runtime["cryptography_package"] not in candidate["package_names"]:
            raise ManifestError("%s.runtime_python.cryptography_package must be included in package_names" % path)
        for target in _target_keys_for_candidate(candidate):
            if target in crypto_by_target:
                raise ManifestError("%s overlaps Python cryptography policy for %s" % (path, target[1]))
            crypto_by_target[target] = runtime
    expected_targets = {
        ("stable", release_id)
        for release_id, release in manifest["releases"].items()
        if manifest["distributions"][release["distribution"]]["release_model"] == "stable"
    }
    expected_targets.update(
        ("rolling", distro_id)
        for distro_id, distro in manifest["distributions"].items()
        if distro["release_model"] == "rolling"
    )
    if set(runtime_by_target) != expected_targets:
        missing = sorted(target[1] for target in expected_targets - set(runtime_by_target))
        extra = sorted(target[1] for target in set(runtime_by_target) - expected_targets)
        raise ManifestError("Python runtime policy target mismatch missing=%s extra=%s" % (missing, extra))
    if set(crypto_by_target) != expected_targets:
        missing = sorted(target[1] for target in expected_targets - set(crypto_by_target))
        extra = sorted(target[1] for target in set(crypto_by_target) - expected_targets)
        raise ManifestError("Python cryptography policy target mismatch missing=%s extra=%s" % (missing, extra))
    for target in expected_targets:
        runtime = runtime_by_target[target]
        crypto = crypto_by_target[target]
        if runtime["executable"] != crypto["executable"]:
            raise ManifestError("Python executable diverges for target %s" % (target[1],))
        if runtime["cryptography_package"] != crypto["cryptography_package"]:
            raise ManifestError("Python cryptography package diverges for target %s" % (target[1],))


def _validate_mapped_base_target(manifest, own_release, target_id, series, path):
    releases = manifest["releases"]
    distributions = manifest["distributions"]
    derivatives = manifest["derivatives"]
    if own_release not in releases:
        raise ManifestError("%s own_release references unknown release %r" % (path, own_release))
    own_distribution = releases[own_release]["distribution"]
    owner = distributions[own_distribution]
    if owner["lineage"]["is_derivative"] is not True:
        raise ManifestError("%s own_release distribution is not derivative" % path)
    matches = [
        derivative
        for derivative in derivatives.values()
        if derivative["distribution"] == own_distribution and derivative["mapping_type"] == "codename_map"
    ]
    if len(matches) != 1:
        raise ManifestError("%s own_release must have exactly one codename mapping" % path)
    derivative = matches[0]
    mapped = derivative["codename_map"].get(series)
    if mapped != target_id:
        raise ManifestError(
            "%s target_id %r is not authorized by derivative mapping for series %r"
            % (path, target_id, series)
        )
    if releases[target_id]["distribution"] != derivative["lineage_distribution"]:
        raise ManifestError("%s target_id is outside derivative lineage distribution" % path)


def _validate_artifact_assets(candidate, arches, path):
    assets = _require_list(candidate.get("assets"), path + ".assets")
    by_arch = {}
    for index, asset in enumerate(assets):
        asset_path = "%s.assets[%d]" % (path, index)
        _require_obj(asset, asset_path)
        _reject_unknown_keys(asset, _ENTITY_KEYS["artifact_asset"], asset_path)
        arch = _require_id(asset.get("architecture"), asset_path + ".architecture")
        if arch in by_arch:
            raise ManifestError("%s duplicates architecture %s" % (asset_path, arch))
        by_arch[arch] = asset
        if arch not in arches:
            raise ManifestError("%s architecture is outside candidate architectures" % asset_path)
        _require_str(asset.get("asset_name"), asset_path + ".asset_name")
        _require_enum(asset.get("archive_or_binary_kind"), ("tar.gz", "binary"), asset_path + ".archive_or_binary_kind")
        _require_https_url(asset.get("official_download_base"), asset_path + ".official_download_base")
        _require_sha256(asset.get("sha256"), asset_path + ".sha256")
        _require_safe_expected_path(asset.get("expected_executable"), asset_path + ".expected_executable")
        if asset["official_download_base"] != candidate["official_download_base"]:
            raise ManifestError("%s official_download_base must match candidate" % asset_path)
        if asset["expected_executable"] != candidate["expected_executable"]:
            raise ManifestError("%s expected_executable must match candidate" % asset_path)
        if asset["sha256"] != candidate["integrity"].get(arch):
            raise ManifestError("%s sha256 must match integrity entry" % asset_path)
    if set(by_arch) != set(arches):
        raise ManifestError("%s.assets must contain exactly one asset for each architecture" % path)


def _validate_source_components(candidate, path):
    components = _require_list(candidate.get("components"), path + ".components")
    if not components:
        raise ManifestError("%s.components must not be empty" % path)
    seen = set()
    for index, component in enumerate(components):
        comp_path = "%s.components[%d]" % (path, index)
        _require_obj(component, comp_path)
        _reject_unknown_keys(component, _ENTITY_KEYS["source_component"], comp_path)
        component_id = _require_id(component.get("component_id"), comp_path + ".component_id")
        if component_id in seen:
            raise ManifestError("%s duplicate component_id %s" % (comp_path, component_id))
        seen.add(component_id)
        _require_https_url(component.get("repository"), comp_path + ".repository")
        _require_enum(component.get("revision_type"), ("commit",), comp_path + ".revision_type")
        revision = _require_str(component.get("revision"), comp_path + ".revision")
        if revision != "unresolved" and not _is_git_commit(revision):
            raise ManifestError("%s.revision must be an immutable Git commit" % comp_path)
        tag = _require_str(component.get("tag"), comp_path + ".tag")
        if not tag.startswith("v"):
            raise ManifestError("%s.tag must be an explicit upstream release tag" % comp_path)
        _require_package_list(component.get("build_dependencies"), comp_path + ".build_dependencies")
        _require_safe_expected_paths(component.get("expected_outputs"), comp_path + ".expected_outputs")
        _require_id(component.get("postcondition"), comp_path + ".postcondition")
    if candidate.get("postcondition") == "proto_amneziawg_runtime":
        _validate_amneziawg_source_components(components, path)


def _validate_amneziawg_source_components(components, path):
    by_id = {component["component_id"]: component for component in components}
    if set(by_id) != {"amneziawg_tools", "amneziawg_transport"}:
        raise ManifestError("%s AmneziaWG source build must contain amneziawg_tools and amneziawg_transport" % path)
    tools = by_id["amneziawg_tools"]
    transport = by_id["amneziawg_transport"]
    if "awg" not in tools["expected_outputs"]:
        raise ManifestError("%s.amneziawg_tools expected_outputs must include awg" % path)
    if tools["postcondition"] != "amneziawg_tools_present":
        raise ManifestError("%s.amneziawg_tools postcondition is not defined" % path)
    if "amneziawg-go" not in transport["expected_outputs"] and "amneziawg" not in transport["expected_outputs"]:
        raise ManifestError("%s.amneziawg_transport expected_outputs must include amneziawg-go or amneziawg" % path)
    if transport["postcondition"] != "amneziawg_transport_present":
        raise ManifestError("%s.amneziawg_transport postcondition is not defined" % path)


def _validate_distributions(manifest):
    distributions = manifest["distributions"]
    families = manifest["technical_families"]
    _require_object_ids(distributions, "distributions")
    os_release_id_owners = {}
    for distro_id, distro in distributions.items():
        path = "distributions.%s" % distro_id
        _require_obj(distro, path)
        _reject_unknown_keys(distro, _ENTITY_KEYS["distribution"], path)
        if _require_id(distro.get("id"), path + ".id") != distro_id:
            raise ManifestError("%s.id must match its object key" % path)
        os_release_ids = _require_id_list(
            distro.get("os_release_ids", [distro_id]),
            path + ".os_release_ids",
        )
        for os_release_id in os_release_ids:
            previous = os_release_id_owners.get(os_release_id)
            if previous is not None:
                raise ManifestError(
                    "os-release ID %r is used by both %s and %s"
                    % (os_release_id, previous, distro_id)
                )
            os_release_id_owners[os_release_id] = distro_id
        lineage = _require_obj(distro.get("lineage"), path + ".lineage")
        _reject_unknown_keys(lineage, _ENTITY_KEYS["lineage"], path + ".lineage")
        _require_bool(lineage.get("is_derivative"), path + ".lineage.is_derivative")
        _require_bool(lineage.get("has_own_evidence"), path + ".lineage.has_own_evidence")
        _require_bool(lineage.get("family_inference_allowed"), path + ".lineage.family_inference_allowed")
        if not lineage["is_derivative"] and lineage["family_inference_allowed"]:
            raise ManifestError("%s non-derivative cannot allow family inference" % path)
        if not lineage["is_derivative"] and not lineage["has_own_evidence"]:
            raise ManifestError("%s non-derivative must carry own-evidence status" % path)
        family_id = _require_id(distro.get("technical_family"), path + ".technical_family")
        if family_id not in families:
            raise ManifestError("%s references unknown technical family %r" % (path, family_id))
        model = _require_enum(distro.get("release_model"), ("stable", "rolling"), path + ".release_model")
        policy = _require_obj(distro.get("policy"), path + ".policy")
        _require_bool(policy.get("inherits_family_support"), path + ".policy.inherits_family_support")
        if policy["inherits_family_support"]:
            raise ManifestError("%s.policy.inherits_family_support must be false" % path)
        if model == "stable":
            stable = _require_obj(policy.get("stable"), path + ".policy.stable")
            _reject_unknown_keys(stable, _ENTITY_KEYS["stable_policy"], path + ".policy.stable")
            for field in ("admitted_releases", "pending_releases", "excluded_releases"):
                _require_id_list(stable.get(field), path + ".policy.stable." + field, allow_empty=True)
            if "minimum_version" in stable:
                raise ManifestError("%s must not encode support as a continuous range" % path)
        else:
            rolling = _require_obj(policy.get("rolling"), path + ".policy.rolling")
            _reject_unknown_keys(rolling, _ENTITY_KEYS["rolling_policy"], path + ".policy.rolling")
            if "minimum_version" in rolling:
                raise ManifestError("%s rolling policy must not declare a numeric minimum" % path)
            for field in ("meets_technical_floor", "expressly_excluded", "eol_or_withdrawn"):
                _require_bool(rolling.get(field), path + ".policy.rolling." + field)
            if "last_validated" not in rolling:
                raise ManifestError("%s.policy.rolling missing last_validated" % path)
            if rolling["last_validated"] is not None:
                _require_rfc3339_utc(rolling["last_validated"], path + ".policy.rolling.last_validated")
            _require_positive_int(rolling.get("evidence_expiry_seconds"), path + ".policy.rolling.evidence_expiry_seconds")


def _allowed_protocol_dispositions(protocol):
    category = protocol["category"]
    if category == "formal_non_green":
        return {"formal_non_green", "green"}
    if category in ("resilient", "compatibility"):
        return {"green"}
    raise ManifestError("unknown protocol category %r" % category)


def _certification_qualification_error(manifest, cert_id):
    cert = manifest["certifications"][cert_id]
    distributions = manifest["distributions"]
    releases = manifest["releases"]
    protocols = manifest["protocols"]
    distro_id = cert.get("distribution")
    if distro_id not in distributions:
        return "unknown distribution"
    scope = cert.get("scope")
    if scope not in _CERTIFICATION_SCOPES:
        return "unknown certification scope"
    if scope != "physical_field_certification":
        return "scope does not qualify for support"
    if cert.get("current") is not True:
        return "certification is not current"
    if not cert.get("evidence"):
        return "certification evidence is empty"
    has_release = "release" in cert
    has_snapshot = "snapshot" in cert
    if has_release == has_snapshot:
        return "must contain exactly one of release or snapshot"
    distro_model = distributions[distro_id]["release_model"]
    if distro_model == "stable":
        if not has_release:
            return "stable certification must reference release"
        release_id = cert["release"]
        if release_id not in releases:
            return "unknown release"
        release = releases[release_id]
        if release["distribution"] != distro_id:
            return "release does not belong to distribution"
        stable_policy = distributions[distro_id]["policy"]["stable"]
        if release["policy_state"] != "admitted":
            return "stable certification target release is not admitted"
        if release_id not in stable_policy["admitted_releases"]:
            return "stable certification target release is not in admitted_releases"
        if release["meets_technical_floor"] is not True:
            return "stable certification target release is below the technical floor"
        if release["eol_or_withdrawn"] is not False:
            return "stable certification target release is EOL or withdrawn"
        if release["vendor_maintained"] is not True:
            return "stable certification target release is not vendor maintained"
    else:
        if not has_snapshot:
            return "rolling certification must reference snapshot"
        if not cert.get("snapshot"):
            return "rolling snapshot is empty"
        rolling_policy = distributions[distro_id]["policy"]["rolling"]
        if rolling_policy["meets_technical_floor"] is not True:
            return "rolling certification target is below the technical floor"
        if rolling_policy["expressly_excluded"] is not False:
            return "rolling certification target is expressly excluded"
        if rolling_policy["eol_or_withdrawn"] is not False:
            return "rolling certification target is EOL or withdrawn"
    results = cert.get("protocol_results")
    if type(results) is not dict:
        return "protocol_results must be an object"
    if set(results.keys()) != set(protocols.keys()):
        return "physical certification must contain exactly all manifest protocols"
    for protocol_id, protocol in protocols.items():
        result = results[protocol_id]
        if type(result) is not dict:
            return "protocol result %s must be an object" % protocol_id
        disposition = result.get("disposition")
        allowed = _allowed_protocol_dispositions(protocol)
        if disposition not in allowed:
            return (
                "protocol %s disposition %s does not match allowed %s"
                % (protocol_id, disposition, ",".join(sorted(allowed)))
            )
        if disposition in ("failed", "not_run", "not_applicable"):
            return "protocol %s has non-qualifying disposition %s" % (protocol_id, disposition)
        if not result.get("evidence"):
            return "protocol %s evidence is empty" % protocol_id
    return None


def certification_qualifies_for_support(manifest, cert_id):
    return _certification_qualification_error(manifest, cert_id) is None


def _qualifying_certification_ids(manifest):
    return sorted(
        cert_id
        for cert_id in manifest["certifications"]
        if certification_qualifies_for_support(manifest, cert_id)
    )


def _release_certifications(manifest, release_id):
    release = manifest["releases"][release_id]
    distro_id = release["distribution"]
    result = []
    for cert_id, cert in manifest["certifications"].items():
        if (
            certification_qualifies_for_support(manifest, cert_id)
            and cert.get("distribution") == distro_id
            and cert.get("release") == release_id
        ):
            result.append(cert_id)
    return sorted(result)


def _family_has_current_certification(manifest, family_id):
    distributions = manifest["distributions"]
    for cert_id, cert in manifest["certifications"].items():
        if not certification_qualifies_for_support(manifest, cert_id):
            continue
        distro_id = cert.get("distribution")
        if distributions[distro_id]["technical_family"] != family_id:
            continue
        return True
    return False


def _rolling_certifications(manifest, distro_id):
    return sorted(
        cert_id
        for cert_id, cert in manifest["certifications"].items()
        if certification_qualifies_for_support(manifest, cert_id)
        and cert.get("distribution") == distro_id
        and "snapshot" in cert
    )


def _per_release_ci_green(manifest, release_id):
    ci = manifest["validation_metadata"]["per_release_ci"].get(release_id)
    if ci is None:
        return False
    return ci["status"] == "green" and ci["l1_l2_green"] is True


def _derive_stable_facts(manifest, release_id):
    releases = manifest["releases"]
    distributions = manifest["distributions"]
    release = releases[release_id]
    distro = distributions[release["distribution"]]
    stable_policy = distro["policy"]["stable"]
    policy_state = release["policy_state"]
    in_admitted = release_id in stable_policy["admitted_releases"]
    in_pending = release_id in stable_policy["pending_releases"]
    in_excluded = release_id in stable_policy["excluded_releases"]
    if sum(1 for value in (in_admitted, in_pending, in_excluded) if value) != 1:
        raise ManifestError("release %s must appear in exactly one stable policy list" % release_id)
    if in_admitted != (policy_state == "admitted"):
        raise ManifestError("release %s policy list contradicts policy_state admitted" % release_id)
    if in_excluded != (policy_state == "excluded"):
        raise ManifestError("release %s policy list contradicts policy_state excluded" % release_id)
    if in_pending != (policy_state == "pending_evaluation"):
        raise ManifestError("release %s policy list contradicts policy_state pending_evaluation" % release_id)
    lineage = distro["lineage"]
    current_certs = _release_certifications(manifest, release_id)
    evidence_refs = sorted(release.get("evidence_refs", []))
    if evidence_refs != current_certs:
        raise ManifestError("release %s evidence_refs must equal current certifications" % release_id)
    return {
        "has_adapter": True,
        "meets_technical_floor": release["meets_technical_floor"],
        "admitted": policy_state == "admitted",
        "expressly_excluded": policy_state == "excluded",
        "future_or_unevaluated": policy_state == "pending_evaluation",
        "eol_or_withdrawn": release["eol_or_withdrawn"],
        "vendor_maintained": release["vendor_maintained"],
        "ci_green": _per_release_ci_green(manifest, release_id),
        "is_derivative": lineage["is_derivative"],
        "has_own_evidence": lineage["has_own_evidence"],
        "family_inference_allowed": lineage["family_inference_allowed"],
        "has_valid_field_certification": bool(current_certs),
        "family_has_certified_anchor": _family_has_current_certification(manifest, distro["technical_family"]),
    }


def _validate_releases_structure(manifest):
    releases = manifest["releases"]
    distributions = manifest["distributions"]
    certifications = manifest["certifications"]
    _require_object_ids(releases, "releases")
    by_distro = {}
    os_release_version_owners = {}
    codename_owners = {}
    for release_id, release in releases.items():
        path = "releases.%s" % release_id
        _require_obj(release, path)
        _reject_unknown_keys(release, _ENTITY_KEYS["release"], path)
        distro_id = _require_id(release.get("distribution"), path + ".distribution")
        if distro_id not in distributions:
            raise ManifestError("%s references unknown distribution %r" % (path, distro_id))
        if distributions[distro_id]["release_model"] != "stable":
            raise ManifestError("%s belongs to rolling distribution %r" % (path, distro_id))
        _require_str(release.get("version"), path + ".version")
        if "codename" in release:
            codename = _require_id(release.get("codename"), path + ".codename")
            previous = codename_owners.get((distro_id, codename))
            if previous is not None:
                raise ManifestError(
                    "%s.codename value %r is also used by release %s"
                    % (path, codename, previous)
                )
            codename_owners[(distro_id, codename)] = release_id
        for os_release_version_id in _require_string_list(
            release.get("os_release_version_ids"),
            path + ".os_release_version_ids",
        ):
            previous = os_release_version_owners.get((distro_id, os_release_version_id))
            if previous is not None:
                raise ManifestError(
                    "%s.os_release_version_ids value %r is also used by release %s"
                    % (path, os_release_version_id, previous)
                )
            os_release_version_owners[(distro_id, os_release_version_id)] = release_id
        _require_enum(release.get("policy_state"), ("admitted", "pending_evaluation", "excluded"), path + ".policy_state")
        _require_bool(release.get("meets_technical_floor"), path + ".meets_technical_floor")
        _require_bool(release.get("vendor_maintained"), path + ".vendor_maintained")
        _require_bool(release.get("eol_or_withdrawn"), path + ".eol_or_withdrawn")
        by_distro.setdefault(distro_id, set()).add(release_id)
        for cert_id in _require_id_list(release.get("evidence_refs", []), path + ".evidence_refs", allow_empty=True):
            if cert_id not in certifications:
                raise ManifestError("%s references unknown certification %r" % (path, cert_id))
    for distro_id, distro in distributions.items():
        if distro["release_model"] != "stable":
            continue
        declared = set()
        stable_policy = distro["policy"]["stable"]
        for field in ("admitted_releases", "pending_releases", "excluded_releases"):
            for release_id in stable_policy[field]:
                if release_id not in releases:
                    raise ManifestError("distributions.%s references unknown release %r" % (distro_id, release_id))
                if releases[release_id]["distribution"] != distro_id:
                    raise ManifestError(
                        "distribution %s policy references release %r owned by %s"
                        % (distro_id, release_id, releases[release_id]["distribution"])
                    )
                if release_id in declared:
                    raise ManifestError("distribution %s lists release %r more than once" % (distro_id, release_id))
                declared.add(release_id)
        actual = by_distro.get(distro_id, set())
        if actual != declared:
            raise ManifestError(
                "distribution %s stable release policy does not match releases section" % distro_id
            )


def _validate_releases_semantics(manifest):
    releases = manifest["releases"]
    for release_id in releases:
        facts = _derive_stable_facts(manifest, release_id)
        if facts["admitted"] and facts["expressly_excluded"]:
            raise ManifestError("release %s derived facts contradict admitted/excluded" % release_id)
        if facts["admitted"] and facts["future_or_unevaluated"]:
            raise ManifestError("release %s derived facts contradict admitted/pending" % release_id)
        if facts["admitted"] and facts["eol_or_withdrawn"]:
            raise ManifestError("release %s derived facts contradict admitted/eol" % release_id)
        if facts["has_valid_field_certification"] and facts["is_derivative"] and not facts["has_own_evidence"]:
            raise ManifestError("release %s certifies a derivative without own evidence" % release_id)


def _validate_derivatives(manifest):
    derivatives = manifest["derivatives"]
    distributions = manifest["distributions"]
    releases = manifest["releases"]
    _require_object_ids(derivatives, "derivatives")
    graph = {}
    mapped_targets = {}
    for derivative_id, derivative in derivatives.items():
        path = "derivatives.%s" % derivative_id
        _require_obj(derivative, path)
        _reject_unknown_keys(derivative, _ENTITY_KEYS["derivative"], path)
        distro_id = _require_id(derivative.get("distribution"), path + ".distribution")
        if distro_id not in distributions:
            raise ManifestError("%s references unknown distribution %r" % (path, distro_id))
        base_id = _require_id(derivative.get("lineage_distribution"), path + ".lineage_distribution")
        if base_id not in distributions:
            raise ManifestError("%s references unknown lineage distribution %r" % (path, base_id))
        graph[distro_id] = base_id
        if not distributions[distro_id]["lineage"]["is_derivative"]:
            raise ManifestError("%s references a distribution not marked as derivative" % path)
        model = distributions[distro_id]["release_model"]
        mapping_type = _require_enum(derivative.get("mapping_type"), ("codename_map", "rolling_lineage"), path + ".mapping_type")
        if model == "stable":
            if mapping_type != "codename_map":
                raise ManifestError("%s stable derivative requires codename_map" % path)
            _require_enum(
                derivative.get("mapping_source"),
                ("ubuntu_codename", "version_codename"),
                path + ".mapping_source",
            )
            codename_map = _require_obj(derivative.get("codename_map"), path + ".codename_map")
            if not codename_map:
                raise ManifestError("%s.codename_map must not be empty" % path)
            for source_codename, release_id in codename_map.items():
                _require_id(source_codename, path + ".codename_map key")
                _require_id(release_id, path + ".codename_map.%s" % source_codename)
                if release_id not in releases:
                    raise ManifestError("%s maps to unknown release %r" % (path, release_id))
                if releases[release_id]["distribution"] != base_id:
                    raise ManifestError("%s maps to release %r outside lineage distribution" % (path, release_id))
                previous = mapped_targets.get((distro_id, source_codename))
                if previous is not None and previous != release_id:
                    raise ManifestError("%s has ambiguous target for %s" % (path, source_codename))
                mapped_targets[(distro_id, source_codename)] = release_id
        else:
            if mapping_type != "rolling_lineage":
                raise ManifestError("%s rolling derivative requires rolling_lineage" % path)
            if "codename_map" in derivative or "base_version" in derivative or "mapping_source" in derivative:
                raise ManifestError("%s rolling derivative must not borrow a stable version" % path)
            _require_bool(derivative.get("base_version_gating"), path + ".base_version_gating")
            if derivative["base_version_gating"]:
                raise ManifestError("%s rolling derivative must disable base_version_gating" % path)
    for start in graph:
        seen = set()
        current = start
        while current in graph:
            if current in seen:
                raise ManifestError("derivative cycle detected at %s" % current)
            seen.add(current)
            current = graph[current]


def _validate_protocols(manifest):
    protocols = manifest["protocols"]
    protocol_caps = manifest["capabilities"]["protocol_capabilities"]
    _require_object_ids(protocols, "protocols")
    for protocol_id, protocol in protocols.items():
        path = "protocols.%s" % protocol_id
        _require_obj(protocol, path)
        _reject_unknown_keys(protocol, _ENTITY_KEYS["protocol"], path)
        _require_enum(protocol.get("category"), ("resilient", "compatibility", "formal_non_green"), path + ".category")
        required = _require_id_list(protocol.get("required_protocol_capabilities"), path + ".required_protocol_capabilities")
        for cap_id in required:
            if cap_id not in protocol_caps:
                raise ManifestError("%s references unknown protocol capability %r" % (path, cap_id))
        _require_str(protocol.get("evidence_policy"), path + ".evidence_policy")


def _validate_certifications(manifest):
    certs = manifest["certifications"]
    distributions = manifest["distributions"]
    releases = manifest["releases"]
    protocols = manifest["protocols"]
    _require_object_ids(certs, "certifications")
    for cert_id, cert in certs.items():
        path = "certifications.%s" % cert_id
        _require_obj(cert, path)
        _reject_unknown_keys(cert, _ENTITY_KEYS["certification"], path)
        distro_id = _require_id(cert.get("distribution"), path + ".distribution")
        if distro_id not in distributions:
            raise ManifestError("%s references unknown distribution %r" % (path, distro_id))
        has_release = "release" in cert
        has_snapshot = "snapshot" in cert
        if has_release == has_snapshot:
            raise ManifestError("%s must contain exactly one of release or snapshot" % path)
        distro_model = distributions[distro_id]["release_model"]
        if distro_model == "stable" and not has_release:
            raise ManifestError("%s stable distribution certification must reference release" % path)
        if distro_model == "rolling" and not has_snapshot:
            raise ManifestError("%s rolling distribution certification must reference snapshot" % path)
        if has_release:
            release_id = _require_id(cert["release"], path + ".release")
            if release_id not in releases:
                raise ManifestError("%s references unknown release %r" % (path, release_id))
            if releases[release_id]["distribution"] != distro_id:
                raise ManifestError("%s release does not belong to distribution" % path)
        else:
            _require_str(cert["snapshot"], path + ".snapshot")
        _require_rfc3339_utc(cert.get("date"), path + ".date")
        _require_enum(cert.get("scope"), _CERTIFICATION_SCOPES, path + ".scope")
        _require_str(cert.get("evidence"), path + ".evidence")
        _require_bool(cert.get("current"), path + ".current")
        results = _require_obj(cert.get("protocol_results"), path + ".protocol_results")
        if "protocols_included" in cert:
            raise ManifestError("%s must store per-protocol results, not protocols_included" % path)
        if cert["scope"] == "physical_field_certification" and not results:
            raise ManifestError("%s physical certification must include protocol results" % path)
        seen = set()
        for protocol_id, result in results.items():
            _require_id(protocol_id, path + ".protocol_results key")
            if protocol_id in seen:
                raise ManifestError("%s duplicate protocol result %r" % (path, protocol_id))
            seen.add(protocol_id)
            if protocol_id not in protocols:
                raise ManifestError("%s references unknown protocol %r" % (path, protocol_id))
            result_path = "%s.protocol_results.%s" % (path, protocol_id)
            _require_obj(result, result_path)
            _reject_unknown_keys(result, _ENTITY_KEYS["protocol_result"], result_path)
            disposition = _require_enum(result.get("disposition"), _PROTOCOL_DISPOSITIONS, result_path + ".disposition")
            if disposition in ("green", "formal_non_green", "failed") and not result.get("evidence"):
                raise ManifestError("%s disposition %s requires evidence" % (result_path, disposition))
            if "evidence" in result and result["evidence"] is not None:
                _require_str(result["evidence"], result_path + ".evidence")
        if cert["current"] and cert["scope"] == "physical_field_certification":
            reason = _certification_qualification_error(manifest, cert_id)
            if reason is not None:
                raise ManifestError("%s does not qualify for support: %s" % (path, reason))


def _validate_certification_review_policy(metadata):
    policy = _require_obj(
        metadata.get("certification_review_policy"), "validation_metadata.certification_review_policy"
    )
    _reject_unknown_keys(
        policy, _ENTITY_KEYS["certification_review_policy"], "validation_metadata.certification_review_policy"
    )
    review_due = _require_positive_int(
        policy.get("review_due_seconds"), "validation_metadata.certification_review_policy.review_due_seconds"
    )
    review_overdue = _require_positive_int(
        policy.get("review_overdue_seconds"),
        "validation_metadata.certification_review_policy.review_overdue_seconds",
    )
    if review_due >= review_overdue:
        raise ManifestError(
            "validation_metadata.certification_review_policy.review_due_seconds "
            "must be strictly less than review_overdue_seconds"
        )


def _validate_validation_metadata(manifest):
    metadata = _require_obj(manifest["validation_metadata"], "validation_metadata")
    _reject_unknown_keys(
        metadata,
        ("rolling_policies", "repository_ci", "per_release_ci", "doc_generation", "certification_review_policy"),
        "validation_metadata",
    )
    _validate_certification_review_policy(metadata)
    rolling = _require_obj(metadata.get("rolling_policies"), "validation_metadata.rolling_policies")
    distributions = manifest["distributions"]
    certifications = manifest["certifications"]
    if "default" not in rolling:
        raise ManifestError("validation_metadata.rolling_policies missing default")
    for key, policy in rolling.items():
        policy_path = "validation_metadata.rolling_policies.%s" % key
        _require_obj(policy, policy_path)
        _reject_unknown_keys(policy, _ENTITY_KEYS["rolling_policy_metadata"], policy_path)
        _require_positive_int(policy.get("expiry_seconds"), "validation_metadata.rolling_policies.%s.expiry_seconds" % key)
        if "last_validated" in policy and policy["last_validated"] is not None:
            _require_rfc3339_utc(policy["last_validated"], "validation_metadata.rolling_policies.%s.last_validated" % key)
        for cert_id in _require_id_list(
            policy.get("evidence_refs", []),
            "validation_metadata.rolling_policies.%s.evidence_refs" % key,
            allow_empty=True,
        ):
            if cert_id not in certifications:
                raise ManifestError("rolling policy %s references unknown certification %r" % (key, cert_id))
            cert = certifications[cert_id]
            if key != "default" and cert["distribution"] != key:
                raise ManifestError("rolling policy %s references certification for %s" % (key, cert["distribution"]))
            if key != "default" and not certification_qualifies_for_support(manifest, cert_id):
                raise ManifestError(
                    "rolling policy %s references non-qualifying certification %r"
                    % (key, cert_id)
                )
        if key != "default" and key not in distributions:
            raise ManifestError("rolling policy references unknown distribution %r" % key)
        if key != "default" and distributions[key]["release_model"] != "rolling":
            raise ManifestError("rolling policy %s does not reference a rolling distribution" % key)
        if key != "default":
            distro_policy = distributions[key]["policy"]["rolling"]
            if policy["expiry_seconds"] != distro_policy["evidence_expiry_seconds"]:
                raise ManifestError("rolling policy %s expiry diverges from distribution policy" % key)
            policy_last = policy.get("last_validated")
            distro_last = distro_policy.get("last_validated")
            if policy_last != distro_last:
                raise ManifestError("rolling policy %s last_validated diverges from distribution policy" % key)
            qualifying_refs = _rolling_certifications(manifest, key)
            policy_refs = sorted(policy.get("evidence_refs", []))
            if policy_refs != qualifying_refs:
                raise ManifestError(
                    "rolling policy %s evidence_refs must equal qualifying certifications" % key
                )
            if qualifying_refs:
                latest = max(certifications[cert_id]["date"] for cert_id in qualifying_refs)
                if policy_last != latest:
                    raise ManifestError(
                        "rolling policy %s last_validated must equal latest qualifying certification date"
                        % key
                    )
            elif policy_last is not None:
                raise ManifestError(
                    "rolling policy %s has last_validated without qualifying certification" % key
                )
    for distro_id, distro in distributions.items():
        if distro["release_model"] == "rolling" and distro_id not in rolling and "default" not in rolling:
            raise ManifestError("rolling distribution %s has no resolvable policy" % distro_id)
    repo_ci = _require_obj(metadata.get("repository_ci"), "validation_metadata.repository_ci")
    _reject_unknown_keys(repo_ci, _ENTITY_KEYS["repository_ci"], "validation_metadata.repository_ci")
    _require_bool(repo_ci.get("latest_known_green"), "validation_metadata.repository_ci.latest_known_green")
    _require_str(repo_ci.get("scope"), "validation_metadata.repository_ci.scope")
    _require_str(repo_ci.get("evidence"), "validation_metadata.repository_ci.evidence")
    per_release = _require_obj(metadata.get("per_release_ci"), "validation_metadata.per_release_ci")
    for release_id, ci in per_release.items():
        if release_id not in manifest["releases"]:
            raise ManifestError("per_release_ci references unknown release %r" % release_id)
        ci_path = "validation_metadata.per_release_ci.%s" % release_id
        _require_obj(ci, ci_path)
        _reject_unknown_keys(ci, _ENTITY_KEYS["per_release_ci"], ci_path)
        status = _require_enum(ci.get("status"), _PER_RELEASE_CI_STATUSES, ci_path + ".status")
        _require_bool(ci.get("l1_l2_green"), ci_path + ".l1_l2_green")
        if status == "green" and ci["l1_l2_green"] is not True:
            raise ManifestError("%s green status requires l1_l2_green=true" % ci_path)
        if status != "green" and ci["l1_l2_green"] is True:
            raise ManifestError("%s l1_l2_green=true requires status green" % ci_path)
        if ci.get("evidence") is not None:
            _require_str(ci["evidence"], ci_path + ".evidence")
    for release_id in manifest["releases"]:
        if release_id not in per_release:
            raise ManifestError("per_release_ci missing release %r" % release_id)
    doc_generation = _require_obj(metadata.get("doc_generation"), "validation_metadata.doc_generation")
    _reject_unknown_keys(doc_generation, _ENTITY_KEYS["doc_generation"], "validation_metadata.doc_generation")
    _require_bool(doc_generation.get("public_claims_generated"), "validation_metadata.doc_generation.public_claims_generated")
    _require_str(doc_generation.get("reason"), "validation_metadata.doc_generation.reason")


def validate_manifest(manifest):
    try:
        _require_obj(manifest, "manifest")
        _walk_no_calculated_states(manifest, "manifest")
        _check_required_top_level(manifest)
        _validate_documentation_schema(manifest)
        if _schema_major(manifest["schema_version"]) != SUPPORTED_SCHEMA_MAJOR:
            raise ManifestError("unsupported schema major: %s" % manifest["schema_version"])
        for section in _REQUIRED_TOP_LEVEL:
            if section != "schema_version":
                _require_obj(manifest[section], section)
        # Phase 1: local structure, required fields and strict primitive types.
        _validate_metadata(manifest)
        _validate_capabilities(manifest)
        _validate_provisioning_methods(manifest)
        _check_unique_entity_ids(manifest)
        _validate_distributions(manifest)
        _validate_technical_families(manifest)
        _validate_protocols(manifest)
        _validate_releases_structure(manifest)
        _validate_certifications(manifest)
        _validate_dependency_requirements(manifest)
        # Phase 2: cross-section metadata and derived semantic invariants.
        _validate_validation_metadata(manifest)
        _validate_releases_semantics(manifest)
        _validate_derivatives(manifest)
    except ManifestError:
        raise
    except (KeyError, TypeError, IndexError) as exc:
        raise ManifestError("invalid manifest structure: %s" % exc)
    return True


def _resolve_path(document, query):
    current = document
    if query == "":
        return current
    for segment in query.split("."):
        if type(current) is dict:
            if segment not in current:
                raise QueryError(query)
            current = current[segment]
        elif type(current) is list:
            try:
                index = int(segment)
            except ValueError:
                raise QueryError(query)
            try:
                current = current[index]
            except IndexError:
                raise QueryError(query)
        else:
            raise QueryError(query)
    return current


def _stable_facts(manifest, release_id):
    releases = manifest["releases"]
    if release_id not in releases:
        raise QueryError(release_id)
    release = releases[release_id]
    facts = _derive_stable_facts(manifest, release_id)
    return {
        "model": "stable",
        "release": release_id,
        "distribution": release["distribution"],
        "facts": facts,
    }


def _rolling_facts(manifest, distro_id):
    distributions = manifest["distributions"]
    if distro_id not in distributions:
        raise QueryError(distro_id)
    distro = distributions[distro_id]
    if distro["release_model"] != "rolling":
        raise QueryError(distro_id)
    policy = manifest["validation_metadata"]["rolling_policies"].get(distro_id, {})
    default_policy = manifest["validation_metadata"]["rolling_policies"].get("default", {})
    rolling_policy = distro["policy"]["rolling"]
    qualifying_certs = _rolling_certifications(manifest, distro_id)
    last_validated = policy.get("last_validated", rolling_policy.get("last_validated"))
    expiry = policy.get("expiry_seconds", rolling_policy.get("evidence_expiry_seconds", default_policy.get("expiry_seconds")))
    facts = {
        "has_adapter": True,
        "meets_technical_floor": _require_bool(rolling_policy.get("meets_technical_floor"), "rolling.meets_technical_floor"),
        "expressly_excluded": _require_bool(rolling_policy.get("expressly_excluded"), "rolling.expressly_excluded"),
        "eol_or_withdrawn": _require_bool(rolling_policy.get("eol_or_withdrawn"), "rolling.eol_or_withdrawn"),
        "is_derivative": distro["lineage"]["is_derivative"],
        "has_own_evidence": distro["lineage"]["has_own_evidence"],
        "family_inference_allowed": distro["lineage"]["family_inference_allowed"],
        "has_valid_field_certification": bool(qualifying_certs),
        "family_has_certified_anchor": _family_has_current_certification(manifest, distro["technical_family"]),
        "last_validated": _normalize_rfc3339_utc_to_naive(last_validated) if last_validated else None,
    }
    return {
        "model": "rolling",
        "distribution": distro_id,
        "expiry_seconds": expiry,
        "facts": facts,
    }


def _json_dump(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def build_parser():
    parser = argparse.ArgumentParser(description="Validate and query WatchdogVPN compatibility manifest")
    parser.add_argument(
        "--manifest",
        default=DEFAULT_MANIFEST_PATH,
        help="manifest path (default: compat/compatibility.json)",
    )
    parser.add_argument(
        "--product-path",
        action="store_true",
        help="enforce product-path safety checks, including rejecting symlinks",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("validate", help="validate manifest and print JSON status")
    get_parser = subparsers.add_parser("get", help="get a dotted manifest path")
    get_parser.add_argument("path")
    list_parser = subparsers.add_parser("list", help="list keys under a dotted object path")
    list_parser.add_argument("path")
    ref_parser = subparsers.add_parser("resolve-reference", help="resolve section/id reference")
    ref_parser.add_argument("section")
    ref_parser.add_argument("id")
    facts_parser = subparsers.add_parser("facts", help="emit support-model-compatible fact data")
    facts_parser.add_argument("kind", choices=("stable-release", "rolling-distribution"))
    facts_parser.add_argument("id")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_usage(sys.stderr)
        return EXIT_USAGE
    product_path = args.product_path or os.path.abspath(args.manifest) == DEFAULT_MANIFEST_PATH
    try:
        manifest = load_manifest_file(args.manifest, product_path=product_path)
        validate_manifest(manifest)
        if args.command == "validate":
            print(_json_dump({"ok": True, "schema_version": manifest["schema_version"]}))
            return 0
        if args.command == "get":
            print(_json_dump(_resolve_path(manifest, args.path)))
            return 0
        if args.command == "list":
            value = _resolve_path(manifest, args.path)
            if type(value) is not dict:
                raise QueryError(args.path)
            print(_json_dump(sorted(value.keys())))
            return 0
        if args.command == "resolve-reference":
            section = _resolve_path(manifest, args.section)
            if type(section) is not dict or args.id not in section:
                raise QueryError("%s.%s" % (args.section, args.id))
            print(_json_dump(section[args.id]))
            return 0
        if args.command == "facts":
            if args.kind == "stable-release":
                print(_json_dump(_stable_facts(manifest, args.id)))
            else:
                print(_json_dump(_rolling_facts(manifest, args.id)))
            return 0
        raise QueryError(args.command)
    except ManifestError as exc:
        print("compatibility manifest invalid: %s" % exc, file=sys.stderr)
        return EXIT_INVALID_MANIFEST
    except QueryError as exc:
        print("compatibility manifest query not found: %s" % exc, file=sys.stderr)
        return EXIT_NOT_FOUND


if __name__ == "__main__":
    sys.exit(main())
