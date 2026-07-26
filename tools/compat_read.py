#!/usr/bin/env python3
"""Bootstrap reader and strict validator for the compatibility manifest.

This script is intentionally stdlib-only and Python 3.6 compatible. It must not
import ``compat`` or any product module that may require the final runtime
Python floor; installers need this reader before that runtime is prepared.
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
    "provisioning_methods",
    "protocols",
    "certifications",
    "validation_metadata",
)

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
    "is_derivative_without_own_evidence",
    "has_valid_field_certification",
    "family_has_certified_anchor",
)

_ROLLING_FACT_KEYS = (
    "has_adapter",
    "meets_technical_floor",
    "expressly_excluded",
    "eol_or_withdrawn",
    "is_derivative_without_own_evidence",
    "has_valid_field_certification",
)


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


def _require_object_ids(obj, path):
    _require_obj(obj, path)
    for key in obj:
        _require_id(key, "%s key" % path)


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
        if key not in _REQUIRED_TOP_LEVEL and key != "metadata":
            raise ManifestError("unknown top-level section: %s" % key)


def _check_unique_entity_ids(manifest):
    owners = {}
    sections = (
        "technical_families",
        "distributions",
        "releases",
        "derivatives",
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
    if "bootstrap_python_min" in metadata:
        if _require_str(metadata["bootstrap_python_min"], "metadata.bootstrap_python_min") != BOOTSTRAP_PYTHON_MIN:
            raise ManifestError("metadata.bootstrap_python_min must be %s" % BOOTSTRAP_PYTHON_MIN)
    if "max_manifest_bytes" in metadata:
        limit = _require_positive_int(metadata["max_manifest_bytes"], "metadata.max_manifest_bytes")
        if limit != MAX_MANIFEST_BYTES:
            raise ManifestError("metadata.max_manifest_bytes must be %d" % MAX_MANIFEST_BYTES)


def _validate_technical_families(manifest):
    families = manifest["technical_families"]
    methods = manifest["provisioning_methods"]
    caps = manifest["capabilities"]["core_host_capabilities"]
    _require_object_ids(families, "technical_families")
    for family_id, family in families.items():
        path = "technical_families.%s" % family_id
        _require_obj(family, path)
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
        _require_enum(
            cap.get("type"),
            ("required", "alternative", "optional", "provisionable", "incompatible", "diagnostic_only"),
            path + ".type",
        )
        _require_str(cap.get("description"), path + ".description")
    for cap_id, cap in capabilities["protocol_capabilities"].items():
        path = "capabilities.protocol_capabilities.%s" % cap_id
        _require_obj(cap, path)
        _require_enum(cap.get("type"), ("provisionable", "required", "optional"), path + ".type")
        _require_str(cap.get("description"), path + ".description")


def _validate_provisioning_methods(manifest):
    methods = manifest["provisioning_methods"]
    _require_object_ids(methods, "provisioning_methods")
    for method_id, method in methods.items():
        path = "provisioning_methods.%s" % method_id
        _require_obj(method, path)
        _require_enum(
            method.get("kind"),
            ("official_package", "external_repo_exact", "official_artifact", "pinned_source_build", "diagnostic_only"),
            path + ".kind",
        )
        _require_bool(method.get("exact_release_required"), path + ".exact_release_required")
        _require_bool(method.get("mutates_system"), path + ".mutates_system")
        _require_str(method.get("provenance"), path + ".provenance")


def _validate_distributions(manifest):
    distributions = manifest["distributions"]
    families = manifest["technical_families"]
    _require_object_ids(distributions, "distributions")
    for distro_id, distro in distributions.items():
        path = "distributions.%s" % distro_id
        _require_obj(distro, path)
        if _require_id(distro.get("id"), path + ".id") != distro_id:
            raise ManifestError("%s.id must match its object key" % path)
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
            for field in ("admitted_releases", "pending_releases", "excluded_releases"):
                _require_id_list(stable.get(field), path + ".policy.stable." + field, allow_empty=True)
            if "minimum_version" in stable:
                raise ManifestError("%s must not encode support as a continuous range" % path)
        else:
            rolling = _require_obj(policy.get("rolling"), path + ".policy.rolling")
            if "minimum_version" in rolling:
                raise ManifestError("%s rolling policy must not declare a numeric minimum" % path)
            if "last_validated" in rolling and rolling["last_validated"] is not None:
                _require_rfc3339_utc(rolling["last_validated"], path + ".policy.rolling.last_validated")
            if "evidence_expiry_seconds" in rolling:
                _require_positive_int(rolling["evidence_expiry_seconds"], path + ".policy.rolling.evidence_expiry_seconds")


def _validate_stable_facts(facts, path):
    _require_obj(facts, path)
    for key in _STABLE_FACT_KEYS:
        if key not in facts:
            raise ManifestError("%s missing fact %s" % (path, key))
        _require_bool(facts[key], "%s.%s" % (path, key))
    for key in facts:
        if key not in _STABLE_FACT_KEYS:
            raise ManifestError("%s has unknown stable fact %s" % (path, key))
    if facts["admitted"] and facts["expressly_excluded"]:
        raise ManifestError("%s cannot be both admitted and expressly_excluded" % path)
    if facts["admitted"] and facts["future_or_unevaluated"]:
        raise ManifestError("%s cannot be both admitted and future_or_unevaluated" % path)
    if facts["admitted"] and facts["eol_or_withdrawn"]:
        raise ManifestError("%s cannot be both admitted and eol_or_withdrawn" % path)
    if facts["has_valid_field_certification"] and facts["is_derivative_without_own_evidence"]:
        raise ManifestError("%s cannot certify a derivative without own evidence" % path)


def _validate_releases(manifest):
    releases = manifest["releases"]
    distributions = manifest["distributions"]
    certifications = manifest["certifications"]
    _require_object_ids(releases, "releases")
    by_distro = {}
    for release_id, release in releases.items():
        path = "releases.%s" % release_id
        _require_obj(release, path)
        distro_id = _require_id(release.get("distribution"), path + ".distribution")
        if distro_id not in distributions:
            raise ManifestError("%s references unknown distribution %r" % (path, distro_id))
        if distributions[distro_id]["release_model"] != "stable":
            raise ManifestError("%s belongs to rolling distribution %r" % (path, distro_id))
        _require_str(release.get("version"), path + ".version")
        _require_enum(release.get("policy_state"), ("admitted", "pending_evaluation", "excluded"), path + ".policy_state")
        _validate_stable_facts(release.get("stable_facts"), path + ".stable_facts")
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
        distro_id = _require_id(derivative.get("distribution"), path + ".distribution")
        if distro_id not in distributions:
            raise ManifestError("%s references unknown distribution %r" % (path, distro_id))
        base_id = _require_id(derivative.get("lineage_distribution"), path + ".lineage_distribution")
        if base_id not in distributions:
            raise ManifestError("%s references unknown lineage distribution %r" % (path, base_id))
        graph[distro_id] = base_id
        model = distributions[distro_id]["release_model"]
        mapping_type = _require_enum(derivative.get("mapping_type"), ("codename_map", "rolling_lineage"), path + ".mapping_type")
        if model == "stable":
            if mapping_type != "codename_map":
                raise ManifestError("%s stable derivative requires codename_map" % path)
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
            if "codename_map" in derivative or "base_version" in derivative:
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
        distro_id = _require_id(cert.get("distribution"), path + ".distribution")
        if distro_id not in distributions:
            raise ManifestError("%s references unknown distribution %r" % (path, distro_id))
        if "release" in cert:
            release_id = _require_id(cert["release"], path + ".release")
            if release_id not in releases:
                raise ManifestError("%s references unknown release %r" % (path, release_id))
            if releases[release_id]["distribution"] != distro_id:
                raise ManifestError("%s release does not belong to distribution" % path)
        elif "snapshot" in cert:
            _require_str(cert["snapshot"], path + ".snapshot")
        else:
            raise ManifestError("%s must reference a release or snapshot" % path)
        _require_rfc3339_utc(cert.get("date"), path + ".date")
        _require_str(cert.get("scope"), path + ".scope")
        _require_str(cert.get("evidence"), path + ".evidence")
        _require_bool(cert.get("current"), path + ".current")
        included = _require_id_list(cert.get("protocols_included"), path + ".protocols_included")
        for protocol_id in included:
            if protocol_id not in protocols:
                raise ManifestError("%s references unknown protocol %r" % (path, protocol_id))


def _validate_validation_metadata(manifest):
    metadata = _require_obj(manifest["validation_metadata"], "validation_metadata")
    rolling = _require_obj(metadata.get("rolling_policies"), "validation_metadata.rolling_policies")
    distributions = manifest["distributions"]
    certifications = manifest["certifications"]
    for key, policy in rolling.items():
        _require_obj(policy, "validation_metadata.rolling_policies.%s" % key)
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
        if key != "default" and key not in distributions:
            raise ManifestError("rolling policy references unknown distribution %r" % key)
    ci = _require_obj(metadata.get("ci_status"), "validation_metadata.ci_status")
    for release_id, status in ci.items():
        if release_id not in manifest["releases"]:
            raise ManifestError("ci_status references unknown release %r" % release_id)
        _require_bool(status, "validation_metadata.ci_status.%s" % release_id)


def validate_manifest(manifest):
    _require_obj(manifest, "manifest")
    _walk_no_calculated_states(manifest, "manifest")
    _check_required_top_level(manifest)
    if _schema_major(manifest["schema_version"]) != SUPPORTED_SCHEMA_MAJOR:
        raise ManifestError("unsupported schema major: %s" % manifest["schema_version"])
    for section in _REQUIRED_TOP_LEVEL:
        if section != "schema_version":
            _require_obj(manifest[section], section)
    _validate_metadata(manifest)
    _validate_capabilities(manifest)
    _validate_provisioning_methods(manifest)
    _check_unique_entity_ids(manifest)
    _validate_distributions(manifest)
    _validate_technical_families(manifest)
    _validate_protocols(manifest)
    _validate_certifications(manifest)
    _validate_releases(manifest)
    _validate_derivatives(manifest)
    _validate_validation_metadata(manifest)
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
    facts = release["stable_facts"].copy()
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
    last_validated = policy.get("last_validated", rolling_policy.get("last_validated"))
    expiry = policy.get("expiry_seconds", rolling_policy.get("evidence_expiry_seconds", default_policy.get("expiry_seconds")))
    facts = {
        "has_adapter": True,
        "meets_technical_floor": _require_bool(rolling_policy.get("meets_technical_floor"), "rolling.meets_technical_floor"),
        "expressly_excluded": _require_bool(rolling_policy.get("expressly_excluded"), "rolling.expressly_excluded"),
        "eol_or_withdrawn": _require_bool(rolling_policy.get("eol_or_withdrawn"), "rolling.eol_or_withdrawn"),
        "is_derivative_without_own_evidence": _require_bool(
            rolling_policy.get("is_derivative_without_own_evidence"),
            "rolling.is_derivative_without_own_evidence",
        ),
        "has_valid_field_certification": _require_bool(
            rolling_policy.get("has_valid_field_certification"),
            "rolling.has_valid_field_certification",
        ),
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
