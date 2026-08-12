"""Real focused L2 dependency checks.

Set WATCHDOGVPN_REAL_L2=1 to run these against disposable Docker/Podman
containers. Metadata refreshes, when required, happen only inside containers.
These checks do not certify kernel, TUN, firewall or protocol behavior.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
import unittest
from datetime import datetime
from unittest import mock

from compat import dependency_resolution as resolver
from compat import detection
from tools.compat_l2_reporter import dnf_repository_series_path


REAL_L2_ENABLED = os.environ.get("WATCHDOGVPN_REAL_L2") == "1"
TIMEOUT_SECONDS = 120
OUTPUT_LIMIT = 12000
CONTROLLED_MANAGERS = frozenset(("apt-get", "dnf", "zypper", "pacman"))

# Markers used only to interpret already-failed (non-zero/exception) results.
# A parser never overrides a runtime_status of "timeout" or "runtime_error"
# coming from the process layer itself (subprocess.TimeoutExpired / OSError);
# these lists only disambiguate a non-zero returncode that DID execute.
RUNTIME_INFRA_ERROR_MARKERS = (
    "no such container",
    "is not running",
    "oci runtime exec failed",
    "oci runtime create failed",
    "unable to start container process",
    "cannot connect to the docker daemon",
)
MISSING_CONTAINER_MARKERS = ("no such container",)
# Only unambiguous manifest-absence phrasing may ever produce image_not_found.
# Generic phrases such as "manifest for", "repository does not exist" or
# "no such image" are deliberately excluded: real registries reuse them for
# both a genuinely missing image AND an unauthenticated/private one, so they
# are not sufficient proof on their own.
PULL_IMAGE_NOT_FOUND_MARKERS = (
    "manifest unknown",
    "not found: manifest",
)
PULL_AUTH_MARKERS = (
    "unauthorized",
    "authentication required",
    "docker login",
    "podman login",
    "no basic auth credentials",
)
PULL_REGISTRY_MARKERS = (
    "no such host",
    "dial tcp",
    "connection refused",
    "tls handshake",
    "tls",
    "i/o timeout",
    "timeout",
    "temporary failure in name resolution",
    "dns",
    "network is unreachable",
    "network unreachable",
    "context deadline exceeded",
)
# POSIX only guarantees a non-zero exit status for "command -v" when the
# target is not found; it does not fix the exact value. 1 and 127 are the
# clean, no-output results admitted here as a demonstrated absence for the
# shell implementations this contract covers (dash, bash and similar
# POSIX-compatible shells), not "the exact POSIX code".
MANAGER_NOT_FOUND_RETURNCODES = frozenset((1, 127))


CASES = (
    {"target": "ubuntu_24_04", "image": "ubuntu:24.04", "id": "ubuntu", "codename": "noble", "manager": "apt-get", "packages": ("python3", "openvpn"), "kind": "apt"},
    {"target": "ubuntu_26_04", "image": "ubuntu:26.04", "id": "ubuntu", "codename": "resolute", "manager": "apt-get", "packages": ("python3", "openvpn"), "kind": "apt", "optional_image": True},
    {"target": "debian_13", "image": "debian:13", "id": "debian", "codename": "trixie", "manager": "apt-get", "packages": ("python3", "openvpn"), "kind": "apt"},
    {"target": "fedora_44", "image": "fedora:44", "id": "fedora", "codename": None, "manager": "dnf", "packages": ("python3", "openvpn"), "kind": "dnf"},
    {"target": "rocky_9", "image": "rockylinux:9", "id": "rocky", "codename": None, "manager": "dnf", "packages": ("python3.11", "epel-release", "openvpn"), "kind": "dnf", "architecture": "x86_64", "repository_id": "epel_9", "series": "epel9", "epel_repo_url": "https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/", "refresh": "true"},
    {"target": "opensuse_leap_15_6", "image": "opensuse/leap:15.6", "id": "opensuse-leap", "codename": None, "manager": "zypper", "packages": ("python311", "openvpn"), "kind": "zypper"},
    {"target": "arch", "image": "archlinux:latest", "id": "arch", "codename": None, "manager": "pacman", "packages": ("python", "openvpn"), "kind": "pacman", "refresh": "pacman -Sy --noconfirm"},
)


def _runtime() -> str | None:
    for name in ("podman", "docker"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _run(runtime: str, args: list[str], *, timeout: int = TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    return subprocess.run([runtime] + args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout)


def _trim(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[:OUTPUT_LIMIT]


def _looks_like(markers: tuple[str, ...], *texts: str) -> bool:
    haystack = "\n".join((text or "") for text in texts).lower()
    return any(marker in haystack for marker in markers)


def _looks_like_runtime_infra_error(stderr: str) -> bool:
    return _looks_like(RUNTIME_INFRA_ERROR_MARKERS, stderr)


def _looks_like_missing_container_error(stderr: str) -> bool:
    return _looks_like(MISSING_CONTAINER_MARKERS, stderr)


def _phase(status: str) -> dict:
    """Build a not-yet-executed phase stub with the full evidence contract."""
    return {
        "status": status,
        "runtime_status": "not_run",
        "semantic_status": None,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "reason": "",
    }


def _run_phase(runtime: str, args: list[str], *, timeout: int = TIMEOUT_SECONDS) -> dict:
    """Execute a runtime command and return raw process-level evidence only.

    This never inspects stdout/stderr content: runtime_status distinguishes
    "the process could not be run to completion" (timeout, runtime_error)
    from "executed" (a returncode exists, content may now be interpreted).
    """
    try:
        completed = _run(runtime, args, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {"runtime_status": "timeout", "returncode": None, "stdout": _trim(exc.stdout), "stderr": _trim(exc.stderr)}
    except OSError as exc:
        return {"runtime_status": "runtime_error", "returncode": None, "stdout": "", "stderr": str(exc)}
    return {"runtime_status": "executed", "returncode": completed.returncode, "stdout": _trim(completed.stdout), "stderr": _trim(completed.stderr)}


def _finalize(phase: dict, status: str, reason: str) -> dict:
    """Merge a classifier's verdict into a raw phase, preserving semantic_status
    as None whenever the process itself never reached completion."""
    phase["status"] = status
    phase["reason"] = reason
    phase["semantic_status"] = status if phase.get("runtime_status") == "executed" else None
    return phase


def _looks_like_unambiguous_image_not_found(stdout: str, stderr: str, image: str | None) -> bool:
    if _looks_like(PULL_IMAGE_NOT_FOUND_MARKERS, stdout, stderr):
        return True
    if not image:
        return False
    haystack = ((stdout or "") + "\n" + (stderr or "")).lower()
    return "manifest" in haystack and "not found" in haystack and image.lower() in haystack


def classify_pull_result(phase: dict, image: str | None = None) -> tuple[str, str]:
    if phase["runtime_status"] == "timeout":
        return "timeout", "image pull timed out"
    if phase["runtime_status"] == "runtime_error":
        return "runtime_error", "container runtime failed before the image pull completed"
    if phase["returncode"] == 0:
        return "available", "image pulled successfully"
    stdout, stderr = phase.get("stdout") or "", phase.get("stderr") or ""
    # Precedence matters: an infrastructure failure, an authentication
    # requirement or a registry/network problem must never be shadowed by an
    # image-not-found marker that happens to co-occur in the same message
    # (real registries routinely combine both in one error string).
    if _looks_like_runtime_infra_error(stderr):
        return "runtime_error", "container runtime reported an infrastructure error during pull"
    if _looks_like(PULL_AUTH_MARKERS, stdout, stderr):
        return "authentication_error", "registry requires authentication"
    if _looks_like(PULL_REGISTRY_MARKERS, stdout, stderr):
        return "registry_error", "registry or network connectivity failed"
    if _looks_like_unambiguous_image_not_found(stdout, stderr, image):
        return "image_not_found", "registry unambiguously reported the image or manifest does not exist"
    return "unknown", "image pull failed for an unrecognized reason"


def classify_lifecycle_phase(phase: dict, *, verb: str) -> tuple[str, str]:
    if phase["runtime_status"] == "timeout":
        return "timeout", "container %s timed out" % verb
    if phase["runtime_status"] == "runtime_error":
        return "runtime_error", "container runtime failed during %s" % verb
    if phase["returncode"] == 0:
        return "available", "container %s completed" % verb
    if _looks_like_runtime_infra_error(phase.get("stderr") or ""):
        return "runtime_error", "container runtime reported an infrastructure error during %s" % verb
    return "unknown", "container %s failed" % verb


def classify_os_release(phase: dict, case: dict) -> tuple[str, str]:
    if phase["runtime_status"] == "timeout":
        return "timeout", "os-release read timed out"
    if phase["runtime_status"] == "runtime_error":
        return "runtime_error", "container runtime failed before os-release could be read"
    if phase["returncode"] != 0:
        if _looks_like_runtime_infra_error(phase.get("stderr") or ""):
            return "runtime_error", "container runtime reported an infrastructure error while reading os-release"
        return "unknown", "os-release read command failed"
    values = _extract_os_release(phase.get("stdout") or "")
    if values.get("ID") != case["id"]:
        return "malformed_response", "ID mismatch"
    release = detection.load_product_manifest()["releases"].get(case["target"], {})
    expected_version_ids = tuple(release.get("os_release_version_ids") or ())
    if expected_version_ids and values.get("VERSION_ID") not in expected_version_ids:
        return "malformed_response", "VERSION_ID mismatch"
    expected_codename = case.get("codename")
    if expected_codename and values.get("VERSION_CODENAME") != expected_codename:
        return "malformed_response", "VERSION_CODENAME mismatch"
    return "available", "os-release identity matched"


def classify_package_manager(phase: dict) -> tuple[str, str]:
    if phase["runtime_status"] == "timeout":
        return "timeout", "manager lookup timed out"
    if phase["runtime_status"] == "runtime_error":
        return "runtime_error", "container runtime failed before manager lookup completed"
    returncode = phase["returncode"]
    stderr, stdout = phase.get("stderr") or "", phase.get("stdout") or ""
    if returncode != 0:
        if _looks_like_runtime_infra_error(stderr):
            return "runtime_error", "container runtime reported an infrastructure error during manager lookup"
        # Only a clean 1/127 with both streams truly empty counts as a
        # demonstrated absence. 126 (POSIX: "found but not executable") and
        # any 1/127 with non-empty output are inconclusive, not a proven
        # absence.
        if returncode in MANAGER_NOT_FOUND_RETURNCODES and not stdout.strip() and not stderr.strip():
            return "manager_unavailable", "package manager executable not found"
        return "unknown", "manager lookup failed with an unrecognized return code"
    if not stdout.strip():
        return "malformed_response", "package manager path was empty"
    return "available", "package manager path observed"


def classify_package_query(phase: dict, kind: str, package_name: str) -> tuple[str, str]:
    if phase["runtime_status"] == "timeout":
        return "timeout", "query timed out"
    if phase["runtime_status"] == "runtime_error":
        return "runtime_error", "container runtime failed before the package query completed"
    stdout, stderr, returncode = phase.get("stdout") or "", phase.get("stderr") or "", phase["returncode"]
    if returncode != 0 and _looks_like_runtime_infra_error(stderr):
        return "runtime_error", "container runtime reported an infrastructure error during package query"
    if kind == "apt":
        # "available" requires the full positive contract: the process
        # executed, exited zero, AND a real Candidate line was observed.
        # A non-zero returncode can never end in "available", even if
        # stdout happens to contain what looks like a valid Candidate line.
        if returncode != 0:
            if "Candidate: (none)" in stdout:
                return "unavailable", "APT candidate missing"
            return "unknown", "APT query failed with a non-zero return code"
        if "Candidate: (none)" in stdout:
            return "unavailable", "APT candidate missing"
        if "Candidate:" in stdout and package_name in stdout:
            return "available", "APT candidate present"
        return "malformed_response", "APT candidate metadata missing"
    if kind == "dnf":
        if returncode == 0 and package_name in stdout:
            return "available", "DNF package metadata present"
        if returncode != 0 and ("No matching" in stderr or "No matching" in stdout):
            return "unavailable", "DNF package missing"
        return "unknown", "DNF query inconclusive"
    if kind == "zypper":
        if returncode == 0 and package_name in stdout:
            return "available", "zypper package metadata present"
        if returncode == 0:
            return "unavailable", "zypper package missing"
        return "unknown", "zypper query inconclusive"
    if kind == "pacman":
        if returncode == 0 and ("Name" in stdout and package_name in stdout):
            return "available", "pacman package metadata present"
        if returncode != 0 and ("was not found" in stderr or "target not found" in stderr):
            return "unavailable", "pacman package missing"
        return "unknown", "pacman query inconclusive"
    return "malformed_response", "unknown package manager"


def aggregate_package_status(items: list[dict]) -> str:
    statuses = {item["status"] for item in items}
    if statuses == {"available"}:
        return "available"
    if "timeout" in statuses:
        return "timeout"
    if "runtime_error" in statuses:
        return "runtime_error"
    if "manager_unavailable" in statuses:
        return "unavailable"
    if "unknown" in statuses or "malformed_response" in statuses:
        return "unknown"
    return "unavailable"


def aggregate_dependency_status(decisions: list[dict]) -> str:
    if not decisions:
        return "unknown"
    statuses = {decision["resolution_status"] for decision in decisions}
    resolved = {"already_present", "method_selected", "recipe_not_implemented"}
    if statuses <= resolved:
        return "available"
    if "timeout" in statuses:
        return "timeout"
    if "internal_error" in statuses:
        return "runtime_error"
    if "availability_unknown" in statuses:
        return "unknown"
    if "no_safe_route" in statuses or "out_of_contract" in statuses:
        return "unavailable"
    return "unknown"


def combine_probe_statuses(*statuses: str) -> str:
    return aggregate_package_status([{"status": status} for status in statuses])


def compute_overall_status(probe_aggregate: str, cleanup: dict) -> str:
    """Fold cleanup outcome into a single gate-facing status without ever
    hiding or replacing the primary probe result. "cleaned" and "not_needed"
    (nothing existed to remove) are the only cleanup outcomes considered ok."""
    cleanup_ok = cleanup.get("status") in ("cleaned", "not_needed") and not cleanup.get("residual_possible")
    if cleanup_ok:
        return probe_aggregate
    if probe_aggregate == "available":
        return "cleanup_failed"
    return "%s_with_cleanup_failure" % probe_aggregate


def is_optional_image_exception(case: dict, result: dict) -> bool:
    """Only a demonstrated image_not_found pull result may excuse an
    optional_image target (currently Ubuntu 26.04). Any other pull failure
    (timeout, runtime_error, registry_error, authentication_error, unknown)
    must still fail the real L2 gate like every other target."""
    return bool(case.get("optional_image")) and result["pull"]["status"] == "image_not_found"


def _core_capability_result(capability_id: str) -> detection.CapabilityResult:
    return detection.CapabilityResult(capability_id, "partial", "provisionable", "fixture", "fixture", "fixture")


def _protocol_capability_result(capability_id: str) -> detection.CapabilityResult:
    return detection.CapabilityResult(capability_id, "absent", "provisionable", "fixture", "fixture", "fixture")


def _fixture_core_capabilities(manifest: dict, facts: detection.DistroFacts) -> tuple[detection.CapabilityResult, ...]:
    if facts.technical_family is None:
        family_caps = manifest["capabilities"]["core_host_capabilities"]
    else:
        family_caps = manifest["technical_families"][facts.technical_family]["core_capabilities"]
    return tuple(_core_capability_result(cap_id) for cap_id in sorted(family_caps))


def _fixture_protocol_capabilities(manifest: dict) -> tuple[detection.CapabilityResult, ...]:
    return tuple(
        _protocol_capability_result(cap_id)
        for cap_id in sorted(manifest["capabilities"]["protocol_capabilities"])
    )


def _all_fixture_capabilities(manifest: dict, facts: detection.DistroFacts) -> tuple[detection.CapabilityResult, ...]:
    return _fixture_core_capabilities(manifest, facts) + _fixture_protocol_capabilities(manifest)


_PACKAGE_QUERY_STATUS_TO_AVAILABILITY = {
    "available": resolver.AvailabilityStatus.AVAILABLE,
    "unavailable": resolver.AvailabilityStatus.UNAVAILABLE,
    "timeout": resolver.AvailabilityStatus.TIMEOUT,
    "runtime_error": resolver.AvailabilityStatus.PROVIDER_ERROR,
    "unknown": resolver.AvailabilityStatus.UNKNOWN,
    "malformed_response": resolver.AvailabilityStatus.MALFORMED_RESPONSE,
    "manager_unavailable": resolver.AvailabilityStatus.UNAVAILABLE,
}


def _availability_from_query(status: str, reason: str) -> resolver.AvailabilityObservation:
    enum_value = _PACKAGE_QUERY_STATUS_TO_AVAILABILITY.get(status, resolver.AvailabilityStatus.UNKNOWN)
    return resolver.AvailabilityObservation(enum_value.value, evidence=reason, reason=reason)


def _debian_repo_arch(machine_architecture: str | None) -> str:
    if machine_architecture == "x86_64":
        return "amd64"
    if machine_architecture == "aarch64":
        return "arm64"
    return machine_architecture or "amd64"


def _external_apt_packages_url(candidate_data: dict, machine_architecture: str | None) -> str | None:
    repo = candidate_data.get("repository", {})
    base_url = (repo.get("url") or "").rstrip("/")
    series = repo.get("series") or ""
    if not base_url or not series:
        return None
    arch = _debian_repo_arch(machine_architecture)
    return "%s/dists/%s/main/binary-%s/Packages.gz" % (base_url, series, arch)


def _external_apt_package_query_command(candidate_data: dict, package_name: str, machine_architecture: str | None) -> str | None:
    packages_url = _external_apt_packages_url(candidate_data, machine_architecture)
    if packages_url is None:
        return None
    tmp_var = "wdvpn_external_apt_packages"
    return (
        "%s=$(mktemp) || exit 2; "
        "trap 'rm -f \"$%s\"' EXIT; "
        "curl -fsSL --max-time 30 %s -o \"$%s\" || exit 2; "
        "gzip -t \"$%s\" || exit 2; "
        "gzip -dc \"$%s\" | grep -Fx %s"
        % (
            tmp_var,
            tmp_var,
            shlex.quote(packages_url),
            tmp_var,
            tmp_var,
            tmp_var,
            shlex.quote("Package: %s" % package_name),
        )
    )


def classify_external_apt_package_query(phase: dict, package_name: str) -> tuple[str, str]:
    if phase["runtime_status"] != "executed":
        return phase["runtime_status"], "external APT package index probe did not execute"
    if phase["returncode"] == 0:
        return "available", "external APT package %s listed" % package_name
    if phase["returncode"] == 1:
        return "unavailable", "external APT package %s missing" % package_name
    return "unknown", "external APT package index probe failed"


class ContainerAvailabilityProvider(resolver.AvailabilityProvider):
    """Injected availability provider that probes packages, repositories,
    source tags and pinned artifacts inside a running disposable container.
    The container identity, package manager kind and host architecture are
    taken from the L2 case and observed DistroFacts.
    """

    provider_type = "container_probe"
    authoritative = False

    def __init__(self, runtime: str, name: str, case: dict, facts: detection.DistroFacts):
        self._runtime = runtime
        self._name = name
        self._case = case
        self._facts = facts

    def _exec(self, command: str) -> dict:
        return _run_phase(self._runtime, ["exec", self._name, "sh", "-lc", command])

    def _curl_available(self) -> bool:
        phase = self._exec("command -v curl")
        return phase["runtime_status"] == "executed" and phase["returncode"] == 0

    def _head_url(self, url: str, evidence_prefix: str) -> resolver.AvailabilityObservation:
        if not self._curl_available():
            return resolver.AvailabilityObservation(
                resolver.AvailabilityStatus.UNKNOWN.value,
                evidence="curl not available in container for HEAD probe",
                reason="head_probe_tool_missing",
                error_kind="provider_error",
            )
        # Reintentar fallos transitorios de la sonda (timeouts, resets de
        # conexión, rate-limiting del runner) antes de concluir que el
        # artefacto no está disponible. Un 404 definitivo NO se reintenta:
        # significa que el artefacto genuinamente no existe y debe marcarse
        # como UNAVAILABLE de inmediato para no enmascarar fallos reales.
        # Se conserva el último error de curl para incluirlo en la evidencia
        # y poder diagnosticar fallos persistentes (p.ej. egress del runner).
        max_attempts = 5
        backoff_seconds = 3.0
        last_error = ""
        for attempt in range(1, max_attempts + 1):
            probe = self._exec("curl -I -L -f -sS --max-time 15 %s" % shlex.quote(url))
            if probe["runtime_status"] != "executed":
                last_error = "exec status=%s" % probe["runtime_status"]
                if attempt < max_attempts:
                    time.sleep(backoff_seconds * attempt)
                    continue
                return _availability_from_query(probe["runtime_status"], "%s HEAD probe did not execute" % evidence_prefix)
            if probe["returncode"] == 0:
                stdout = probe.get("stdout") or ""
                content_length = ""
                for line in stdout.splitlines():
                    if line.lower().startswith("content-length:"):
                        content_length = line.split(":", 1)[1].strip()
                        break
                return resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.AVAILABLE.value,
                    evidence="%s HEAD reachable: %s (Content-Length: %s)" % (evidence_prefix, url, content_length or "unknown"),
                    reason="%s_head_reachable" % evidence_prefix.replace(" ", "_"),
                )
            stderr = (probe.get("stderr") or "").lower()
            stdout = (probe.get("stdout") or "").lower()
            if "404" in stderr or "404" in stdout or "not found" in stderr or "not found" in stdout:
                return resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.UNAVAILABLE.value,
                    evidence="%s HEAD returned 404: %s" % (evidence_prefix, url),
                    reason="%s_not_found" % evidence_prefix.replace(" ", "_"),
                    error_kind="%s_not_found" % evidence_prefix.replace(" ", "_"),
                )
            last_error = "rc=%s stderr=%r" % (probe.get("returncode"), (probe.get("stderr") or "").strip()[:200])
            if attempt < max_attempts:
                time.sleep(backoff_seconds * attempt)
                continue
        return resolver.AvailabilityObservation(
            resolver.AvailabilityStatus.UNKNOWN.value,
            evidence="%s HEAD probe inconclusive after %d attempts: %s | last_error=%s" % (evidence_prefix, max_attempts, url, last_error),
            reason="%s_head_inconclusive" % evidence_prefix.replace(" ", "_"),
            error_kind="%s_head_inconclusive" % evidence_prefix.replace(" ", "_"),
        )

    def _external_apt_package_exists(self, candidate: resolver.MethodCandidate, package_name: str) -> resolver.AvailabilityObservation:
        packages_url = _external_apt_packages_url(dict(candidate.data), self._facts.machine_architecture)
        command = _external_apt_package_query_command(dict(candidate.data), package_name, self._facts.machine_architecture)
        if packages_url is None or command is None:
            return resolver.AvailabilityObservation(
                resolver.AvailabilityStatus.UNKNOWN.value,
                evidence="external APT repository metadata incomplete",
                reason="repository_metadata_incomplete",
                error_kind="malformed_response",
            )
        phase = self._exec(command)
        status, reason = classify_external_apt_package_query(phase, package_name)
        if status == "available":
            return resolver.AvailabilityObservation(
                resolver.AvailabilityStatus.AVAILABLE.value,
                evidence="external APT package %s listed in %s" % (package_name, packages_url),
                reason="external_apt_package_listed",
            )
        if status == "unavailable":
            return resolver.AvailabilityObservation(
                resolver.AvailabilityStatus.UNAVAILABLE.value,
                evidence="external APT package %s absent from %s" % (package_name, packages_url),
                reason="external_apt_package_missing",
                error_kind="unavailable",
            )
        if status in _PACKAGE_QUERY_STATUS_TO_AVAILABILITY:
            return _availability_from_query(status, reason)
        return resolver.AvailabilityObservation(
            resolver.AvailabilityStatus.UNKNOWN.value,
            evidence="external APT package index probe failed for %s: %s" % (packages_url, phase.get("stderr") or ""),
            reason="external_apt_package_probe_failed",
            error_kind="provider_error",
        )

    def package_exists(self, candidate: resolver.MethodCandidate, exact_target: str, package_name: str) -> resolver.AvailabilityObservation:
        if (
            candidate.kind == "external_repo_exact"
            and self._case["kind"] == "apt"
            and package_name in set(candidate.data.get("package_names", ()))
        ):
            return self._external_apt_package_exists(candidate, package_name)
        phase = self._exec(_query_command(self._case, package_name))
        status, reason = classify_package_query(phase, self._case["kind"], package_name)
        return _availability_from_query(status, reason)

    def _repository_metadata_url(self, base_url: str, series: str) -> str | None:
        """Return the repository metadata URL for the package manager family."""
        kind = self._case["kind"]
        base = base_url.rstrip("/")
        if kind == "apt":
            return "%s/dists/%s/Release" % (base, series)
        if kind == "dnf":
            series_num = dnf_repository_series_path(series)
            arch = self._facts.machine_architecture or "x86_64"
            # Real EPEL layout: .../9/Everything/x86_64/repodata/repomd.xml
            # (no /os/ segment). Verified against dl.fedoraproject.org.
            return "%s/%s/Everything/%s/repodata/repomd.xml" % (base, series_num, arch)
        if kind == "zypper":
            return "%s/%s/repodata/repomd.xml" % (base, series)
        return None

    def repository_supports_exact_target(self, candidate: resolver.MethodCandidate, target_id: str) -> resolver.AvailabilityObservation:
        compatible = candidate.data.get("compatible_targets", ())
        repo = candidate.data.get("repository", {})
        series = repo.get("series", "")
        if compatible:
            matched = any(
                item.get("target_id") == target_id and item.get("series") == series
                for item in compatible
            )
            if not matched:
                return resolver.AvailabilityObservation(
                    resolver.AvailabilityStatus.UNAVAILABLE.value,
                    evidence="compatible_targets=%s target=%s" % (compatible, target_id),
                    reason="target_release_not_explicitly_compatible",
                    error_kind="target_release_not_explicitly_compatible",
                )
        base_url = repo.get("url", "")
        if not base_url or not series:
            return resolver.AvailabilityObservation(
                resolver.AvailabilityStatus.UNKNOWN.value,
                evidence="repository metadata incomplete",
                reason="repository_metadata_incomplete",
                error_kind="malformed_response",
            )
        metadata_url = self._repository_metadata_url(base_url, series)
        if metadata_url is None:
            return resolver.AvailabilityObservation(
                resolver.AvailabilityStatus.UNKNOWN.value,
                evidence="unsupported package manager family for repository probe: %s" % self._case["kind"],
                reason="repository_probe_family_unsupported",
                error_kind="provider_error",
            )
        return self._head_url(metadata_url, "repository metadata")

    def source_revision_available(self, candidate: resolver.MethodCandidate, target_id: str) -> resolver.AvailabilityObservation:
        components = candidate.data.get("components", ())
        if not components:
            components = (candidate.data,)
        urls = []
        for component in components:
            repo = component.get("repository", "")
            tag = component.get("tag", "")
            if repo and tag:
                urls.append("%s/releases/tag/%s" % (repo.rstrip("/"), tag))
        if not urls:
            return resolver.AvailabilityObservation(
                resolver.AvailabilityStatus.UNKNOWN.value,
                evidence="source build candidate has no reachable tag URLs",
                reason="source_build_metadata_incomplete",
                error_kind="malformed_response",
            )
        for url in urls:
            observation = self._head_url(url, "source tag")
            if observation.status != resolver.AvailabilityStatus.AVAILABLE.value:
                return observation
        return resolver.AvailabilityObservation(
            resolver.AvailabilityStatus.AVAILABLE.value,
            evidence="all source tag HEAD probes reachable",
            reason="source_tags_reachable",
        )

    def artifact_exists(self, candidate: resolver.MethodCandidate, target_id: str, selected_asset: resolver.SelectedArtifact) -> resolver.AvailabilityObservation:
        url = "%s/%s" % (selected_asset.official_download_base.rstrip("/"), selected_asset.asset_name)
        observation = self._head_url(url, "artifact")
        if not isinstance(observation, resolver.ArtifactAvailabilityObservation):
            return resolver.ArtifactAvailabilityObservation(
                observation.status,
                evidence=observation.evidence,
                reason=observation.reason,
                error_kind=observation.error_kind,
                target_id=target_id,
                architecture=selected_asset.architecture,
                asset_name=selected_asset.asset_name,
                official_download_base=selected_asset.official_download_base,
                sha256=selected_asset.sha256,
                expected_executable=selected_asset.expected_executable,
            )
        return observation

    def artifact_integrity_metadata_available(self, candidate: resolver.MethodCandidate, target_id: str, selected_asset: resolver.SelectedArtifact) -> resolver.AvailabilityObservation:
        # L2 only checks that the manifest structurally declares a SHA-256 for
        # the selected asset. The actual hash-vs-binary verification is a
        # transactional provisioning responsibility (Tasks 23.7.5.6a/6b), not
        # a network availability probe.
        integrity = candidate.data.get("integrity", {})
        declared = integrity.get(selected_asset.architecture) if isinstance(integrity, dict) else None
        if integrity.get("type") == "sha256" and declared == selected_asset.sha256:
            return resolver.ArtifactAvailabilityObservation(
                resolver.AvailabilityStatus.AVAILABLE.value,
                evidence="manifest declares a SHA-256 for the selected asset architecture",
                reason="integrity_metadata_present",
                target_id=target_id,
                architecture=selected_asset.architecture,
                asset_name=selected_asset.asset_name,
                official_download_base=selected_asset.official_download_base,
                sha256=selected_asset.sha256,
                expected_executable=selected_asset.expected_executable,
            )
        return resolver.ArtifactAvailabilityObservation(
            resolver.AvailabilityStatus.UNAVAILABLE.value,
            evidence="manifest SHA-256 declaration missing or malformed for architecture %s" % selected_asset.architecture,
            reason="integrity_metadata_missing",
            error_kind="integrity_metadata_missing",
            target_id=target_id,
            architecture=selected_asset.architecture,
            asset_name=selected_asset.asset_name,
            official_download_base=selected_asset.official_download_base,
            sha256=selected_asset.sha256,
            expected_executable=selected_asset.expected_executable,
        )


def _extract_os_release(stdout: str) -> dict[str, str]:
    values = {}
    for raw in stdout.splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def _query_command(case: dict, package_name: str) -> str:
    kind = case["kind"]
    if kind == "apt":
        return "apt-cache policy %s" % package_name
    if kind == "dnf":
        if package_name == "openvpn" and case.get("epel_repo_url"):
            return "dnf -q --repofrompath=epel,%s --repo=epel list %s" % (case["epel_repo_url"], package_name)
        return "dnf -q list %s" % package_name
    if kind == "zypper":
        return "zypper --non-interactive search --match-exact %s" % package_name
    if kind == "pacman":
        return "pacman -Si %s" % package_name
    raise AssertionError(kind)


def _manager_command(manager: str) -> str:
    if manager not in CONTROLLED_MANAGERS:
        raise AssertionError("uncontrolled package manager: %s" % manager)
    return "command -v -- %s" % shlex.quote(manager)


def _refresh_command(case: dict) -> str:
    if case["kind"] == "apt":
        return "apt-get update"
    if case["kind"] == "zypper":
        return "zypper --non-interactive refresh"
    return case.get("refresh", "true")


def _curl_prepare_command(case: dict) -> str:
    kind = case["kind"]
    if kind == "apt":
        return "command -v curl >/dev/null 2>&1 || apt-get install -y curl"
    if kind == "dnf":
        return "command -v curl >/dev/null 2>&1 || dnf -y install curl"
    if kind == "zypper":
        return "command -v curl >/dev/null 2>&1 || zypper --non-interactive install curl"
    if kind == "pacman":
        return "command -v curl >/dev/null 2>&1 || pacman -S --noconfirm --needed curl"
    raise AssertionError(kind)


def _base_result(runtime: str, case: dict, name: str) -> dict:
    return {
        "target": case["target"],
        "image": case["image"],
        "runtime": runtime,
        "container_name": name,
        "pull": _phase("not_run"),
        "create": _phase("not_run"),
        "start": _phase("not_run"),
        "os_release": _phase("not_run"),
        "package_manager": _phase("not_run"),
        "metadata_refresh": _phase("not_run"),
        "http_probe_tool": _phase("not_run"),
        "package_queries": [],
        "cleanup": {
            "attempted": False,
            "status": "not_run",
            "runtime_status": "not_run",
            "semantic_status": None,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "reason": "",
            "residual_possible": False,
        },
        "probe_aggregate": "unknown",
        "overall_status": "unknown",
        "limitations": [],
    }


def _classify_cleanup(phase: dict) -> tuple[str, str]:
    if phase["runtime_status"] == "timeout":
        return "timeout", "container cleanup timed out"
    if phase["runtime_status"] == "runtime_error":
        return "runtime_error", "container runtime failed before cleanup completed"
    if phase["returncode"] == 0:
        return "cleaned", ""
    stderr = phase.get("stderr") or ""
    if _looks_like_missing_container_error(stderr):
        return "not_needed", "no container existed to remove"
    if _looks_like_runtime_infra_error(stderr):
        return "runtime_error", "container runtime reported an infrastructure error during cleanup"
    return "unknown", "container cleanup failed"


def _cleanup_container(runtime: str, name: str) -> dict:
    phase = _run_phase(runtime, ["rm", "-f", name], timeout=30)
    status, reason = _classify_cleanup(phase)
    _finalize(phase, status, reason)
    phase["attempted"] = True
    phase["residual_possible"] = status not in ("cleaned", "not_needed")
    return phase


def execute_l2_case(runtime: str, case: dict, name: str) -> dict:
    result = _base_result(runtime, case, name)
    try:
        pull = _run_phase(runtime, ["pull", case["image"]])
        status, reason = classify_pull_result(pull, case["image"])
        _finalize(pull, status, reason)
        result["pull"] = pull
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("image pull failed: %s" % status)
            return result

        create = _run_phase(runtime, ["create", "--name", name, case["image"], "sleep", "600"])
        status, reason = classify_lifecycle_phase(create, verb="create")
        _finalize(create, status, reason)
        result["create"] = create
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("container create failed")
            return result

        start = _run_phase(runtime, ["start", name])
        status, reason = classify_lifecycle_phase(start, verb="start")
        _finalize(start, status, reason)
        result["start"] = start
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("container start failed")
            return result

        os_release = _run_phase(runtime, ["exec", name, "cat", "/etc/os-release"])
        status, reason = classify_os_release(os_release, case)
        _finalize(os_release, status, reason)
        if os_release["runtime_status"] == "executed" and os_release["returncode"] == 0:
            values = _extract_os_release(os_release["stdout"])
        else:
            values = {}
        os_release["observed_id"] = values.get("ID", "")
        os_release["observed_version_id"] = values.get("VERSION_ID", "")
        result["os_release"] = os_release
        if status != "available":
            result["probe_aggregate"] = status
            return result

        manager_command = _manager_command(case["manager"])
        manager = _run_phase(runtime, ["exec", name, "sh", "-lc", manager_command])
        status, reason = classify_package_manager(manager)
        _finalize(manager, status, reason)
        manager["command"] = manager_command
        manager["path"] = manager["stdout"].strip() if manager.get("returncode") == 0 else ""
        result["package_manager"] = manager
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("package manager lookup failed")
            return result

        refresh_cmd = _refresh_command(case)
        refresh = _run_phase(runtime, ["exec", name, "sh", "-lc", refresh_cmd])
        status, reason = classify_lifecycle_phase(refresh, verb="metadata refresh")
        _finalize(refresh, status, reason)
        refresh["command"] = refresh_cmd
        result["metadata_refresh"] = refresh
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("metadata refresh failed")
            return result

        package_statuses = []
        for package in case["packages"]:
            command = _query_command(case, package)
            query = _run_phase(runtime, ["exec", name, "sh", "-lc", command])
            status, reason = classify_package_query(query, case["kind"], package)
            _finalize(query, status, reason)
            query["package"] = package
            query["command"] = command
            if package == "openvpn" and case.get("repository_id") and query["runtime_status"] == "executed":
                if "Everything//" in case["epel_repo_url"] or "$" in case["epel_repo_url"]:
                    query["status"] = "malformed_response"
                    query["reason"] = "EPEL repository URL is not exact"
                    query["semantic_status"] = "malformed_response"
                query["repository_id"] = case["repository_id"]
                query["series"] = case["series"]
                query["architecture"] = case["architecture"]
                query["repository_url_exact"] = case["epel_repo_url"]
                query["target"] = case["target"]
            package_statuses.append(query)
        result["package_queries"] = package_statuses
        result["probe_aggregate"] = aggregate_package_status(package_statuses)
        return result
    finally:
        result["cleanup"] = _cleanup_container(runtime, name)
        result["overall_status"] = compute_overall_status(result["probe_aggregate"], result["cleanup"])


def _resolve_dependency_queries(
    runtime: str,
    name: str,
    case: dict,
    manifest: dict,
    facts: detection.DistroFacts,
    all_capabilities: tuple[detection.CapabilityResult, ...],
) -> tuple[str, list[dict], list[dict]]:
    """Run the resolver inside the container context and query the packages of
    the selected candidate for each dependency requirement.

    Returns (probe_aggregate, dependency_decisions, package_queries).
    """
    provider = ContainerAvailabilityProvider(runtime, name, case, facts)
    evaluation = detection.evaluate(
        manifest,
        facts,
        _fixture_core_capabilities(manifest, facts),
        _fixture_protocol_capabilities(manifest),
        now=datetime.now(),
    )
    report = resolver.resolve_all(
        manifest,
        facts,
        evaluation.support_classification,
        all_capabilities,
        availability=provider,
    )
    decisions_out = []
    queries_out = []
    for decision in report.decisions:
        decisions_out.append(
            {
                "dependency_id": decision.dependency_id,
                "capability_id": decision.capability_id,
                "resolution_status": decision.resolution_status,
                "selected_method_id": decision.selected_method_id,
                "selected_method_kind": decision.selected_method_kind,
                "execution_ready": decision.execution_ready,
                "reason": decision.reason,
                "rejected_candidates": [
                    {
                        "method_id": r.method_id,
                        "method_kind": r.method_kind,
                        "reason": r.reason,
                        "error_kind": r.error_kind,
                    }
                    for r in decision.rejected_candidates
                ],
            }
        )
        if decision.resolution_status not in ("method_selected", "recipe_not_implemented"):
            continue
        if not decision.selected_method_id:
            continue
        requirement = manifest["dependency_requirements"][decision.dependency_id]
        candidate_data = next(
            (c for c in requirement["method_chain"] if c["id"] == decision.selected_method_id),
            None,
        )
        if candidate_data is None:
            continue
        kind = candidate_data["kind"]
        if kind in ("official_package_exact", "external_repo_exact"):
            for package_name in candidate_data.get("package_names", ()):
                external_apt_query = (
                    kind == "external_repo_exact"
                    and case["kind"] == "apt"
                    and package_name in set(candidate_data.get("package_names", ()))
                )
                command = (
                    _external_apt_package_query_command(candidate_data, package_name, facts.machine_architecture)
                    if external_apt_query
                    else _query_command(case, package_name)
                )
                if command is None:
                    query = _phase("malformed_response", reason="external APT repository metadata incomplete")
                else:
                    query = _run_phase(runtime, ["exec", name, "sh", "-lc", command])
                    if external_apt_query:
                        status, reason = classify_external_apt_package_query(query, package_name)
                    else:
                        status, reason = classify_package_query(query, case["kind"], package_name)
                    _finalize(query, status, reason)
                query["package"] = package_name
                query["dependency_id"] = decision.dependency_id
                query["method_id"] = decision.selected_method_id
                query["command"] = command
                if external_apt_query:
                    query["repository_package_index"] = _external_apt_packages_url(candidate_data, facts.machine_architecture)
                queries_out.append(query)
        elif kind == "pinned_source_build":
            for package_name in candidate_data.get("build_dependencies", ()):
                command = _query_command(case, package_name)
                query = _run_phase(runtime, ["exec", name, "sh", "-lc", command])
                status, reason = classify_package_query(query, case["kind"], package_name)
                _finalize(query, status, reason)
                query["package"] = package_name
                query["dependency_id"] = decision.dependency_id
                query["method_id"] = decision.selected_method_id
                query["command"] = command
                queries_out.append(query)
    package_aggregate = aggregate_package_status([{"status": q["status"]} for q in queries_out]) if queries_out else "unknown"
    decision_aggregate = aggregate_dependency_status(decisions_out)
    aggregate = combine_probe_statuses(package_aggregate, decision_aggregate)
    return aggregate, decisions_out, queries_out


def execute_l2_matrix_case(runtime: str, case: dict, name: str, manifest: dict) -> dict:
    """Run the full per-family/release L2 matrix case.

    Reuses the lifecycle phases from execute_l2_case, then runs the resolver
    with a ContainerAvailabilityProvider to select candidates and query the
    packages they declare.
    """
    result = _base_result(runtime, case, name)
    result["dependency_decisions"] = []
    result["resolver_package_queries"] = []
    all_capabilities: tuple[detection.CapabilityResult, ...] = ()
    try:
        pull = _run_phase(runtime, ["pull", case["image"]])
        status, reason = classify_pull_result(pull, case["image"])
        _finalize(pull, status, reason)
        result["pull"] = pull
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("image pull failed: %s" % status)
            return result

        create = _run_phase(runtime, ["create", "--name", name, case["image"], "sleep", "600"])
        status, reason = classify_lifecycle_phase(create, verb="create")
        _finalize(create, status, reason)
        result["create"] = create
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("container create failed")
            return result

        start = _run_phase(runtime, ["start", name])
        status, reason = classify_lifecycle_phase(start, verb="start")
        _finalize(start, status, reason)
        result["start"] = start
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("container start failed")
            return result

        os_release = _run_phase(runtime, ["exec", name, "cat", "/etc/os-release"])
        status, reason = classify_os_release(os_release, case)
        _finalize(os_release, status, reason)
        if os_release["runtime_status"] == "executed" and os_release["returncode"] == 0:
            values = _extract_os_release(os_release["stdout"])
        else:
            values = {}
        os_release["observed_id"] = values.get("ID", "")
        os_release["observed_version_id"] = values.get("VERSION_ID", "")
        result["os_release"] = os_release
        if status != "available":
            result["probe_aggregate"] = status
            return result

        manager_command = _manager_command(case["manager"])
        manager = _run_phase(runtime, ["exec", name, "sh", "-lc", manager_command])
        status, reason = classify_package_manager(manager)
        _finalize(manager, status, reason)
        manager["command"] = manager_command
        manager["path"] = manager["stdout"].strip() if manager.get("returncode") == 0 else ""
        result["package_manager"] = manager
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("package manager lookup failed")
            return result

        refresh_cmd = _refresh_command(case)
        refresh = _run_phase(runtime, ["exec", name, "sh", "-lc", refresh_cmd])
        status, reason = classify_lifecycle_phase(refresh, verb="metadata refresh")
        _finalize(refresh, status, reason)
        refresh["command"] = refresh_cmd
        result["metadata_refresh"] = refresh
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("metadata refresh failed")
            return result

        curl_cmd = _curl_prepare_command(case)
        curl_prepare = _run_phase(runtime, ["exec", name, "sh", "-lc", curl_cmd])
        status, reason = classify_lifecycle_phase(curl_prepare, verb="curl preparation")
        _finalize(curl_prepare, status, reason)
        curl_prepare["command"] = curl_cmd
        result["http_probe_tool"] = curl_prepare
        if status != "available":
            result["probe_aggregate"] = status
            result["limitations"].append("HTTP probe tool preparation failed")
            return result

        os_release_data = detection.parse_os_release_text(os_release["stdout"])
        facts = detection.distro_facts_from_os_release(
            os_release_data,
            manifest,
            kernel_release="container-l2",
            machine_architecture="x86_64",
        )
        all_capabilities = _all_fixture_capabilities(manifest, facts)
        aggregate, decisions, queries = _resolve_dependency_queries(
            runtime, name, case, manifest, facts, all_capabilities
        )
        result["dependency_decisions"] = decisions
        result["resolver_package_queries"] = queries
        result["probe_aggregate"] = aggregate
        return result
    finally:
        result["cleanup"] = _cleanup_container(runtime, name)
        result["overall_status"] = compute_overall_status(result["probe_aggregate"], result["cleanup"])


class L2ParserTests(unittest.TestCase):
    # --- pull classification (correction 1) ---

    def test_pull_success_is_available(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 0, "stdout": "", "stderr": ""}
        self.assertEqual(classify_pull_result(phase)[0], "available")

    def test_pull_classifies_image_not_found(self) -> None:
        phase = {
            "runtime_status": "executed",
            "returncode": 1,
            "stdout": "",
            "stderr": "Error response from daemon: manifest for ubuntu:26.04 not found: manifest unknown: manifest unknown",
        }
        self.assertEqual(classify_pull_result(phase)[0], "image_not_found")

    def test_pull_classifies_authentication_error(self) -> None:
        phase = {
            "runtime_status": "executed",
            "returncode": 1,
            "stdout": "",
            "stderr": 'Error response from daemon: Get "https://registry-1.docker.io/v2/": unauthorized: authentication required',
        }
        self.assertEqual(classify_pull_result(phase)[0], "authentication_error")

    def test_pull_classifies_registry_error(self) -> None:
        phase = {
            "runtime_status": "executed",
            "returncode": 1,
            "stdout": "",
            "stderr": 'Error response from daemon: Get "https://registry-1.docker.io/v2/": dial tcp: lookup registry-1.docker.io: no such host',
        }
        self.assertEqual(classify_pull_result(phase)[0], "registry_error")

    def test_pull_classifies_runtime_error_from_infra_marker(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": "Cannot connect to the Docker daemon at unix:///var/run/docker.sock"}
        self.assertEqual(classify_pull_result(phase)[0], "runtime_error")

    def test_pull_classifies_runtime_error_from_oserror(self) -> None:
        # _run_phase itself reports runtime_error when the runtime binary
        # cannot even be invoked (OSError), independent of any stderr text.
        phase = {"runtime_status": "runtime_error", "returncode": None, "stdout": "", "stderr": "runtime execution failed"}
        self.assertEqual(classify_pull_result(phase)[0], "runtime_error")

    def test_pull_classifies_timeout(self) -> None:
        phase = {"runtime_status": "timeout", "returncode": None, "stdout": "", "stderr": ""}
        self.assertEqual(classify_pull_result(phase)[0], "timeout")

    def test_pull_classifies_unknown_for_unrecognized_failure(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 125, "stdout": "", "stderr": "an unrecognized internal error occurred"}
        self.assertEqual(classify_pull_result(phase)[0], "unknown")

    def test_pull_unambiguous_manifest_unknown_is_image_not_found(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": "Error response from daemon: manifest unknown: manifest unknown"}
        self.assertEqual(classify_pull_result(phase, "ubuntu:26.04")[0], "image_not_found")

    def test_pull_repository_does_not_exist_with_docker_login_is_authentication_error(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": "pull access denied for privaterepo, repository does not exist or may require 'docker login'"}
        self.assertEqual(classify_pull_result(phase, "privaterepo")[0], "authentication_error")

    def test_pull_manifest_for_with_dial_tcp_is_registry_error(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": "manifest for ubuntu:26.04 not found: dial tcp: lookup registry-1.docker.io: no such host"}
        self.assertEqual(classify_pull_result(phase, "ubuntu:26.04")[0], "registry_error")

    def test_pull_manifest_unknown_with_unauthorized_is_authentication_error(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": "Error response from daemon: manifest unknown: unauthorized: authentication required"}
        self.assertEqual(classify_pull_result(phase, "ubuntu:26.04")[0], "authentication_error")

    def test_pull_absence_with_dns_error_is_registry_error(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": "manifest unknown: no such host: temporary failure in name resolution"}
        self.assertEqual(classify_pull_result(phase, "ubuntu:26.04")[0], "registry_error")

    def test_pull_unrecognized_message_is_unknown(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": "an internal daemon error occurred"}
        self.assertEqual(classify_pull_result(phase, "ubuntu:26.04")[0], "unknown")

    def test_pull_exact_image_not_found_without_generic_marker_is_image_not_found(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": "manifest ubuntu:26.04 not found in registry-1.docker.io/library/ubuntu"}
        self.assertEqual(classify_pull_result(phase, "ubuntu:26.04")[0], "image_not_found")

    def test_only_unambiguous_manifest_unknown_case_excuses_optional_image(self) -> None:
        optional_case = dict(CASES[1])
        mixed_messages = (
            ("Error response from daemon: manifest unknown: manifest unknown", "image_not_found"),
            ("pull access denied for privaterepo, repository does not exist or may require 'docker login'", "authentication_error"),
            ("manifest for ubuntu:26.04 not found: dial tcp: lookup registry-1.docker.io: no such host", "registry_error"),
            ("Error response from daemon: manifest unknown: unauthorized: authentication required", "authentication_error"),
            ("manifest unknown: no such host: temporary failure in name resolution", "registry_error"),
            ("an internal daemon error occurred", "unknown"),
        )
        for stderr, expected_status in mixed_messages:
            phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": stderr}
            status, _ = classify_pull_result(phase, optional_case["image"])
            with self.subTest(stderr=stderr):
                self.assertEqual(status, expected_status)
                excused = is_optional_image_exception(optional_case, {"pull": {"status": status}})
                self.assertEqual(excused, expected_status == "image_not_found")

    def test_only_image_not_found_excuses_optional_image(self) -> None:
        optional_case = dict(CASES[1])
        self.assertTrue(is_optional_image_exception(optional_case, {"pull": {"status": "image_not_found"}}))
        for other_status in ("timeout", "runtime_error", "registry_error", "authentication_error", "unknown"):
            with self.subTest(status=other_status):
                self.assertFalse(is_optional_image_exception(optional_case, {"pull": {"status": other_status}}))
        non_optional_case = dict(CASES[0])
        self.assertFalse(is_optional_image_exception(non_optional_case, {"pull": {"status": "image_not_found"}}))

    # --- probe_aggregate / cleanup / overall_status (correction 2) ---

    def test_success_result_preserves_phase_evidence(self) -> None:
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[0] == "exec" and args[2:] == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "")
            if args[0] == "exec" and args[2:] == ["sh", "-lc", "command -v -- apt-get"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/apt-get\n", "")
            if args[0] == "exec" and args[-1].startswith("apt-cache policy"):
                package = args[-1].split()[-1]
                return subprocess.CompletedProcess([runtime] + args, 0, "%s:\n  Candidate: 1.0\n" % package, "")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-phases")
        self.assertEqual(result["probe_aggregate"], "available")
        self.assertEqual(result["overall_status"], "available")
        self.assertEqual(result["cleanup"]["status"], "cleaned")
        for key in ("target", "image", "runtime", "container_name", "pull", "create", "start", "os_release", "package_manager", "metadata_refresh", "package_queries", "cleanup", "probe_aggregate", "overall_status", "limitations"):
            self.assertIn(key, result)
        self.assertEqual(result["os_release"]["observed_id"], "ubuntu")
        self.assertEqual(result["os_release"]["observed_version_id"], "24.04")
        self.assertEqual(result["os_release"]["semantic_status"], "available")
        self.assertEqual(result["package_manager"]["path"], "/usr/bin/apt-get")
        self.assertTrue(result["package_queries"])

    def test_timeout_and_runtime_error_attempt_cleanup(self) -> None:
        calls = []

        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            calls.append(tuple(args))
            if args[0] == "pull":
                raise subprocess.TimeoutExpired(args, timeout)
            return subprocess.CompletedProcess([runtime] + args, 0, "", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-test")
        self.assertEqual(result["probe_aggregate"], "timeout")
        self.assertEqual(result["pull"]["status"], "timeout")
        self.assertIn(("rm", "-f", "watchdogvpn-test"), calls)
        self.assertEqual(result["cleanup"]["status"], "cleaned")
        self.assertEqual(result["overall_status"], "timeout")

    def test_pull_unrecognized_failure_is_unknown_end_to_end(self) -> None:
        calls = []

        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            calls.append(tuple(args))
            if args[0] == "pull":
                return subprocess.CompletedProcess([runtime] + args, 125, "", "an unrecognized internal error occurred")
            return subprocess.CompletedProcess([runtime] + args, 0, "", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("podman", CASES[0], "watchdogvpn-error")
        self.assertEqual(result["probe_aggregate"], "unknown")
        self.assertEqual(result["overall_status"], "unknown")
        self.assertIn(("rm", "-f", "watchdogvpn-error"), calls)
        self.assertEqual(result["cleanup"]["status"], "cleaned")

    def test_cleanup_rc_nonzero_after_available_probe_yields_cleanup_failed(self) -> None:
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[0] == "rm":
                return subprocess.CompletedProcess([runtime] + args, 1, "", "some cleanup problem")
            if args[0] == "exec" and args[2:] == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "")
            if args[0] == "exec" and args[2:] == ["sh", "-lc", "command -v -- apt-get"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/apt-get\n", "")
            if args[0] == "exec" and args[-1].startswith("apt-cache policy"):
                package = args[-1].split()[-1]
                return subprocess.CompletedProcess([runtime] + args, 0, "%s:\n  Candidate: 1.0\n" % package, "")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-cleanup-rc")
        self.assertEqual(result["probe_aggregate"], "available")
        self.assertTrue(result["cleanup"]["residual_possible"])
        self.assertEqual(result["overall_status"], "cleanup_failed")

    def test_cleanup_timeout_after_available_probe_yields_cleanup_failed(self) -> None:
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[0] == "rm":
                raise subprocess.TimeoutExpired(args, timeout)
            if args[0] == "exec" and args[2:] == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "")
            if args[0] == "exec" and args[2:] == ["sh", "-lc", "command -v -- apt-get"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/apt-get\n", "")
            if args[0] == "exec" and args[-1].startswith("apt-cache policy"):
                package = args[-1].split()[-1]
                return subprocess.CompletedProcess([runtime] + args, 0, "%s:\n  Candidate: 1.0\n" % package, "")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-cleanup-timeout")
        self.assertEqual(result["probe_aggregate"], "available")
        self.assertEqual(result["cleanup"]["status"], "timeout")
        self.assertTrue(result["cleanup"]["residual_possible"])
        self.assertEqual(result["overall_status"], "cleanup_failed")

    def test_cleanup_oserror_after_available_probe_yields_cleanup_failed(self) -> None:
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[0] == "rm":
                raise OSError("runtime missing")
            if args[0] == "exec" and args[2:] == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "")
            if args[0] == "exec" and args[2:] == ["sh", "-lc", "command -v -- apt-get"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/apt-get\n", "")
            if args[0] == "exec" and args[-1].startswith("apt-cache policy"):
                package = args[-1].split()[-1]
                return subprocess.CompletedProcess([runtime] + args, 0, "%s:\n  Candidate: 1.0\n" % package, "")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-cleanup-oserror")
        self.assertEqual(result["probe_aggregate"], "available")
        self.assertEqual(result["cleanup"]["status"], "runtime_error")
        self.assertTrue(result["cleanup"]["residual_possible"])
        self.assertEqual(result["overall_status"], "cleanup_failed")

    def test_timeout_probe_with_cleanup_failure_yields_timeout_with_cleanup_failure(self) -> None:
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[0] == "pull":
                raise subprocess.TimeoutExpired(args, timeout)
            if args[0] == "rm":
                return subprocess.CompletedProcess([runtime] + args, 1, "", "some cleanup problem")
            return subprocess.CompletedProcess([runtime] + args, 0, "", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-timeout-cleanup-fail")
        self.assertEqual(result["probe_aggregate"], "timeout")
        self.assertTrue(result["cleanup"]["residual_possible"])
        self.assertEqual(result["overall_status"], "timeout_with_cleanup_failure")

    def test_optional_image_missing_cleanup_not_needed_keeps_probe_aggregate(self) -> None:
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[0] == "pull":
                return subprocess.CompletedProcess(
                    [runtime] + args, 1, "", "Error response from daemon: manifest for ubuntu:26.04 not found: manifest unknown: manifest unknown"
                )
            if args[0] == "rm":
                return subprocess.CompletedProcess([runtime] + args, 1, "", "Error: No such container: watchdogvpn-optional")
            return subprocess.CompletedProcess([runtime] + args, 0, "", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[1], "watchdogvpn-optional")
        self.assertEqual(result["pull"]["status"], "image_not_found")
        self.assertEqual(result["probe_aggregate"], "image_not_found")
        self.assertEqual(result["cleanup"]["status"], "not_needed")
        self.assertFalse(result["cleanup"]["residual_possible"])
        self.assertEqual(result["overall_status"], "image_not_found")
        self.assertTrue(is_optional_image_exception(CASES[1], result))

    def test_cleanup_statuses_are_observable_and_do_not_hide_primary_result(self) -> None:
        cleanup_statuses = (
            subprocess.CompletedProcess(["docker", "rm", "-f", "name"], 1, "out", "denied"),
            subprocess.TimeoutExpired(["docker", "rm", "-f", "name"], 30, output="partial", stderr="slow"),
            OSError("runtime missing"),
        )
        for failure in cleanup_statuses:
            with self.subTest(failure=type(failure).__name__):
                calls = []

                def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
                    calls.append(tuple(args))
                    if args[0] == "pull":
                        raise subprocess.TimeoutExpired(args, timeout, output="pull", stderr="timeout")
                    if args[0] == "rm":
                        if isinstance(failure, BaseException):
                            raise failure
                        return failure
                    return subprocess.CompletedProcess([runtime] + args, 0, "", "")

                with mock.patch(__name__ + "._run", side_effect=fake_run):
                    result = execute_l2_case("docker", CASES[0], "watchdogvpn-cleanup")
                self.assertEqual(result["probe_aggregate"], "timeout")
                self.assertEqual(result["pull"]["status"], "timeout")
                self.assertTrue(result["cleanup"]["attempted"])
                self.assertTrue(result["cleanup"]["residual_possible"])
                self.assertEqual(result["overall_status"], "timeout_with_cleanup_failure")
                self.assertIn(("rm", "-f", "watchdogvpn-cleanup"), calls)

    # --- runtime status respected before content parsing (correction 3) ---

    def test_os_release_timeout_is_preserved_without_parsing(self) -> None:
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[0] == "exec" and args[2:] == ["cat", "/etc/os-release"]:
                raise subprocess.TimeoutExpired(args, timeout)
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-osrelease-timeout")
        self.assertEqual(result["os_release"]["status"], "timeout")
        self.assertIsNone(result["os_release"]["semantic_status"])
        self.assertEqual(result["os_release"]["observed_id"], "")
        self.assertEqual(result["probe_aggregate"], "timeout")

    def test_os_release_runtime_error_is_preserved_without_parsing(self) -> None:
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[0] == "exec" and args[2:] == ["cat", "/etc/os-release"]:
                raise OSError("runtime missing")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-osrelease-runtime-error")
        self.assertEqual(result["os_release"]["status"], "runtime_error")
        self.assertIsNone(result["os_release"]["semantic_status"])
        self.assertEqual(result["os_release"]["observed_id"], "")
        self.assertEqual(result["probe_aggregate"], "runtime_error")

    def test_os_release_nonzero_returncode_is_not_parsed_as_identity(self) -> None:
        # Even if stdout happened to contain something that looked like a
        # coincidental identity match, a non-zero returncode must never be
        # treated as a valid identity read.
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[0] == "exec" and args[2:] == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess([runtime] + args, 1, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "cat: /etc/os-release: Permission denied")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-osrelease-nonzero")
        self.assertEqual(result["os_release"]["status"], "unknown")
        self.assertEqual(result["os_release"]["observed_id"], "")
        self.assertEqual(result["probe_aggregate"], "unknown")

    def test_wrong_os_release_is_malformed(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 0, "stdout": "ID=debian\nVERSION_ID=13\n", "stderr": ""}
        status, _ = classify_os_release(phase, CASES[0])
        self.assertEqual(status, "malformed_response")

    def test_os_release_version_ids_come_from_manifest(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 0, "stdout": "ID=rocky\nVERSION_ID=9.3\n", "stderr": ""}
        status, _ = classify_os_release(phase, CASES[4])
        self.assertEqual(status, "available")

    def test_rolling_target_without_release_entry_is_available(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 0, "stdout": "ID=arch\n", "stderr": ""}
        status, _ = classify_os_release(phase, CASES[6])
        self.assertEqual(status, "available")

    def test_manager_distinguishes_absence_from_runtime_error(self) -> None:
        absent = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": ""}
        self.assertEqual(classify_package_manager(absent)[0], "manager_unavailable")
        infra_failure = {"runtime_status": "executed", "returncode": 126, "stdout": "", "stderr": "Error: watchdogvpn-x is not running"}
        self.assertEqual(classify_package_manager(infra_failure)[0], "runtime_error")

    def test_manager_timeout(self) -> None:
        phase = {"runtime_status": "timeout", "returncode": None, "stdout": "", "stderr": ""}
        self.assertEqual(classify_package_manager(phase)[0], "timeout")

    def test_manager_normal_absence_is_manager_unavailable(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": ""}
        self.assertEqual(classify_package_manager(phase)[0], "manager_unavailable")

    def test_manager_clean_rc_127_absence_is_manager_unavailable(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 127, "stdout": "", "stderr": ""}
        self.assertEqual(classify_package_manager(phase)[0], "manager_unavailable")

    def test_manager_rc_126_is_unknown(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 126, "stdout": "", "stderr": ""}
        self.assertEqual(classify_package_manager(phase)[0], "unknown")

    def test_manager_rc_127_with_shell_error_is_unknown(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 127, "stdout": "", "stderr": "sh: line 1: command: not found"}
        self.assertEqual(classify_package_manager(phase)[0], "unknown")

    def test_manager_rc_1_with_unrecognized_stderr_is_unknown(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "", "stderr": "some unexpected shell warning"}
        self.assertEqual(classify_package_manager(phase)[0], "unknown")

    def test_manager_infra_marker_is_runtime_error(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 126, "stdout": "", "stderr": "Error: watchdogvpn-x is not running"}
        self.assertEqual(classify_package_manager(phase)[0], "runtime_error")

    def test_manager_success_with_path_is_available(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 0, "stdout": "/usr/bin/apt-get\n", "stderr": ""}
        self.assertEqual(classify_package_manager(phase)[0], "available")

    def test_manager_success_with_empty_path_is_malformed(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 0, "stdout": "", "stderr": ""}
        self.assertEqual(classify_package_manager(phase)[0], "malformed_response")

    def test_manager_lookup_runs_command_inside_shell(self) -> None:
        calls = []

        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            calls.append(tuple(args))
            if args[0] == "exec" and args[2:] == ["sh", "-lc", "command -v -- apt-get"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/apt-get\n", "")
            if args[0] == "exec" and args[2:] == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-manager")
        self.assertIn(("exec", "watchdogvpn-manager", "sh", "-lc", "command -v -- apt-get"), calls)
        self.assertEqual(result["package_manager"]["status"], "available")
        self.assertEqual(result["package_manager"]["path"], "/usr/bin/apt-get")
        self.assertNotEqual(result["metadata_refresh"]["status"], "not_run")

    def test_epel_repository_url_is_exact_for_architecture(self) -> None:
        rocky = CASES[4]
        command = _query_command(rocky, "openvpn")
        self.assertIn("Everything/x86_64/", command)
        self.assertNotIn("$basearch", command)
        self.assertNotIn("Everything//", command)

    def test_refresh_failure_is_unknown(self) -> None:
        self.assertEqual(aggregate_package_status([{"status": "unknown"}]), "unknown")

    def test_apt_without_candidate_is_not_available(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 0, "stdout": "openvpn:\n  Candidate: (none)\n", "stderr": ""}
        status, _ = classify_package_query(phase, "apt", "openvpn")
        self.assertEqual(status, "unavailable")

    def test_apt_nonzero_returncode_with_valid_looking_stdout_is_not_available(self) -> None:
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "python3:\n  Candidate: 1.0\n", "stderr": ""}
        status, _ = classify_package_query(phase, "apt", "python3")
        self.assertNotEqual(status, "available")
        self.assertEqual(status, "unknown")

    def test_apt_aggregate_is_not_available_when_one_query_has_nonzero_returncode(self) -> None:
        good = {"status": "available"}
        phase = {"runtime_status": "executed", "returncode": 1, "stdout": "python3:\n  Candidate: 1.0\n", "stderr": ""}
        status, _ = classify_package_query(phase, "apt", "python3")
        self.assertEqual(aggregate_package_status([good, {"status": status}]), "unknown")

    def test_one_missing_package_fails_aggregate(self) -> None:
        self.assertEqual(aggregate_package_status([{"status": "available"}, {"status": "unavailable"}]), "unavailable")

    def test_manager_unavailable_fails_aggregate(self) -> None:
        self.assertEqual(aggregate_package_status([{"status": "available"}, {"status": "manager_unavailable"}]), "unavailable")

    def test_dependency_unknown_blocks_available_aggregate(self) -> None:
        self.assertEqual(
            aggregate_dependency_status([
                {"resolution_status": "method_selected"},
                {"resolution_status": "availability_unknown"},
            ]),
            "unknown",
        )
        self.assertEqual(combine_probe_statuses("available", "unknown"), "unknown")


class L2MatrixResolverTests(unittest.TestCase):
    # Deterministic tests for the resolver-driven matrix harness. They mock the
    # container runtime so they run without WATCHDOGVPN_REAL_L2 and without any
    # network access.

    def _matrix_fake_run(self, case: dict, available_packages: frozenset[str]):
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            cmd = args[-1] if args else ""
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and args[2:5] == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and "command -v -- apt-get" in cmd:
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/apt-get\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and cmd == "apt-get update":
                return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and cmd.startswith("command -v curl"):
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/curl\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and cmd.startswith("command -v git"):
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/git\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and "Packages.gz" in cmd and "Package: amneziawg" in cmd:
                return subprocess.CompletedProcess([runtime] + args, 0, "Package: amneziawg\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and cmd.startswith("curl -I"):
                return subprocess.CompletedProcess([runtime] + args, 0, "HTTP/1.1 200 OK\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and cmd.startswith("apt-cache policy"):
                package = cmd.split()[-1]
                if package in available_packages:
                    return subprocess.CompletedProcess([runtime] + args, 0, "%s:\n  Candidate: 1.0\n" % package, "")
                return subprocess.CompletedProcess([runtime] + args, 0, "%s:\n  Candidate: (none)\n" % package, "")
            if args[0] == "pull":
                return subprocess.CompletedProcess([runtime] + args, 0, "", "")
            if args[0] in ("create", "start"):
                return subprocess.CompletedProcess([runtime] + args, 0, "", "")
            if args[0] == "rm":
                return subprocess.CompletedProcess([runtime] + args, 0, "", "")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")
        return fake_run

    def test_matrix_case_resolves_dependencies_and_queries_packages(self) -> None:
        manifest = detection.load_product_manifest()
        case = CASES[0]
        base_run = self._matrix_fake_run(case, frozenset(("python3", "openvpn", "golang-go", "git", "make", "gcc")))

        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            cmd = args[-1] if args else ""
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and "Packages.gz" in cmd and "Package: amneziawg" in cmd:
                return subprocess.CompletedProcess([runtime] + args, 1, "", "")
            return base_run(runtime, args, timeout)

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_matrix_case("docker", case, "watchdogvpn-matrix-ubuntu", manifest)
        self.assertEqual(result["os_release"]["status"], "available")
        self.assertEqual(result["package_manager"]["status"], "available")
        self.assertEqual(result["metadata_refresh"]["status"], "available")
        self.assertTrue(result["resolver_package_queries"])
        queried_packages = {q["package"] for q in result["resolver_package_queries"]}
        self.assertIn("python3", queried_packages)
        self.assertIn("golang-go", queried_packages)
        self.assertIn("git", queried_packages)
        self.assertEqual(result["overall_status"], "unavailable")

    def test_matrix_case_fails_when_source_build_dependency_missing(self) -> None:
        manifest = detection.load_product_manifest()
        case = CASES[0]
        # Make the source-build dependency "git" unavailable in the APT candidate.
        base_run = self._matrix_fake_run(case, frozenset(("python3", "openvpn", "golang-go", "make", "gcc")))

        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            cmd = args[-1] if args else ""
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and "Packages.gz" in cmd and "Package: amneziawg" in cmd:
                return subprocess.CompletedProcess([runtime] + args, 1, "", "")
            return base_run(runtime, args, timeout)

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_matrix_case("docker", case, "watchdogvpn-matrix-ubuntu", manifest)
        self.assertEqual(result["overall_status"], "unavailable")
        self.assertTrue(result["resolver_package_queries"])
        self.assertTrue(
            any(q["package"] == "git" and q["status"] == "unavailable" for q in result["resolver_package_queries"])
        )

    def test_artifact_dependency_is_probed_and_selected(self) -> None:
        manifest = detection.load_product_manifest()
        case = CASES[0]
        base_run = self._matrix_fake_run(case, frozenset(("python3", "openvpn")))

        def artifact_run(runtime, args, timeout=TIMEOUT_SECONDS):
            cmd = args[-1] if args else ""
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and cmd.startswith("curl -I"):
                return subprocess.CompletedProcess([runtime] + args, 0, "HTTP/1.1 200 OK\nContent-Length: 12345\n", "")
            return base_run(runtime, args, timeout)

        with mock.patch(__name__ + "._run", side_effect=artifact_run):
            result = execute_l2_matrix_case("docker", case, "watchdogvpn-matrix-ubuntu", manifest)
        sing_box = next(
            (d for d in result["dependency_decisions"] if d["dependency_id"] == "dep_sing_box_runtime"),
            None,
        )
        self.assertIsNotNone(sing_box)
        self.assertEqual(sing_box["resolution_status"], "recipe_not_implemented")
        self.assertEqual(sing_box["selected_method_kind"], "official_artifact_pinned")
        self.assertEqual(sing_box["selected_method_id"], "sing_box_official_artifact_stable")

    def test_matrix_case_prepares_curl_before_artifact_probe(self) -> None:
        manifest = detection.load_product_manifest()
        case = CASES[0]
        calls = []
        base_run = self._matrix_fake_run(case, frozenset(("python3", "openvpn", "golang-go", "git", "make", "gcc")))

        def instrumented_run(runtime, args, timeout=TIMEOUT_SECONDS):
            calls.append(tuple(args))
            return base_run(runtime, args, timeout)

        with mock.patch(__name__ + "._run", side_effect=instrumented_run):
            result = execute_l2_matrix_case("docker", case, "watchdogvpn-matrix-ubuntu", manifest)
        self.assertEqual(result["http_probe_tool"]["status"], "available")
        self.assertIn(("exec", "watchdogvpn-matrix-ubuntu", "sh", "-lc", "command -v curl >/dev/null 2>&1 || apt-get install -y curl"), calls)

    def test_matrix_case_fails_when_curl_preparation_fails(self) -> None:
        manifest = detection.load_product_manifest()
        case = CASES[0]
        base_run = self._matrix_fake_run(case, frozenset(("python3", "openvpn", "golang-go", "git", "make", "gcc")))

        def no_curl_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and args[-1] == "command -v curl >/dev/null 2>&1 || apt-get install -y curl":
                return subprocess.CompletedProcess([runtime] + args, 100, "", "unable to locate package curl")
            return base_run(runtime, args, timeout)

        with mock.patch(__name__ + "._run", side_effect=no_curl_run):
            result = execute_l2_matrix_case("docker", case, "watchdogvpn-matrix-ubuntu", manifest)
        self.assertEqual(result["http_probe_tool"]["status"], "unknown")
        self.assertEqual(result["overall_status"], "unknown")

    def test_external_apt_repo_package_is_checked_from_declared_repo_index(self) -> None:
        manifest = detection.load_product_manifest()
        candidate = resolver.load_requirement(manifest, "dep_amneziawg_runtime").method_chain[0]
        facts = detection.distro_facts_from_os_release(
            detection.parse_os_release_text("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n"),
            manifest,
            machine_architecture="x86_64",
        )
        calls = []

        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            calls.append(tuple(args))
            cmd = args[-1] if args else ""
            if "Packages.gz" in cmd and "Package: amneziawg" in cmd:
                return subprocess.CompletedProcess([runtime] + args, 0, "Package: amneziawg\n", "")
            return subprocess.CompletedProcess([runtime] + args, 1, "", "unexpected command")

        provider = ContainerAvailabilityProvider("docker", "watchdogvpn-matrix-ubuntu", CASES[0], facts)
        with mock.patch(__name__ + "._run", side_effect=fake_run):
            observation = provider.package_exists(candidate, "ubuntu_24_04", "amneziawg")
        self.assertEqual(observation.status, resolver.AvailabilityStatus.AVAILABLE.value)
        self.assertTrue(any("Packages.gz" in call[-1] and "Package: amneziawg" in call[-1] for call in calls))
        self.assertFalse(any(call[-1] == "apt-cache policy amneziawg" for call in calls))

    def test_matrix_records_external_apt_repo_query_without_base_apt_cache(self) -> None:
        manifest = detection.load_product_manifest()
        case = CASES[0]
        fake_run = self._matrix_fake_run(case, frozenset(("python3", "openvpn", "dnsutils")))
        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_matrix_case("docker", case, "watchdogvpn-matrix-ubuntu", manifest)
        amnezia_queries = [
            q
            for q in result["resolver_package_queries"]
            if q["dependency_id"] == "dep_amneziawg_runtime" and q["package"] == "amneziawg"
        ]
        self.assertEqual(len(amnezia_queries), 1)
        self.assertEqual(amnezia_queries[0]["status"], "available")
        self.assertIn("Packages.gz", amnezia_queries[0]["command"])
        self.assertNotEqual(amnezia_queries[0]["command"], "apt-cache policy amneziawg")

    def test_dependency_availability_unknown_blocks_overall_available(self) -> None:
        manifest = detection.load_product_manifest()
        case = CASES[0]
        base_run = self._matrix_fake_run(case, frozenset(("python3", "openvpn", "golang-go", "git", "make", "gcc")))

        def no_curl_after_prepare_run(runtime, args, timeout=TIMEOUT_SECONDS):
            cmd = args[-1] if args else ""
            if args[:2] == ["exec", "watchdogvpn-matrix-ubuntu"] and cmd == "command -v curl":
                return subprocess.CompletedProcess([runtime] + args, 1, "", "")
            return base_run(runtime, args, timeout)

        with mock.patch(__name__ + "._run", side_effect=no_curl_after_prepare_run):
            result = execute_l2_matrix_case("docker", case, "watchdogvpn-matrix-ubuntu", manifest)
        self.assertTrue(
            any(d["resolution_status"] == "availability_unknown" for d in result["dependency_decisions"]),
            result["dependency_decisions"],
        )
        self.assertEqual(result["overall_status"], "unknown")

    def _rocky_matrix_fake_run(self, case: dict, available_packages: frozenset[str]):
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            cmd = args[-1] if args else ""
            if args[:2] == ["exec", "watchdogvpn-matrix-rocky"] and args[2:5] == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "ID=rocky\nVERSION_ID=9.6\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-rocky"] and "command -v -- dnf" in cmd:
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/dnf\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-rocky"] and cmd == "true":
                return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-rocky"] and cmd.startswith("command -v curl"):
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/curl\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-rocky"] and cmd.startswith("curl -I"):
                return subprocess.CompletedProcess([runtime] + args, 0, "HTTP/1.1 200 OK\n", "")
            if args[:2] == ["exec", "watchdogvpn-matrix-rocky"] and cmd.startswith("dnf -q") and " list " in cmd:
                package = cmd.split()[-1]
                if package in available_packages:
                    return subprocess.CompletedProcess([runtime] + args, 0, "%s.x86_64 1.0 repo\n" % package, "")
                return subprocess.CompletedProcess([runtime] + args, 1, "", "No matching Packages to list")
            if args[0] == "pull":
                return subprocess.CompletedProcess([runtime] + args, 0, "", "")
            if args[0] in ("create", "start"):
                return subprocess.CompletedProcess([runtime] + args, 0, "", "")
            if args[0] == "rm":
                return subprocess.CompletedProcess([runtime] + args, 0, "", "")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")
        return fake_run

    def test_dnf_repository_is_probed_with_repomd_xml(self) -> None:
        manifest = detection.load_product_manifest()
        case = CASES[4]
        epel_packages = frozenset((
            "bash", "git", "coreutils", "findutils", "grep", "gawk", "sed", "gzip",
            "glibc-common", "shadow-utils", "systemd", "sudo", "kmod", "ca-certificates",
            "python3", "curl", "tar", "iproute", "NetworkManager", "logrotate", "libnotify",
            "openvpn", "util-linux", "polkit", "nftables", "iptables-nft", "iputils",
            "procps-ng", "firewalld", "systemd-resolved", "python3.11", "epel-release",
            "golang", "make", "gcc",
        ))
        calls = []

        def instrumented_run(runtime, args, timeout=TIMEOUT_SECONDS):
            calls.append(tuple(args))
            return self._rocky_matrix_fake_run(case, epel_packages)(runtime, args, timeout)

        with mock.patch(__name__ + "._run", side_effect=instrumented_run):
            result = execute_l2_matrix_case("docker", case, "watchdogvpn-matrix-rocky", manifest)
        self.assertEqual(result["os_release"]["status"], "available")
        base_runtime = next(
            (d for d in result["dependency_decisions"] if d["dependency_id"] == "dep_base_runtime_commands"),
            None,
        )
        self.assertIsNotNone(base_runtime)
        self.assertEqual(base_runtime["selected_method_id"], "base_runtime_dnf_rhel9_with_epel_exact")
        self.assertEqual(base_runtime["selected_method_kind"], "external_repo_exact")
        self.assertEqual(base_runtime["resolution_status"], "recipe_not_implemented")
        repository_probe = next(
            (cmd for cmd in calls if len(cmd) >= 2 and cmd[0] == "exec" and cmd[1] == "watchdogvpn-matrix-rocky" and isinstance(cmd[-1], str) and "repodata/repomd.xml" in cmd[-1]),
            None,
        )
        self.assertIsNotNone(repository_probe)
        # Real EPEL layout is .../Everything/x86_64/repodata/repomd.xml (no /os/).
        self.assertIn("Everything/x86_64/repodata/repomd.xml", repository_probe[-1])
        self.assertNotIn("Everything/x86_64/os/repodata/repomd.xml", repository_probe[-1])


@unittest.skipUnless(REAL_L2_ENABLED, "WATCHDOGVPN_REAL_L2=1 not set")
class RealFocusedDependencyL2Tests(unittest.TestCase):
    def test_real_container_package_queries(self) -> None:
        runtime = _runtime()
        if runtime is None:
            raise unittest.SkipTest("podman or docker is not available for real focused L2 checks")
        for case in CASES:
            name = "watchdogvpn-l2-%s-%d" % (case["target"], int(time.time() * 1000))
            with self.subTest(target=case["target"], image=case["image"]):
                result = execute_l2_case(runtime, case, name)
                if is_optional_image_exception(case, result):
                    self.assertIn("image pull failed", result["limitations"][0])
                    continue
                self.assertEqual(result["overall_status"], "available", result)

    def test_real_container_dependency_resolution_matrix(self) -> None:
        runtime = _runtime()
        if runtime is None:
            raise unittest.SkipTest("podman or docker is not available for real focused L2 checks")
        manifest = detection.load_product_manifest()
        for case in CASES:
            name = "watchdogvpn-l2-matrix-%s-%d" % (case["target"], int(time.time() * 1000))
            with self.subTest(target=case["target"], image=case["image"]):
                result = execute_l2_matrix_case(runtime, case, name, manifest)
                if is_optional_image_exception(case, result):
                    self.assertIn("image pull failed", result["limitations"][0])
                    continue
                self.assertEqual(result["overall_status"], "available", result)


if __name__ == "__main__":
    unittest.main()
