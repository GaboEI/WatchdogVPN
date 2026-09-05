"""AmneziaWG lifecycle guidance for the WatchdogVPN CLI and doctor.

Implements the maintainer-approved AmneziaWG lifecycle for openSUSE Leap:

* contextual detection (no global detection or doctor noise when no AmneziaWG
  profile exists);
* five explicit states: awg_context_absent, awg_profile_present_runtime_available,
  awg_profile_present_runtime_missing, awg_profile_imported_runtime_missing and
  awg_profile_present_runtime_unknown;
* exact recipe generation from the official AmneziaWG sources resolved as an
  official release tag plus its exact commit - never main/master/HEAD and never
  a third-party source;
* a durable local install-metadata registry so provenance is verified by binary
  digest (not inferred from a numeric version) and rollback can restore a real
  previously installed release;
* user-executed setup/update/repair/rollback: this module only generates and
  verifies, it never runs zypper, git clone, make, privileged installs or any
  network/interface mutation.

Only sources allowed: https://github.com/amnezia-vpn/amneziawg-tools and
https://github.com/amnezia-vpn/amneziawg-go. No binaries are shipped in the
WatchdogVPN repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat as stat_module
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping, Sequence

# Official upstream repositories (the only permitted sources).
AMNEZIAWG_TOOLS_REPO = "amnezia-vpn/amneziawg-tools"
AMNEZIAWG_TRANSPORT_REPO = "amnezia-vpn/amneziawg-go"
AMNEZIAWG_TOOLS_URL = f"https://github.com/{AMNEZIAWG_TOOLS_REPO}"
AMNEZIAWG_TRANSPORT_URL = f"https://github.com/{AMNEZIAWG_TRANSPORT_REPO}"

# The runtime components installed by the official recipe.
AMNEZIAWG_OUTPUTS = ("awg", "awg-quick", "amneziawg-go")
INSTALL_ROOT = Path("/usr/local/bin")
PROBE_CANDIDATES = (Path("/usr/local/bin"), Path("/usr/bin"))

# Certified pins recorded for the L3.1 openSUSE Leap matrix (Task 23.7.5.6b).
# A runtime whose recorded metadata (binary digest) matches these is
# "supported". Any newer official release is "experimental" until it passes
# real validation on openSUSE Leap. A detected runtime with no recorded
# metadata is "unknown" and is never silently overwritten.
CERTIFIED_PINS: Mapping[str, Mapping[str, str]] = {
    AMNEZIAWG_TOOLS_REPO: {
        "tag": "v1.0.20260618-2",
        "commit": "61e741780e8465a67a7d7fb6cffe14a8a15d624a",
    },
    AMNEZIAWG_TRANSPORT_REPO: {
        "tag": "v3.0.2",
        "commit": "0527dfa47639714dd8f5c9ffbd9d40d19083f0ba",
    },
}

# Lifecycle states defined by the maintainer spec.
STATE_CONTEXT_ABSENT = "awg_context_absent"
STATE_PROFILE_AVAILABLE = "awg_profile_present_runtime_available"
STATE_PROFILE_MISSING = "awg_profile_present_runtime_missing"
STATE_IMPORTED_MISSING = "awg_profile_imported_runtime_missing"
STATE_PROFILE_UNKNOWN = "awg_profile_present_runtime_unknown"

# Provenance per component.
PROVENANCE_SUPPORTED = "supported"
PROVENANCE_EXPERIMENTAL = "experimental"
PROVENANCE_UNKNOWN = "unknown"
PROVENANCE_MISSING = "missing"

# Install-metadata registry file name inside the shared config directory.
INSTALL_REGISTRY_NAME = "amneziawg_installed.json"

# Build manifest: independent evidence produced by the recipe at build time,
# tying the exact commits to the SHA-256 of the binaries actually built before
# install. `watchdog awg verify` refuses to record a release as verified
# without this evidence.
BUILD_MANIFEST_NAME = "amneziawg_build_manifest.json"
BUILD_MANIFEST_SYSTEM_PATH = "/var/lib/watchdogvpn/" + BUILD_MANIFEST_NAME
BUILD_MANIFEST_ETC_PATH = "/etc/watchdogvpn/" + BUILD_MANIFEST_NAME


class ReleaseResolutionError(RuntimeError):
    """Raised when an official AmneziaWG release cannot be resolved or verified.

    The caller must explain the block and must never fall back silently to
    main/master/HEAD or to an unverified tag.
    """


@dataclass(frozen=True)
class RuntimeComponent:
    name: str
    present: bool
    path: str | None
    version: str | None
    sha256: str | None
    mode: str | None
    uid: int | None
    gid: int | None
    provenance: str


@dataclass(frozen=True)
class RuntimeProbe:
    components: Mapping[str, RuntimeComponent]
    all_present: bool
    runtime_available: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "all_present": self.all_present,
            "runtime_available": self.runtime_available,
            "components": {
                name: {
                    "present": component.present,
                    "path": component.path,
                    "version": component.version,
                    "sha256": component.sha256,
                    "mode": component.mode,
                    "uid": component.uid,
                    "gid": component.gid,
                    "provenance": component.provenance,
                }
                for name, component in self.components.items()
            },
        }


@dataclass(frozen=True)
class InstalledRelease:
    """A release the user confirmed was installed, with verifiable metadata."""

    repository: str
    tag: str
    commit: str
    resolved_at: str
    recorded_at: str
    arch: str
    distro: str
    binary_sha256: dict[str, str]
    build_manifest_sha256: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "tag": self.tag,
            "commit": self.commit,
            "resolved_at": self.resolved_at,
            "recorded_at": self.recorded_at,
            "arch": self.arch,
            "distro": self.distro,
            "binary_sha256": dict(self.binary_sha256),
            "build_manifest_sha256": self.build_manifest_sha256,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "InstalledRelease":
        raw_sha = data.get("binary_sha256", {})
        binary_sha256 = (
            {str(k): str(v) for k, v in dict(raw_sha).items()} if isinstance(raw_sha, dict) else {}
        )
        return cls(
            repository=str(data["repository"]),
            tag=str(data["tag"]),
            commit=str(data["commit"]),
            resolved_at=str(data.get("resolved_at", "")),
            recorded_at=str(data.get("recorded_at", "")),
            arch=str(data.get("arch", "")),
            distro=str(data.get("distro", "")),
            binary_sha256=binary_sha256,
            build_manifest_sha256=str(data["build_manifest_sha256"]) if data.get("build_manifest_sha256") else None,
        )


def _config_dir() -> Path:
    from config.paths import resolve_config_dir

    return resolve_config_dir()


def _registry_path() -> Path:
    return _config_dir() / INSTALL_REGISTRY_NAME


def _load_registry() -> dict[str, object]:
    path = _registry_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return {"installed": [], "pending": []}
    if not isinstance(raw, dict):
        return {"installed": [], "pending": []}
    return raw


def _write_registry(data: dict[str, object]) -> None:
    path = _registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=1)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(payload + "\n", encoding="utf-8")
    tmp.replace(path)


def _installed_entries(data: dict[str, object]) -> list[InstalledRelease]:
    raw = data.get("installed", [])
    entries: list[InstalledRelease] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                try:
                    entries.append(InstalledRelease.from_dict(item))
                except (KeyError, TypeError, ValueError):
                    continue
    return entries


def load_installed_history() -> list[InstalledRelease]:
    return _installed_entries(_load_registry())


def save_installed_history(entries: Sequence[InstalledRelease]) -> None:
    data = _load_registry()
    data["installed"] = [entry.as_dict() for entry in entries]
    _write_registry(data)


def record_installed_release(
    releases: Sequence[ResolvedRelease],
    probe: RuntimeProbe,
    *,
    platform: Mapping[str, str] | None = None,
    build_manifest_sha256: str | None = None,
) -> list[InstalledRelease]:
    """Record a release the user confirmed as installed (durable metadata).

    Only call this after `validate_build_manifest` accepted the independent
    build evidence; `build_manifest_sha256` ties the recorded entries to that
    evidence. The recorded binary digests are what later provenance checks use;
    a numeric version string is never treated as reliable provenance.
    """
    platform = platform or _platform()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    sha256_by_name: dict[str, str] = {}
    for name in AMNEZIAWG_OUTPUTS:
        component = probe.components.get(name)
        if component is not None and component.sha256:
            sha256_by_name[name] = component.sha256
    entries = load_installed_history()
    created: list[InstalledRelease] = []
    for release in releases:
        entry = InstalledRelease(
            repository=release.repository,
            tag=release.tag,
            commit=release.commit,
            resolved_at=release.resolved_at,
            recorded_at=now,
            arch=str(platform["arch"]),
            distro=str(platform["distro"]),
            binary_sha256=sha256_by_name,
            build_manifest_sha256=build_manifest_sha256,
        )
        if not any(
            other.repository == entry.repository and other.commit == entry.commit
            and other.binary_sha256 == entry.binary_sha256
            for other in entries
        ):
            entries.append(entry)
            created.append(entry)
    save_installed_history(entries)
    return created if created else entries[-len(releases):] if entries else []


def store_pending_releases(releases: Sequence[ResolvedRelease]) -> None:
    """Persist the release pair the user was just told to install.

    `watchdog awg verify` later confirms that pair against the installed
    binaries and moves it into the installed history.
    """
    data = _load_registry()
    data["pending"] = [
        {
            "repository": release.repository,
            "tag": release.tag,
            "commit": release.commit,
            "resolved_at": release.resolved_at,
        }
        for release in releases
    ]
    _write_registry(data)


def load_pending_releases() -> list[ResolvedRelease]:
    data = _load_registry()
    raw = data.get("pending", [])
    releases: list[ResolvedRelease] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                try:
                    releases.append(
                        ResolvedRelease(
                            repository=str(item["repository"]),
                            tag=str(item["tag"]),
                            commit=str(item["commit"]),
                            resolved_at=str(item.get("resolved_at", "")),
                        )
                    )
                except (KeyError, TypeError, ValueError):
                    continue
    return releases


def clear_pending_releases() -> None:
    data = _load_registry()
    data["pending"] = []
    _write_registry(data)


def previous_installed_release(probe: RuntimeProbe) -> list[InstalledRelease]:
    """Return the most recent recorded release pair that differs from the current one.

    Used by `watchdog awg rollback`: the previous release is restored by
    regenerating its exact recipe from recorded metadata. Entries recorded by
    the same `recorded_at` form one install (amneziawg-tools + amneziawg-go).
    """
    entries = load_installed_history()
    if not entries:
        return []
    by_time: dict[str, list[InstalledRelease]] = {}
    for entry in entries:
        by_time.setdefault(entry.recorded_at, []).append(entry)
    current = _release_matching_probe(probe, entries)
    for recorded_at in sorted(by_time, reverse=True):
        group = by_time[recorded_at]
        if current is None or not any(
            (entry.repository, entry.commit) == (current.repository, current.commit) for entry in group
        ):
            return group
    return []


def _release_matching_probe(probe: RuntimeProbe, entries: Sequence[InstalledRelease]) -> InstalledRelease | None:
    sha_by_name = {
        name: component.sha256
        for name, component in probe.components.items()
        if component.sha256
    }
    for entry in reversed(entries):
        recorded = entry.binary_sha256
        if recorded and any(recorded.get(name) == digest for name, digest in sha_by_name.items()):
            return entry
    return None


def build_manifest_candidates() -> list[Path]:
    return [
        _config_dir() / BUILD_MANIFEST_NAME,
        Path(BUILD_MANIFEST_SYSTEM_PATH),
        Path(BUILD_MANIFEST_ETC_PATH),
    ]


def load_build_manifest() -> dict[str, object] | None:
    """Read the independent build manifest produced by the recipe, if any."""
    for path in build_manifest_candidates():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return None


def build_manifest_sha256() -> str | None:
    for path in build_manifest_candidates():
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
    return None


def validate_build_manifest(
    manifest: dict[str, object] | None,
    releases: Sequence[ResolvedRelease],
    probe: RuntimeProbe,
    *,
    platform: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Decide whether the build manifest proves the installed runtime origin.

    Returns a verdict with individual checks. `valid` is true only when the
    manifest exists with a supported schema, its tools/transport reference the
    two official repositories and match the pending recipe, its arch/distro
    match the current host platform, and every installed binary digest matches
    the digest the recipe recorded at build time for those exact commits.
    Without this evidence the runtime is `unknown`, never `supported`.
    """
    if manifest is None:
        return {"valid": False, "reason": "no independent build manifest found", "checks": {}}
    if not releases:
        return {"valid": False, "reason": "no pending recipe to compare against", "checks": {}}
    by_repo = {release.repository: release for release in releases}
    tools = by_repo.get(AMNEZIAWG_TOOLS_REPO)
    transport = by_repo.get(AMNEZIAWG_TRANSPORT_REPO)
    if tools is None or transport is None:
        return {"valid": False, "reason": "pending recipe is missing a component", "checks": {}}

    manifest_tools = manifest.get("tools")
    manifest_transport = manifest.get("transport")
    manifest_outputs = manifest.get("outputs")
    checks: dict[str, object] = {
        "manifest_present": isinstance(manifest, dict),
        "schema_supported": manifest.get("schema") == 1,
        "tools_repo_official": (
            isinstance(manifest_tools, dict) and manifest_tools.get("repository") == AMNEZIAWG_TOOLS_REPO
        ),
        "transport_repo_official": (
            isinstance(manifest_transport, dict) and manifest_transport.get("repository") == AMNEZIAWG_TRANSPORT_REPO
        ),
        "tools_commit_matches": (
            isinstance(manifest_tools, dict)
            and manifest_tools.get("commit") == tools.commit
            and manifest_tools.get("tag") == tools.tag
        ),
        "transport_commit_matches": (
            isinstance(manifest_transport, dict)
            and manifest_transport.get("commit") == transport.commit
            and manifest_transport.get("tag") == transport.tag
        ),
    }
    reasons: list[str] = []
    if not bool(checks["schema_supported"]):
        reasons.append("manifest schema is missing or not supported")
    if not bool(checks["tools_repo_official"]):
        reasons.append("manifest tools repository is not an official AmneziaWG source")
    if not bool(checks["transport_repo_official"]):
        reasons.append("manifest transport repository is not an official AmneziaWG source")
    if not bool(checks["tools_commit_matches"]):
        reasons.append("tools commit/tag in the manifest does not match the pending recipe")
    if not bool(checks["transport_commit_matches"]):
        reasons.append("transport commit/tag in the manifest does not match the pending recipe")

    outputs_ok = isinstance(manifest_outputs, dict)
    for name in AMNEZIAWG_OUTPUTS:
        expected = manifest_outputs.get(name) if outputs_ok else None
        observed = probe.components.get(name)
        observed_digest = observed.sha256 if observed is not None else None
        checks[f"output_{name}_matches"] = bool(expected and observed_digest and str(expected) == observed_digest)
        if not bool(checks[f"output_{name}_matches"]):
            reasons.append(f"{name} digest does not match the build manifest")

    current = _platform() if platform is None else dict(platform)
    manifest_arch = str(manifest.get("arch", "") or "")
    manifest_distro = str(manifest.get("distro", "") or "")
    host_arch = str(current.get("arch", "") or "")
    host_distro = str(current.get("distro", "") or "")
    checks["arch_present"] = bool(manifest_arch)
    checks["distro_present"] = bool(manifest_distro)
    checks["host_arch_known"] = bool(host_arch)
    checks["host_distro_known"] = bool(host_distro) and host_distro not in ("unknown",)
    checks["arch_matches"] = bool(manifest_arch) and bool(host_arch) and manifest_arch == host_arch
    checks["distro_matches"] = bool(manifest_distro) and bool(host_distro) and manifest_distro == host_distro
    if not bool(checks["arch_present"]):
        reasons.append("manifest has no architecture")
    if not bool(checks["distro_present"]):
        reasons.append("manifest has no distro")
    if not bool(checks["host_arch_known"]):
        reasons.append("current host architecture is unknown")
    if not bool(checks["host_distro_known"]):
        reasons.append("current host distro is unknown")
    if not bool(checks["arch_matches"]):
        reasons.append("architecture in the manifest does not match the host")
    if not bool(checks["distro_matches"]):
        reasons.append("distro in the manifest does not match the host")

    gate_keys = (
        "schema_",
        "tools_repo_",
        "transport_repo_",
        "tools_commit_",
        "transport_commit_",
        "output_",
        "arch_",
        "distro_",
    )
    valid = all(bool(value) for key, value in checks.items() if key.startswith(gate_keys))
    return {
        "valid": valid,
        "reason": "; ".join(reasons) if reasons else "build manifest matches the installed runtime and the pending recipe",
        "checks": checks,
    }


def _find_binary(name: str, root: Path | None = None) -> Path | None:
    candidates: list[Path] = []
    if root is not None:
        candidates.append(root / name)
    candidates.extend(Path(directory) / name for directory in PROBE_CANDIDATES)
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which(name)
    return Path(found) if found else None


def _sha256_of(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _run_version(path: Path, timeout: float = 3.0) -> str | None:
    import subprocess

    try:
        result = subprocess.run(
            [str(path), "--version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or result.stderr or "").strip()
    return output or None


def _provenance_from_metadata(
    name: str,
    sha256: str | None,
    recorded: Sequence[InstalledRelease],
) -> str:
    if not sha256:
        return PROVENANCE_UNKNOWN
    for entry in reversed(recorded):
        if entry.binary_sha256.get(name) == sha256:
            # A recorded entry is only trusted evidence when it was created by
            # `watchdog awg verify` against an independent build manifest. A
            # registry entry without that evidence (hand-edited or legacy) never
            # elevates provenance.
            if not entry.build_manifest_sha256:
                return PROVENANCE_UNKNOWN
            certified = CERTIFIED_PINS.get(entry.repository, {}).get("commit") == entry.commit
            return PROVENANCE_SUPPORTED if certified else PROVENANCE_EXPERIMENTAL
    return PROVENANCE_UNKNOWN


def probe_runtime(root: Path | None = None) -> RuntimeProbe:
    """Inspect the local AmneziaWG runtime without mutating anything.

    `root` is used first when provided (isolated tests), then the standard
    candidates. Provenance is resolved from durable recorded metadata (binary
    digest), never inferred from a bare numeric version string.
    """
    recorded = load_installed_history()
    components: dict[str, RuntimeComponent] = {}
    for name in AMNEZIAWG_OUTPUTS:
        path = _find_binary(name, root=root)
        present = path is not None
        version = None
        sha256 = None
        mode = None
        uid = None
        gid = None
        if path is not None:
            version = _run_version(path)
            sha256 = _sha256_of(path)
            try:
                st = path.stat()
                mode = oct(stat_module.S_IMODE(st.st_mode))
                uid = st.st_uid
                gid = st.st_gid
            except OSError:
                pass
        components[name] = RuntimeComponent(
            name=name,
            present=present,
            path=str(path) if path else None,
            version=version,
            sha256=sha256,
            mode=mode,
            uid=uid,
            gid=gid,
            provenance=PROVENANCE_MISSING if path is None else _provenance_from_metadata(name, sha256, recorded),
        )
    all_present = all(component.present for component in components.values())
    awg_present = components["awg"].present
    go_present = components["amneziawg-go"].present
    kernel_module = Path("/sys/module/amneziawg").exists()
    runtime_available = bool(all_present and awg_present and (go_present or kernel_module))
    return RuntimeProbe(
        components=components,
        all_present=all_present,
        runtime_available=runtime_available,
    )


def lifecycle_state(
    *,
    awg_profiles: int,
    probe: RuntimeProbe,
    just_imported: bool = False,
) -> str:
    """Resolve the AmneziaWG lifecycle state from profile context and probe."""
    if awg_profiles <= 0:
        return STATE_CONTEXT_ABSENT
    if probe.runtime_available:
        return STATE_PROFILE_AVAILABLE
    if just_imported:
        return STATE_IMPORTED_MISSING
    if any(component.present for component in probe.components.values()):
        unknown = any(
            component.present and component.provenance in (PROVENANCE_UNKNOWN, PROVENANCE_EXPERIMENTAL)
            for component in probe.components.values()
        )
        if unknown and not probe.all_present:
            return STATE_PROFILE_UNKNOWN
        return STATE_PROFILE_MISSING
    return STATE_PROFILE_MISSING


@dataclass(frozen=True)
class ResolvedRelease:
    repository: str
    tag: str
    commit: str
    resolved_at: str

    def as_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "url": f"https://github.com/{self.repository}",
            "tag": self.tag,
            "commit": self.commit,
            "resolved_at": self.resolved_at,
        }


FetchFn = Callable[[str], str]


class OfficialReleaseResolver:
    """Resolve the latest official AmneziaWG release as tag plus exact commit.

    Uses the GitHub REST API only against the two permitted official
    repositories. Annotated tags are dereferenced to their commit. If the
    release cannot be resolved or verified the resolution fails loudly and
    never falls back to main/master/HEAD.
    """

    def __init__(self, fetch: FetchFn | None = None, timeout: float = 10.0) -> None:
        self._fetch = fetch or self._default_fetch
        self.timeout = timeout

    @staticmethod
    def _default_fetch(url: str) -> str:
        import urllib.request

        request = urllib.request.Request(
            url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "watchdogvpn-awg-lifecycle"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - fixed official host
            return response.read().decode("utf-8")

    def _get_json(self, url: str) -> dict[str, object]:
        payload = self._get_json_any(url)
        if not isinstance(payload, dict):
            raise ReleaseResolutionError(f"GitHub returned an unexpected response shape for {url}")
        return payload

    def _get_json_any(self, url: str) -> object:
        import json as json_module

        try:
            raw = self._fetch(url)
        except (OSError, ValueError) as exc:
            raise ReleaseResolutionError(f"cannot reach GitHub to resolve the official release: {url}: {exc}") from exc
        try:
            return json_module.loads(raw)
        except (TypeError, ValueError) as exc:
            raise ReleaseResolutionError(f"GitHub returned an unparseable response for {url}") from exc

    def _resolve_latest_tag(self, repository: str) -> str:
        # Prefer the latest GitHub Release. Some official AmneziaWG repositories
        # (amneziawg-go) publish tags without GitHub Releases, so `/releases/latest`
        # returns 404; in that case fall back to the latest official tag and
        # dereference it to its exact commit. main/master/HEAD is never used.
        try:
            latest = self._get_json(f"https://api.github.com/repos/{repository}/releases/latest")
            tag = latest.get("tag_name")
            if isinstance(tag, str) and tag:
                return tag
        except ReleaseResolutionError:
            pass
        tags = self._get_json_any(f"https://api.github.com/repos/{repository}/tags?per_page=1")
        if isinstance(tags, list) and tags and isinstance(tags[0], dict):
            name = tags[0].get("name")
            if isinstance(name, str) and name:
                return name
        raise ReleaseResolutionError(
            f"official release for {repository} could not be resolved (no latest release and no resolvable tags)"
        )

    def resolve(self, repository: str) -> ResolvedRelease:
        if repository not in (AMNEZIAWG_TOOLS_REPO, AMNEZIAWG_TRANSPORT_REPO):
            raise ReleaseResolutionError(f"unsupported repository {repository}; only official AmneziaWG sources are allowed")
        tag = self._resolve_latest_tag(repository)
        commit = self._resolve_commit_for_tag(repository, tag)
        if not commit:
            raise ReleaseResolutionError(f"official release {repository}@{tag} has no resolvable commit")
        return ResolvedRelease(
            repository=repository,
            tag=tag,
            commit=commit,
            resolved_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def _resolve_commit_for_tag(self, repository: str, tag: str) -> str | None:
        ref = self._get_json(f"https://api.github.com/repos/{repository}/git/ref/tags/{tag}")
        obj = ref.get("object")
        if not isinstance(obj, dict):
            return None
        sha = obj.get("sha")
        obj_type = obj.get("type")
        if not isinstance(sha, str) or not sha:
            return None
        if obj_type == "commit":
            return sha
        if obj_type == "tag":
            # Annotated tag: dereference the tag object to its commit.
            tag_obj = self._get_json(f"https://api.github.com/repos/{repository}/git/tags/{sha}")
            target = tag_obj.get("object")
            if isinstance(target, dict) and isinstance(target.get("sha"), str):
                return target["sha"]
        return None


def detect_platform() -> dict[str, str]:
    """Detect the running distro/version/architecture for recipe generation."""
    arch = os.uname().machine if hasattr(os, "uname") else "x86_64"
    distro = "unknown"
    version = "unknown"
    try:
        os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        os_release = ""
    for line in os_release.splitlines():
        if line.startswith("ID="):
            distro = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("VERSION_ID="):
            version = line.split("=", 1)[1].strip().strip('"')
    return {"distro": distro, "version": version, "arch": arch}


def _platform(distro: str | None = None, version: str | None = None, arch: str | None = None) -> dict[str, str]:
    detected = detect_platform()
    return {
        "distro": distro or os.environ.get("WATCHDOGVPN_LIFECYCLE_DISTRO", detected["distro"]),
        "version": version or os.environ.get("WATCHDOGVPN_LIFECYCLE_DISTRO_VERSION", detected["version"]),
        "arch": arch or os.environ.get("WATCHDOGVPN_LIFECYCLE_ARCH", detected["arch"]),
    }


def _build_dependency_command(platform: Mapping[str, str]) -> dict[str, str]:
    if platform["distro"] in ("opensuse_leap", "opensuse_tumbleweed"):
        install = "sudo zypper --non-interactive install go gcc make git"
    elif platform["distro"] in ("fedora", "rhel", "centos", "rocky", "almalinux"):
        install = "sudo dnf install -y golang git make gcc"
    elif platform["distro"] in ("ubuntu", "debian", "linuxmint"):
        install = "sudo apt-get install -y golang-go git make gcc"
    elif platform["distro"] in ("arch", "cachyos"):
        install = "sudo pacman -S --needed --noconfirm go git make gcc"
    else:
        install = "sudo zypper --non-interactive install go gcc make git"
    return {"command": install, "purpose": "Install the build dependencies required to build AmneziaWG from official source"}


def _checkout_and_verify(repository: str, tag: str, commit: str, workdir: str) -> str:
    return (
        f"git clone --branch {tag} https://github.com/{repository} {workdir} "
        f"&& git -C {workdir} checkout {commit} "
        f"&& test \"$(git -C {workdir} rev-parse HEAD)\" = \"{commit}\""
    )


def _manifest_python(tools_release: ResolvedRelease, transport_release: ResolvedRelease) -> str:
    return (
        "import datetime, hashlib, json, os, sys\n"
        "build_dir = sys.argv[1]; out = sys.argv[2]\n"
        "paths = {\n"
        "  'awg': os.path.join(build_dir, 'amneziawg-tools/src/wg'),\n"
        "  'awg-quick': os.path.join(build_dir, 'amneziawg-tools/src/wg-quick/linux.bash'),\n"
        "  'amneziawg-go': os.path.join(build_dir, 'amneziawg-go/amneziawg-go'),\n"
        "}\n"
        "digests = {name: hashlib.sha256(open(p, 'rb').read()).hexdigest() for name, p in paths.items()}\n"
        "distro = 'unknown'\n"
        "try:\n"
        "  with open('/etc/os-release') as f:\n"
        "    for line in f:\n"
        "      if line.startswith('ID='): distro = line.split('=', 1)[1].strip().strip('\\\"')\n"
        "except OSError:\n"
        "  pass\n"
        "manifest = {\n"
        "  'schema': 1,\n"
        f"  'tools': {{'repository': {AMNEZIAWG_TOOLS_REPO!r}, 'tag': {tools_release.tag!r}, 'commit': {tools_release.commit!r}}},\n"
        f"  'transport': {{'repository': {AMNEZIAWG_TRANSPORT_REPO!r}, 'tag': {transport_release.tag!r}, 'commit': {transport_release.commit!r}}},\n"
        "  'outputs': digests,\n"
        "  'arch': os.uname().machine,\n"
        "  'distro': distro,\n"
        "  'built_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),\n"
        "}\n"
        "open(out, 'w').write(json.dumps(manifest, indent=1))\n"
    )


def _manifest_generate_command(tools_release: ResolvedRelease, transport_release: ResolvedRelease) -> dict[str, str]:
    python = _manifest_python(tools_release, transport_release)
    return {
        "command": (
            f'python3 -c "{python}" "$build_dir" "$build_dir/amneziawg_build_manifest.json"'
        ),
        "purpose": (
            "Generate the independent build manifest (commits + SHA-256 of the built awg, awg-quick and "
            "amneziawg-go) before installing; watchdog awg verify requires it"
        ),
    }


def _manifest_install_command() -> dict[str, str]:
    target_dir = str(Path(BUILD_MANIFEST_SYSTEM_PATH).parent)
    return {
        "command": f"sudo mkdir -p {target_dir} && sudo install -m 0644 \"$build_dir/amneziawg_build_manifest.json\" {BUILD_MANIFEST_SYSTEM_PATH}",
        "purpose": "Install the build manifest where `watchdog awg verify` reads it",
    }


def build_recipe(
    *,
    releases: Sequence[ResolvedRelease],
    distro: str | None = None,
    version: str | None = None,
    arch: str | None = None,
) -> dict[str, object]:
    """Generate the exact, user-executed recipe for an AmneziaWG runtime.

    The recipe is only printed for the user to review and run. WatchdogVPN
    never executes these commands itself.

    Safety: the build workspace is a unique mktemp directory owned by this
    recipe and cleaned only through its own trap/cleanup; no fixed temporary
    path is ever removed. Every checkout verifies that the observed commit
    matches the resolved commit before compiling.
    """
    platform = _platform(distro, version, arch)
    releases_by_repo = {release.repository: release for release in releases}
    tools_release = releases_by_repo.get(AMNEZIAWG_TOOLS_REPO)
    transport_release = releases_by_repo.get(AMNEZIAWG_TRANSPORT_REPO)
    if tools_release is None or transport_release is None:
        raise ReleaseResolutionError(
            "recipe requires both amneziawg-tools and amneziawg-go official releases"
        )

    tools_workdir = '"$build_dir/amneziawg-tools"'
    transport_workdir = '"$build_dir/amneziawg-go"'
    commands: list[dict[str, str]] = []
    commands.append(
        {
            "command": 'build_dir="$(mktemp -d /tmp/watchdogvpn-amneziawg.XXXXXX)" && echo "build_dir=$build_dir"',
            "purpose": "Create a unique temporary build workspace owned by this recipe (run the numbered steps in the same shell)",
        }
    )
    commands.append(_build_dependency_command(platform))
    commands.extend(
        [
            {
                "command": _checkout_and_verify(AMNEZIAWG_TOOLS_REPO, tools_release.tag, tools_release.commit, tools_workdir),
                "purpose": f"Fetch official {AMNEZIAWG_TOOLS_REPO} release {tools_release.tag} at exact commit {tools_release.commit} and verify it",
            },
            {
                "command": f'make -C {tools_workdir}/src WITH_WGQUICK=yes WITH_SYSTEMDUNITS=no WITH_BASHCOMPLETION=no',
                "purpose": "Build awg and awg-quick from the official amneziawg-tools source",
            },
            {
                "command": _checkout_and_verify(AMNEZIAWG_TRANSPORT_REPO, transport_release.tag, transport_release.commit, transport_workdir),
                "purpose": f"Fetch official {AMNEZIAWG_TRANSPORT_REPO} release {transport_release.tag} at exact commit {transport_release.commit} and verify it",
            },
            {
                "command": f'make -C {transport_workdir}',
                "purpose": "Build the amneziawg-go userspace transport from the official amneziawg-go source",
            },
            _manifest_generate_command(tools_release, transport_release),
            {
                "command": f'sudo make -C {tools_workdir}/src install',
                "purpose": "Install awg and awg-quick under /usr/local/bin",
            },
            {
                "command": f'sudo install -m 0755 {transport_workdir}/amneziawg-go /usr/local/bin/amneziawg-go',
                "purpose": "Install amneziawg-go under /usr/local/bin with 0755 ownership",
            },
            _manifest_install_command(),
        ]
    )
    commands.append(
        {
            "command": 'rm -rf "$build_dir"',
            "purpose": "Remove only this recipe's unique temporary workspace (created with mktemp, owned by this recipe)",
        }
    )
    commands.append(
        {
            "command": "watchdog awg verify",
            "purpose": "Record and verify the installed AmneziaWG runtime with WatchdogVPN after the recipe",
        }
    )

    certified = all(
        CERTIFIED_PINS.get(release.repository, {}).get("commit") == release.commit
        for release in (tools_release, transport_release)
    )
    compatibility = (
        {
            "status": "verified",
            "note": "Both components match the WatchdogVPN-certified pins for openSUSE Leap.",
        }
        if certified
        else {
            "status": "not_verified",
            "note": (
                "Latest upstream pair resolved, but compatibility between amneziawg-tools and "
                "amneziawg-go is NOT yet verified. This pair is experimental and is NOT supported "
                "until it passes real validation on openSUSE Leap."
            ),
        }
    )
    return {
        "commands": commands,
        "script": _recipe_script(tools_release, transport_release, platform),
        "platform": platform,
        "certified_on_opensuse_leap": certified,
        "compatibility": compatibility,
        "releases": [release.as_dict() for release in (tools_release, transport_release)],
        "sources": [AMNEZIAWG_TOOLS_URL, AMNEZIAWG_TRANSPORT_URL],
        "executed_by_watchdogvpn": False,
    }


def _recipe_script(
    tools_release: ResolvedRelease,
    transport_release: ResolvedRelease,
    platform: Mapping[str, str],
) -> str:
    """Self-contained, interrupt-safe recipe the user can run as one unit."""
    dependency = _build_dependency_command(platform)["command"]
    manifest_python = _manifest_python(tools_release, transport_release)
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        'build_dir="$(mktemp -d /tmp/watchdogvpn-amneziawg.XXXXXX)"',
        'trap \'rm -rf "$build_dir"\' EXIT',
        dependency,
        _checkout_and_verify(AMNEZIAWG_TOOLS_REPO, tools_release.tag, tools_release.commit, '"$build_dir/amneziawg-tools"'),
        'make -C "$build_dir/amneziawg-tools/src" WITH_WGQUICK=yes WITH_SYSTEMDUNITS=no WITH_BASHCOMPLETION=no',
        _checkout_and_verify(AMNEZIAWG_TRANSPORT_REPO, transport_release.tag, transport_release.commit, '"$build_dir/amneziawg-go"'),
        'make -C "$build_dir/amneziawg-go"',
        'python3 - "$build_dir" "$build_dir/amneziawg_build_manifest.json" <<PYEOF',
        manifest_python,
        "PYEOF",
        'sudo make -C "$build_dir/amneziawg-tools/src" install',
        'sudo install -m 0755 "$build_dir/amneziawg-go/amneziawg-go" /usr/local/bin/amneziawg-go',
        f"sudo mkdir -p {Path(BUILD_MANIFEST_SYSTEM_PATH).parent} && sudo install -m 0644 \"$build_dir/amneziawg_build_manifest.json\" {BUILD_MANIFEST_SYSTEM_PATH}",
        "watchdog awg verify",
    ]
    return "\n".join(lines) + "\n"


def recipe_for_certified_pins(
    *,
    distro: str | None = None,
    version: str | None = None,
    arch: str | None = None,
) -> dict[str, object]:
    """Build an exact offline recipe pinned to the certified tags/commits.

    Used by `watchdog awg repair` and the restore-to-supported path so a broken
    runtime can be rebuilt without a network call. This is not a rollback: it
    restores the certified supported release, not a user's previous release.
    """
    platform = _platform(distro, version, arch)
    tools_pin = CERTIFIED_PINS[AMNEZIAWG_TOOLS_REPO]
    transport_pin = CERTIFIED_PINS[AMNEZIAWG_TRANSPORT_REPO]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    releases = [
        ResolvedRelease(AMNEZIAWG_TOOLS_REPO, tools_pin["tag"], tools_pin["commit"], now),
        ResolvedRelease(AMNEZIAWG_TRANSPORT_REPO, transport_pin["tag"], transport_pin["commit"], now),
    ]
    recipe = build_recipe(releases=releases, distro=distro, version=version, arch=arch)
    recipe["certified_on_opensuse_leap"] = True
    recipe["resolution_note"] = "Recipe pinned to the certified WatchdogVPN release tags; no network resolution was required."
    return recipe


def import_guidance_payload(*, distro: str | None = None, version: str | None = None, arch: str | None = None) -> dict[str, object]:
    """Dynamic guidance for the import/provider flows.

    Uses the same official-release resolver as `watchdog awg setup/update`, so
    the guidance shown after importing an AWG profile always reflects the
    latest official release (tag + commit), never a silently static pin. If the
    official release cannot be resolved, the guidance blocks explicitly.
    """
    probe = probe_runtime()
    platform = _platform(distro, version, arch)
    base: dict[str, object] = {
        "available": probe.runtime_available,
        "distro": platform["distro"],
        "distro_adapter": _distro_adapter_id(platform["distro"]),
        "tools_available": probe.components["awg"].present,
        "kernel_module_available": Path("/sys/module/amneziawg").exists(),
        "userspace_fallback_available": probe.components["amneziawg-go"].present,
        "executed_by_watchdogvpn": False,
    }
    if probe.runtime_available:
        base["message"] = "AmneziaWG runtime is available; nothing to set up."
        base["commands"] = []
        return base
    resolver = OfficialReleaseResolver()
    try:
        tools = resolver.resolve(AMNEZIAWG_TOOLS_REPO)
        transport = resolver.resolve(AMNEZIAWG_TRANSPORT_REPO)
    except ReleaseResolutionError as exc:
        base["available"] = False
        base["blocked"] = True
        base["commands"] = []
        base["reason"] = str(exc)
        base["message"] = (
            "AmneziaWG profile saved, but the exact official recipe could not be resolved.\n"
            f"Reason: {exc}\n"
            "WatchdogVPN never falls back to main/master/HEAD or to a static recipe without resolution."
        )
        return base
    recipe = build_recipe(releases=[tools, transport], distro=platform["distro"], version=platform["version"], arch=platform["arch"])
    store_pending_releases([tools, transport])
    base["available"] = False
    base["blocked"] = False
    base["commands"] = recipe["commands"]
    base["script"] = recipe["script"]
    base["certified_on_opensuse_leap"] = recipe["certified_on_opensuse_leap"]
    base["compatibility"] = recipe["compatibility"]
    base["releases"] = recipe["releases"]
    base["sources"] = recipe["sources"]
    base["message"] = (
        "AmneziaWG profile saved, but its local runtime is not ready yet.\n"
        "Review and run the exact official recipe below yourself; WatchdogVPN never executes it."
    )
    return base


def _distro_adapter_id(distro: str) -> str:
    mapping = {
        "opensuse-leap": "opensuse",
        "opensuse_tumbleweed": "opensuse",
        "opensuse": "opensuse",
        "ubuntu": "ubuntu",
        "debian": "debian",
        "linuxmint": "ubuntu",
        "fedora": "fedora",
        "rhel": "fedora",
        "centos": "fedora",
        "rocky": "fedora",
        "almalinux": "fedora",
        "arch": "arch",
        "cachyos": "arch",
    }
    return mapping.get(distro, "unknown")


def build_manifest_matches_current(manifest: dict[str, object] | None, probe: RuntimeProbe) -> bool:
    """Check whether the present build manifest matches the currently installed binaries.

    Used by `watchdog awg status` to detect a binary substituted after install
    (digest mismatch). A missing manifest is a mismatch (no evidence).
    """
    if manifest is None:
        return False
    outputs = manifest.get("outputs")
    if not isinstance(outputs, dict):
        return False
    for name in AMNEZIAWG_OUTPUTS:
        component = probe.components.get(name)
        observed = component.sha256 if component is not None else None
        expected = outputs.get(name)
        if not (observed and expected and str(expected) == observed):
            return False
    return True


def verification_report(probe: RuntimeProbe) -> dict[str, object]:
    """Produce the post-recipe verification contract."""
    checks: list[dict[str, object]] = []
    for name, component in probe.components.items():
        checks.append(
            {
                "component": name,
                "present": component.present,
                "version_identifiable": component.version is not None,
                "provenance": component.provenance,
                "digest_recorded": component.sha256 is not None,
                "permissions_ok": component.mode in ("0o755", "0o755") and component.uid == 0,
            }
        )
    return {
        "runtime_available": probe.runtime_available,
        "all_outputs_present": probe.all_present,
        "checks": checks,
        "verified": probe.runtime_available,
    }