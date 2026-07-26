"""Internal read-only compatibility detection layer (Phase 23.7.5.4)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Mapping, Sequence

from compat.support_model import (
    CoreCapabilityStatus,
    HostReadiness,
    ProtocolReadiness,
    ProtocolRuntimeStatus,
    RollingFacts,
    StableReleaseFacts,
    SupportClassification,
    classify_host_readiness,
    classify_protocol_readiness,
    classify_support_rolling,
    classify_support_stable,
)
from tools import compat_read


MAX_OS_RELEASE_BYTES = 64 * 1024
_OS_RELEASE_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_ARCH_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86-64": "x86_64",
    "arm64": "aarch64",
}


class DetectionError(ValueError):
    """Raised for controlled detection/input errors."""


@dataclass(frozen=True)
class OsReleaseData:
    values: Mapping[str, str]
    source: str

    def get(self, key: str) -> str | None:
        return self.values.get(key)


@dataclass(frozen=True)
class DistroFacts:
    id_raw: str | None
    id_normalized: str | None
    id_like_ordered: tuple[str, ...]
    version_id: str | None
    version_codename: str | None
    ubuntu_codename: str | None
    pretty_name: str | None
    release_model: str | None
    resolved_distribution: str | None
    resolved_release: str | None
    technical_family: str | None
    adapter: str | None
    package_manager: str | None
    is_derivative: bool
    lineage_distribution: str | None
    mapping_evidence: str | None
    kernel_release: str | None
    machine_architecture: str | None
    os_release_source: str | None
    resolution_status: str


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    status: str
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    reason: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(frozen=True)
class CapabilityResult:
    capability_id: str
    observed_status: str
    domain_status: str
    evidence: str
    probe_method: str
    reason: str
    error_kind: str | None = None


@dataclass(frozen=True)
class EvaluationReport:
    distro_facts: DistroFacts
    support_classification: str
    host_readiness: str
    protocol_readiness: Mapping[str, str]
    core_capabilities: tuple[CapabilityResult, ...]
    protocol_capabilities: tuple[CapabilityResult, ...]


def _enum_value(value):
    return value.value if hasattr(value, "value") else value


def stable_json(value) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def to_jsonable(value):
    if hasattr(value, "__dataclass_fields__"):
        return {k: to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, tuple):
        return [to_jsonable(v) for v in value]
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: to_jsonable(v) for k, v in value.items()}
    return _enum_value(value)


class SafeCommandRunner:
    """Single read-only command runner abstraction used by every external probe."""

    def __init__(self, *, path: str = _SAFE_PATH, output_limit: int = 8192):
        self.path = path
        self.output_limit = output_limit

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        if not isinstance(argv, (list, tuple)) or not argv:
            raise DetectionError("argv must be a non-empty list")
        if any(not isinstance(part, str) or not part for part in argv):
            raise DetectionError("argv entries must be non-empty strings")
        if timeout <= 0:
            raise DetectionError("timeout must be positive")
        if self.output_limit <= 0:
            raise DetectionError("output_limit must be positive")
        program = argv[0]
        try:
            if "/" not in program:
                resolved = shutil.which(program, path=self.path)
                if resolved is None:
                    return CommandResult(tuple(argv), "command_missing", reason="command not found")
                command = [resolved] + list(argv[1:])
            else:
                command = list(argv)
                if not os.path.exists(program):
                    return CommandResult(tuple(argv), "command_missing", reason="command not found")
                if not os.path.isfile(program):
                    return CommandResult(tuple(argv), "invalid_executable", reason="executable is not a regular file")
        except (OSError, ValueError) as exc:
            return CommandResult(tuple(argv), "unknown", reason="executable resolution failed: %s" % exc)
        env = {"PATH": self.path, "LC_ALL": "C", "LANG": "C"}
        process = None
        try:
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                process = subprocess.Popen(
                    command,
                    shell=False,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    env=env,
                    text=False,
                    close_fds=True,
                )
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    return CommandResult(tuple(argv), "timeout", reason="command timed out")
                stdout, stdout_truncated = _read_limited_output(stdout_file, self.output_limit)
                stderr, stderr_truncated = _read_limited_output(stderr_file, self.output_limit)
        except FileNotFoundError:
            return CommandResult(tuple(argv), "command_missing", reason="command not found")
        except PermissionError as exc:
            return CommandResult(tuple(argv), "permission_denied", reason=str(exc))
        except (OSError, ValueError) as exc:
            return CommandResult(tuple(argv), "unknown", reason="command execution failed: %s" % exc)
        if process is None:
            return CommandResult(tuple(argv), "unknown", reason="command did not start")
        if process.returncode != 0:
            status = "permission_denied" if process.returncode in (1, 13, 126) and "permission" in stderr.lower() else "nonzero_exit"
            return CommandResult(
                tuple(argv),
                status,
                process.returncode,
                stdout,
                stderr,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )
        return CommandResult(
            tuple(argv),
            "ok",
            process.returncode,
            stdout,
            stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )


def _read_limited_output(handle, limit: int) -> tuple[str, bool]:
    handle.seek(0)
    data = handle.read(limit + 1)
    truncated = len(data) > limit
    if truncated:
        data = data[:limit]
    return data.decode("utf-8", errors="replace"), truncated


class FakeCommandRunner:
    def __init__(self, results: Mapping[tuple[str, ...], CommandResult] | None = None):
        self.results = dict(results or {})
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        key = tuple(argv)
        self.calls.append(key)
        return self.results.get(key, CommandResult(key, "command_missing", reason="fake missing"))


def parse_os_release_text(text: str, *, source: str = "<memory>") -> OsReleaseData:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise DetectionError("%s:%d malformed os-release line" % (source, line_number))
        key, raw_value = line.split("=", 1)
        if not _OS_RELEASE_KEY_RE.match(key):
            raise DetectionError("%s:%d invalid os-release key" % (source, line_number))
        if key in values:
            raise DetectionError("%s:%d duplicate os-release key %s" % (source, line_number, key))
        values[key] = _parse_os_release_value(raw_value, source, line_number)
    return OsReleaseData(values=values, source=source)


def _parse_os_release_value(raw_value: str, source: str, line_number: int) -> str:
    if raw_value == "":
        return ""
    if raw_value[0] in ("'", '"'):
        quote = raw_value[0]
        if len(raw_value) < 2 or raw_value[-1] != quote:
            raise DetectionError("%s:%d unterminated os-release quote" % (source, line_number))
        body = raw_value[1:-1]
        if "$" in body or "`" in body:
            raise DetectionError("%s:%d os-release expansion is not allowed" % (source, line_number))
        return _decode_quoted_value(body, quote, source, line_number)
    if any(token in raw_value for token in ("$", "`", "$(", "${")):
        raise DetectionError("%s:%d os-release expansion is not allowed" % (source, line_number))
    if any(ch.isspace() for ch in raw_value):
        raise DetectionError("%s:%d unquoted os-release whitespace is not allowed" % (source, line_number))
    return raw_value


def _decode_quoted_value(body: str, quote: str, source: str, line_number: int) -> str:
    output: list[str] = []
    index = 0
    while index < len(body):
        ch = body[index]
        if ch == "\\":
            index += 1
            if index >= len(body):
                raise DetectionError("%s:%d trailing escape" % (source, line_number))
            escaped = body[index]
            if quote == '"' and escaped in ('"', "\\", "$", "`"):
                output.append(escaped)
            elif quote == "'" and escaped in ("'", "\\"):
                output.append(escaped)
            else:
                raise DetectionError("%s:%d unsupported os-release escape" % (source, line_number))
        else:
            output.append(ch)
        index += 1
    return "".join(output)


def read_os_release(
    *,
    etc_path: Path = Path("/etc/os-release"),
    usr_path: Path = Path("/usr/lib/os-release"),
) -> OsReleaseData:
    etc_exists = _safe_exists(etc_path, "etc os-release")
    if not etc_exists and _safe_is_symlink(etc_path, "etc os-release"):
        raise DetectionError("os-release symlink is broken: %s" % etc_path)
    selected = etc_path if etc_exists else usr_path
    if not _safe_exists(selected, "os-release"):
        if _safe_is_symlink(selected, "os-release"):
            raise DetectionError("os-release symlink is broken: %s" % selected)
        raise DetectionError("os-release file not found")
    try:
        resolved = selected.resolve(strict=True)
    except OSError as exc:
        raise DetectionError("cannot resolve os-release path: %s" % exc) from exc
    if _safe_is_symlink(selected, "os-release") and resolved != usr_path.resolve(strict=False):
        raise DetectionError("os-release symlink target is outside allowed paths")
    try:
        if not resolved.is_file():
            raise DetectionError("os-release target must be a regular file")
        size = resolved.stat().st_size
    except DetectionError:
        raise
    except OSError as exc:
        raise DetectionError("cannot stat os-release: %s" % exc) from exc
    if size > MAX_OS_RELEASE_BYTES:
        raise DetectionError("os-release exceeds %d byte limit" % MAX_OS_RELEASE_BYTES)
    try:
        with resolved.open("rb") as handle:
            raw = handle.read(MAX_OS_RELEASE_BYTES + 1)
    except OSError as exc:
        raise DetectionError("cannot read os-release: %s" % exc) from exc
    if len(raw) > MAX_OS_RELEASE_BYTES:
        raise DetectionError("os-release exceeds %d byte limit" % MAX_OS_RELEASE_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DetectionError("os-release must be valid UTF-8: %s" % exc) from exc
    return parse_os_release_text(text, source=str(selected))


def _safe_exists(path: Path, label: str) -> bool:
    try:
        return path.exists()
    except OSError as exc:
        raise DetectionError("cannot check %s existence: %s" % (label, exc)) from exc


def _safe_is_symlink(path: Path, label: str) -> bool:
    try:
        return path.is_symlink()
    except OSError as exc:
        raise DetectionError("cannot check %s symlink status: %s" % (label, exc)) from exc


def normalize_id(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip().lower().replace("-", "_")
    return text or None


def normalize_arch(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip().lower()
    return _ARCH_ALIASES.get(text, text)


def distro_facts_from_os_release(
    os_release: OsReleaseData,
    manifest: Mapping,
    *,
    kernel_release: str | None = None,
    machine_architecture: str | None = None,
) -> DistroFacts:
    raw_id = os_release.get("ID")
    normalized = normalize_id(raw_id)
    id_like = tuple(filter(None, (normalize_id(v) for v in (os_release.get("ID_LIKE") or "").split())))
    version_id = os_release.get("VERSION_ID")
    version_codename = os_release.get("VERSION_CODENAME")
    ubuntu_codename = os_release.get("UBUNTU_CODENAME")
    pretty_name = os_release.get("PRETTY_NAME")
    kernel = kernel_release if kernel_release is not None else platform.release()
    arch = normalize_arch(machine_architecture if machine_architecture is not None else platform.machine())
    return resolve_distribution(
        manifest,
        id_raw=raw_id,
        id_normalized=normalized,
        id_like_ordered=id_like,
        version_id=version_id,
        version_codename=version_codename,
        ubuntu_codename=ubuntu_codename,
        pretty_name=pretty_name,
        kernel_release=kernel,
        machine_architecture=arch,
        os_release_source=os_release.source,
    )


def resolve_distribution(
    manifest: Mapping,
    *,
    id_raw: str | None,
    id_normalized: str | None,
    id_like_ordered: tuple[str, ...],
    version_id: str | None,
    version_codename: str | None,
    ubuntu_codename: str | None,
    pretty_name: str | None,
    kernel_release: str | None,
    machine_architecture: str | None,
    os_release_source: str | None,
) -> DistroFacts:
    distributions = manifest["distributions"]
    os_release_id_map = _os_release_id_map(manifest)
    distro_id = os_release_id_map.get(id_normalized)
    status = "unknown_distribution"
    mapping_evidence = None
    lineage_distribution = None
    resolved_release = None
    family_distro_id = None
    if distro_id is not None:
        status = "resolved"
    else:
        for derivative_id, derivative in sorted(manifest["derivatives"].items()):
            if derivative["distribution"] == id_normalized:
                distro_id = derivative["distribution"]
                mapping_evidence = derivative_id
                status = "resolved_derivative"
                break
    if distro_id is None:
        for like_id in id_like_ordered:
            like_distro_id = os_release_id_map.get(like_id)
            if like_distro_id is not None:
                family_distro_id = like_distro_id
                status = "family_recognized_by_id_like"
                mapping_evidence = "id_like:%s" % like_id
                break
    release_model = None
    technical_family = None
    adapter = None
    package_manager = None
    is_derivative = False
    source_distro_id = distro_id or family_distro_id
    if source_distro_id is not None:
        distro = distributions[source_distro_id]
        release_model = distro["release_model"]
        technical_family = distro["technical_family"]
        family = manifest["technical_families"][technical_family]
        adapter = family["adapter"]
        package_manager = family["package_manager"]
        if distro_id is not None:
            is_derivative = distro["lineage"]["is_derivative"]
        for derivative_id, derivative in manifest["derivatives"].items():
            if derivative["distribution"] == source_distro_id:
                lineage_distribution = derivative["lineage_distribution"]
                mapping_evidence = mapping_evidence or derivative_id
        if distro_id is not None and release_model == "stable":
            resolved_release, release_status = _resolve_stable_release(
                manifest, distro_id, version_id, version_codename, ubuntu_codename
            )
            if release_status != "resolved":
                status = release_status
        elif distro_id is not None:
            resolved_release = None
    return DistroFacts(
        id_raw=id_raw,
        id_normalized=id_normalized,
        id_like_ordered=id_like_ordered,
        version_id=version_id,
        version_codename=version_codename,
        ubuntu_codename=ubuntu_codename,
        pretty_name=pretty_name,
        release_model=release_model,
        resolved_distribution=distro_id,
        resolved_release=resolved_release,
        technical_family=technical_family,
        adapter=adapter,
        package_manager=package_manager,
        is_derivative=is_derivative,
        lineage_distribution=lineage_distribution,
        mapping_evidence=mapping_evidence,
        kernel_release=kernel_release,
        machine_architecture=machine_architecture,
        os_release_source=os_release_source,
        resolution_status=status,
    )


def _resolve_stable_release(
    manifest: Mapping,
    distro_id: str,
    version_id: str | None,
    version_codename: str | None,
    ubuntu_codename: str | None,
):
    distro = manifest["distributions"][distro_id]
    for derivative_id, derivative in manifest["derivatives"].items():
        if derivative["distribution"] == distro_id and derivative["mapping_type"] == "codename_map":
            codename = ubuntu_codename or version_codename
            if codename in derivative["codename_map"]:
                release_id = _find_release_for_distribution(
                    manifest, distro_id, version_id, version_codename
                )
                if release_id is not None:
                    return release_id, "resolved"
                return None, "release_unknown"
            return None, "derivative_mapping_unknown"
    found = _find_release_for_distribution(manifest, distro_id, version_id, version_codename)
    if found is not None:
        return found, "resolved"
    if distro["release_model"] == "stable":
        return None, "release_unknown"
    return None, "resolved"


def _os_release_id_map(manifest: Mapping) -> dict[str, str]:
    result = {}
    for distro_id, distro in manifest["distributions"].items():
        for os_release_id in distro.get("os_release_ids", [distro_id]):
            result[os_release_id] = distro_id
    return result


def _find_release_for_distribution(
    manifest: Mapping,
    distro_id: str,
    version_id: str | None,
    version_codename: str | None,
) -> str | None:
    for release_id, release in manifest["releases"].items():
        if release["distribution"] == distro_id and release["version"] == version_id:
            return release_id
        if (
            release["distribution"] == distro_id
            and version_codename is not None
            and release.get("codename") == version_codename
        ):
            return release_id
    return None


def _find_release_by_distribution(manifest: Mapping, distro_id: str) -> str | None:
    candidates = sorted(release_id for release_id, release in manifest["releases"].items() if release["distribution"] == distro_id)
    return candidates[0] if candidates else None


def _supported_architectures(manifest: Mapping) -> set[str]:
    values = manifest["capabilities"]["core_host_capabilities"]["cap_architecture"]["supported_values"]
    return {normalize_arch(value) for value in values}


class ProbeEnvironment:
    def __init__(
        self,
        *,
        runner=None,
        files: Mapping[str, str] | None = None,
        existing_paths: set[str] | None = None,
        machine_architecture: str | None = None,
        kernel_release: str | None = None,
        python_version: tuple[int, int, int] | None = None,
        allow_host_fallback: bool = True,
    ):
        self.runner = runner or SafeCommandRunner()
        self.files = dict(files or {})
        self.existing_paths = set(existing_paths or set())
        self.allow_host_fallback = allow_host_fallback
        self.machine_architecture = normalize_arch(
            machine_architecture if machine_architecture is not None else (platform.machine() if allow_host_fallback else "")
        )
        self.kernel_release = kernel_release if kernel_release is not None else (platform.release() if allow_host_fallback else "")
        self.python_version = python_version if python_version is not None else (sys.version_info[:3] if allow_host_fallback else (0, 0, 0))

    def read_file(self, path: str) -> str | None:
        if path in self.files:
            return self.files[path]
        if not self.allow_host_fallback:
            return None
        try:
            return Path(path).read_text(encoding="utf-8")
        except OSError:
            return None
        except UnicodeDecodeError:
            return None

    def exists(self, path: str) -> bool:
        if path in self.existing_paths:
            return True
        if not self.allow_host_fallback:
            return False
        try:
            return Path(path).exists()
        except OSError:
            return False

    def run(self, argv: Sequence[str], *, timeout: float = 2.0) -> CommandResult:
        return self.runner.run(argv, timeout=timeout)


def probe_core_capabilities(manifest: Mapping, facts: DistroFacts, env: ProbeEnvironment | None = None) -> tuple[CapabilityResult, ...]:
    env = env or ProbeEnvironment()
    env.manifest = manifest
    family_caps = []
    if facts.technical_family:
        family_caps = list(manifest["technical_families"][facts.technical_family]["core_capabilities"])
    else:
        family_caps = sorted(manifest["capabilities"]["core_host_capabilities"])
    results = [_probe_core(cap_id, facts, env) for cap_id in family_caps]
    if not results:
        raise DetectionError("core capability list must not be empty")
    return tuple(results)


def _cap(capability_id: str, observed: str, status, evidence: str, method: str, reason: str, error: str | None = None) -> CapabilityResult:
    return CapabilityResult(capability_id, observed, status.value, evidence, method, reason, error)


def _probe_core(capability_id: str, facts: DistroFacts, env: ProbeEnvironment) -> CapabilityResult:
    if capability_id == "cap_systemd":
        comm = (env.read_file("/proc/1/comm") or "").strip()
        if comm == "systemd":
            return _cap(capability_id, "present", CoreCapabilityStatus.PRESENT, comm, "read:/proc/1/comm", "systemd is PID 1")
        return _cap(capability_id, "absent", CoreCapabilityStatus.PROVISIONABLE, comm, "read:/proc/1/comm", "systemd not proven as PID 1")
    if capability_id == "cap_package_manager":
        command = {"apt": "apt-get", "dnf": "dnf", "zypper": "zypper", "pacman": "pacman"}.get(facts.package_manager or "")
        result = env.run([command, "--version"], timeout=2.0) if command else CommandResult((), "not_applicable")
        if result.status == "ok":
            return _cap(capability_id, "partial", CoreCapabilityStatus.PROVISIONABLE, result.stdout.strip(), "command:" + " ".join(result.argv), "package manager binary observed; install transaction not verified")
        return _command_cap(capability_id, result, "package manager probe")
    if capability_id == "cap_architecture":
        if facts.machine_architecture in _supported_architectures(env.manifest):
            return _cap(capability_id, "present", CoreCapabilityStatus.PRESENT, facts.machine_architecture or "", "manifest.cap_architecture.supported_values", "architecture admitted by manifest")
        return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, facts.machine_architecture or "", "platform.machine", "architecture not recognized", "unknown")
    if capability_id == "cap_kernel":
        return _cap(capability_id, "partial" if env.kernel_release else "unknown", CoreCapabilityStatus.PROVISIONABLE, env.kernel_release or "", "platform.release", "kernel release observed; required kernel capabilities not verified")
    if capability_id == "cap_python310":
        version = env.python_version
        ok = version >= (3, 10)
        return _cap(capability_id, "present" if ok else "absent", CoreCapabilityStatus.PRESENT if ok else CoreCapabilityStatus.PROVISIONABLE, "%d.%d.%d" % version[:3], "sys.version_info", "final Python floor check")
    if capability_id == "cap_sudo":
        result = env.run(["sudo", "-V"], timeout=2.0)
        if result.status == "ok":
            return _cap(capability_id, "partial", CoreCapabilityStatus.PROVISIONABLE, result.stdout.strip(), "command:sudo -V", "sudo binary observed; usable elevation path not verified")
        return _command_cap(capability_id, result, "sudo binary probe")
    if capability_id == "cap_polkit":
        result = env.run(["pkaction", "--version"], timeout=2.0)
        if result.status == "ok":
            return _cap(capability_id, "partial", CoreCapabilityStatus.PROVISIONABLE, result.stdout.strip(), "command:pkaction --version", "polkit client observed; WatchdogVPN action path not verified")
        return _command_cap(capability_id, result, "polkit client probe")
    if capability_id == "cap_network_manager":
        result = env.run(["nmcli", "-t", "-f", "RUNNING", "general"], timeout=2.0)
        if result.status == "ok" and result.stdout.strip().lower() == "running":
            return _cap(capability_id, "present", CoreCapabilityStatus.PRESENT, result.stdout, "nmcli general", "NetworkManager reports running")
        if result.status == "ok":
            return _cap(capability_id, "absent", CoreCapabilityStatus.PROVISIONABLE, result.stdout, "nmcli general", "NetworkManager is not running")
        return _command_cap(capability_id, result, "NetworkManager not proven active")
    if capability_id == "cap_dns_backend":
        resolv = env.read_file("/etc/resolv.conf")
        if resolv and "systemd" in resolv.lower():
            return _cap(capability_id, "partial", CoreCapabilityStatus.PROVISIONABLE, "systemd marker in resolv.conf", "read:/etc/resolv.conf", "DNS backend is partial read-only evidence")
        return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, "resolv.conf observed" if resolv else "", "read:/etc/resolv.conf", "DNS backend not authoritatively proven")
    if capability_id == "cap_tun":
        if env.exists("/dev/net/tun"):
            return _cap(capability_id, "partial", CoreCapabilityStatus.PROVISIONABLE, "/dev/net/tun exists", "stat:/dev/net/tun", "TUN node visible; no interface created")
        return _cap(capability_id, "absent", CoreCapabilityStatus.PROVISIONABLE, "", "stat:/dev/net/tun", "TUN node absent")
    if capability_id == "cap_nftables":
        result = env.run(["nft", "--version"], timeout=2.0)
        if result.status == "ok":
            return _cap(capability_id, "partial", CoreCapabilityStatus.PROVISIONABLE, result.stdout.strip(), "command:nft --version", "nft binary observed; no rules applied")
        return _command_cap(capability_id, result, "nft version probe only; no rules applied")
    if capability_id == "cap_policy_routing":
        result = env.run(["ip", "rule", "show"], timeout=2.0)
        if result.status == "ok":
            return _cap(capability_id, "partial", CoreCapabilityStatus.PROVISIONABLE, result.stdout.strip(), "command:ip rule show", "policy routing observable; rule creation not verified")
        return _command_cap(capability_id, result, "ip rule show read-only probe")
    if capability_id == "cap_persistence":
        return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, "", "not-verified", "persistence cannot be demonstrated read-only in this task")
    if capability_id == "cap_rollback":
        return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, "", "not-verified", "rollback cannot be demonstrated before provisioning records exist")
    if capability_id == "cap_selinux":
        result = env.run(["getenforce"], timeout=2.0)
        return _diagnostic_cap(capability_id, result, "SELinux diagnostic")
    if capability_id == "cap_apparmor":
        text = env.read_file("/sys/module/apparmor/parameters/enabled")
        if text is not None:
            return _cap(capability_id, "present" if text.strip().upper() == "Y" else "absent", CoreCapabilityStatus.PRESENT, text.strip(), "read:/sys/module/apparmor/parameters/enabled", "AppArmor diagnostic")
        return _cap(capability_id, "unknown", CoreCapabilityStatus.PRESENT, "", "read:/sys/module/apparmor/parameters/enabled", "AppArmor diagnostic unavailable")
    if capability_id == "cap_firewalld":
        result = env.run(["firewall-cmd", "--state"], timeout=2.0)
        return _diagnostic_cap(capability_id, result, "firewalld diagnostic")
    return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, "", "unknown", "no probe implemented", "unknown")


def _command_cap(capability_id: str, result: CommandResult, reason: str) -> CapabilityResult:
    if result.status == "ok":
        return _cap(capability_id, "present", CoreCapabilityStatus.PRESENT, result.stdout.strip(), "command:" + " ".join(result.argv), reason)
    if result.status == "permission_denied":
        return _cap(capability_id, "unknown", CoreCapabilityStatus.PREPARATION_FAILED, result.stderr, "command:" + " ".join(result.argv), reason, result.status)
    return _cap(capability_id, "absent" if result.status == "command_missing" else "unknown", CoreCapabilityStatus.PROVISIONABLE, result.stderr or result.stdout, "command:" + " ".join(result.argv), reason, result.status)


def _diagnostic_cap(capability_id: str, result: CommandResult, reason: str) -> CapabilityResult:
    if result.status == "ok":
        return _cap(capability_id, "present", CoreCapabilityStatus.PRESENT, result.stdout.strip(), "command:" + " ".join(result.argv), reason)
    return _cap(capability_id, "unknown", CoreCapabilityStatus.PRESENT, result.stderr or result.stdout, "command:" + " ".join(result.argv), reason, result.status)


def probe_protocol_capabilities(manifest: Mapping, env: ProbeEnvironment | None = None) -> tuple[CapabilityResult, ...]:
    env = env or ProbeEnvironment()
    caps = sorted(manifest["capabilities"]["protocol_capabilities"])
    return tuple(_probe_protocol(cap_id, env) for cap_id in caps)


def _pcap(capability_id: str, observed: str, status, evidence: str, method: str, reason: str, error: str | None = None) -> CapabilityResult:
    return CapabilityResult(capability_id, observed, status.value, evidence, method, reason, error)


def _probe_protocol(capability_id: str, env: ProbeEnvironment) -> CapabilityResult:
    if capability_id == "proto_sing_box_runtime":
        return _runtime_cap(capability_id, env.run(["sing-box", "version"], timeout=2.0), "sing-box runtime")
    if capability_id == "proto_openvpn_runtime":
        return _runtime_cap(capability_id, env.run(["openvpn", "--version"], timeout=2.0), "OpenVPN runtime")
    if capability_id == "proto_ck_client_runtime":
        return _runtime_cap(capability_id, env.run(["ck-client", "-v"], timeout=2.0), "Cloak ck-client runtime")
    if capability_id == "proto_amneziawg_runtime":
        awg = env.run(["awg", "--version"], timeout=2.0)
        go = env.run(["amneziawg-go", "--version"], timeout=2.0)
        module = env.read_file("/proc/modules") or ""
        if awg.status == "ok" and ("amneziawg" in module or go.status == "ok"):
            return _pcap(capability_id, "present", ProtocolRuntimeStatus.PRESENT, "awg plus module/go observed", "command+read:/proc/modules", "AmneziaWG runtime present")
        if awg.status == "ok" or go.status == "ok" or "amneziawg" in module:
            return _pcap(capability_id, "partial", ProtocolRuntimeStatus.PROVISIONABLE, "partial AmneziaWG evidence", "command+read:/proc/modules", "AmneziaWG runtime partial")
        return _pcap(capability_id, "absent", ProtocolRuntimeStatus.PROVISIONABLE, "", "command+read:/proc/modules", "AmneziaWG runtime absent", "command_missing")
    return _pcap(capability_id, "unknown", ProtocolRuntimeStatus.ABSENT, "", "unknown", "no probe implemented", "unknown")


def _runtime_cap(capability_id: str, result: CommandResult, reason: str) -> CapabilityResult:
    if result.status == "ok":
        return _pcap(capability_id, "present", ProtocolRuntimeStatus.PRESENT, result.stdout.strip(), "command:" + " ".join(result.argv), reason)
    if result.status == "permission_denied":
        return _pcap(capability_id, "unknown", ProtocolRuntimeStatus.IMPOSSIBLE, result.stderr, "command:" + " ".join(result.argv), reason, result.status)
    return _pcap(capability_id, "absent" if result.status == "command_missing" else "unknown", ProtocolRuntimeStatus.PROVISIONABLE, result.stderr or result.stdout, "command:" + " ".join(result.argv), reason, result.status)


def evaluate(
    manifest: Mapping,
    distro_facts: DistroFacts,
    core_capabilities: Sequence[CapabilityResult],
    protocol_capabilities: Sequence[CapabilityResult],
    *,
    now: datetime,
) -> EvaluationReport:
    support = _support_classification(manifest, distro_facts, now=now)
    _validate_core_capability_contract(manifest, distro_facts, core_capabilities)
    _validate_protocol_capability_contract(manifest, protocol_capabilities)
    core_statuses = [CoreCapabilityStatus(cap.domain_status) for cap in core_capabilities]
    host = classify_host_readiness(core_statuses)
    protocol_status_map = {cap.capability_id: ProtocolRuntimeStatus(cap.domain_status) for cap in protocol_capabilities}
    protocol_readiness = {}
    for protocol_id, protocol in manifest["protocols"].items():
        statuses = [protocol_status_map.get(cap_id, ProtocolRuntimeStatus.ABSENT) for cap_id in protocol["required_protocol_capabilities"]]
        protocol_readiness[protocol_id] = classify_protocol_readiness(statuses).value
    return EvaluationReport(
        distro_facts=distro_facts,
        support_classification=support.value,
        host_readiness=host.value,
        protocol_readiness=dict(sorted(protocol_readiness.items())),
        core_capabilities=tuple(core_capabilities),
        protocol_capabilities=tuple(protocol_capabilities),
    )


def _validate_core_capability_contract(
    manifest: Mapping,
    distro_facts: DistroFacts,
    core_capabilities: Sequence[CapabilityResult],
) -> None:
    if not distro_facts.technical_family:
        raise DetectionError("cannot evaluate core capabilities without a resolved technical family")
    expected = tuple(manifest["technical_families"][distro_facts.technical_family]["core_capabilities"])
    _validate_capability_result_set(
        core_capabilities,
        expected,
        set(manifest["capabilities"]["core_host_capabilities"]),
        CoreCapabilityStatus,
        "core_capabilities",
    )


def _validate_protocol_capability_contract(
    manifest: Mapping,
    protocol_capabilities: Sequence[CapabilityResult],
) -> None:
    expected = tuple(sorted(manifest["capabilities"]["protocol_capabilities"]))
    _validate_capability_result_set(
        protocol_capabilities,
        expected,
        set(manifest["capabilities"]["protocol_capabilities"]),
        ProtocolRuntimeStatus,
        "protocol_capabilities",
    )


def _validate_capability_result_set(
    results: Sequence[CapabilityResult],
    expected_ids: Sequence[str],
    known_ids: set[str],
    enum_cls,
    label: str,
) -> None:
    if not results:
        raise DetectionError("%s must not be empty" % label)
    received = []
    seen = set()
    for index, result in enumerate(results):
        if not isinstance(result, CapabilityResult):
            raise DetectionError("%s[%d] must be CapabilityResult" % (label, index))
        cap_id = result.capability_id
        if type(cap_id) is not str or not cap_id:
            raise DetectionError("%s[%d].capability_id must be a non-empty string" % (label, index))
        if cap_id in seen:
            raise DetectionError("%s contains duplicate capability %s" % (label, cap_id))
        seen.add(cap_id)
        if cap_id not in known_ids:
            raise DetectionError("%s contains unknown capability %s" % (label, cap_id))
        try:
            enum_cls(result.domain_status)
        except ValueError as exc:
            raise DetectionError("%s.%s has invalid domain_status %r" % (label, cap_id, result.domain_status)) from exc
        received.append(cap_id)
    if set(received) != set(expected_ids):
        missing = sorted(set(expected_ids) - set(received))
        extra = sorted(set(received) - set(expected_ids))
        raise DetectionError("%s contract mismatch missing=%s extra=%s" % (label, missing, extra))


def _support_classification(manifest: Mapping, facts: DistroFacts, *, now: datetime) -> SupportClassification:
    if facts.resolved_distribution is None:
        return SupportClassification.UNSUPPORTED
    distro = manifest["distributions"][facts.resolved_distribution]
    if distro["release_model"] == "rolling":
        data = compat_read._rolling_facts(manifest, facts.resolved_distribution)
        payload = dict(data["facts"])
        if payload["last_validated"] is not None:
            payload["last_validated"] = datetime.strptime(payload["last_validated"], "%Y-%m-%dT%H:%M:%S")
        return classify_support_rolling(
            RollingFacts(**payload),
            expiry=timedelta(seconds=data["expiry_seconds"]),
            now=now,
        )
    if facts.resolved_release is not None:
        data = compat_read._stable_facts(manifest, facts.resolved_release)
        return classify_support_stable(StableReleaseFacts(**data["facts"]))
    family_anchor = compat_read._family_has_current_certification(manifest, distro["technical_family"])
    synthetic = StableReleaseFacts(
        has_adapter=True,
        meets_technical_floor=True,
        admitted=False,
        expressly_excluded=False,
        future_or_unevaluated=True,
        eol_or_withdrawn=False,
        vendor_maintained=True,
        ci_green=False,
        is_derivative=distro["lineage"]["is_derivative"],
        has_own_evidence=distro["lineage"]["has_own_evidence"],
        family_inference_allowed=False,
        has_valid_field_certification=False,
        family_has_certified_anchor=family_anchor,
    )
    return classify_support_stable(synthetic)


def load_product_manifest() -> Mapping:
    manifest = compat_read.load_manifest_file(Path(compat_read.DEFAULT_MANIFEST_PATH), product_path=True)
    compat_read.validate_manifest(manifest)
    return manifest


def detect_current(
    *,
    manifest: Mapping | None = None,
    env: ProbeEnvironment | None = None,
    etc_os_release_path: Path = Path("/etc/os-release"),
    usr_os_release_path: Path = Path("/usr/lib/os-release"),
    now_provider: Callable[[], datetime] | None = None,
) -> EvaluationReport:
    manifest = manifest or load_product_manifest()
    env = env or ProbeEnvironment()
    os_release = read_os_release(etc_path=etc_os_release_path, usr_path=usr_os_release_path)
    facts = distro_facts_from_os_release(
        os_release,
        manifest,
        kernel_release=env.kernel_release,
        machine_architecture=env.machine_architecture,
    )
    core = probe_core_capabilities(manifest, facts, env)
    protocols = probe_protocol_capabilities(manifest, env)
    now = now_provider() if now_provider is not None else datetime.now(timezone.utc).replace(tzinfo=None)
    if now.tzinfo is not None:
        now = now.astimezone(timezone.utc).replace(tzinfo=None)
    return evaluate(manifest, facts, core, protocols, now=now)
