"""Internal read-only compatibility detection layer (Phase 23.7.5.4)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
from typing import Callable, Mapping, Sequence

from compat.support_model import (
    CertificationReviewStatus,
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
    evaluate_certification_review,
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
    mapped_base_release: str | None
    identity_evidence: Mapping[str, str]
    identity_conflicts: tuple[str, ...]
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
        pgid = None
        try:
            process = subprocess.Popen(
                command,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=False,
                close_fds=True,
                start_new_session=True,
            )
            pgid = process.pid
            stdout, stderr, stdout_truncated, stderr_truncated, timed_out = _drain_process_output(
                process, pgid=pgid, timeout=timeout, limit=self.output_limit
            )
            if timed_out:
                return CommandResult(
                    tuple(argv),
                    "timeout",
                    reason="command timed out",
                    stdout=stdout,
                    stderr=stderr,
                    stdout_truncated=stdout_truncated,
                    stderr_truncated=stderr_truncated,
                )
        except FileNotFoundError:
            return CommandResult(tuple(argv), "command_missing", reason="command not found")
        except PermissionError as exc:
            return CommandResult(tuple(argv), "permission_denied", reason=str(exc))
        except (OSError, ValueError) as exc:
            if process is not None:
                _terminate_process_group(process, pgid)
                try:
                    process.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                        process.wait()
                    except OSError:
                        process.returncode = -signal.SIGKILL
                except OSError:
                    process.returncode = process.returncode if process.returncode is not None else -signal.SIGKILL
                if process.returncode is None:
                    process.returncode = -signal.SIGKILL
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


def _drain_process_output(process, *, pgid: int | None, timeout: float, limit: int):
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    streams = ((process.stdout, "stdout"), (process.stderr, "stderr"))
    for stream, name in streams:
        if stream is None:
            continue
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process_group(process, pgid)
                break
            for key, _events in selector.select(timeout=min(0.1, remaining)):
                name = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                current = buffers[name]
                keep = max(0, limit - len(current))
                if keep:
                    current.extend(chunk[:keep])
                if len(chunk) > keep:
                    truncated[name] = True
            if process.poll() is not None and not selector.get_map():
                break
        while not timed_out and process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process_group(process, pgid)
                break
            try:
                process.wait(timeout=min(0.1, remaining))
            except subprocess.TimeoutExpired:
                continue
        if timed_out:
            _drain_remaining(selector, buffers, truncated, limit)
        elif process.returncode is None:
            process.wait(timeout=0)
    finally:
        for key in list(selector.get_map().values()):
            try:
                selector.unregister(key.fileobj)
            except Exception:
                pass
            try:
                key.fileobj.close()
            except Exception:
                pass
        selector.close()
    return (
        bytes(buffers["stdout"]).decode("utf-8", errors="replace"),
        bytes(buffers["stderr"]).decode("utf-8", errors="replace"),
        truncated["stdout"],
        truncated["stderr"],
        timed_out,
    )


def _drain_remaining(selector, buffers, truncated, limit: int) -> None:
    for key in list(selector.get_map().values()):
        name = key.data
        while True:
            try:
                chunk = os.read(key.fileobj.fileno(), 4096)
            except BlockingIOError:
                break
            except OSError:
                break
            if not chunk:
                break
            keep = max(0, limit - len(buffers[name]))
            if keep:
                buffers[name].extend(chunk[:keep])
            if len(chunk) > keep:
                truncated[name] = True


def _terminate_process_group(process, pgid: int | None) -> None:
    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            pass
    else:
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
    else:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait()
    except OSError:
        pass


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
    try:
        usr_resolved = usr_path.resolve(strict=False)
    except OSError as exc:
        raise DetectionError("cannot resolve fallback os-release path: %s" % exc) from exc
    if _safe_is_symlink(selected, "os-release") and resolved != usr_resolved:
        raise DetectionError("os-release symlink target is outside allowed paths")
    raw = _read_regular_file_atomically(resolved)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DetectionError("os-release must be valid UTF-8: %s" % exc) from exc
    return parse_os_release_text(text, source=str(selected))


def _read_regular_file_atomically(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = None
    try:
        before = path.stat()
        fd = os.open(str(path), flags)
        after = os.fstat(fd)
        if not stat_is_regular(after.st_mode):
            raise DetectionError("os-release target must be a regular file")
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise DetectionError("os-release identity changed during read")
        size = after.st_size
        if size > MAX_OS_RELEASE_BYTES:
            raise DetectionError("os-release exceeds %d byte limit" % MAX_OS_RELEASE_BYTES)
        chunks = []
        remaining = MAX_OS_RELEASE_BYTES + 1
        while remaining > 0:
            try:
                chunk = os.read(fd, min(4096, remaining))
            except OSError as exc:
                raise DetectionError("cannot read os-release: %s" % exc) from exc
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except DetectionError:
        raise
    except OSError as exc:
        raise DetectionError("cannot open/stat os-release: %s" % exc) from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    if len(raw) > MAX_OS_RELEASE_BYTES:
        raise DetectionError("os-release exceeds %d byte limit" % MAX_OS_RELEASE_BYTES)
    return raw


def stat_is_regular(mode: int) -> bool:
    import stat

    return stat.S_ISREG(mode)


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
    mapped_base_release = None
    identity_evidence = {}
    identity_conflicts = ()
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
            resolved_release, release_status, identity_evidence, identity_conflicts, mapped_base_release = _resolve_stable_release(
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
        mapped_base_release=mapped_base_release,
        identity_evidence=identity_evidence,
        identity_conflicts=identity_conflicts,
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
    evidence = {}
    conflicts = []
    mapped_base_release = None
    distro = manifest["distributions"][distro_id]
    derivative_mapping = None
    for derivative_id, derivative in manifest["derivatives"].items():
        if derivative["distribution"] == distro_id and derivative["mapping_type"] == "codename_map":
            derivative_mapping = derivative
            mapping_source = derivative["mapping_source"]
            codename = ubuntu_codename if mapping_source == "ubuntu_codename" else version_codename
            if not codename or codename not in derivative["codename_map"]:
                return None, "derivative_mapping_unknown", evidence, tuple(conflicts), None
            mapped_base_release = derivative["codename_map"][codename]
            evidence["derivative_mapping"] = mapped_base_release
            base_release = manifest["releases"].get(mapped_base_release)
            if base_release is None:
                conflicts.append("derivative mapping target %s is not an enumerated release" % mapped_base_release)
            elif base_release["distribution"] != derivative["lineage_distribution"]:
                conflicts.append("derivative mapping target %s is outside lineage distribution" % mapped_base_release)
            elif base_release["policy_state"] != "admitted":
                conflicts.append("derivative mapping target %s is not admitted" % mapped_base_release)
            break

    if version_id is not None:
        release_id = _find_release_by_version(manifest, distro_id, version_id)
        if release_id is not None:
            evidence["version_id"] = release_id
        else:
            conflicts.append("VERSION_ID=%s does not match an enumerated release" % version_id)
    if version_codename:
        release_id = _find_release_by_codename(manifest, distro_id, version_codename)
        if release_id is not None:
            evidence["version_codename"] = release_id
        else:
            conflicts.append("VERSION_CODENAME=%s does not match an enumerated release" % version_codename)
    resolved = sorted(set(evidence.values()) - ({mapped_base_release} if mapped_base_release else set()))
    release_evidence = {
        key: value
        for key, value in evidence.items()
        if key != "derivative_mapping"
    }
    release_ids = sorted(set(release_evidence.values()))
    if len(release_ids) > 1:
        conflicts.append("release anchors resolve to multiple releases: %s" % ",".join(release_ids))
    if conflicts and (release_ids or mapped_base_release):
        return None, "release_identity_conflict", evidence, tuple(conflicts), mapped_base_release
    if len(release_ids) == 1:
        return release_ids[0], "resolved", evidence, tuple(), mapped_base_release
    if derivative_mapping is not None and mapped_base_release is not None:
        # A derivative mapping proves lineage only; the derivative release still
        # needs one of its own exact release anchors to identify a stable release.
        return None, "release_unknown", evidence, tuple(conflicts), mapped_base_release
    if distro["release_model"] == "stable":
        return None, "release_unknown", evidence, tuple(conflicts), mapped_base_release
    return None, "resolved", evidence, tuple(conflicts), mapped_base_release


def _os_release_id_map(manifest: Mapping) -> dict[str, str]:
    result = {}
    for distro_id, distro in manifest["distributions"].items():
        for os_release_id in distro.get("os_release_ids", [distro_id]):
            result[os_release_id] = distro_id
    return result


def _find_release_by_version(manifest: Mapping, distro_id: str, version_id: str) -> str | None:
    matches = []
    for release_id, release in manifest["releases"].items():
        if release["distribution"] == distro_id and version_id in release["os_release_version_ids"]:
            matches.append(release_id)
    if len(matches) == 1:
        return matches[0]
    return None


def _find_release_by_codename(manifest: Mapping, distro_id: str, codename: str) -> str | None:
    for release_id, release in manifest["releases"].items():
        if release["distribution"] == distro_id and release.get("codename") == codename:
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
        status, runtime = _runtime_python_policy(env.manifest, facts)
        if status != "exact_runtime_policy_resolved" or runtime is None:
            return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, "", "manifest.dep_python_runtime.runtime_python", status, status)
        executable = runtime["executable"]
        result = env.run([executable, "-c", "import sys; print('%d.%d.%d' % sys.version_info[:3])"], timeout=2.0)
        if result.status != "ok":
            return _command_cap(capability_id, result, "runtime Python executable probe")
        version = _parse_python_version(result.stdout.strip())
        if version is None:
            return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, result.stdout.strip(), "command:" + " ".join(result.argv), "runtime Python version malformed", "malformed_output")
        ok = version >= (3, 10)
        return _cap(capability_id, "present" if ok else "absent", CoreCapabilityStatus.PRESENT if ok else CoreCapabilityStatus.PROVISIONABLE, "runtime_python_executable=%s runtime_python_version=%s" % (executable, result.stdout.strip()), "command:" + " ".join(result.argv), "final Python floor check")
    if capability_id == "cap_python_cryptography":
        status, runtime = _runtime_python_policy(env.manifest, facts)
        if status != "exact_runtime_policy_resolved" or runtime is None:
            return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, "", "manifest.dep_python_runtime.runtime_python", status, status)
        executable = runtime["executable"]
        result = env.run([executable, "-c", "import cryptography; print(cryptography.__version__)"], timeout=2.0)
        if result.status == "ok":
            return _cap(capability_id, "present", CoreCapabilityStatus.PRESENT, "runtime_python_executable=%s cryptography_version=%s" % (executable, result.stdout.strip()), "command:" + " ".join(result.argv), "cryptography module import observed")
        return _command_cap(capability_id, result, "cryptography module import probe")
    if capability_id == "cap_base_runtime_commands":
        required = (
            "bash", "git", "python3", "curl", "tar", "ip", "ss", "systemctl",
            "systemd-run", "sudo", "logrotate", "awk", "sed", "grep", "find",
            "sort", "sha256sum", "install", "getent", "useradd", "usermod",
            "openvpn", "setpriv", "sysctl", "modinfo", "nmcli", "nft",
            "iptables", "ip6tables", "ping", "pgrep", "resolvectl",
        )
        present = []
        missing = []
        unknown = []
        for command in required:
            result = env.run([command, "--version"], timeout=1.0)
            if result.status == "command_missing":
                missing.append(command)
            elif result.status in ("ok", "nonzero_exit"):
                present.append(command)
            else:
                unknown.append(command)
        evidence = "present_commands=%s missing_commands=%s unknown_commands=%s" % (
            ",".join(present),
            ",".join(missing),
            ",".join(unknown),
        )
        if not missing and not unknown:
            return _cap(capability_id, "present", CoreCapabilityStatus.PRESENT, evidence, "required_commands read-only command resolution", "required command surface observed; package provenance not verified")
        return _cap(capability_id, "partial", CoreCapabilityStatus.PROVISIONABLE, evidence, "required_commands read-only command resolution", "required command surface incomplete or not fully observable")
    if capability_id == "cap_dns_runtime_package":
        backend, evidence = _detect_dns_backend(env)
        policy = env.manifest["capabilities"]["core_host_capabilities"][capability_id]["dns_backend_policy"]
        helper_requirement = policy[backend]["helper_requirement"]
        if helper_requirement in ("satisfied_by_backend", "optional"):
            return _cap(capability_id, "present", CoreCapabilityStatus.PRESENT, evidence, "manifest.dns_backend_policy+read:/etc/resolv.conf", "DNS backend does not require an extra helper package")
        if helper_requirement == "unknown":
            return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, evidence, "manifest.dns_backend_policy+read:/etc/resolv.conf", "DNS backend could not be determined", "dns_backend_unknown")
        return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, evidence, "manifest.dns_backend_policy", "DNS helper package requirement needs a package-specific probe")
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
        backend, evidence = _detect_dns_backend(env)
        if backend != "unknown":
            return _cap(capability_id, "partial", CoreCapabilityStatus.PROVISIONABLE, evidence, "read:/etc/resolv.conf", "DNS backend detected with read-only evidence")
        return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, evidence, "read:/etc/resolv.conf", "DNS backend not authoritatively proven")
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
        return _probe_selinux(env)
    if capability_id == "cap_apparmor":
        return _probe_apparmor(env)
    if capability_id == "cap_firewalld":
        return _probe_firewalld(env)
    return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, "", "unknown", "no probe implemented", "unknown")


def _parse_python_version(value: str) -> tuple[int, int, int] | None:
    match = re.match(r"^([0-9]+)\.([0-9]+)\.([0-9]+)$", value)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _runtime_python_policy(manifest: Mapping, facts: DistroFacts) -> tuple[str, Mapping | None]:
    matches = []
    for candidate in manifest["dependency_requirements"]["dep_python_runtime"]["method_chain"]:
        runtime = candidate.get("runtime_python")
        if not runtime:
            continue
        if _candidate_matches_facts(candidate, facts):
            matches.append(runtime)
    if len(matches) == 1:
        return "exact_runtime_policy_resolved", matches[0]
    if len(matches) > 1:
        return "runtime_python_policy_ambiguous", None
    return "runtime_python_policy_missing", None


def _runtime_python_executable(manifest: Mapping, facts: DistroFacts) -> str | None:
    status, runtime = _runtime_python_policy(manifest, facts)
    if status != "exact_runtime_policy_resolved" or runtime is None:
        return None
    return runtime["executable"]


def _detect_dns_backend(env: ProbeEnvironment) -> tuple[str, str]:
    resolv = env.read_file("/etc/resolv.conf") or ""
    lowered = resolv.lower()
    if "systemd" in lowered or env.exists("/run/systemd/resolve/stub-resolv.conf"):
        return "systemd_resolved", "backend=systemd_resolved resolv.conf=%s" % ("observed" if resolv else "absent")
    if "networkmanager" in lowered or "network manager" in lowered:
        return "networkmanager", "backend=networkmanager resolv.conf=observed"
    for line in resolv.splitlines():
        stripped = line.strip()
        if stripped.startswith("nameserver "):
            return "static_resolv_conf", "backend=static_resolv_conf nameserver=observed"
    return "unknown", "backend=unknown resolv.conf=%s" % ("observed" if resolv else "absent")


def _candidate_matches_facts(candidate: Mapping, facts: DistroFacts) -> bool:
    scope = candidate["target_scope"]
    if facts.technical_family not in scope["technical_families"]:
        return False
    if candidate["target_identity"] == "resolved_release":
        return facts.release_model == "stable" and facts.resolved_release in scope["stable_releases"]
    if candidate["target_identity"] == "rolling_distribution":
        return facts.release_model == "rolling" and facts.resolved_distribution in scope["rolling_distributions"]
    if candidate["target_identity"] == "mapped_base_release":
        return facts.release_model == "stable" and facts.resolved_release in scope["stable_releases"] and bool(facts.mapped_base_release)
    return False


def _command_cap(capability_id: str, result: CommandResult, reason: str) -> CapabilityResult:
    if result.status == "ok":
        return _cap(capability_id, "present", CoreCapabilityStatus.PRESENT, result.stdout.strip(), "command:" + " ".join(result.argv), reason)
    if result.status == "permission_denied":
        return _cap(capability_id, "unknown", CoreCapabilityStatus.PROVISIONABLE, result.stderr or result.reason, "command:" + " ".join(result.argv), reason, result.status)
    return _cap(capability_id, "absent" if result.status == "command_missing" else "unknown", CoreCapabilityStatus.PROVISIONABLE, result.stderr or result.stdout, "command:" + " ".join(result.argv), reason, result.status)


def _probe_selinux(env: ProbeEnvironment) -> CapabilityResult:
    result = env.run(["getenforce"], timeout=2.0)
    if result.status == "ok":
        if result.stdout_truncated or result.stderr_truncated:
            return _cap("cap_selinux", "unknown", CoreCapabilityStatus.PROVISIONABLE, result.stdout.strip(), "command:getenforce", "SELinux diagnostic output truncated", "malformed_output")
        normalized = result.stdout.strip().lower()
        states = {
            "enforcing": "enforcing",
            "permissive": "permissive",
            "disabled": "disabled",
        }
        if normalized in states:
            return _cap("cap_selinux", states[normalized], CoreCapabilityStatus.PRESENT, states[normalized], "command:getenforce", "SELinux state observed")
        return _cap("cap_selinux", "unknown", CoreCapabilityStatus.PROVISIONABLE, result.stdout.strip(), "command:getenforce", "SELinux diagnostic output is not recognized", "malformed_output")
    return _cap("cap_selinux", "unknown", CoreCapabilityStatus.PROVISIONABLE, result.stderr or result.stdout or result.reason, "command:getenforce", "SELinux diagnostic unavailable", result.status)


def _probe_apparmor(env: ProbeEnvironment) -> CapabilityResult:
    path = "/sys/module/apparmor/parameters/enabled"
    text = env.read_file(path)
    if text is None:
        error = "unknown" if env.exists(path) else "command_missing"
        return _cap("cap_apparmor", "unknown", CoreCapabilityStatus.PROVISIONABLE, "", "read:" + path, "AppArmor diagnostic unavailable", error)
    normalized = text.strip()
    if normalized == "Y":
        return _cap("cap_apparmor", "active", CoreCapabilityStatus.PRESENT, "Y", "read:" + path, "AppArmor state observed")
    if normalized == "N":
        return _cap("cap_apparmor", "inactive", CoreCapabilityStatus.PRESENT, "N", "read:" + path, "AppArmor state observed")
    return _cap("cap_apparmor", "unknown", CoreCapabilityStatus.PROVISIONABLE, normalized, "read:" + path, "AppArmor diagnostic output is not recognized", "malformed_output")


def _probe_firewalld(env: ProbeEnvironment) -> CapabilityResult:
    result = env.run(["firewall-cmd", "--state"], timeout=2.0)
    method = "command:firewall-cmd --state"
    if result.status == "command_missing":
        return _cap("cap_firewalld", "inactive", CoreCapabilityStatus.PRESENT, result.reason, method, "firewalld command is not installed", "command_missing")
    if result.status in ("permission_denied", "timeout", "invalid_executable", "unknown"):
        return _cap("cap_firewalld", "unknown", CoreCapabilityStatus.PROVISIONABLE, result.stderr or result.stdout or result.reason, method, "firewalld diagnostic unavailable", result.status)
    if result.stdout_truncated or result.stderr_truncated:
        return _cap("cap_firewalld", "unknown", CoreCapabilityStatus.PROVISIONABLE, result.stdout.strip() or result.stderr.strip(), method, "firewalld diagnostic output truncated", "malformed_output")
    stdout = result.stdout.strip().lower()
    stderr = result.stderr.strip().lower()
    if result.status == "ok" and stdout == "running":
        return _cap("cap_firewalld", "active", CoreCapabilityStatus.PRESENT, "running", method, "firewalld state observed")
    if stdout == "not running" or stderr == "not running":
        return _cap("cap_firewalld", "inactive", CoreCapabilityStatus.PRESENT, "not running", method, "firewalld state observed")
    return _cap("cap_firewalld", "unknown", CoreCapabilityStatus.PROVISIONABLE, result.stdout.strip() or result.stderr.strip(), method, "firewalld diagnostic output is not recognized", "malformed_output")


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
        if awg.status == "permission_denied" or go.status == "permission_denied":
            return _pcap(
                capability_id,
                "unknown",
                ProtocolRuntimeStatus.PROVISIONABLE,
                (awg.stderr or awg.reason or go.stderr or go.reason),
                "command+read:/proc/modules",
                "AmneziaWG runtime cannot be checked without permission",
                "permission_denied",
            )
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
        return _pcap(capability_id, "unknown", ProtocolRuntimeStatus.PROVISIONABLE, result.stderr or result.reason, "command:" + " ".join(result.argv), reason, result.status)
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
    core_statuses = _host_readiness_statuses(manifest, core_capabilities)
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


def _host_readiness_statuses(manifest: Mapping, core_capabilities: Sequence[CapabilityResult]) -> list[CoreCapabilityStatus]:
    capability_defs = manifest["capabilities"]["core_host_capabilities"]
    statuses = []
    for cap in core_capabilities:
        cap_type = capability_defs[cap.capability_id]["type"]
        if cap_type in ("required", "provisionable"):
            statuses.append(CoreCapabilityStatus(cap.domain_status))
        elif cap_type in ("diagnostic_only", "optional"):
            continue
        elif cap_type == "alternative":
            raise DetectionError("alternative capability groups are not modeled in schema 1")
        else:
            raise DetectionError("unknown capability type %s for %s" % (cap_type, cap.capability_id))
    if not statuses:
        raise DetectionError("host readiness has no participating core capabilities")
    return statuses


def _validate_core_capability_contract(
    manifest: Mapping,
    distro_facts: DistroFacts,
    core_capabilities: Sequence[CapabilityResult],
) -> None:
    # technical_family=None (distro no reconocido) NO es un error: el probe
    # ya sondeó el conjunto completo de core capabilities en ese caso y la
    # clasificación de soporte es UNSUPPORTED. El contrato se sigue validando
    # contra el conjunto completo, sin inventar ningún valor de family
    # (HostReadiness no tiene UNKNOWN).
    if distro_facts.technical_family:
        expected = tuple(manifest["technical_families"][distro_facts.technical_family]["core_capabilities"])
    else:
        expected = tuple(sorted(manifest["capabilities"]["core_host_capabilities"]))
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
    if facts.resolution_status == "release_identity_conflict":
        return SupportClassification.UNSUPPORTED
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


def _certification_review_status(manifest: Mapping, facts: DistroFacts, *, now: datetime) -> str | None:
    """Return the review status of the qualifying certification behind this
    distro's classification, or ``None`` when there is no qualifying
    certification to review (never certified, or identity unresolved).

    This is purely informational (Task 23.7.5.11-PRE): it never feeds back
    into ``support_classification``. A distribution stays ``certified``
    regardless of what this returns.
    """
    if facts.resolved_distribution is None:
        return None
    distro = manifest["distributions"][facts.resolved_distribution]
    if distro["release_model"] == "rolling":
        cert_ids = compat_read._rolling_certifications(manifest, facts.resolved_distribution)
    elif facts.resolved_release is not None:
        cert_ids = compat_read._release_certifications(manifest, facts.resolved_release)
    else:
        cert_ids = ()
    if not cert_ids:
        return None
    certifications = manifest["certifications"]
    latest_cert_id = max(cert_ids, key=lambda cert_id: certifications[cert_id]["date"])
    cert_date = datetime.strptime(
        compat_read._normalize_rfc3339_utc_to_naive(certifications[latest_cert_id]["date"]),
        "%Y-%m-%dT%H:%M:%S",
    )
    policy = manifest["validation_metadata"]["certification_review_policy"]
    status = evaluate_certification_review(
        cert_date,
        review_due=timedelta(seconds=policy["review_due_seconds"]),
        review_overdue=timedelta(seconds=policy["review_overdue_seconds"]),
        now=now,
    )
    return status.value


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
    if not isinstance(now, datetime):
        raise DetectionError("now_provider must return datetime")
    if now.tzinfo is not None:
        now = now.astimezone(timezone.utc).replace(tzinfo=None)
    return evaluate(manifest, facts, core, protocols, now=now)
