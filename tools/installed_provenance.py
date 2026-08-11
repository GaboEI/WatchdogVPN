#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
MARKER_SCHEMA_VERSION = "2"
RUNTIME_GENERATION_SHA256_ENV = "WATCHDOGVPN_RUNTIME_GENERATION_SHA256"
DEFAULT_MARKER_PATH = Path("/usr/local/lib/watchdogvpn/installed-version")
DEFAULT_MANIFEST_PATH = Path("/usr/local/lib/watchdogvpn/installed-provenance.json")
DEFAULT_RUNTIME_ROOT = Path("/usr/local/lib/watchdogvpn")
DEFAULT_DAEMON_DEPLOYMENTS = (
    Path("/etc/systemd/system/watchdogvpn.service"),
    Path("/usr/local/bin/watchdogvpn-daemon"),
)
EXCLUDED_ROOT_FILES = frozenset({"installed-version", "installed-provenance.json"})
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ProvenanceError(RuntimeError):
    pass


class IncompleteProvenanceError(ProvenanceError):
    pass


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    commit: str
    state: str


@dataclass(frozen=True, slots=True)
class OpenDeployment:
    path: Path
    parent_fd: int
    file_fd: int
    parent_before: os.stat_result
    file_before: os.stat_result


def _sha256_open_fd(fd: int, path: Path) -> tuple[str, int, int, int, int, int, int]:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise ProvenanceError(f"runtime path is not a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    after = os.fstat(fd)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) or size != after.st_size:
        raise ProvenanceError(f"runtime file changed while hashing: {path}")
    return (
        digest.hexdigest(),
        size,
        stat.S_IMODE(after.st_mode),
        after.st_uid,
        after.st_gid,
        after.st_dev,
        after.st_ino,
    )


def _sha256_file(
    path: Path,
    *,
    dir_fd: int | None = None,
    name: str | None = None,
) -> tuple[str, int, int, int, int, int, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(name if name is not None else path, flags, dir_fd=dir_fd)
    except OSError as exc:
        raise ProvenanceError(f"cannot open runtime file safely: {path}: {exc}") from exc
    try:
        return _sha256_open_fd(fd, path)
    finally:
        os.close(fd)


def _validate_root(root: Path, label: str) -> Path:
    if not root.is_absolute():
        raise ProvenanceError(f"{label} must be absolute: {root}")
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise ProvenanceError(f"cannot inspect {label}: {root}: {exc}") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ProvenanceError(f"{label} must be a real directory: {root}")
    return root


def _validate_include(include: str) -> str:
    candidate = PurePosixPath(include)
    if (
        not include
        or candidate.is_absolute()
        or include in {".", ".."}
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ProvenanceError(f"unsafe include path: {include}")
    return candidate.as_posix()


def _should_exclude(relative_path: PurePosixPath, *, python_cache: bool = False) -> bool:
    if len(relative_path.parts) == 1 and relative_path.name in EXCLUDED_ROOT_FILES:
        return True
    if python_cache and "__pycache__" in relative_path.parts:
        return True
    return python_cache and relative_path.suffix in {".pyc", ".pyo"}


def _validate_symlink_target(relative_path: PurePosixPath, target: str) -> str:
    target_path = PurePosixPath(target)
    if target_path.is_absolute() or not target:
        raise ProvenanceError(f"runtime symlink escapes the installed tree: {relative_path}")
    combined = relative_path.parent / target_path
    depth = 0
    for part in combined.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                raise ProvenanceError(f"runtime symlink escapes the installed tree: {relative_path}")
        else:
            depth += 1
    return target


def _metadata(path_stat: os.stat_result) -> dict[str, int]:
    return {
        "mode": stat.S_IMODE(path_stat.st_mode),
        "uid": path_stat.st_uid,
        "gid": path_stat.st_gid,
    }


def _directory_entry(relative_path: PurePosixPath, path_stat: os.stat_result) -> dict[str, Any]:
    return {
        "path": relative_path.as_posix(),
        "type": "directory",
        **_metadata(path_stat),
    }


def _walk_directory(
    root: Path,
    relative_dir: PurePosixPath,
    entries: list[dict[str, Any]],
    *,
    exclude_python_cache: bool,
    expected_stat: os.stat_result,
) -> None:
    directory = root.joinpath(*relative_dir.parts) if relative_dir.parts else root
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(directory, flags)
    except OSError as exc:
        raise ProvenanceError(f"cannot open runtime directory safely: {directory}: {exc}") from exc
    try:
        before = os.fstat(directory_fd)
        identity_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(expected_stat, field) != getattr(before, field) for field in identity_fields):
            raise ProvenanceError(f"runtime directory was replaced before hashing: {directory}")
        with os.scandir(directory_fd) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            relative_path = relative_dir / child.name
            display_path = root.joinpath(*relative_path.parts)
            if _should_exclude(relative_path, python_cache=exclude_python_cache):
                continue
            try:
                child_stat = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise ProvenanceError(f"cannot inspect runtime path: {display_path}: {exc}") from exc
            if stat.S_ISDIR(child_stat.st_mode):
                entries.append(_directory_entry(relative_path, child_stat))
                _walk_directory(
                    root,
                    relative_path,
                    entries,
                    exclude_python_cache=exclude_python_cache,
                    expected_stat=child_stat,
                )
                continue
            if stat.S_ISREG(child_stat.st_mode):
                digest, size, mode, uid, gid, device, inode = _sha256_file(
                    display_path,
                    dir_fd=directory_fd,
                    name=child.name,
                )
                named_after = os.stat(child.name, dir_fd=directory_fd, follow_symlinks=False)
                if (child_stat.st_dev, child_stat.st_ino) != (device, inode) or (
                    named_after.st_dev,
                    named_after.st_ino,
                ) != (device, inode):
                    raise ProvenanceError(f"runtime file was replaced while hashing: {display_path}")
                entries.append(
                    {
                        "path": relative_path.as_posix(),
                        "type": "file",
                        "sha256": digest,
                        "size": size,
                        "mode": mode,
                        "uid": uid,
                        "gid": gid,
                    }
                )
                continue
            if stat.S_ISLNK(child_stat.st_mode):
                try:
                    target = os.readlink(child.name, dir_fd=directory_fd)
                except OSError as exc:
                    raise ProvenanceError(f"cannot read runtime symlink: {display_path}: {exc}") from exc
                entries.append(
                    {
                        "path": relative_path.as_posix(),
                        "type": "symlink",
                        "target": _validate_symlink_target(relative_path, target),
                        **_metadata(child_stat),
                    }
                )
                continue
            raise ProvenanceError(f"unsupported runtime file type: {display_path}")
        after = os.fstat(directory_fd)
        named_after = os.lstat(directory)
        stable_fields = identity_fields
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields) or (
            named_after.st_dev,
            named_after.st_ino,
        ) != (after.st_dev, after.st_ino):
            raise ProvenanceError(f"runtime directory changed while hashing: {directory}")
    except OSError as exc:
        raise ProvenanceError(f"cannot enumerate runtime directory: {directory}: {exc}") from exc
    finally:
        os.close(directory_fd)


def collect_tree(
    root: Path,
    includes: Sequence[str] | None = None,
    *,
    exclude_python_cache: bool = False,
) -> list[dict[str, Any]]:
    root = _validate_root(root, "runtime root")
    root_stat = os.lstat(root)
    entries: list[dict[str, Any]] = []
    if includes is None:
        _walk_directory(
            root,
            PurePosixPath(),
            entries,
            exclude_python_cache=exclude_python_cache,
            expected_stat=root_stat,
        )
        return entries
    normalized = sorted({_validate_include(include) for include in includes})
    if not normalized:
        raise ProvenanceError("at least one runtime include is required")
    for include in normalized:
        relative = PurePosixPath(include)
        path = root.joinpath(*relative.parts)
        try:
            path_stat = os.lstat(path)
        except OSError as exc:
            raise ProvenanceError(f"runtime include is missing: {include}: {exc}") from exc
        if stat.S_ISDIR(path_stat.st_mode):
            entries.append(_directory_entry(relative, path_stat))
            _walk_directory(
                root,
                relative,
                entries,
                exclude_python_cache=exclude_python_cache,
                expected_stat=path_stat,
            )
        elif stat.S_ISREG(path_stat.st_mode):
            digest, size, mode, uid, gid, device, inode = _sha256_file(path)
            named_after = os.lstat(path)
            if (path_stat.st_dev, path_stat.st_ino) != (device, inode) or (
                named_after.st_dev,
                named_after.st_ino,
            ) != (device, inode):
                raise ProvenanceError(f"runtime include was replaced while hashing: {include}")
            entries.append(
                {
                    "path": relative.as_posix(),
                    "type": "file",
                    "sha256": digest,
                    "size": size,
                    "mode": mode,
                    "uid": uid,
                    "gid": gid,
                }
            )
        elif stat.S_ISLNK(path_stat.st_mode):
            target = os.readlink(path)
            entries.append(
                {
                    "path": relative.as_posix(),
                    "type": "symlink",
                    "target": _validate_symlink_target(relative, target),
                    **_metadata(path_stat),
                }
            )
        else:
            raise ProvenanceError(f"unsupported runtime include type: {include}")
    return sorted(entries, key=lambda entry: str(entry["path"]))


def _canonical_entries(entries: Sequence[Mapping[str, Any]]) -> bytes:
    return json.dumps(
        list(entries),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def tree_sha256(entries: Sequence[Mapping[str, Any]]) -> str:
    return hashlib.sha256(_canonical_entries(entries)).hexdigest()


def fingerprint_tree(root: Path) -> str:
    return tree_sha256(collect_tree(root))


def _open_deployment(path: Path) -> OpenDeployment:
    path_text = str(path)
    normalized_path = PurePosixPath(path_text)
    if (
        not path.is_absolute()
        or path_text != normalized_path.as_posix()
        or any(part in {"", ".", ".."} for part in normalized_path.parts[1:])
    ):
        raise ProvenanceError(f"deployed runtime path must be absolute: {path}")
    parent = path.parent
    parent_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        parent_flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        parent_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    try:
        parent_fd = os.open(parent, parent_flags)
    except OSError as exc:
        raise ProvenanceError(f"cannot open deployed runtime parent safely: {parent}: {exc}") from exc
    file_flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        file_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    try:
        parent_before = os.fstat(parent_fd)
        file_before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(file_before.st_mode):
            raise ProvenanceError(f"deployed runtime path is not a regular file: {path}")
        file_fd = os.open(path.name, file_flags, dir_fd=parent_fd)
        opened = os.fstat(file_fd)
        if (file_before.st_dev, file_before.st_ino) != (opened.st_dev, opened.st_ino):
            os.close(file_fd)
            raise ProvenanceError(f"deployed runtime file was replaced before hashing: {path}")
        return OpenDeployment(
            path=path,
            parent_fd=parent_fd,
            file_fd=file_fd,
            parent_before=parent_before,
            file_before=file_before,
        )
    except (OSError, ProvenanceError) as exc:
        os.close(parent_fd)
        if isinstance(exc, ProvenanceError):
            raise
        raise ProvenanceError(f"cannot inspect deployed runtime file: {path}: {exc}") from exc


def collect_deployments(paths: Sequence[Path]) -> list[dict[str, Any]]:
    normalized = sorted({str(path) for path in paths})
    opened: list[OpenDeployment] = []
    entries: list[dict[str, Any]] = []
    try:
        for path in normalized:
            opened.append(_open_deployment(Path(path)))
        for deployment in opened:
            digest, size, mode, uid, gid, device, inode = _sha256_open_fd(
                deployment.file_fd,
                deployment.path,
            )
            if (deployment.file_before.st_dev, deployment.file_before.st_ino) != (device, inode):
                raise ProvenanceError(
                    f"deployed runtime file changed before hashing: {deployment.path}"
                )
            entries.append(
                {
                    "path": str(deployment.path),
                    "type": "file",
                    "sha256": digest,
                    "size": size,
                    "mode": mode,
                    "uid": uid,
                    "gid": gid,
                }
            )
        stable_fields = ("st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        for deployment in opened:
            file_after = os.fstat(deployment.file_fd)
            named_after = os.stat(
                deployment.path.name,
                dir_fd=deployment.parent_fd,
                follow_symlinks=False,
            )
            parent_after = os.fstat(deployment.parent_fd)
            parent_named_after = os.lstat(deployment.path.parent)
            if any(
                getattr(deployment.file_before, field) != getattr(file_after, field)
                for field in stable_fields
            ) or (named_after.st_dev, named_after.st_ino) != (
                file_after.st_dev,
                file_after.st_ino,
            ):
                raise ProvenanceError(
                    f"deployed runtime file changed while hashing set: {deployment.path}"
                )
            if (deployment.parent_before.st_dev, deployment.parent_before.st_ino) != (
                parent_named_after.st_dev,
                parent_named_after.st_ino,
            ) or any(
                getattr(deployment.parent_before, field) != getattr(parent_after, field)
                for field in ("st_mode", "st_uid", "st_gid", "st_mtime_ns", "st_ctime_ns")
            ):
                raise ProvenanceError(
                    f"deployed runtime parent changed while hashing set: {deployment.path.parent}"
                )
        return entries
    except OSError as exc:
        raise ProvenanceError(f"cannot verify deployed runtime set: {exc}") from exc
    finally:
        for deployment in opened:
            os.close(deployment.file_fd)
            os.close(deployment.parent_fd)


def _collect_deployment(path: Path) -> dict[str, Any]:
    return collect_deployments((path,))[0]


def _parse_expected_deployment_hashes(specs: Sequence[str]) -> dict[str, str]:
    expected: dict[str, str] = {}
    for spec in specs:
        path, separator, digest = spec.rpartition("=")
        if not separator or path in expected or not SHA256_RE.fullmatch(digest):
            raise ProvenanceError(f"invalid expected deployment digest: {spec}")
        normalized_path = PurePosixPath(path)
        if not normalized_path.is_absolute() or path != normalized_path.as_posix():
            raise ProvenanceError(f"invalid expected deployment path: {path}")
        expected[path] = digest
    return expected


def generation_sha256(runtime_tree_sha256: str, deployments: Sequence[Mapping[str, Any]]) -> str:
    payload = {
        "runtime_tree_sha256": runtime_tree_sha256,
        "deployments": list(deployments),
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def fingerprint_generation(
    root: Path,
    deployment_paths: Sequence[Path],
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> str:
    entries = collect_tree(root)
    deployments = collect_deployments(deployment_paths)
    if (expected_uid is None) != (expected_gid is None):
        raise ProvenanceError("expected runtime UID and GID must be specified together")
    if expected_uid is not None and expected_gid is not None:
        _validate_secure_ancestors(root, expected_uid, expected_gid)
        for deployment_path in deployment_paths:
            _validate_secure_ancestors(deployment_path, expected_uid, expected_gid)
        _validate_secure_metadata(
            root_metadata=_root_metadata(root),
            entries=entries,
            deployments=deployments,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    return generation_sha256(tree_sha256(entries), deployments)


def _content_identity(entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for entry in entries:
        if entry.get("type") == "file":
            result.append(
                {
                    "path": entry.get("path"),
                    "type": "file",
                    "sha256": entry.get("sha256"),
                    "size": entry.get("size"),
                }
            )
        elif entry.get("type") == "symlink":
            result.append(
                {
                    "path": entry.get("path"),
                    "type": "symlink",
                    "target": entry.get("target"),
                }
            )
        else:
            result.append({"path": entry.get("path"), "type": "directory"})
    return result


def _root_metadata(root: Path) -> dict[str, int]:
    return _metadata(os.lstat(root))


def _validate_secure_ancestors(path: Path, expected_uid: int, expected_gid: int) -> None:
    parent = path.parent
    if not parent.is_absolute():
        raise ProvenanceError(f"installed runtime path must be absolute: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        current_fd = os.open("/", flags)
    except OSError as exc:
        raise ProvenanceError(f"cannot open installed runtime ancestor /: {exc}") from exc
    current_path = Path("/")
    try:
        for component in (None, *parent.parts[1:]):
            if component is not None:
                named = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                next_fd = os.open(component, flags, dir_fd=current_fd)
                opened = os.fstat(next_fd)
                if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                    os.close(next_fd)
                    raise ProvenanceError(
                        f"installed runtime ancestor was replaced: {current_path / component}"
                    )
                os.close(current_fd)
                current_fd = next_fd
                current_path /= component
            current_stat = os.fstat(current_fd)
            if current_stat.st_uid != expected_uid or current_stat.st_gid != expected_gid:
                raise ProvenanceError(
                    f"installed runtime ancestor has unexpected ownership: {current_path}"
                )
            if stat.S_IMODE(current_stat.st_mode) & 0o022:
                raise ProvenanceError(
                    f"installed runtime ancestor is writable by group or others: {current_path}"
                )
    except OSError as exc:
        raise ProvenanceError(f"cannot validate installed runtime ancestor: {current_path}: {exc}") from exc
    finally:
        os.close(current_fd)


def _validate_secure_metadata(
    *,
    root_metadata: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
    deployments: Sequence[Mapping[str, Any]],
    expected_uid: int,
    expected_gid: int,
) -> None:
    paths: list[tuple[str, Mapping[str, Any]]] = [("runtime root", root_metadata)]
    paths.extend((str(item["path"]), item) for item in entries)
    paths.extend((str(item["path"]), item) for item in deployments)
    for label, entry in paths:
        if entry.get("uid") != expected_uid or entry.get("gid") != expected_gid:
            raise ProvenanceError(f"installed runtime path has unexpected ownership: {label}")
        mode = entry.get("mode")
        if not isinstance(mode, int) or mode & 0o022:
            raise ProvenanceError(f"installed runtime path is writable by group or others: {label}")


def _run_git(source_root: Path, argv: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
    env = {
        "HOME": os.environ.get("HOME", "/"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        return subprocess.run(
            ["git", "-C", str(source_root), *argv],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _run_git_bytes(source_root: Path, argv: Sequence[str]) -> subprocess.CompletedProcess[bytes] | None:
    env = {
        "HOME": os.environ.get("HOME", "/"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        return subprocess.run(
            ["git", "-C", str(source_root), *argv],
            check=False,
            capture_output=True,
            timeout=10,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def source_identity(
    source_root: Path,
    includes: Sequence[str],
    source_entries: Sequence[Mapping[str, Any]],
) -> SourceIdentity:
    head = _run_git(source_root, ("rev-parse", "--verify", "HEAD^{commit}"))
    if head is None or head.returncode != 0:
        return SourceIdentity(commit="unknown", state="unversioned")
    commit = head.stdout.strip().lower()
    if not COMMIT_RE.fullmatch(commit):
        return SourceIdentity(commit="unknown", state="unversioned")
    tree_result = _run_git_bytes(
        source_root,
        ("ls-tree", "-r", "-z", "--full-tree", commit, "--", *includes),
    )
    if tree_result is None or tree_result.returncode != 0:
        return SourceIdentity(commit=commit, state="unverifiable")
    committed: dict[str, tuple[str, str]] = {}
    try:
        for record in tree_result.stdout.split(b"\0"):
            if not record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
            if object_type != "blob":
                return SourceIdentity(commit=commit, state="dirty")
            committed[raw_path.decode("utf-8")] = (mode, object_id)
    except (UnicodeDecodeError, ValueError):
        return SourceIdentity(commit=commit, state="unverifiable")
    observed = {
        str(entry["path"]): entry
        for entry in source_entries
        if entry.get("type") != "directory"
    }
    if set(committed) != set(observed):
        return SourceIdentity(commit=commit, state="dirty")
    for path, entry in observed.items():
        committed_mode, object_id = committed[path]
        expected_mode = "120000" if entry["type"] == "symlink" else (
            "100755" if int(entry["mode"]) & 0o111 else "100644"
        )
        if committed_mode != expected_mode:
            return SourceIdentity(commit=commit, state="dirty")
        blob_result = _run_git_bytes(source_root, ("cat-file", "blob", object_id))
        if blob_result is None or blob_result.returncode != 0:
            return SourceIdentity(commit=commit, state="unverifiable")
        if entry["type"] == "file":
            if len(blob_result.stdout) != entry["size"] or hashlib.sha256(blob_result.stdout).hexdigest() != entry["sha256"]:
                return SourceIdentity(commit=commit, state="dirty")
        elif blob_result.stdout != os.fsencode(entry["target"]):
            return SourceIdentity(commit=commit, state="dirty")
    return SourceIdentity(commit=commit, state="clean")


def build_manifest(
    *,
    source_root: Path,
    installed_root: Path,
    includes: Sequence[str],
    deployment_paths: Sequence[Path] = (),
    expected_deployment_sha256: Mapping[str, str] | None = None,
    expected_generation_sha256: str | None = None,
    installed_at: str,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> dict[str, Any]:
    source_root = _validate_root(source_root, "source root")
    installed_root = _validate_root(installed_root, "installed root")
    normalized_includes = tuple(sorted({_validate_include(include) for include in includes}))
    if not normalized_includes:
        raise ProvenanceError("at least one runtime include is required")
    if not TIMESTAMP_RE.fullmatch(installed_at):
        raise ProvenanceError("installed_at must be an RFC 3339 UTC timestamp")
    source_entries = collect_tree(source_root, normalized_includes, exclude_python_cache=True)
    installed_entries = collect_tree(installed_root)
    if _content_identity(source_entries) != _content_identity(installed_entries):
        raise ProvenanceError("source and installed runtime differ; refusing provenance publication")
    root_metadata = _root_metadata(installed_root)
    deployments = collect_deployments(deployment_paths)
    if expected_deployment_sha256 is not None:
        observed_deployment_hashes = {
            str(entry["path"]): str(entry["sha256"])
            for entry in deployments
        }
        if observed_deployment_hashes != dict(expected_deployment_sha256):
            raise ProvenanceError("deployed runtime files differ from their expected generation")
    if (expected_uid is None) != (expected_gid is None):
        raise ProvenanceError("expected runtime UID and GID must be specified together")
    if expected_uid is not None and expected_gid is not None:
        if expected_uid == 0 and expected_gid == 0:
            _validate_secure_ancestors(installed_root, expected_uid, expected_gid)
            for deployment_path in deployment_paths:
                _validate_secure_ancestors(deployment_path, expected_uid, expected_gid)
        _validate_secure_metadata(
            root_metadata=root_metadata,
            entries=installed_entries,
            deployments=deployments,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    identity = source_identity(
        source_root,
        normalized_includes,
        source_entries,
    )
    if identity.state != "clean" or identity.commit == "unknown":
        raise ProvenanceError(
            f"source checkout is not attributable to a clean committed tree: {identity.state}"
        )
    runtime_tree_digest = tree_sha256(installed_entries)
    generation_digest = generation_sha256(runtime_tree_digest, deployments)
    if expected_generation_sha256 is not None:
        if not SHA256_RE.fullmatch(expected_generation_sha256):
            raise ProvenanceError("expected generation digest is invalid")
        if generation_digest != expected_generation_sha256:
            raise ProvenanceError("installed generation differs from the daemon-approved smoke digest")
    return {
        "schema_version": SCHEMA_VERSION,
        "source_commit": identity.commit,
        "source_state": identity.state,
        "installed_at": installed_at,
        "runtime_root": str(installed_root),
        "includes": list(normalized_includes),
        "runtime_root_metadata": root_metadata,
        "tree_sha256": runtime_tree_digest,
        "generation_sha256": generation_digest,
        "files": installed_entries,
        "deployments": deployments,
    }


def write_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    payload = json.dumps(
        manifest,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ) + "\n"
    path.write_text(payload, encoding="utf-8")


def write_marker(path: Path, manifest: Mapping[str, Any], manifest_path: Path) -> None:
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    payload = (
        f"schema_version={MARKER_SCHEMA_VERSION}\n"
        f"commit={manifest['source_commit']}\n"
        f"installed_at={manifest['installed_at']}\n"
        f"manifest_sha256={manifest_sha256}\n"
    )
    path.write_text(payload, encoding="utf-8")


def _reject_duplicate_pairs(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceError(f"duplicate JSON key in provenance manifest: {key}")
        result[key] = value
    return result


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise IncompleteProvenanceError(f"installed provenance manifest is missing: {path}") from exc
    except OSError as exc:
        raise ProvenanceError(f"cannot read installed provenance manifest: {path}: {exc}") from exc
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"installed provenance manifest is invalid JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ProvenanceError("installed provenance manifest has an unsupported schema")
    commit = data.get("source_commit")
    source_state = data.get("source_state")
    installed_at = data.get("installed_at")
    runtime_root = data.get("runtime_root")
    digest = data.get("tree_sha256")
    generation_digest = data.get("generation_sha256")
    files = data.get("files")
    deployments = data.get("deployments")
    runtime_root_metadata = data.get("runtime_root_metadata")
    includes = data.get("includes")
    if commit != "unknown" and not (isinstance(commit, str) and COMMIT_RE.fullmatch(commit)):
        raise ProvenanceError("installed provenance manifest has an invalid source commit")
    if source_state not in {"clean", "dirty", "unversioned", "unverifiable"}:
        raise ProvenanceError("installed provenance manifest has an invalid source state")
    if not isinstance(installed_at, str) or not TIMESTAMP_RE.fullmatch(installed_at):
        raise ProvenanceError("installed provenance manifest has an invalid timestamp")
    if not isinstance(runtime_root, str) or not runtime_root.startswith("/"):
        raise ProvenanceError("installed provenance manifest has an invalid runtime root")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ProvenanceError("installed provenance manifest has an invalid tree digest")
    if not isinstance(generation_digest, str) or not SHA256_RE.fullmatch(generation_digest):
        raise ProvenanceError("installed provenance manifest has an invalid generation digest")
    if not isinstance(includes, list) or not includes or not all(isinstance(item, str) for item in includes):
        raise ProvenanceError("installed provenance manifest has invalid includes")
    normalized_includes = sorted({_validate_include(item) for item in includes})
    if normalized_includes != includes:
        raise ProvenanceError("installed provenance manifest includes are not canonical")
    if not isinstance(files, list):
        raise ProvenanceError("installed provenance manifest has an invalid file inventory")
    _validate_manifest_entries(files)
    if not isinstance(deployments, list):
        raise ProvenanceError("installed provenance manifest has invalid deployed runtime files")
    _validate_deployments(deployments)
    if not isinstance(runtime_root_metadata, dict) or set(runtime_root_metadata) != {"mode", "uid", "gid"}:
        raise ProvenanceError("installed provenance runtime root metadata has unknown fields")
    _validate_metadata_object(runtime_root_metadata, "runtime root")
    if tree_sha256(files) != digest:
        raise ProvenanceError("installed provenance manifest tree digest is internally inconsistent")
    if generation_sha256(digest, deployments) != generation_digest:
        raise ProvenanceError("installed provenance manifest generation digest is internally inconsistent")
    return data


def _validate_manifest_entries(entries: list[Any]) -> None:
    previous_path = ""
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProvenanceError("installed provenance file entry must be an object")
        path = entry.get("path")
        entry_type = entry.get("type")
        if not isinstance(path, str):
            raise ProvenanceError("installed provenance file entry has an invalid path")
        normalized = _validate_include(path)
        if normalized <= previous_path:
            raise ProvenanceError("installed provenance file inventory is not unique and sorted")
        previous_path = normalized
        if _should_exclude(PurePosixPath(path)):
            raise ProvenanceError("installed provenance inventory contains an excluded path")
        if entry_type == "file":
            if set(entry) != {"path", "type", "sha256", "size", "mode", "uid", "gid"}:
                raise ProvenanceError("installed provenance file entry has unknown fields")
            if not isinstance(entry.get("sha256"), str) or not SHA256_RE.fullmatch(entry["sha256"]):
                raise ProvenanceError("installed provenance file entry has an invalid digest")
            if not isinstance(entry.get("size"), int) or isinstance(entry.get("size"), bool) or entry["size"] < 0:
                raise ProvenanceError("installed provenance file entry has an invalid size")
            _validate_metadata_object(entry, f"runtime file {path}")
        elif entry_type == "symlink":
            if set(entry) != {"path", "type", "target", "mode", "uid", "gid"} or not isinstance(entry.get("target"), str):
                raise ProvenanceError("installed provenance symlink entry is invalid")
            _validate_symlink_target(PurePosixPath(path), entry["target"])
            _validate_metadata_object(entry, f"runtime symlink {path}")
        elif entry_type == "directory":
            if set(entry) != {"path", "type", "mode", "uid", "gid"}:
                raise ProvenanceError("installed provenance directory entry is invalid")
            _validate_metadata_object(entry, f"runtime directory {path}")
        else:
            raise ProvenanceError("installed provenance entry has an unsupported type")


def _validate_metadata_object(entry: Any, label: str) -> None:
    if not isinstance(entry, Mapping):
        raise ProvenanceError(f"installed provenance {label} metadata is invalid")
    for field in ("mode", "uid", "gid"):
        value = entry.get(field)
        upper_bound = 0o7777 if field == "mode" else 2**32 - 1
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= upper_bound:
            raise ProvenanceError(f"installed provenance {label} has an invalid {field}")


def _validate_deployments(entries: list[Any]) -> None:
    previous_path = ""
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") != "file":
            raise ProvenanceError("installed provenance deployed entry must be a file object")
        if set(entry) != {"path", "type", "sha256", "size", "mode", "uid", "gid"}:
            raise ProvenanceError("installed provenance deployed entry has unknown fields")
        path = entry.get("path")
        if not isinstance(path, str) or path <= previous_path:
            raise ProvenanceError("installed provenance deployed paths are invalid or not sorted")
        normalized_path = PurePosixPath(path)
        if (
            not normalized_path.is_absolute()
            or path != normalized_path.as_posix()
            or any(part in {"", ".", ".."} for part in normalized_path.parts[1:])
        ):
            raise ProvenanceError("installed provenance deployed path is unsafe")
        previous_path = path
        if not isinstance(entry.get("sha256"), str) or not SHA256_RE.fullmatch(entry["sha256"]):
            raise ProvenanceError("installed provenance deployed file has an invalid digest")
        if not isinstance(entry.get("size"), int) or isinstance(entry.get("size"), bool) or entry["size"] < 0:
            raise ProvenanceError("installed provenance deployed file has an invalid size")
        _validate_metadata_object(entry, f"deployed file {path}")


def load_marker(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise IncompleteProvenanceError(f"installed version marker is missing: {path}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ProvenanceError(f"cannot read installed version marker: {path}: {exc}") from exc
    fields: dict[str, str] = {}
    for line in lines:
        if not line or "=" not in line:
            raise ProvenanceError("installed version marker is malformed")
        key, value = line.split("=", 1)
        if key in fields:
            raise ProvenanceError(f"installed version marker has duplicate field: {key}")
        fields[key] = value
    if fields.get("schema_version") != MARKER_SCHEMA_VERSION or "manifest_sha256" not in fields:
        raise IncompleteProvenanceError("installed version marker predates hashed provenance")
    if set(fields) != {"schema_version", "commit", "installed_at", "manifest_sha256"}:
        raise ProvenanceError("installed version marker has unknown or missing fields")
    if fields["commit"] != "unknown" and not COMMIT_RE.fullmatch(fields["commit"]):
        raise ProvenanceError("installed version marker has an invalid commit")
    if not TIMESTAMP_RE.fullmatch(fields["installed_at"]):
        raise ProvenanceError("installed version marker has an invalid timestamp")
    if not SHA256_RE.fullmatch(fields["manifest_sha256"]):
        raise ProvenanceError("installed version marker has an invalid manifest digest")
    return fields


def verify_installation(
    *,
    marker_path: Path,
    manifest_path: Path,
    installed_root: Path,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> dict[str, Any]:
    marker = load_marker(marker_path)
    try:
        manifest_raw = manifest_path.read_bytes()
    except OSError as exc:
        raise IncompleteProvenanceError(f"cannot read installed provenance manifest: {manifest_path}: {exc}") from exc
    observed_manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if observed_manifest_sha256 != marker["manifest_sha256"]:
        raise ProvenanceError("installed provenance manifest digest differs from the version marker")
    manifest = load_manifest(manifest_path)
    if marker["commit"] != manifest["source_commit"]:
        raise ProvenanceError("installed version marker commit differs from provenance manifest")
    if marker["installed_at"] != manifest["installed_at"]:
        raise ProvenanceError("installed version marker timestamp differs from provenance manifest")
    if str(installed_root) != manifest["runtime_root"]:
        raise ProvenanceError("installed runtime root differs from provenance manifest")
    if _root_metadata(installed_root) != manifest["runtime_root_metadata"]:
        raise ProvenanceError("installed runtime root metadata differs from published provenance")
    observed_entries = collect_tree(installed_root)
    if observed_entries != manifest["files"]:
        raise ProvenanceError("installed runtime tree differs from the published provenance inventory")
    observed_deployments = collect_deployments(
        tuple(Path(entry["path"]) for entry in manifest["deployments"])
    )
    if observed_deployments != manifest["deployments"]:
        raise ProvenanceError("deployed runtime files differ from published provenance")
    if (expected_uid is None) != (expected_gid is None):
        raise ProvenanceError("expected runtime UID and GID must be specified together")
    if expected_uid is not None and expected_gid is not None:
        _validate_secure_ancestors(installed_root, expected_uid, expected_gid)
        for deployment in observed_deployments:
            _validate_secure_ancestors(Path(str(deployment["path"])), expected_uid, expected_gid)
        _validate_secure_metadata(
            root_metadata=_root_metadata(installed_root),
            entries=observed_entries,
            deployments=observed_deployments,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    if manifest["source_state"] != "clean" or manifest["source_commit"] == "unknown":
        raise ProvenanceError("installed provenance source is not attributable to a clean committed tree")
    return {
        "status": "verified",
        "commit": manifest["source_commit"],
        "source_state": manifest["source_state"],
        "installed_at": manifest["installed_at"],
        "tree_sha256": manifest["tree_sha256"],
        "generation_sha256": manifest["generation_sha256"],
        "manifest_sha256": marker["manifest_sha256"],
        "file_count": len(manifest["files"]),
    }


def process_runtime_identity() -> dict[str, str]:
    digest = os.environ.get(RUNTIME_GENERATION_SHA256_ENV, "").strip().lower()
    if not SHA256_RE.fullmatch(digest):
        return {"status": "unavailable"}
    runtime_root = Path(__file__).resolve().parents[1]
    try:
        observed = fingerprint_generation(
            runtime_root,
            DEFAULT_DAEMON_DEPLOYMENTS,
            expected_uid=0,
            expected_gid=0,
        )
    except ProvenanceError:
        return {"status": "unavailable"}
    if observed != digest:
        return {"status": "unavailable"}
    return {
        "status": "captured",
        "generation_sha256": digest,
    }


def verify_daemon_status(
    *,
    status_payload: Mapping[str, Any],
    manifest_path: Path,
) -> dict[str, str]:
    manifest = load_manifest(manifest_path)
    payload = status_payload.get("payload")
    if not isinstance(payload, Mapping):
        raise ProvenanceError("daemon status response has no payload")
    provenance = payload.get("runtime_provenance")
    if not isinstance(provenance, Mapping) or provenance.get("status") != "captured":
        raise IncompleteProvenanceError("daemon did not report a captured runtime digest")
    digest = provenance.get("generation_sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ProvenanceError("daemon reported an invalid runtime digest")
    if digest != manifest["generation_sha256"]:
        raise ProvenanceError("daemon generation digest differs from installed provenance")
    return {
        "status": "verified",
        "generation_sha256": digest,
    }


def verify_running_generation(
    *,
    status_payload: Mapping[str, Any],
    runtime_root: Path,
    deployment_paths: Sequence[Path],
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> dict[str, str]:
    payload = status_payload.get("payload")
    if not isinstance(payload, Mapping):
        raise ProvenanceError("daemon status response has no payload")
    provenance = payload.get("runtime_provenance")
    if not isinstance(provenance, Mapping) or provenance.get("status") != "captured":
        raise ProvenanceError("daemon did not report a captured generation digest")
    reported = provenance.get("generation_sha256")
    if not isinstance(reported, str) or not SHA256_RE.fullmatch(reported):
        raise ProvenanceError("daemon reported an invalid generation digest")
    observed = fingerprint_generation(
        runtime_root,
        deployment_paths,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if reported != observed:
        raise ProvenanceError("daemon generation digest differs from current installed runtime")
    return {"status": "verified", "generation_sha256": reported}


def launch_daemon(
    runtime_root: Path,
    deployment_paths: Sequence[Path],
    daemon_args: Sequence[str],
) -> int:
    before = fingerprint_generation(
        runtime_root,
        deployment_paths,
        expected_uid=0,
        expected_gid=0,
    )
    os.environ[RUNTIME_GENERATION_SHA256_ENV] = before
    try:
        from daemon import main as daemon_main
    except Exception as exc:
        raise ProvenanceError(f"cannot import daemon generation: {exc}") from exc
    after = fingerprint_generation(
        runtime_root,
        deployment_paths,
        expected_uid=0,
        expected_gid=0,
    )
    if before != after:
        raise ProvenanceError("runtime generation changed while importing daemon modules")
    return int(daemon_main.main(list(daemon_args)))


def _load_status_payload(path: str) -> Mapping[str, Any]:
    try:
        if path == "-":
            data = json.load(sys.stdin, object_pairs_hook=_reject_duplicate_pairs)
        else:
            with Path(path).open("r", encoding="utf-8") as handle:
                data = json.load(handle, object_pairs_hook=_reject_duplicate_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"daemon status response is invalid: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ProvenanceError("daemon status response must be an object")
    return data


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="installed_provenance")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--source-root", type=Path, required=True)
    build_parser.add_argument("--installed-root", type=Path, required=True)
    build_parser.add_argument("--installed-at", required=True)
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--marker-output", type=Path, required=True)
    build_parser.add_argument("--include", action="append", required=True)
    build_parser.add_argument("--deployment", action="append", type=Path, default=[])
    build_parser.add_argument("--expected-deployment-sha256", action="append", default=[])
    build_parser.add_argument("--expected-generation-sha256")
    build_parser.add_argument("--expected-uid", type=int)
    build_parser.add_argument("--expected-gid", type=int)

    fingerprint_parser = subparsers.add_parser("fingerprint")
    fingerprint_parser.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)
    fingerprint_parser.add_argument("--deployment", action="append", type=Path, default=[])

    launch_parser = subparsers.add_parser("launch-daemon")
    launch_parser.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)
    launch_parser.add_argument("--deployment", action="append", type=Path, default=[])
    launch_parser.add_argument("daemon_args", nargs=argparse.REMAINDER)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--marker", type=Path, default=DEFAULT_MARKER_PATH)
    verify_parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    verify_parser.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)

    daemon_parser = subparsers.add_parser("verify-daemon")
    daemon_parser.add_argument("--status-file", default="-")
    daemon_parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_PATH)

    running_parser = subparsers.add_parser("verify-running")
    running_parser.add_argument("--status-file", default="-")
    running_parser.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)
    running_parser.add_argument("--deployment", action="append", type=Path, default=[])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "build":
            manifest = build_manifest(
                source_root=args.source_root,
                installed_root=args.installed_root,
                includes=tuple(args.include),
                deployment_paths=tuple(args.deployment),
                expected_deployment_sha256=(
                    _parse_expected_deployment_hashes(args.expected_deployment_sha256)
                    if args.expected_deployment_sha256
                    else None
                ),
                expected_generation_sha256=args.expected_generation_sha256,
                installed_at=args.installed_at,
                expected_uid=args.expected_uid,
                expected_gid=args.expected_gid,
            )
            write_manifest(args.output, manifest)
            write_marker(args.marker_output, manifest, args.output)
            print(
                json.dumps(
                    {
                        "status": "built",
                        "source_commit": manifest["source_commit"],
                        "source_state": manifest["source_state"],
                        "tree_sha256": manifest["tree_sha256"],
                        "generation_sha256": manifest["generation_sha256"],
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "fingerprint":
            print(
                fingerprint_generation(
                    args.runtime_root,
                    tuple(args.deployment),
                    expected_uid=0,
                    expected_gid=0,
                )
            )
            return 0
        if args.command == "launch-daemon":
            daemon_args = args.daemon_args
            if daemon_args[:1] == ["--"]:
                daemon_args = daemon_args[1:]
            return launch_daemon(args.runtime_root, tuple(args.deployment), daemon_args)
        if args.command == "verify":
            result = verify_installation(
                marker_path=args.marker,
                manifest_path=args.manifest,
                installed_root=args.runtime_root,
                expected_uid=0,
                expected_gid=0,
            )
            print(json.dumps(result, sort_keys=True))
            return 0 if result["status"] == "verified" else 3
        if args.command == "verify-daemon":
            result = verify_daemon_status(
                status_payload=_load_status_payload(args.status_file),
                manifest_path=args.manifest,
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "verify-running":
            result = verify_running_generation(
                status_payload=_load_status_payload(args.status_file),
                runtime_root=args.runtime_root,
                deployment_paths=tuple(args.deployment),
                expected_uid=0,
                expected_gid=0,
            )
            print(json.dumps(result, sort_keys=True))
            return 0
    except IncompleteProvenanceError as exc:
        print(json.dumps({"status": "incomplete", "error": str(exc)}, sort_keys=True))
        return 3
    except ProvenanceError as exc:
        print(json.dumps({"status": "invalid", "error": str(exc)}, sort_keys=True))
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
