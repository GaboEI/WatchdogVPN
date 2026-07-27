"""Path protection primitives for transactional provisioning (Phase 23.7.5.6a).

Every mutated path must come from a trusted executor's own logic, never
directly from the compatibility manifest or from user/profile input. These
helpers give executors a single, auditable choke point to validate a target
path against an explicit allowlist before ever touching the filesystem.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Sequence

from compat.provisioning.errors import PathPolicyError

CANARY_FORBIDDEN_ROOTS: tuple[Path, ...] = (
    Path("/etc"),
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
)


def canary_forbidden_roots() -> tuple[Path, ...]:
    """Roots the canary executor must never write under, plus $HOME."""
    return CANARY_FORBIDDEN_ROOTS + (Path.home(),)


def validate_target_path(path: Path, *, allowed_roots: Sequence[Path], forbidden_roots: Sequence[Path] = ()) -> Path:
    """Validate ``path`` against structural policy and an explicit allowlist.

    Returns the validated, un-resolved path (never silently substituting a
    resolved/symlink-followed path) once every ancestor component has been
    confirmed not to be a symlink. Raises ``PathPolicyError`` for anything
    else: relative paths, ``..``, the filesystem root, an empty path, a path
    outside every allowed root, a path under a forbidden root, or a path with
    an unexpected symlink component.
    """
    path = Path(path)
    if not path.is_absolute():
        raise PathPolicyError("target path must be absolute: %s" % path)
    raw = path.as_posix()
    if raw == "/":
        raise PathPolicyError("target path must not be the filesystem root")
    if not raw.strip("/"):
        raise PathPolicyError("target path must not be empty")
    if ".." in path.parts:
        raise PathPolicyError("target path must not contain '..' components: %s" % path)

    for forbidden in forbidden_roots:
        if _is_under(path, Path(forbidden)):
            raise PathPolicyError("target path must not fall under forbidden root %s: %s" % (forbidden, path))

    for root in allowed_roots:
        root = Path(root)
        try:
            resolved_root = root.resolve(strict=True)
        except OSError as exc:
            raise PathPolicyError("allowed root does not exist: %s (%s)" % (root, exc)) from exc
        if not _is_under(path, root) and not _is_under(path, resolved_root):
            continue
        relative = path.relative_to(root) if _is_under(path, root) else path.relative_to(resolved_root)
        current = resolved_root
        for part in relative.parts:
            candidate = current / part
            if candidate.is_symlink():
                raise PathPolicyError("target path has an unexpected symlink component: %s" % candidate)
            current = candidate
        return resolved_root / relative

    raise PathPolicyError("target path %s is outside every allowed root %s" % (path, list(allowed_roots)))


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def create_file_exclusive(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Create a brand-new regular file, refusing to follow or replace anything
    that already exists at ``path`` (including a dangling symlink)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def remove_file_if_owned(path: Path, *, expected_sha256: str | None = None) -> bool:
    """Remove ``path`` only if it is a regular file (never a symlink) and, when
    given, its content hash matches what this transaction is expected to own.
    Returns True if removed, False if the path was already absent. A content
    mismatch raises ``PathPolicyError`` (ownership drift) rather than
    silently deleting a resource the user may have modified since."""
    try:
        stat_result = os.lstat(path)
    except FileNotFoundError:
        return False
    import stat as stat_module

    if stat_module.S_ISLNK(stat_result.st_mode):
        raise PathPolicyError("refusing to remove a symlink: %s" % path)
    if not stat_module.S_ISREG(stat_result.st_mode):
        raise PathPolicyError("refusing to remove a non-regular file: %s" % path)
    if expected_sha256 is not None:
        import hashlib

        try:
            actual = path.read_bytes()
        except OSError as exc:
            raise PathPolicyError("cannot verify content before removal of %s: %s" % (path, exc)) from exc
        if hashlib.sha256(actual).hexdigest() != expected_sha256:
            raise PathPolicyError(
                "refusing to remove %s: content hash diverged from what this transaction created (ownership drift)" % path
            )
    os.unlink(path)
    return True
