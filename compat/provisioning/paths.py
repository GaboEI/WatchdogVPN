"""Path protection primitives for transactional provisioning (Phase 23.7.5.6a).

Every mutated path must come from a trusted executor's own logic, never
directly from the compatibility manifest or from user/profile input. These
helpers give executors a single, auditable choke point to validate a target
path against an explicit allowlist before ever touching the filesystem.

Every identifier used to build a persistent path (``transaction_id``,
``capability_id``, ``dependency_id``) must pass ``validate_identifier`` first
-- a persistent path is never constructed directly from an unvalidated
identifier.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat as stat_module
from pathlib import Path
from typing import Sequence

from compat.provisioning.errors import IdentifierError, PathPolicyError
from compat.provisioning.storage import fsync_parent_directory

CANARY_FORBIDDEN_ROOTS: tuple[Path, ...] = (
    Path("/etc"),
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
    Path("/boot"),
    Path("/dev"),
    Path("/proc"),
    Path("/sys"),
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_-]+$")
IDENTIFIER_MAX_LENGTH = 128


def canary_forbidden_roots() -> tuple[Path, ...]:
    """Roots the canary executor must never write under, plus $HOME."""
    return CANARY_FORBIDDEN_ROOTS + (Path.home(),)


def validate_identifier(value: object, *, field: str, max_length: int = IDENTIFIER_MAX_LENGTH) -> str:
    """Validate an identifier that will be used to build a persistent path
    (a filename component, never a full path). Rejects anything empty, too
    long, containing '/', '\\\\', NUL, '..', or any character outside a
    restrictive allowlist -- a persistent path is never built from an
    identifier that has not passed through here first."""
    if not isinstance(value, str) or not value:
        raise IdentifierError("%s must be a non-empty string" % field)
    if len(value) > max_length:
        raise IdentifierError("%s exceeds the maximum identifier length (%d)" % (field, max_length))
    if value in (".", ".."):
        raise IdentifierError("%s must not be '.' or '..'" % field)
    if "\x00" in value or "/" in value or "\\" in value:
        raise IdentifierError("%s must not contain a path separator or NUL byte" % field)
    if not _IDENTIFIER_RE.match(value):
        raise IdentifierError("%s contains characters outside the allowed identifier grammar" % field)
    return value


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
    that already exists at ``path`` (including a dangling symlink). Durable:
    fsyncs the file and, once created, the parent directory entry."""
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
    fsync_parent_directory(path)


def remove_file_if_owned(path: Path, *, expected_sha256: str | None = None) -> bool:
    """Remove ``path`` only if it is a regular file (never a symlink) and, when
    given, its content hash matches what this transaction is expected to own.
    Returns True if removed, False if the path was already absent. A content
    mismatch raises ``PathPolicyError`` (ownership drift) rather than
    silently deleting a resource the user may have modified since. Durable:
    fsyncs the parent directory entry once the unlink itself succeeds."""
    try:
        stat_result = os.lstat(path)
    except FileNotFoundError:
        return False

    if stat_module.S_ISLNK(stat_result.st_mode):
        raise PathPolicyError("refusing to remove a symlink: %s" % path)
    if not stat_module.S_ISREG(stat_result.st_mode):
        raise PathPolicyError("refusing to remove a non-regular file: %s" % path)
    if expected_sha256 is not None:
        try:
            actual = path.read_bytes()
        except OSError as exc:
            raise PathPolicyError("cannot verify content before removal of %s: %s" % (path, exc)) from exc
        if hashlib.sha256(actual).hexdigest() != expected_sha256:
            raise PathPolicyError(
                "refusing to remove %s: content hash diverged from what this transaction created (ownership drift)" % path
            )
    os.unlink(path)
    fsync_parent_directory(path)
    return True


def stat_identity(path: Path) -> dict:
    """Read-only ownership/type identity of a path: uid, gid, mode, st_nlink,
    is_symlink, is_regular. Never follows a symlink for the target itself."""
    lstat_result = os.lstat(path)
    return {
        "uid": lstat_result.st_uid,
        "gid": lstat_result.st_gid,
        "mode": stat_module.S_IMODE(lstat_result.st_mode),
        "nlink": lstat_result.st_nlink,
        "is_symlink": stat_module.S_ISLNK(lstat_result.st_mode),
        "is_regular": stat_module.S_ISREG(lstat_result.st_mode),
    }


def _real_product_state_dir() -> Path | None:
    """The real product's own system state directory (``/var/lib/watchdogvpn``),
    imported lazily to avoid an import-time dependency from ``compat`` onto
    ``config``. Returns ``None`` if that module is unavailable for any
    reason -- the lab-confinement check simply skips that one comparison
    rather than failing to import."""
    try:
        from config import paths as config_paths
    except ImportError:
        return None
    return getattr(config_paths, "SYSTEM_CONFIG_DIR", None)


def validate_lab_root(path: Path, *, label: str) -> Path:
    """Confinement policy for the canary lab harness's ``--sandbox``/
    ``--state-root`` CLI arguments -- deliberately stricter and independent
    from ``validate_target_path`` (which requires its allowed root to
    already exist): these arguments may legitimately name a path that does
    not exist yet, so every check here must work before any mutation.

    Rejects: a relative path, a ``..`` component, the filesystem root, any
    of the reserved system roots (``/etc``, ``/usr``, ``/bin``, ``/sbin``,
    ``/lib``, ``/lib64``, ``/boot``, ``/dev``, ``/proc``, ``/sys``), the
    real product's own state directory (``/var/lib/watchdogvpn``) or
    anything under it, ``$HOME`` itself (a private subdirectory *under*
    ``$HOME`` remains allowed, since some hosts wipe ``/tmp`` on every
    boot), and a symlink at the leaf or at any existing ancestor component
    (checked BEFORE any resolution, which would otherwise silently follow
    it). Returns the resolved, canonical path only once every check has
    passed."""
    raw = Path(path)
    if not raw.is_absolute():
        raise PathPolicyError("%s must be an absolute path: %s" % (label, raw))
    if ".." in raw.parts:
        raise PathPolicyError("%s must not contain '..' components: %s" % (label, raw))

    current = Path(raw.anchor)
    for part in raw.relative_to(raw.anchor).parts:
        current = current / part
        if current.is_symlink():
            raise PathPolicyError("%s has a symlink component, refusing: %s" % (label, current))
        if not current.exists():
            break

    resolved = raw.resolve(strict=False)
    if resolved == Path("/"):
        raise PathPolicyError("%s must not be the filesystem root" % label)
    if resolved == Path.home():
        raise PathPolicyError("%s must not be $HOME itself (a subdirectory under it is fine): %s" % (label, raw))
    for forbidden in CANARY_FORBIDDEN_ROOTS:
        if resolved == forbidden or _is_under(resolved, forbidden):
            raise PathPolicyError("%s must not be a reserved system path (%s): %s" % (label, forbidden, raw))
    real_product_state_dir = _real_product_state_dir()
    if real_product_state_dir is not None:
        resolved_product_dir = Path(real_product_state_dir).resolve(strict=False)
        if resolved == resolved_product_dir or _is_under(resolved, resolved_product_dir):
            raise PathPolicyError(
                "%s must not overlap the real product state directory %s: %s" % (label, resolved_product_dir, raw)
            )
    return resolved
