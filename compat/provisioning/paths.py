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

from dataclasses import dataclass, field
import ctypes
import errno
import hashlib
import os
import re
import stat as stat_module
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Sequence

from compat.provisioning.errors import DurabilityError, IdentifierError, PathPolicyError
from compat.provisioning.model import IntermediateIdentity
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
            root_lstat = os.lstat(root)
        except OSError as exc:
            raise PathPolicyError("allowed root does not exist: %s (%s)" % (root, exc)) from exc
        if stat_module.S_ISLNK(root_lstat.st_mode):
            # An allowed root that has itself been replaced by a symlink
            # must never be silently followed: resolve() would otherwise
            # redirect every path-under-this-root check to wherever the
            # symlink points, letting an attacker who can swap the root
            # (e.g. rename it aside and drop a symlink to an empty
            # directory in its place) make an ancestor-swap attack look
            # like a genuine absence.
            raise PathPolicyError("allowed root must not be a symlink: %s" % root)
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
            try:
                st = os.lstat(candidate)
            except FileNotFoundError:
                pass  # a not-yet-existing tail component is fine; nothing to reject
            except OSError as exc:
                raise PathPolicyError("cannot inspect target path component %s: %s" % (candidate, exc)) from exc
            else:
                if stat_module.S_ISLNK(st.st_mode):
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


_PARENT_DIR_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_RELATIVE_DIR_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_RELATIVE_FILE_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _verify_canonical_dev_ino(path: Path, expected_dev: int, expected_ino: int, *, label: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise PathPolicyError("%s is no longer present at its canonical path: %s" % (label, path)) from exc
    except OSError as exc:
        raise PathPolicyError("cannot verify %s identity at %s: %s" % (label, path, exc)) from exc
    if (st.st_dev, st.st_ino) != (expected_dev, expected_ino):
        raise PathPolicyError(
            "%s at %s no longer refers to the directory this transaction is bound to (identity changed)" % (label, path)
        )


@dataclass
class _IntermediateHandle:
    fd: int
    dev: int
    ino: int


@dataclass
class AllowedRootHandle:
    """An OPEN, identity-bound handle to one of ``context.allowed_roots``
    (point 2, fifth correction round) -- captured once, under the
    provisioner lock, immediately before apply/rollback/uninstall, and held
    for the rest of that critical section. Every executor operation
    (create, inspect, verify, hash, undo, unlink, the transaction-level
    postcondition check, and the revocation absence check) resolves against
    this handle's descriptor, never against a freshly re-resolved ``Path``
    -- a later rename/symlink-swap/directory-replace of the allowed root
    itself is detected (via ``st_dev``/``st_ino`` captured at open time),
    exactly like ``StateRootHandle`` for the provisioning state root.

    Point 2, sixth correction round: this binding is NOT limited to the top
    of the allowed root. Every INTERMEDIATE directory between the allowed
    root and a resource's parent is also opened once, its descriptor cached
    (keyed by its relative path tuple, built progressively so a deeper path
    reuses its own parents' cached fds), and its identity re-verified
    alongside the root's own -- a rename/replace of an intermediate
    subdirectory (never the root itself, and never the leaf resource) is
    exactly as detectable as a swap of the root, closing a gap where a
    fresh, uncached open of an intermediate component on every single call
    would otherwise silently walk into whatever real directory now sits at
    that name."""

    path: Path
    fd: int
    dev: int
    ino: int
    _intermediates: dict = field(default_factory=dict, repr=False, compare=False)

    def intermediate_fd(self, relative_parts: tuple) -> int:
        """Returns a cached, verified directory fd for the intermediate
        component chain ``relative_parts`` (e.g. ``("resources",)``),
        strictly inside this handle's allowed root, opening it (and any of
        its own uncached parents) on first use and reusing the SAME fd for
        the rest of this handle's lifetime -- an external rename/replace of
        that subdirectory after the first call cannot redirect subsequent
        operations, for the same reason the allowed root's own fd is
        immune to it."""
        relative_parts = tuple(relative_parts)
        if not relative_parts:
            return self.fd
        if relative_parts not in self._intermediates:
            parent_fd = self.intermediate_fd(relative_parts[:-1])
            fd = _open_dir_component_relative(parent_fd, relative_parts[-1])
            st = os.fstat(fd)
            self._intermediates[relative_parts] = _IntermediateHandle(fd=fd, dev=st.st_dev, ino=st.st_ino)
        return self._intermediates[relative_parts].fd

    def verify_identity(self) -> None:
        """Re-confirm, via a fresh inspection of the CONFIGURED (canonical)
        allowed-root path AND every cached intermediate subdirectory's own
        canonical path, that each still refers to exactly the physical
        directory this handle was bound to when first opened/cached. Raises
        ``PathPolicyError`` on any mismatch, absence, or inspection
        failure -- callers must never report a clean/terminal outcome
        (COMMITTED, UNINSTALLED, ...) once this has failed, exactly like
        ``StateRootHandle.verify_identity()`` for the state root: fd-bound
        operations against this handle remain correct even after a
        rename/replace of the allowed root or an intermediate subdirectory,
        but silently reporting success anyway would create a split-brain
        against whatever a fresh process using the same configured path
        would now see."""
        _verify_canonical_dev_ino(self.path, self.dev, self.ino, label="allowed root")
        for relative_parts, sub in self._intermediates.items():
            canonical = self.path.joinpath(*relative_parts)
            _verify_canonical_dev_ino(canonical, sub.dev, sub.ino, label="allowed root intermediate %r" % (relative_parts,))

    def close(self) -> None:
        for sub in self._intermediates.values():
            try:
                os.close(sub.fd)
            except OSError:
                pass
        self._intermediates.clear()
        try:
            os.close(self.fd)
        except OSError:
            pass


def open_allowed_root(path: Path) -> AllowedRootHandle:
    """Open ``path`` (one configured allowed root) with ``O_NOFOLLOW``,
    verify it is a real directory, and capture its ``st_dev``/``st_ino``.
    The root itself must already exist -- an allowed root is something the
    caller creates ahead of time (e.g. ``tools/compat_provision.py``'s
    ``--sandbox`` handling), never something this function improvises."""
    path = Path(path)
    try:
        fd = os.open(str(path), _RELATIVE_DIR_OPEN_FLAGS)
    except FileNotFoundError as exc:
        raise PathPolicyError("allowed root does not exist: %s" % path) from exc
    except NotADirectoryError as exc:
        raise PathPolicyError("allowed root exists but is not a directory: %s" % path) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PathPolicyError("allowed root must not be a symlink: %s" % path) from exc
        raise PathPolicyError("cannot open allowed root %s: %s" % (path, exc)) from exc
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISDIR(st.st_mode):
            raise PathPolicyError("allowed root is not a directory: %s" % path)
    except Exception:
        os.close(fd)
        raise
    return AllowedRootHandle(path=path, fd=fd, dev=st.st_dev, ino=st.st_ino)


def _open_dir_component_relative(parent_fd: int, name: str) -> int:
    """Opens directory component ``name`` strictly within ``parent_fd``,
    ``O_NOFOLLOW``, verifying it is a real directory. Used only to walk any
    intermediate components between an allowed root and a validated target
    path -- never to resolve the final (leaf) component, which callers open
    with whatever flags their own operation (read/create/unlink) needs."""
    try:
        fd = os.open(name, _RELATIVE_DIR_OPEN_FLAGS, dir_fd=parent_fd)
    except NotADirectoryError as exc:
        raise PathPolicyError("path component exists but is not a directory: %s" % name) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PathPolicyError("path has an unexpected symlink component: %s" % name) from exc
        raise
    return fd


@contextmanager
def _relative_to_handle(handle: AllowedRootHandle, validated_path: Path):
    """Yields ``(parent_fd, basename)`` for ``validated_path``, resolved
    entirely relative to ``handle``. Every intermediate component is
    resolved via ``handle.intermediate_fd()`` (point 2, sixth correction
    round) -- opened and identity-cached on first use, then REUSED for the
    rest of this handle's lifetime, never freshly re-opened by name on each
    call -- so a rename/replace of an intermediate directory after its
    first use cannot silently redirect a later operation into a substitute
    directory nobody has verified. ``validated_path`` must already be a
    strict descendant of ``handle.path`` (as returned by
    ``validate_target_path``)."""
    try:
        relative = validated_path.relative_to(handle.path)
    except ValueError as exc:
        raise PathPolicyError("%s is not a descendant of allowed root %s" % (validated_path, handle.path)) from exc
    parts = relative.parts
    if not parts:
        raise PathPolicyError("path must be a strict descendant of the allowed root, not the root itself: %s" % validated_path)
    parent_fd = handle.intermediate_fd(parts[:-1])
    yield parent_fd, parts[-1]


def create_file_exclusive_relative(handle: AllowedRootHandle, validated_path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Descriptor-relative equivalent of ``create_file_exclusive`` (point 2,
    fifth correction round): creates a brand-new regular file resolved
    entirely relative to ``handle``, refusing to follow or replace anything
    already there (including a dangling symlink). Durable: fsyncs the file
    and, once created, the containing directory entry."""
    with _relative_to_handle(handle, validated_path) as (parent_fd, basename):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(basename, flags, mode, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.unlink(basename, dir_fd=parent_fd)
            except OSError:
                pass
            raise
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            raise DurabilityError("write to %s completed but its directory could not be durably fsynced: %s" % (validated_path, exc)) from exc


# Test-only synchronization seam (point 3, fifth correction round): normally
# a no-op. A test may monkeypatch this to pause A's execution, between its
# own hash verification and its final re-verify-then-unlink, for exactly as
# long as it takes a second process to substitute the basename underneath
# it -- deterministically reproducing the TOCTOU window being defended
# against, without weakening the real defense itself.
def _default_unlink_pause() -> None:
    return None


def _default_quarantine_name(basename: str) -> str:
    return ".wdvpn-quarantine.%s.%s" % (basename, uuid.uuid4().hex)


UNLINK_REVERIFY_HOOK: Callable[[], None] = _default_unlink_pause
QUARANTINE_POST_VERIFY_HOOK: Callable[[], None] = _default_unlink_pause
QUARANTINE_BEFORE_RESTORE_HOOK: Callable[[], None] = _default_unlink_pause
QUARANTINE_NAME_FACTORY: Callable[[str], str] = _default_quarantine_name

RENAME_NOREPLACE = 1
_RENAMEAT2_SYSCALLS = {
    "x86_64": 316,
    "amd64": 316,
    "aarch64": 276,
    "arm64": 276,
}


def _rename_noreplace(src_name: str, dst_name: str, *, src_dir_fd: int, dst_dir_fd: int) -> None:
    """Linux ``renameat2(RENAME_NOREPLACE)`` wrapper. This intentionally
    has no ``os.rename`` fallback: if the platform cannot provide
    no-replace rename semantics, the secure remove/restore protocol must
    fail closed instead of quietly weakening the guarantee."""
    machine = os.uname().machine.lower()
    syscall_no = _RENAMEAT2_SYSCALLS.get(machine)
    if syscall_no is None:
        raise PathPolicyError("renameat2(RENAME_NOREPLACE) is not mapped for architecture %s" % machine)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        ctypes.c_long(syscall_no),
        ctypes.c_int(src_dir_fd),
        ctypes.c_char_p(os.fsencode(src_name)),
        ctypes.c_int(dst_dir_fd),
        ctypes.c_char_p(os.fsencode(dst_name)),
        ctypes.c_uint(RENAME_NOREPLACE),
    )
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), src_name)


def _hash_fd_from_start(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _verify_private_directory_fd(dir_fd: int, *, label: str) -> None:
    st = os.fstat(dir_fd)
    if not stat_module.S_ISDIR(st.st_mode):
        raise PathPolicyError("%s is not a directory" % label)
    if st.st_uid != os.getuid():
        raise PathPolicyError("%s is owned by uid %d, expected %d" % (label, st.st_uid, os.getuid()))
    mode = stat_module.S_IMODE(st.st_mode)
    if mode & 0o022:
        raise PathPolicyError("%s must not be writable by group/world actors, found mode %o" % (label, mode))


def remove_file_if_owned_relative(
    handle: AllowedRootHandle, validated_path: Path, *, expected_sha256: str | None = None
) -> bool:
    """Descriptor-relative equivalent of ``remove_file_if_owned`` that also
    eliminates the TOCTOU window between verifying a resource's identity
    and actually deleting it (point 3, fifth correction round; made
    genuinely atomic in the sixth). The file is opened ONCE, ``O_NOFOLLOW``,
    and every check -- regular file, content hash -- is performed against
    that SAME open file descriptor.

    A bare ``lstat()`` immediately before ``unlink()`` (the fifth round's
    approach) still leaves a window between that check and the destructive
    syscall itself, since ``unlink`` operates on the NAME, not the inode: a
    concurrent rename of the basename in that exact window would still get
    deleted. Instead, the basename is atomically RENAMED into a private,
    unpredictable quarantine name within the SAME directory (a
    ``uuid4``-derived name never otherwise used, so a pre-existing collision
    is not realistically triggerable): whatever inode is CURRENTLY at the
    basename at the moment of that single atomic ``renameat`` syscall is
    what moves, collapsing "read the name" and "claim the entry" into one
    kernel operation with no window for a third party to intervene in
    between. Only THEN is the quarantined entry's identity compared against
    what was hashed -- if a concurrent substitution beat us to the rename,
    we quarantined the WRONG (foreign) inode, and it is restored to its
    original name (best-effort) rather than ever being deleted; if the
    restore itself fails, the quarantined entry is left in place as
    recoverable evidence, never silently deleted. Only a quarantined entry
    that matches the exact inode just hashed is ever unlinked -- and by then
    its name is private to this call, so no further substitution is
    possible."""
    with _relative_to_handle(handle, validated_path) as (parent_fd, basename):
        _verify_private_directory_fd(parent_fd, label="quarantine parent for %s" % validated_path)
        try:
            fd = os.open(basename, _RELATIVE_FILE_READ_FLAGS, dir_fd=parent_fd)
        except FileNotFoundError:
            return False
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PathPolicyError("refusing to remove a symlink: %s" % validated_path) from exc
            raise PathPolicyError("cannot open %s for removal: %s" % (validated_path, exc)) from exc
        expected_hash = None
        try:
            st = os.fstat(fd)
            if not stat_module.S_ISREG(st.st_mode):
                raise PathPolicyError("refusing to remove a non-regular file: %s" % validated_path)
            if expected_sha256 is not None:
                expected_hash = _hash_fd_from_start(fd)
                if expected_hash != expected_sha256:
                    raise PathPolicyError(
                        "refusing to remove %s: content hash diverged from what this transaction created (ownership drift)"
                        % validated_path
                    )

            # Test seam: after the original fd and content have been
            # verified, while the fd is still held open, before the
            # no-replace quarantine move.
            UNLINK_REVERIFY_HOOK()

            quarantine_name = QUARANTINE_NAME_FACTORY(basename)
            try:
                _rename_noreplace(basename, quarantine_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            except FileNotFoundError:
                return False
            except FileExistsError as exc:
                raise PathPolicyError("cannot quarantine %s for removal: quarantine destination already exists" % validated_path) from exc
            except OSError as exc:
                raise PathPolicyError("cannot quarantine %s for removal with no-replace rename: %s" % (validated_path, exc)) from exc
            try:
                os.fsync(parent_fd)
            except OSError as exc:
                raise DurabilityError(
                    "quarantine of %s completed but its directory could not be durably fsynced: %s" % (validated_path, exc)
                ) from exc

            try:
                qfd = os.open(quarantine_name, _RELATIVE_FILE_READ_FLAGS, dir_fd=parent_fd)
            except FileNotFoundError as exc:
                raise PathPolicyError("quarantined entry for %s vanished unexpectedly" % validated_path) from exc
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise PathPolicyError("quarantined entry for %s is a symlink" % validated_path) from exc
                raise PathPolicyError("cannot open quarantined entry for %s: %s" % (validated_path, exc)) from exc
            try:
                quarantined = os.fstat(qfd)
                if not stat_module.S_ISREG(quarantined.st_mode):
                    raise PathPolicyError("quarantined entry for %s is not a regular file" % validated_path)
                if (quarantined.st_dev, quarantined.st_ino) != (st.st_dev, st.st_ino):
                    _restore_quarantine_or_raise(parent_fd, quarantine_name, basename, validated_path, "quarantined a different inode")
                if expected_sha256 is not None:
                    post_move_hash = _hash_fd_from_start(qfd)
                    if post_move_hash != expected_sha256:
                        raise PathPolicyError(
                            "refusing to remove %s: quarantined inode content hash changed after initial verification; "
                            "residual quarantine entry %s remains for recovery" % (validated_path, quarantine_name)
                        )

                # Test seam: after post-move identity/content verification,
                # before the destructive unlink of the quarantine entry.
                QUARANTINE_POST_VERIFY_HOOK()

                try:
                    qfd_after_hook = os.open(quarantine_name, _RELATIVE_FILE_READ_FLAGS, dir_fd=parent_fd)
                except FileNotFoundError as exc:
                    raise PathPolicyError(
                        "refusing to remove %s: quarantine entry vanished before unlink; residual %s"
                        % (validated_path, quarantine_name)
                    ) from exc
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise PathPolicyError(
                            "refusing to remove %s: quarantine entry became a symlink before unlink; residual %s"
                            % (validated_path, quarantine_name)
                        ) from exc
                    raise PathPolicyError(
                        "refusing to remove %s: cannot reopen quarantine entry before unlink; residual %s: %s"
                        % (validated_path, quarantine_name, exc)
                    ) from exc
                try:
                    post_hook = os.fstat(qfd_after_hook)
                    if (post_hook.st_dev, post_hook.st_ino) != (st.st_dev, st.st_ino):
                        raise PathPolicyError(
                            "refusing to remove %s: quarantine entry identity changed before unlink; residual %s"
                            % (validated_path, quarantine_name)
                        )
                    if expected_sha256 is not None and _hash_fd_from_start(qfd_after_hook) != expected_sha256:
                        raise PathPolicyError(
                            "refusing to remove %s: quarantine entry content changed before unlink; residual %s"
                            % (validated_path, quarantine_name)
                        )
                finally:
                    os.close(qfd_after_hook)
            finally:
                os.close(qfd)

            os.unlink(quarantine_name, dir_fd=parent_fd)
            try:
                os.fsync(parent_fd)
            except OSError as exc:
                raise DurabilityError(
                    "removal of %s completed but its directory could not be durably fsynced: %s" % (validated_path, exc)
                ) from exc
            return True
        finally:
            os.close(fd)


def _restore_quarantine_or_raise(parent_fd: int, quarantine_name: str, basename: str, validated_path: Path, reason: str) -> None:
    try:
        QUARANTINE_BEFORE_RESTORE_HOOK()
        _rename_noreplace(quarantine_name, basename, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    except OSError as exc:
        raise PathPolicyError(
            "refusing to remove %s: %s; could not restore quarantine entry %s without replacement: %s"
            % (validated_path, reason, quarantine_name, exc)
        ) from exc
    try:
        os.fsync(parent_fd)
    except OSError as exc:
        raise DurabilityError(
            "restore of quarantined %s completed but its directory could not be durably fsynced: %s" % (validated_path, exc)
        ) from exc
    raise PathPolicyError(
        "refusing to remove %s: %s; restored quarantined entry without replacement" % (validated_path, reason)
    )


def capture_intermediate_identities(handle: AllowedRootHandle, validated_path: Path) -> tuple[IntermediateIdentity, ...]:
    try:
        relative = validated_path.relative_to(handle.path)
    except ValueError as exc:
        raise PathPolicyError("%s is not a descendant of allowed root %s" % (validated_path, handle.path)) from exc
    identities = []
    for index in range(1, len(relative.parts)):
        parts = relative.parts[:index]
        fd = handle.intermediate_fd(parts)
        st = os.fstat(fd)
        identities.append(
            IntermediateIdentity(
                relative_name="/".join(parts),
                dev=st.st_dev,
                ino=st.st_ino,
                uid=st.st_uid,
                mode=stat_module.S_IMODE(st.st_mode),
            )
        )
    return tuple(identities)


def verify_intermediate_identities(handle: AllowedRootHandle, expected: Sequence[IntermediateIdentity]) -> None:
    for identity in expected:
        parts = tuple(Path(identity.relative_name).parts)
        if not parts or Path(identity.relative_name).is_absolute() or ".." in parts:
            raise PathPolicyError("invalid persisted intermediate identity name: %s" % identity.relative_name)
        fd = handle.intermediate_fd(parts)
        st = os.fstat(fd)
        actual = (st.st_dev, st.st_ino, st.st_uid, stat_module.S_IMODE(st.st_mode))
        expected_tuple = (identity.dev, identity.ino, identity.uid, identity.mode)
        if actual != expected_tuple:
            raise PathPolicyError(
                "intermediate %s identity changed: expected dev/ino/uid/mode %r, found %r"
                % (identity.relative_name, expected_tuple, actual)
            )


def stat_identity_relative(handle: AllowedRootHandle, validated_path: Path) -> dict:
    """Descriptor-relative equivalent of ``stat_identity``, resolved via
    ``handle`` rather than a fresh path-based lstat."""
    with _relative_to_handle(handle, validated_path) as (parent_fd, basename):
        st = os.lstat(basename, dir_fd=parent_fd)
    return {
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": stat_module.S_IMODE(st.st_mode),
        "nlink": st.st_nlink,
        "is_symlink": stat_module.S_ISLNK(st.st_mode),
        "is_regular": stat_module.S_ISREG(st.st_mode),
    }


def read_bytes_relative(handle: AllowedRootHandle, validated_path: Path) -> bytes:
    """Reads the full content of ``validated_path``, resolved via
    ``handle``, opened ``O_NOFOLLOW`` (never following a symlink swapped in
    for the leaf component)."""
    with _relative_to_handle(handle, validated_path) as (parent_fd, basename):
        try:
            fd = os.open(basename, _RELATIVE_FILE_READ_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PathPolicyError("refusing to read a symlink: %s" % validated_path) from exc
            raise
        with os.fdopen(fd, "rb") as f:
            return f.read()


def confirm_absent_descriptor_safe(
    resource_identity: str, *, allowed_root_handles: Sequence[AllowedRootHandle], forbidden_roots: Sequence[Path] = ()
) -> tuple[bool, str | None]:
    """Descriptor-safe absence check for revocation (point 5, fourth
    correction round; bound to an already-captured ``AllowedRootHandle`` in
    the fifth): never an isolated ``os.lstat()`` on a bare, previously-
    persisted path string, and never a fresh path-based ``os.open`` of the
    parent directory either -- both are vulnerable to a TOCTOU ancestor-
    swap between whenever the allowed root was last confirmed and the
    moment this check runs. ``resource_identity`` is first validated
    through the SAME allowlist/forbidden-roots policy as everywhere else
    (``validate_target_path``); the matching ``AllowedRootHandle`` (already
    opened, under the lock, before this critical section began) is then
    re-confirmed to still refer to the SAME physical directory it was
    captured from, and the absence check itself walks descriptor-relative
    from that SAME handle -- never reopening the allowed root from a
    string.

    Returns ``(True, None)`` only on a genuine ``FileNotFoundError`` for the
    basename relative to the held descriptor chain. Any of the following
    returns ``(False, reason)`` instead -- a path-policy violation, no
    matching handle, an allowed root whose identity has changed, an
    unexpected symlink, any other inspection error, or the resource still
    being present -- so the caller must never treat the resource as safely
    absent in any of those cases."""
    allowed_roots = [h.path for h in allowed_root_handles]
    try:
        validated = validate_target_path(Path(resource_identity), allowed_roots=allowed_roots, forbidden_roots=forbidden_roots)
    except PathPolicyError as exc:
        return False, "cannot validate path for %s: %s" % (resource_identity, exc)

    handle = next((h for h in allowed_root_handles if validated == h.path or _is_under(validated, h.path)), None)
    if handle is None:
        return False, "no matching allowed root handle for %s" % resource_identity

    # Point 2, sixth correction round: re-verify the ROOT and every cached
    # INTERMEDIATE component's identity, not just the root -- an
    # intermediate directory swapped after being cached is exactly as
    # disqualifying as the allowed root itself being swapped.
    try:
        handle.verify_identity()
    except PathPolicyError as exc:
        return False, str(exc)

    try:
        with _relative_to_handle(handle, validated) as (parent_fd, basename):
            try:
                st = os.lstat(basename, dir_fd=parent_fd)
            except FileNotFoundError:
                return True, None
            except OSError as exc:
                return False, "cannot confirm absence of %s: %s" % (resource_identity, exc)
            if stat_module.S_ISLNK(st.st_mode):
                return False, "%s exists as an unexpected symlink" % resource_identity
            return False, "resource %s is still present" % resource_identity
    except PathPolicyError as exc:
        return False, "cannot walk to %s: %s" % (resource_identity, exc)


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


def _reject_symlink_components(raw: Path, *, label: str) -> None:
    """Walks every existing component of ``raw`` (stopping at the first
    component that does not yet exist) and rejects a symlink anywhere along
    the way -- checked BEFORE any resolution, which would otherwise silently
    follow it. Uses ``os.lstat`` directly, never ``Path.is_symlink()``/
    ``Path.exists()``: pathlib's internal ``OSError``-handling for those two
    calls differs across Python versions (propagates on 3.12, silently
    returns ``False`` on 3.14 -- see the round-2 hardening notes) and can
    turn a genuine inspection failure (permission denied, EIO, ESTALE) into
    a false "not a symlink"/"doesn't exist". Only a genuine
    ``FileNotFoundError`` on a component means "nothing deeper to check";
    any OTHER ``OSError`` fails closed as ``PathPolicyError``."""
    current = Path(raw.anchor)
    for part in raw.relative_to(raw.anchor).parts:
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError as exc:
            raise PathPolicyError("%s: cannot inspect path component %s: %s" % (label, current, exc)) from exc
        if stat_module.S_ISLNK(st.st_mode):
            raise PathPolicyError("%s has a symlink component, refusing: %s" % (label, current))


def _reject_reserved_destination(raw: Path, *, label: str) -> Path:
    """Rejects the filesystem root, any reserved system root, the real
    product's own state directory, or ``$HOME`` itself (a private
    subdirectory *under* ``$HOME`` remains allowed, since some hosts wipe
    ``/tmp`` on every boot). Returns the resolved, canonical path."""
    resolved = Path(raw).resolve(strict=False)
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


def validate_dedicated_lab_root(path: Path, *, label: str = "--lab-root") -> Path:
    """Positive confinement policy for the canary lab harness's dedicated
    ``--lab-root``. Unlike a denylist (which can only ever name the roots it
    already knows about, and would still accept an arbitrary path like
    ``/var/log``, ``/var/spool``, ``/opt`` or ``/srv``), every mutating path
    the harness touches must now be a strict descendant of ONE explicitly
    validated root.

    The lab root itself must already exist -- it is deliberately never
    created here, since a dedicated lab root is something the operator
    creates and approves ahead of time, not something this tool improvises.
    It must not be a symlink at any component, must be a real directory
    owned by our own uid, and must be mode exactly ``0700``. It is also
    rejected outright if it resolves to the filesystem root, a reserved
    system root, the real product's own state directory, or ``$HOME``
    itself."""
    raw = Path(path)
    if not raw.is_absolute():
        raise PathPolicyError("%s must be an absolute path: %s" % (label, raw))
    if ".." in raw.parts:
        raise PathPolicyError("%s must not contain '..' components: %s" % (label, raw))
    _reject_symlink_components(raw, label=label)
    resolved = _reject_reserved_destination(raw, label=label)
    try:
        st = os.lstat(raw)
    except FileNotFoundError as exc:
        raise PathPolicyError(
            "%s must already exist as a dedicated, pre-approved directory (never auto-created): %s" % (label, raw)
        ) from exc
    if stat_module.S_ISLNK(st.st_mode):
        raise PathPolicyError("%s must not be a symlink: %s" % (label, raw))
    if not stat_module.S_ISDIR(st.st_mode):
        raise PathPolicyError("%s must be a directory: %s" % (label, raw))
    if st.st_uid != os.getuid():
        raise PathPolicyError("%s %s is owned by uid %d, expected %d" % (label, raw, st.st_uid, os.getuid()))
    if stat_module.S_IMODE(st.st_mode) != 0o700:
        raise PathPolicyError("%s %s must be mode 0700, found %o" % (label, raw, stat_module.S_IMODE(st.st_mode)))
    return resolved


def validate_lab_descendant(lab_root: Path, path: Path, *, label: str) -> Path:
    """Validates ``path`` (the harness's ``--sandbox``/``--state-root``) as
    a STRICT descendant of an already-validated ``lab_root`` -- deliberately
    stricter and independent from ``validate_target_path`` (which requires
    its allowed root to already exist): ``path`` may legitimately name
    something that does not exist yet, so every check here works before any
    mutation.

    Rejects: a relative path, a ``..`` component, a symlink at the leaf or
    any existing ancestor component, equality with ``lab_root`` itself, and
    anything that does not resolve to a descendant of ``lab_root``. An
    arbitrary path outside the lab root (``/var/log``, ``/opt``, ...) is
    never acceptable no matter what it is, since it can never be a
    descendant of the one approved root. Also independently re-checked
    against the reserved-destination policy (filesystem root, reserved
    system roots, the real product state directory) as defense in depth: a
    misconfigured ``lab_root`` must never let one of those slip through just
    because it happens to be nested underneath it."""
    raw = Path(path)
    if not raw.is_absolute():
        raise PathPolicyError("%s must be an absolute path: %s" % (label, raw))
    if ".." in raw.parts:
        raise PathPolicyError("%s must not contain '..' components: %s" % (label, raw))
    _reject_symlink_components(raw, label=label)
    resolved = _reject_reserved_destination(raw, label=label)
    lab_root = Path(lab_root)
    if resolved == lab_root:
        raise PathPolicyError("%s must not be the lab root itself: %s" % (label, raw))
    if not _is_under(resolved, lab_root):
        raise PathPolicyError("%s must be a descendant of the dedicated lab root %s: %s" % (label, lab_root, raw))
    return resolved
