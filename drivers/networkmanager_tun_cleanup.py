from __future__ import annotations

import subprocess
import sys
import os
import secrets
import stat
from pathlib import Path
from uuid import UUID

import privileged_state


CONNECTION_NAME = "wdvpn-tun0"
CONNECTION_TYPE = "tun"
# The ownership registry must survive a reboot: a NetworkManager profile is
# persistent, so an authority stored under the volatile /run tmpfs could not
# authorise its later cleanup. It lives in the root-only state tree instead,
# readable and writable only by the fixed root helper (never by the daemon).
OWNED_UUIDS_PATH = Path("/var/lib/watchdogvpn/nm-tun/owned-uuid")
# Before the ownership registry moved into the durable state tree, the previous
# helper stored the same root-owned 0600 record under the systemd runtime
# directory /run/watchdogvpn-nm-tun, which is cleared on reboot. A supported
# upgrade must promote that trusted legacy record into the durable authority
# before cleanup needs it.
LEGACY_OWNED_UUIDS_PATH = Path("/run/watchdogvpn-nm-tun/owned-uuid")
EXPECTED_REGISTRY_UID = 0
EXPECTED_REGISTRY_GID = 0
EXPECTED_REGISTRY_DIR_MODE = 0o700
EXPECTED_REGISTRY_FILE_MODE = 0o600


class NetworkManagerTunCleanupError(RuntimeError):
    pass


def record_active_tun_connection() -> bool:
    """Record the active WatchdogVPN NM TUN profile identity as root-owned state."""
    listing = _run_nmcli([
        "nmcli", "--terse", "--fields", "UUID,NAME,TYPE,DEVICE", "--escape", "no",
        "connection", "show", "--active",
    ])
    connection_uuids = [
        uuid
        for uuid, name, connection_type, device in _parse_connection_rows(listing.stdout)
        if name == CONNECTION_NAME and connection_type == CONNECTION_TYPE and device == CONNECTION_NAME
    ]
    if len(connection_uuids) > 1:
        # Ownership cannot be attributed to exactly one adopted connection, so
        # no registry may be kept: a stale entry would later authorise deleting
        # a profile this attempt cannot prove it owns.
        _remove_owned_uuid_registry()
        raise NetworkManagerTunCleanupError("ambiguous WatchdogVPN NetworkManager TUN ownership")
    if not connection_uuids:
        # NetworkManager did not adopt the TUN: there is no confirmed
        # ownership, so no registry may be created or kept.
        _remove_owned_uuid_registry()
        return False
    _write_owned_uuid_registry(connection_uuids[0])
    return True


def remove_stale_tun_connections() -> bool:
    """Remove only the NetworkManager profile identity previously registered.

    Returns True when the owned resource is reconciled: the registered profile
    was deleted, or it is provably absent. Returns False when there is no
    ownership authority but a product-shaped residual profile exists, because
    the teardown cannot be reported clean without either owning the profile or
    reconciling its absence. An unsafe, ambiguous or invalid registry, or a
    failed delete, raises so the caller fails closed.
    """
    owned_uuid = _read_owned_uuid_registry()
    listing = _run_nmcli([
        "nmcli", "--terse", "--fields", "UUID,NAME,TYPE", "--escape", "no",
        "connection", "show",
    ])
    rows = _parse_connection_rows(listing.stdout)
    if owned_uuid is None:
        # No ownership authority: never delete a candidate by name, but a
        # product-shaped residual (for example a profile left by an install
        # whose previous volatile registry was lost on reboot) must not be
        # reported as cleaned either.
        return not _has_product_tun_candidate(rows)

    connection_uuids: list[str] = []
    for uuid, name, connection_type, _device in rows:
        if uuid == owned_uuid and name == CONNECTION_NAME and connection_type == CONNECTION_TYPE:
            connection_uuids.append(uuid)

    if len(connection_uuids) > 1:
        raise NetworkManagerTunCleanupError("ambiguous WatchdogVPN NetworkManager TUN cleanup target")

    for connection_uuid in connection_uuids:
        _run_nmcli(["nmcli", "connection", "delete", "uuid", connection_uuid])
    _remove_owned_uuid_registry()
    return True


def migrate_legacy_owned_uuid_registry() -> bool:
    """Promote a trusted legacy runtime registry into the durable authority.

    Run by the installer as root so a pre-existing install keeps its cleanup
    ability across an upgrade that moved the registry out of volatile /run. The
    legacy source must meet the same trust bar as the durable authority --
    root-owned, a regular file, not writable by group or others, reached without
    symlink traversal, and a single unambiguous UUID -- because a registry the
    unprivileged daemon could write must never be promoted to root authority. It
    never removes the legacy source and never authorises a delete on its own; an
    absent, unsafe, malformed or ambiguous source is a no-op with no authority
    created.

    The durable registry is published only when no entry exists at the moment of
    publication: the check and the write are one atomic no-replace operation, so
    a live registration created by the daemon after this migration begins is
    never overwritten by the stale legacy UUID. A presence that wins the race is
    reported as no migration.
    """
    if os.geteuid() != 0:
        raise NetworkManagerTunCleanupError(
            "root is required to migrate the WatchdogVPN NetworkManager TUN ownership registry"
        )
    if _owned_uuid_registry_present():
        return False
    try:
        legacy_uuid = _read_legacy_owned_uuid_registry()
    except NetworkManagerTunCleanupError:
        return False
    if legacy_uuid is None:
        return False
    return _write_owned_uuid_registry(legacy_uuid, replace=False)


def _owned_uuid_registry_present() -> bool:
    try:
        os.lstat(OWNED_UUIDS_PATH)
    except FileNotFoundError:
        return False
    except OSError:
        return False
    return True


def _has_product_tun_candidate(rows: list[tuple[str, str, str, str]]) -> bool:
    return any(
        name == CONNECTION_NAME and connection_type == CONNECTION_TYPE
        for _uuid, name, connection_type, _device in rows
    )


def _parse_connection_rows(output: str) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for line in output.splitlines():
        columns = line.split(":")
        if len(columns) == 3:
            uuid, name, connection_type = columns
            device = ""
        elif len(columns) == 4:
            uuid, name, connection_type, device = columns
        else:
            continue
        if _is_uuid(uuid):
            rows.append((uuid, name, connection_type, device))
    return rows


def _write_owned_uuid_registry(connection_uuid: str, *, replace: bool = True) -> bool:
    """Write the durable registry, atomically and never partially visible.

    With ``replace=True`` (the live-registration path) an existing entry is
    atomically replaced. With ``replace=False`` (the legacy-migration path) the
    entry is published only when no entry exists at that instant, so a registry
    created concurrently is never overwritten. Returns True when the registry
    was published by this call.
    """
    if not _is_uuid(connection_uuid):
        raise NetworkManagerTunCleanupError("invalid WatchdogVPN NetworkManager TUN UUID")
    parent_fd: int | None = None
    tmp_name: str | None = None
    published = False
    try:
        _ensure_registry_parent()
        parent_fd = _open_directory(OWNED_UUIDS_PATH.parent)
        _validate_registry_parent_fd(parent_fd)
        payload = f"{connection_uuid}\n".encode("ascii")
        for _attempt in range(10):
            tmp_name = f".{OWNED_UUIDS_PATH.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                tmp_fd = os.open(tmp_name, flags, EXPECTED_REGISTRY_FILE_MODE, dir_fd=parent_fd)
                break
            except FileExistsError:
                tmp_name = None
        else:
            raise NetworkManagerTunCleanupError("cannot allocate WatchdogVPN NetworkManager TUN ownership registry")
        try:
            os.write(tmp_fd, payload)
            os.fchmod(tmp_fd, EXPECTED_REGISTRY_FILE_MODE)
            tmp_stat = os.fstat(tmp_fd)
            _validate_registry_file_stat(tmp_stat)
            os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)
        if replace:
            os.rename(tmp_name, OWNED_UUIDS_PATH.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            tmp_name = None
            published = True
        else:
            # link(2) fails with FileExistsError when the destination already
            # exists, so the decision and the publication are one atomic step.
            try:
                os.link(
                    tmp_name,
                    OWNED_UUIDS_PATH.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                return False
            os.unlink(tmp_name, dir_fd=parent_fd)
            tmp_name = None
            published = True
        os.fsync(parent_fd)
        # Postcondition: the required durable pathname must still resolve to a
        # validated registry. Live registration publishes the current active UUID
        # and therefore requires the exact UUID it wrote. Legacy migration uses
        # no-replace publication: a concurrently refreshed live registration may
        # safely supersede the stale legacy UUID after the link succeeds but
        # before this final read. In that case the descriptor-relative read below
        # has already proven there is valid root-owned durable authority at the
        # required path, so the install can continue with the live UUID as the
        # authoritative current registration. Missing, unsafe, unreachable or
        # replaced-elsewhere paths still fail closed because the read raises or
        # returns no validated UUID.
        durable = _read_owned_uuid_registry()
        if durable is None or (replace and durable != connection_uuid):
            raise NetworkManagerTunCleanupError(
                "the WatchdogVPN NetworkManager TUN ownership registry is not durable at the required path"
            )
    except OSError as exc:
        raise NetworkManagerTunCleanupError("cannot record WatchdogVPN NetworkManager TUN ownership") from exc
    finally:
        if tmp_name is not None and parent_fd is not None:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if parent_fd is not None:
            os.close(parent_fd)
    return published


def _read_owned_uuid_registry() -> str | None:
    return _read_registry_uuid(OWNED_UUIDS_PATH)


def _read_legacy_owned_uuid_registry() -> str | None:
    # The legacy source must be the exact historical payload, not merely a
    # string that a permissive strip() would normalise into a UUID.
    return _read_registry_uuid(LEGACY_OWNED_UUIDS_PATH, canonical=True)


def _read_registry_uuid(registry_path: Path, *, canonical: bool = False) -> str | None:
    parent_fd: int | None = None
    file_fd: int | None = None
    try:
        parent_fd = _open_directory(registry_path.parent)
        file_fd = os.open(
            registry_path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        # An absent registry means no authority exists; it is not an error.
        return None
    except OSError as exc:
        raise NetworkManagerTunCleanupError("cannot inspect WatchdogVPN NetworkManager TUN ownership") from exc
    try:
        _validate_registry_parent_fd(parent_fd)
        path_stat = os.fstat(file_fd)
        _validate_registry_file_stat(path_stat)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_fd, 128)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(part) for part in chunks) > 128:
                raise NetworkManagerTunCleanupError("invalid WatchdogVPN NetworkManager TUN ownership registry")
        raw = b"".join(chunks)
        value = _decode_canonical_registry_payload(raw) if canonical else raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise NetworkManagerTunCleanupError("invalid WatchdogVPN NetworkManager TUN ownership registry") from exc
    except OSError as exc:
        raise NetworkManagerTunCleanupError("cannot read WatchdogVPN NetworkManager TUN ownership") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if parent_fd is not None:
            os.close(parent_fd)
    if not _is_uuid(value):
        raise NetworkManagerTunCleanupError("invalid WatchdogVPN NetworkManager TUN ownership registry")
    return value


def _decode_canonical_registry_payload(raw: bytes) -> str:
    # The historical legacy registry is exactly one canonical lowercase UUID
    # followed by a single newline (the pre-move helper wrote f"{uuid}\n").
    # Anything else -- leading/trailing whitespace or tabs, extra blank lines, a
    # missing newline, duplicate lines, uppercase or non-ASCII bytes, or an
    # overlong payload -- is not the trusted historical format and must never be
    # promoted to root authority.
    text = raw.decode("ascii")
    if not text.endswith("\n") or text.count("\n") != 1:
        raise NetworkManagerTunCleanupError("invalid WatchdogVPN NetworkManager TUN ownership registry")
    value = text[:-1]
    if not _is_uuid(value) or value != str(UUID(value)):
        raise NetworkManagerTunCleanupError("invalid WatchdogVPN NetworkManager TUN ownership registry")
    return value


def _remove_owned_uuid_registry() -> None:
    parent_fd: int | None = None
    try:
        parent_fd = _open_directory(OWNED_UUIDS_PATH.parent)
        _validate_registry_parent_fd(parent_fd)
        os.unlink(OWNED_UUIDS_PATH.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise NetworkManagerTunCleanupError("cannot remove WatchdogVPN NetworkManager TUN ownership") from exc
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def _ensure_registry_parent() -> None:
    # Delegate creation and validation to the shared descriptor-relative
    # primitive. Callers re-open the parent with O_NOFOLLOW before reading,
    # writing or removing owned-uuid, so a swap performed after this returns is
    # rejected instead of followed.
    child_fd: int | None = None
    try:
        child_fd = privileged_state.open_state_directory(
            OWNED_UUIDS_PATH.parent,
            uid=EXPECTED_REGISTRY_UID,
            gid=EXPECTED_REGISTRY_GID,
            directory_mode=EXPECTED_REGISTRY_DIR_MODE,
        )
    except privileged_state.PrivilegedStateError as exc:
        raise NetworkManagerTunCleanupError(
            "unsafe WatchdogVPN NetworkManager TUN ownership directory"
        ) from exc
    finally:
        if child_fd is not None:
            os.close(child_fd)


def _open_directory(directory: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(directory, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise NetworkManagerTunCleanupError("cannot inspect WatchdogVPN NetworkManager TUN ownership directory") from exc


def _validate_registry_parent_fd(parent_fd: int) -> None:
    parent_stat = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise NetworkManagerTunCleanupError("unsafe WatchdogVPN NetworkManager TUN ownership directory")
    if (
        parent_stat.st_uid != EXPECTED_REGISTRY_UID
        or parent_stat.st_gid != EXPECTED_REGISTRY_GID
        or stat.S_IMODE(parent_stat.st_mode) != EXPECTED_REGISTRY_DIR_MODE
    ):
        raise NetworkManagerTunCleanupError("unsafe WatchdogVPN NetworkManager TUN ownership directory")


def _validate_registry_file_stat(path_stat: os.stat_result) -> None:
    if not stat.S_ISREG(path_stat.st_mode):
        raise NetworkManagerTunCleanupError("unsafe WatchdogVPN NetworkManager TUN ownership registry")
    if (
        path_stat.st_uid != EXPECTED_REGISTRY_UID
        or path_stat.st_gid != EXPECTED_REGISTRY_GID
        or stat.S_IMODE(path_stat.st_mode) != EXPECTED_REGISTRY_FILE_MODE
    ):
        raise NetworkManagerTunCleanupError("unsafe WatchdogVPN NetworkManager TUN ownership registry")


def _run_nmcli(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetworkManagerTunCleanupError("NetworkManager TUN cleanup failed") from exc
    if completed.returncode != 0:
        raise NetworkManagerTunCleanupError("NetworkManager TUN cleanup failed")
    return completed


def _is_uuid(value: str) -> bool:
    try:
        return str(UUID(value)) == value.lower()
    except ValueError:
        return False


def main() -> int:
    try:
        mode = sys.argv[1] if len(sys.argv) > 1 else Path(sys.argv[0]).name
        if mode == "register" or mode.endswith("register"):
            # A register helper that cannot confirm NetworkManager adoption must
            # exit non-zero: its caller (the sing-box driver via systemd) treats
            # exit 0 as "ownership recorded" and would otherwise proceed with an
            # unprotected NetworkManager-managed TUN.
            if not record_active_tun_connection():
                return 1
        elif mode == "cleanup" or mode.endswith("cleanup"):
            # An unresolved cleanup (no authority but a product-shaped residual
            # profile) must not be reported as success: the caller would then
            # treat a possibly-unclean teardown as done.
            if not remove_stale_tun_connections():
                return 1
        elif mode == "migrate" or mode.endswith("migrate"):
            # Installer-only step: promote a trusted legacy /run registry into
            # the durable authority. A no-op (absent/unsafe/none) is success;
            # only a failed write surfaces as an error so the upgrade fails
            # loudly instead of silently losing cleanup authority.
            migrate_legacy_owned_uuid_registry()
        else:
            raise NetworkManagerTunCleanupError("unknown NetworkManager TUN helper mode")
    except NetworkManagerTunCleanupError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
