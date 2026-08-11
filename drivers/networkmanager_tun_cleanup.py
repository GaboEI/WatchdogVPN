from __future__ import annotations

import subprocess
import sys
import os
import secrets
import stat
from pathlib import Path
from uuid import UUID


CONNECTION_NAME = "wdvpn-tun0"
CONNECTION_TYPE = "tun"
OWNED_UUIDS_PATH = Path("/run/watchdogvpn-nm-tun/owned-uuid")
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
        raise NetworkManagerTunCleanupError("ambiguous WatchdogVPN NetworkManager TUN ownership")
    if not connection_uuids:
        _remove_owned_uuid_registry()
        return False
    _write_owned_uuid_registry(connection_uuids[0])
    return True


def remove_stale_tun_connections() -> bool:
    """Remove only the NetworkManager profile identity previously registered by WatchdogVPN."""
    owned_uuid = _read_owned_uuid_registry()
    if owned_uuid is None:
        return False

    listing = _run_nmcli([
        "nmcli", "--terse", "--fields", "UUID,NAME,TYPE", "--escape", "no",
        "connection", "show",
    ])
    connection_uuids: list[str] = []
    for uuid, name, connection_type, _device in _parse_connection_rows(listing.stdout):
        if uuid == owned_uuid and name == CONNECTION_NAME and connection_type == CONNECTION_TYPE:
            connection_uuids.append(uuid)

    if len(connection_uuids) > 1:
        raise NetworkManagerTunCleanupError("ambiguous WatchdogVPN NetworkManager TUN cleanup target")

    for connection_uuid in connection_uuids:
        _run_nmcli(["nmcli", "connection", "delete", "uuid", connection_uuid])
    _remove_owned_uuid_registry()
    return bool(connection_uuids)


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


def _write_owned_uuid_registry(connection_uuid: str) -> None:
    if not _is_uuid(connection_uuid):
        raise NetworkManagerTunCleanupError("invalid WatchdogVPN NetworkManager TUN UUID")
    parent_fd: int | None = None
    tmp_name: str | None = None
    try:
        _ensure_registry_parent()
        parent_fd = _open_registry_parent()
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
        os.rename(tmp_name, OWNED_UUIDS_PATH.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        tmp_name = None
        os.fsync(parent_fd)
        _read_owned_uuid_registry()
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


def _read_owned_uuid_registry() -> str | None:
    parent_fd: int | None = None
    file_fd: int | None = None
    try:
        parent_fd = _open_registry_parent()
        file_fd = os.open(
            OWNED_UUIDS_PATH.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
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
        value = b"".join(chunks).decode("ascii").strip()
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


def _remove_owned_uuid_registry() -> None:
    parent_fd: int | None = None
    try:
        parent_fd = _open_registry_parent()
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
    try:
        try:
            parent_stat = OWNED_UUIDS_PATH.parent.lstat()
        except FileNotFoundError:
            OWNED_UUIDS_PATH.parent.mkdir(mode=EXPECTED_REGISTRY_DIR_MODE, parents=True, exist_ok=False)
        else:
            if not stat.S_ISDIR(parent_stat.st_mode):
                raise NetworkManagerTunCleanupError("unsafe WatchdogVPN NetworkManager TUN ownership directory")
    except OSError as exc:
        raise NetworkManagerTunCleanupError("cannot prepare WatchdogVPN NetworkManager TUN ownership directory") from exc


def _open_registry_parent() -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(OWNED_UUIDS_PATH.parent, flags)
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
        if Path(sys.argv[0]).name.endswith("register"):
            record_active_tun_connection()
        else:
            remove_stale_tun_connections()
    except NetworkManagerTunCleanupError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
