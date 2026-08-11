from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from uuid import UUID


CONNECTION_NAME = "wdvpn-tun0"
CONNECTION_TYPE = "tun"
OWNED_UUIDS_PATH = Path("/run/watchdogvpn/networkmanager-tun-owned-uuids")
EXPECTED_REGISTRY_UID = 0
EXPECTED_REGISTRY_GID = 0


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
    try:
        OWNED_UUIDS_PATH.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        tmp_path = OWNED_UUIDS_PATH.with_name(f".{OWNED_UUIDS_PATH.name}.tmp")
        tmp_path.write_text(f"{connection_uuid}\n", encoding="ascii")
        tmp_path.chmod(0o600)
        tmp_path.replace(OWNED_UUIDS_PATH)
    except OSError as exc:
        raise NetworkManagerTunCleanupError("cannot record WatchdogVPN NetworkManager TUN ownership") from exc


def _read_owned_uuid_registry() -> str | None:
    try:
        path_stat = OWNED_UUIDS_PATH.stat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise NetworkManagerTunCleanupError("cannot inspect WatchdogVPN NetworkManager TUN ownership") from exc
    if (
        path_stat.st_uid != EXPECTED_REGISTRY_UID
        or path_stat.st_gid != EXPECTED_REGISTRY_GID
        or path_stat.st_mode & 0o177
    ):
        raise NetworkManagerTunCleanupError("unsafe WatchdogVPN NetworkManager TUN ownership registry")
    try:
        value = OWNED_UUIDS_PATH.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise NetworkManagerTunCleanupError("cannot read WatchdogVPN NetworkManager TUN ownership") from exc
    if not _is_uuid(value):
        raise NetworkManagerTunCleanupError("invalid WatchdogVPN NetworkManager TUN ownership registry")
    return value


def _remove_owned_uuid_registry() -> None:
    try:
        OWNED_UUIDS_PATH.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise NetworkManagerTunCleanupError("cannot remove WatchdogVPN NetworkManager TUN ownership") from exc


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
