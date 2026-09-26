from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from config.paths import resolve_config_dir


SNAPSHOT_DIRECTORY = Path("/var/lib/watchdogvpn/nm-dns-restore")
SNAPSHOT_PATH = SNAPSHOT_DIRECTORY / "snapshot.json"
SNAPSHOT_VERSION = 1
DNS_PROPERTIES = (
    "ipv4.ignore-auto-dns",
    "ipv4.dns",
    "ipv6.ignore-auto-dns",
    "ipv6.dns",
)
LEGACY_SNAPSHOT_ENV = "WATCHDOGVPN_NM_DNS_RESTORE_LEGACY"
LEGACY_SNAPSHOT_NAME = "dns-state.json"
NETWORK_MANAGER_VALUE = "networkmanager"
# The legacy runtime snapshot stores connection DNS under underscore keys; the
# root snapshot uses the NetworkManager property spelling.
LEGACY_DNS_FIELDS = {
    "ipv4.ignore-auto-dns": "ipv4_ignore_auto_dns",
    "ipv4.dns": "ipv4_dns",
    "ipv6.ignore-auto-dns": "ipv6_ignore_auto_dns",
    "ipv6.dns": "ipv6_dns",
}


class NetworkManagerRestoreError(RuntimeError):
    pass


def root_snapshot_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_NM_DNS_RESTORE_SNAPSHOT")
    return Path(override) if override else SNAPSHOT_PATH


def root_snapshot_exists() -> bool:
    try:
        os.lstat(root_snapshot_path())
    except FileNotFoundError:
        return False
    except OSError:
        return False
    return True


def legacy_snapshot_path() -> Path:
    """The runtime DNS snapshot that predates the root-only restore authority."""
    override = os.environ.get(LEGACY_SNAPSHOT_ENV)
    if override:
        return Path(override)
    return resolve_config_dir() / LEGACY_SNAPSHOT_NAME


def save_root_snapshot(connections: list[dict[str, str]]) -> None:
    """Persist the DNS-only restore authority before a root DNS apply."""
    if os.geteuid() != 0:
        raise NetworkManagerRestoreError("root is required to save the NetworkManager DNS restore snapshot")
    payload = {"version": SNAPSHOT_VERSION, "connections": connections}
    _validate_snapshot(payload)
    path = root_snapshot_path()
    if not path.parent.exists():
        path.parent.mkdir(mode=0o700, parents=True)
    _validate_metadata(os.lstat(path.parent), path.parent, 0o700, directory=True)
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def restore_root_snapshot() -> bool:
    """Restore the root snapshot, falling back to validated legacy state.

    The root-only snapshot is the primary authority. When it is absent (for
    example on an install upgraded from before the root helper existed) a valid
    legacy runtime snapshot is used instead, but only when it is trustworthy:
    root-owned and not writable by group or others, so the unprivileged daemon
    cannot forge the DNS values that this root helper would apply. Exactly one
    restore path runs, and an absent, corrupt or untrusted snapshot produces an
    actionable error without mutating DNS.
    """
    path = root_snapshot_path()
    if root_snapshot_exists():
        payload = _load_validated_snapshot(path)
        _restore_connections(payload["connections"])
        path.unlink()
        _fsync_directory(path.parent)
        return True
    connections = _load_legacy_connections(legacy_snapshot_path(), require_trusted=True)
    _restore_connections(connections)
    return True


def migrate_legacy_snapshot() -> bool:
    """Promote a legacy runtime snapshot into the root-only restore authority.

    Run by the installer as root so a pre-existing install keeps its restore
    ability across an upgrade. It never overwrites an existing root snapshot and
    never mutates live DNS; it only materialises the durable authority from the
    already recorded legacy state.
    """
    if os.geteuid() != 0:
        raise NetworkManagerRestoreError(
            "root is required to migrate the NetworkManager DNS restore snapshot"
        )
    if root_snapshot_exists():
        return False
    try:
        connections = _load_legacy_connections(legacy_snapshot_path(), require_trusted=False)
    except NetworkManagerRestoreError:
        return False
    save_root_snapshot(connections)
    return True


def _restore_connections(connections: list[dict[str, str]]) -> None:
    for connection in connections:
        _run_nmcli(connection)


def _load_legacy_connections(path: Path, *, require_trusted: bool) -> list[dict[str, str]]:
    metadata = _load_legacy_metadata(path)
    if require_trusted and not _legacy_snapshot_is_trusted(metadata):
        raise NetworkManagerRestoreError(
            "legacy NetworkManager DNS restore snapshot is untrusted"
        )
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
            payload = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkManagerRestoreError(
            "invalid legacy NetworkManager DNS restore snapshot"
        ) from exc
    finally:
        os.close(descriptor)
    return _connections_from_runtime_snapshot(payload)


def _load_legacy_metadata(path: Path) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as exc:
        raise NetworkManagerRestoreError("NetworkManager DNS restore snapshot is absent") from exc
    except OSError as exc:
        raise NetworkManagerRestoreError(
            "cannot inspect the legacy NetworkManager DNS restore snapshot"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise NetworkManagerRestoreError(
            "invalid legacy NetworkManager DNS restore snapshot path"
        )
    return metadata


def _legacy_snapshot_is_trusted(metadata: os.stat_result) -> bool:
    # Integrity, not confidentiality: root owns the file and neither the group
    # nor others may write it, so the unprivileged daemon cannot change the DNS
    # values this root helper applies.
    return metadata.st_uid == 0 and (stat.S_IMODE(metadata.st_mode) & 0o022) == 0


def _connections_from_runtime_snapshot(payload: Any) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        raise NetworkManagerRestoreError("invalid legacy NetworkManager DNS restore snapshot")
    inventory = payload.get("inventory")
    if not isinstance(inventory, dict) or inventory.get("manager") != NETWORK_MANAGER_VALUE:
        raise NetworkManagerRestoreError("legacy NetworkManager DNS restore snapshot is not NetworkManager")
    raw_connections = payload.get("network_manager_connections")
    if not isinstance(raw_connections, list) or not raw_connections:
        raise NetworkManagerRestoreError("legacy NetworkManager DNS restore snapshot has no connections")
    connections: list[dict[str, str]] = []
    seen_uuids: set[str] = set()
    for item in raw_connections:
        if not isinstance(item, dict):
            raise NetworkManagerRestoreError("invalid legacy NetworkManager DNS restore snapshot")
        uuid = item.get("uuid")
        if not isinstance(uuid, str) or not _is_uuid(uuid) or uuid in seen_uuids:
            raise NetworkManagerRestoreError("legacy NetworkManager DNS restore snapshot contains an invalid connection UUID")
        seen_uuids.add(uuid)
        connection = {"uuid": uuid}
        for property_name in DNS_PROPERTIES:
            value = item.get(LEGACY_DNS_FIELDS[property_name])
            if not isinstance(value, str):
                raise NetworkManagerRestoreError("invalid legacy NetworkManager DNS restore snapshot")
            connection[property_name] = value
        if connection["ipv4.ignore-auto-dns"] not in {"yes", "no"} or connection["ipv6.ignore-auto-dns"] not in {"yes", "no"}:
            raise NetworkManagerRestoreError("invalid legacy NetworkManager DNS restore snapshot")
        connections.append(connection)
    return connections


def _load_validated_snapshot(path: Path) -> dict[str, Any]:
    _validate_snapshot_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        _validate_metadata(metadata, path, 0o600)
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
            payload = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkManagerRestoreError("invalid NetworkManager DNS restore snapshot") from exc
    finally:
        os.close(descriptor)
    _validate_snapshot(payload)
    return payload


def _validate_snapshot_path(path: Path) -> None:
    parent = path.parent
    try:
        _validate_metadata(os.lstat(parent), parent, 0o700, directory=True)
        _validate_metadata(os.lstat(path), path, 0o600)
    except OSError as exc:
        raise NetworkManagerRestoreError("invalid NetworkManager DNS restore snapshot path") from exc


def _validate_metadata(metadata: os.stat_result, path: Path, mode: int, directory: bool = False) -> None:
    required_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not required_type(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NetworkManagerRestoreError(f"unsafe NetworkManager DNS restore path: {path}")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        raise NetworkManagerRestoreError(f"unsafe NetworkManager DNS restore ownership or permissions: {path}")


def _validate_snapshot(payload: Any) -> None:
    if not isinstance(payload, dict) or set(payload) != {"version", "connections"}:
        raise NetworkManagerRestoreError("invalid NetworkManager DNS restore snapshot structure")
    if payload["version"] != SNAPSHOT_VERSION or not isinstance(payload["connections"], list) or not payload["connections"]:
        raise NetworkManagerRestoreError("invalid NetworkManager DNS restore snapshot structure")
    seen_uuids: set[str] = set()
    for connection in payload["connections"]:
        if not isinstance(connection, dict) or set(connection) != {"uuid", *DNS_PROPERTIES}:
            raise NetworkManagerRestoreError("NetworkManager restore snapshot contains non-DNS properties")
        uuid = connection["uuid"]
        if not isinstance(uuid, str) or not _is_uuid(uuid) or uuid in seen_uuids:
            raise NetworkManagerRestoreError("NetworkManager restore snapshot contains an invalid connection UUID")
        seen_uuids.add(uuid)
        for property_name in DNS_PROPERTIES:
            value = connection[property_name]
            if not isinstance(value, str):
                raise NetworkManagerRestoreError("NetworkManager restore snapshot contains invalid DNS values")
        if connection["ipv4.ignore-auto-dns"] not in {"yes", "no"} or connection["ipv6.ignore-auto-dns"] not in {"yes", "no"}:
            raise NetworkManagerRestoreError("NetworkManager restore snapshot contains invalid DNS values")


def _is_uuid(value: str) -> bool:
    parts = value.split("-")
    return [len(part) for part in parts] == [8, 4, 4, 4, 12] and all(
        all(character in "0123456789abcdefABCDEF" for character in part) for part in parts
    )


def _run_nmcli(connection: dict[str, str]) -> None:
    command = [
        "nmcli", "connection", "modify", "uuid", connection["uuid"],
        "ipv4.ignore-auto-dns", connection["ipv4.ignore-auto-dns"],
        "ipv4.dns", connection["ipv4.dns"],
        "ipv6.ignore-auto-dns", connection["ipv6.ignore-auto-dns"],
        "ipv6.dns", connection["ipv6.dns"],
    ]
    try:
        completed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetworkManagerRestoreError("NetworkManager DNS restore failed") from exc
    if completed.returncode != 0:
        raise NetworkManagerRestoreError("NetworkManager DNS restore failed")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "restore"
    try:
        if mode == "restore":
            restore_root_snapshot()
        elif mode == "migrate":
            migrate_legacy_snapshot()
        else:
            raise NetworkManagerRestoreError("unknown NetworkManager DNS restore helper mode")
    except NetworkManagerRestoreError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
