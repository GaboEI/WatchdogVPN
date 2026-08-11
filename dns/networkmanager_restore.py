from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any


SNAPSHOT_DIRECTORY = Path("/var/lib/watchdogvpn/nm-dns-restore")
SNAPSHOT_PATH = SNAPSHOT_DIRECTORY / "snapshot.json"
SNAPSHOT_VERSION = 1
DNS_PROPERTIES = (
    "ipv4.ignore-auto-dns",
    "ipv4.dns",
    "ipv6.ignore-auto-dns",
    "ipv6.dns",
)


class NetworkManagerRestoreError(RuntimeError):
    pass


def root_snapshot_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_NM_DNS_RESTORE_SNAPSHOT")
    return Path(override) if override else SNAPSHOT_PATH


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
    """Restore an immutable root snapshot, or do nothing when none exists."""
    path = root_snapshot_path()
    try:
        os.lstat(path)
    except FileNotFoundError:
        raise NetworkManagerRestoreError("NetworkManager DNS restore snapshot is absent")
    payload = _load_validated_snapshot(path)
    for connection in payload["connections"]:
        _run_nmcli(connection)
    path.unlink()
    _fsync_directory(path.parent)
    return True


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
    try:
        restore_root_snapshot()
    except NetworkManagerRestoreError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
