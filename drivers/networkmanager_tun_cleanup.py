from __future__ import annotations

import subprocess
from uuid import UUID


CONNECTION_NAME = "wdvpn-tun0"


class NetworkManagerTunCleanupError(RuntimeError):
    pass


def remove_stale_tun_connections() -> bool:
    """Remove every NetworkManager profile with the fixed WatchdogVPN TUN name."""
    listing = _run_nmcli([
        "nmcli", "--terse", "--fields", "UUID,NAME", "--escape", "no",
        "connection", "show",
    ])
    connection_uuids: list[str] = []
    for line in listing.stdout.splitlines():
        uuid, separator, name = line.partition(":")
        if separator and name == CONNECTION_NAME and _is_uuid(uuid):
            connection_uuids.append(uuid)

    for connection_uuid in connection_uuids:
        _run_nmcli(["nmcli", "connection", "delete", "uuid", connection_uuid])
    return bool(connection_uuids)


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
        remove_stale_tun_connections()
    except NetworkManagerTunCleanupError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
