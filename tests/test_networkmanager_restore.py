from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dns.networkmanager_restore import (
    NetworkManagerRestoreError,
    _load_validated_snapshot,
    _validate_metadata,
    _validate_snapshot,
)


UUID = "11111111-1111-1111-1111-111111111111"


def snapshot(connection: dict[str, str] | None = None) -> dict[str, object]:
    return {
        "version": 1,
        "connections": [connection or {
            "uuid": UUID,
            "ipv4.ignore-auto-dns": "no",
            "ipv4.dns": "192.0.2.53",
            "ipv6.ignore-auto-dns": "yes",
            "ipv6.dns": "2001:db8::53",
        }],
    }


class NetworkManagerRestoreTests(unittest.TestCase):
    def test_only_dns_properties_and_uuid_are_accepted(self) -> None:
        for forbidden in ("connection.uuid", "ipv4.gateway", "ipv4.routes", "proxy.method", "ipv4.dns-search", "connection.id"):
            payload = snapshot()
            payload["connections"][0][forbidden] = "attacker-value"  # type: ignore[index]
            with self.subTest(forbidden=forbidden), self.assertRaisesRegex(NetworkManagerRestoreError, "non-DNS"):
                _validate_snapshot(payload)

    def test_rejects_invalid_or_missing_connection_uuid(self) -> None:
        for value in ("", "not-a-uuid", "11111111-1111-1111-1111-11111111111g"):
            payload = snapshot()
            payload["connections"][0]["uuid"] = value  # type: ignore[index]
            with self.subTest(value=value), self.assertRaises(NetworkManagerRestoreError):
                _validate_snapshot(payload)

    def test_rejects_non_string_dns_values_and_invalid_flags(self) -> None:
        for property_name, value in (("ipv4.dns", ["192.0.2.53"]), ("ipv6.ignore-auto-dns", "maybe")):
            payload = snapshot()
            payload["connections"][0][property_name] = value  # type: ignore[index]
            with self.subTest(property_name=property_name), self.assertRaises(NetworkManagerRestoreError):
                _validate_snapshot(payload)

    def test_root_snapshot_rejects_symlink_permissions_and_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            path = state_dir / "snapshot.json"
            path.write_text(json.dumps(snapshot()), encoding="utf-8")
            path.chmod(0o600)
            for setup in (
                lambda: path.chmod(0o644),
                lambda: (path.chmod(0o600), state_dir.chmod(0o755)),
                lambda: (state_dir.chmod(0o700), path.unlink(), path.symlink_to(root / "target")),
            ):
                setup()
                with self.subTest(setup=setup), self.assertRaises(NetworkManagerRestoreError):
                    _load_validated_snapshot(path)
                if path.is_symlink():
                    path.unlink()
                    path.write_text(json.dumps(snapshot()), encoding="utf-8")
                    path.chmod(0o600)
                state_dir.chmod(0o700)

    def test_metadata_validation_rejects_each_root_only_invariant(self) -> None:
        valid = os.stat_result((stat.S_IFREG | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        _validate_metadata(valid, Path("/snapshot.json"), 0o600)
        for mode, uid, gid in (
            (stat.S_IFREG | 0o644, 0, 0),
            (stat.S_IFREG | 0o600, 1000, 0),
            (stat.S_IFREG | 0o600, 0, 1000),
            (stat.S_IFLNK | 0o777, 0, 0),
        ):
            metadata = os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))
            with self.subTest(mode=mode, uid=uid, gid=gid), self.assertRaises(NetworkManagerRestoreError):
                _validate_metadata(metadata, Path("/snapshot.json"), 0o600)

    def test_restore_command_has_no_route_gateway_proxy_or_dns_search_arguments(self) -> None:
        payload = snapshot()
        with patch("dns.networkmanager_restore.subprocess.run") as run:
            from dns.networkmanager_restore import _run_nmcli

            run.return_value.returncode = 0
            _run_nmcli(payload["connections"][0])  # type: ignore[arg-type,index]
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["nmcli", "connection", "modify", "uuid", UUID])
        self.assertEqual(command[5::2], ["ipv4.ignore-auto-dns", "ipv4.dns", "ipv6.ignore-auto-dns", "ipv6.dns"])
        self.assertFalse(any(token in " ".join(command) for token in ("gateway", "route", "proxy", "dns-search", "connection.id")))


if __name__ == "__main__":
    unittest.main()
