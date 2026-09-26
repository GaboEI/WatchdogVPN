from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dns.networkmanager_restore as nm_restore
from dns.networkmanager_restore import (
    NetworkManagerRestoreError,
    _hardened_root_directory,
    _legacy_snapshot_is_trusted,
    _load_validated_snapshot,
    _validate_metadata,
    _validate_snapshot,
    migrate_legacy_snapshot,
    restore_root_snapshot,
)


UUID = "11111111-1111-1111-1111-111111111111"


def legacy_runtime_payload() -> dict[str, object]:
    return {
        "inventory": {"manager": "networkmanager"},
        "network_manager_connections": [
            {
                "name": "Home",
                "uuid": UUID,
                "ipv4_dns": "192.0.2.53",
                "ipv4_ignore_auto_dns": "no",
                "ipv6_dns": "2001:db8::53",
                "ipv6_ignore_auto_dns": "yes",
            }
        ],
    }


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


    def test_hardened_root_directory_clears_inherited_setgid(self) -> None:
        # The snapshot directory is created under the setgid shared state
        # directory; it must end up exactly 0700 or the root-only validation
        # rejects it. Same defect class as the NetworkManager TUN registry.
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "nm-dns-restore"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o2770)
            _hardened_root_directory(state)
            self.assertEqual(state.stat().st_mode & 0o7777, 0o700)

    def test_legacy_snapshot_trust_requires_root_and_no_group_or_other_write(self) -> None:
        def stat_result(mode: int, uid: int) -> os.stat_result:
            return os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))

        self.assertTrue(_legacy_snapshot_is_trusted(stat_result(stat.S_IFREG | 0o644, 0)))
        self.assertFalse(_legacy_snapshot_is_trusted(stat_result(stat.S_IFREG | 0o660, 0)))
        self.assertFalse(_legacy_snapshot_is_trusted(stat_result(stat.S_IFREG | 0o606, 0)))
        self.assertFalse(_legacy_snapshot_is_trusted(stat_result(stat.S_IFREG | 0o600, 1000)))

    def test_restore_falls_back_to_trusted_legacy_snapshot(self) -> None:
        # T-PR23-06: a missing root snapshot plus a valid legacy NetworkManager
        # snapshot must still restore DNS, using only the already-validated state.
        with tempfile.TemporaryDirectory() as tmp:
            legacy = Path(tmp) / "dns-state.json"
            legacy.write_text(json.dumps(legacy_runtime_payload()), encoding="utf-8")
            with patch.object(nm_restore, "root_snapshot_exists", return_value=False), patch.object(
                nm_restore, "legacy_snapshot_path", return_value=legacy
            ), patch.object(nm_restore, "_legacy_snapshot_is_trusted", return_value=True), patch(
                "dns.networkmanager_restore.subprocess.run"
            ) as run:
                run.return_value.returncode = 0
                self.assertTrue(restore_root_snapshot())

        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["nmcli", "connection", "modify", "uuid", UUID])
        self.assertEqual(
            command[5::2],
            ["ipv4.ignore-auto-dns", "ipv4.dns", "ipv6.ignore-auto-dns", "ipv6.dns"],
        )
        self.assertIn("192.0.2.53", command)
        self.assertFalse(any(token in " ".join(command) for token in ("gateway", "route", "proxy", "dns-search")))

    def test_restore_refuses_untrusted_legacy_snapshot_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            legacy = Path(tmp) / "dns-state.json"
            legacy.write_text(json.dumps(legacy_runtime_payload()), encoding="utf-8")
            with patch.object(nm_restore, "root_snapshot_exists", return_value=False), patch.object(
                nm_restore, "legacy_snapshot_path", return_value=legacy
            ), patch.object(nm_restore, "_legacy_snapshot_is_trusted", return_value=False), patch(
                "dns.networkmanager_restore.subprocess.run"
            ) as run:
                with self.assertRaisesRegex(NetworkManagerRestoreError, "untrusted"):
                    restore_root_snapshot()

        run.assert_not_called()

    def test_restore_reports_absent_snapshot_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            with patch.object(nm_restore, "root_snapshot_exists", return_value=False), patch.object(
                nm_restore, "legacy_snapshot_path", return_value=missing
            ), patch("dns.networkmanager_restore.subprocess.run") as run:
                with self.assertRaisesRegex(NetworkManagerRestoreError, "absent"):
                    restore_root_snapshot()

        run.assert_not_called()

    def test_restore_rejects_corrupt_legacy_snapshot_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            legacy = Path(tmp) / "dns-state.json"
            legacy.write_text("not valid json", encoding="utf-8")
            with patch.object(nm_restore, "root_snapshot_exists", return_value=False), patch.object(
                nm_restore, "legacy_snapshot_path", return_value=legacy
            ), patch.object(nm_restore, "_legacy_snapshot_is_trusted", return_value=True), patch(
                "dns.networkmanager_restore.subprocess.run"
            ) as run:
                with self.assertRaises(NetworkManagerRestoreError):
                    restore_root_snapshot()

        run.assert_not_called()

    def test_restore_rejects_non_networkmanager_legacy_snapshot(self) -> None:
        payload = legacy_runtime_payload()
        payload["inventory"] = {"manager": "systemd-resolved"}  # type: ignore[assignment]
        with tempfile.TemporaryDirectory() as tmp:
            legacy = Path(tmp) / "dns-state.json"
            legacy.write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(nm_restore, "root_snapshot_exists", return_value=False), patch.object(
                nm_restore, "legacy_snapshot_path", return_value=legacy
            ), patch.object(nm_restore, "_legacy_snapshot_is_trusted", return_value=True), patch(
                "dns.networkmanager_restore.subprocess.run"
            ) as run:
                with self.assertRaises(NetworkManagerRestoreError):
                    restore_root_snapshot()

        run.assert_not_called()

    def test_migrate_promotes_legacy_snapshot_into_root_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            legacy = Path(tmp) / "dns-state.json"
            legacy.write_text(json.dumps(legacy_runtime_payload()), encoding="utf-8")
            with patch.object(nm_restore.os, "geteuid", return_value=0), patch.object(
                nm_restore, "root_snapshot_exists", return_value=False
            ), patch.object(
                nm_restore, "legacy_snapshot_path", return_value=legacy
            ), patch.object(nm_restore, "save_root_snapshot") as save:
                self.assertTrue(migrate_legacy_snapshot())

        save.assert_called_once()
        connections = save.call_args.args[0]
        self.assertEqual(
            connections,
            [{
                "uuid": UUID,
                "ipv4.ignore-auto-dns": "no",
                "ipv4.dns": "192.0.2.53",
                "ipv6.ignore-auto-dns": "yes",
                "ipv6.dns": "2001:db8::53",
            }],
        )

    def test_migrate_is_a_noop_when_root_snapshot_exists(self) -> None:
        with patch.object(nm_restore.os, "geteuid", return_value=0), patch.object(
            nm_restore, "root_snapshot_exists", return_value=True
        ), patch.object(nm_restore, "save_root_snapshot") as save:
            self.assertFalse(migrate_legacy_snapshot())

        save.assert_not_called()

    def test_main_dispatches_restore_and_migrate_modes(self) -> None:
        with patch.object(nm_restore.sys, "argv", ["wrapper", "migrate"]), patch.object(
            nm_restore, "migrate_legacy_snapshot", return_value=True
        ) as migrate, patch.object(nm_restore, "restore_root_snapshot") as restore:
            self.assertEqual(nm_restore.main(), 0)
        migrate.assert_called_once_with()
        restore.assert_not_called()

        with patch.object(nm_restore.sys, "argv", ["wrapper"]), patch.object(
            nm_restore, "restore_root_snapshot", side_effect=NetworkManagerRestoreError("absent")
        ):
            self.assertEqual(nm_restore.main(), 1)

        with patch.object(nm_restore.sys, "argv", ["wrapper", "unexpected"]):
            self.assertEqual(nm_restore.main(), 1)


if __name__ == "__main__":
    unittest.main()
