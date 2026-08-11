from __future__ import annotations

import subprocess
import tempfile
import unittest
import os
from pathlib import Path
from unittest.mock import patch

from drivers.networkmanager_tun_cleanup import (
    NetworkManagerTunCleanupError,
    record_active_tun_connection,
    remove_stale_tun_connections,
)


UUID_ONE = "11111111-1111-1111-1111-111111111111"
UUID_TWO = "22222222-2222-2222-2222-222222222222"


class NetworkManagerTunCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.registry_path = Path(self.tmpdir.name) / "owned-uuids"

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_absent_registry_is_an_idempotent_success_without_nm_mutation(self) -> None:
        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            self.assertFalse(remove_stale_tun_connections())

        self.assertEqual(run.call_count, 0)

    def test_records_active_fixed_tun_identity(self) -> None:
        listing = "\n".join((
            f"{UUID_ONE}:wdvpn-tun0:tun:wdvpn-tun0",
            f"{UUID_TWO}:wdvpn-tun0:tun:other0",
        ))

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
            self.assertTrue(record_active_tun_connection())

        self.assertEqual(self.registry_path.read_text(encoding="ascii"), f"{UUID_ONE}\n")
        self.assertEqual(self.registry_path.stat().st_mode & 0o777, 0o600)

    def test_deletes_only_registered_fixed_tun_uuid(self) -> None:
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o600)
        listing = "\n".join((
            f"{UUID_ONE}:wdvpn-tun0:tun",
            f"{UUID_TWO}:wdvpn-tun0:tun",
            "not-a-uuid:wdvpn-tun0:tun",
        ))

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout=listing, stderr=""),
                subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ]
            self.assertTrue(remove_stale_tun_connections())

        self.assertEqual(
            run.call_args_list[1].args[0],
            ["nmcli", "connection", "delete", "uuid", UUID_ONE],
        )
        self.assertFalse(self.registry_path.exists())

    def test_registered_uuid_is_not_deleted_if_identity_no_longer_matches(self) -> None:
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o600)
        listing = "\n".join((
            f"{UUID_ONE}:Home:tun",
            f"{UUID_TWO}:wdvpn-tun0:tun",
        ))

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
            self.assertFalse(remove_stale_tun_connections())

        self.assertEqual(run.call_count, 1)
        self.assertFalse(self.registry_path.exists())

    def test_foreign_same_name_is_not_deleted_without_registered_identity(self) -> None:
        listing = f"{UUID_ONE}:wdvpn-tun0:tun\n"

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
            self.assertFalse(remove_stale_tun_connections())

        self.assertEqual(run.call_count, 0)

    def test_unsafe_registry_is_rejected(self) -> None:
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o644)

        with self._patched_registry():
            with self.assertRaises(NetworkManagerTunCleanupError):
                remove_stale_tun_connections()

    def test_listing_or_delete_failure_is_not_reported_as_clean(self) -> None:
        for side_effect in (
            [subprocess.CompletedProcess([], 1, stdout="", stderr="denied")],
            [
                subprocess.CompletedProcess([], 0, stdout=f"{UUID_ONE}:wdvpn-tun0:tun\n", stderr=""),
                subprocess.CompletedProcess([], 1, stdout="", stderr="failed"),
            ],
        ):
            self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
            self.registry_path.chmod(0o600)
            with self.subTest(side_effect=side_effect), patch(
                "drivers.networkmanager_tun_cleanup.OWNED_UUIDS_PATH", self.registry_path
            ), patch("drivers.networkmanager_tun_cleanup.EXPECTED_REGISTRY_UID", os.getuid()), patch(
                "drivers.networkmanager_tun_cleanup.EXPECTED_REGISTRY_GID", os.getgid()
            ), patch(
                "drivers.networkmanager_tun_cleanup.subprocess.run", side_effect=side_effect
            ), self.assertRaises(NetworkManagerTunCleanupError):
                remove_stale_tun_connections()

    def _patched_registry(self):
        return patch.multiple(
            "drivers.networkmanager_tun_cleanup",
            OWNED_UUIDS_PATH=self.registry_path,
            EXPECTED_REGISTRY_UID=os.getuid(),
            EXPECTED_REGISTRY_GID=os.getgid(),
        )


if __name__ == "__main__":
    unittest.main()
