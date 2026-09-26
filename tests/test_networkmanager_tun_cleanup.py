from __future__ import annotations

import subprocess
import tempfile
import unittest
import os
from pathlib import Path
from unittest.mock import patch

import drivers.networkmanager_tun_cleanup as nm_tun_cleanup
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
        self.registry_dir = Path(self.tmpdir.name) / "root-owned-registry"
        self.registry_path = self.registry_dir / "owned-uuids"

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
        self.assertEqual(self.registry_path.parent.stat().st_mode & 0o777, 0o700)

    def test_deletes_only_registered_fixed_tun_uuid(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
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
        self.registry_dir.mkdir(mode=0o700)
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
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o644)

        with self._patched_registry():
            with self.assertRaises(NetworkManagerTunCleanupError):
                remove_stale_tun_connections()

    def test_parent_writable_by_daemon_is_rejected(self) -> None:
        self.registry_dir.mkdir(mode=0o770)
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o600)

        with self._patched_registry():
            with self.assertRaises(NetworkManagerTunCleanupError):
                remove_stale_tun_connections()

    def test_parent_with_unexpected_owner_is_rejected(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o600)

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.EXPECTED_REGISTRY_UID", os.getuid() + 1
        ):
            with self.assertRaises(NetworkManagerTunCleanupError):
                remove_stale_tun_connections()

    def test_parent_symlink_is_rejected(self) -> None:
        target_dir = Path(self.tmpdir.name) / "target"
        target_dir.mkdir(mode=0o700)
        self.registry_dir.symlink_to(target_dir, target_is_directory=True)

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess(
                [], 0, stdout=f"{UUID_ONE}:wdvpn-tun0:tun:wdvpn-tun0\n", stderr=""
            )
            with self.assertRaises(NetworkManagerTunCleanupError):
                record_active_tun_connection()

    def test_registry_symlink_is_rejected(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
        target_file = Path(self.tmpdir.name) / "target-file"
        target_file.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.symlink_to(target_file)

        with self._patched_registry():
            with self.assertRaises(NetworkManagerTunCleanupError):
                remove_stale_tun_connections()

    def test_precreated_temp_symlink_is_not_followed(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
        target_file = Path(self.tmpdir.name) / "target-file"
        target_file.write_text("do-not-touch\n", encoding="ascii")
        (self.registry_dir / f".{self.registry_path.name}.1234.deadbeefdeadbeef.tmp").symlink_to(target_file)

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.os.getpid", return_value=1234
        ), patch(
            "drivers.networkmanager_tun_cleanup.secrets.token_hex", side_effect=["deadbeefdeadbeef", "feedfacefeedface"]
        ), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess(
                [], 0, stdout=f"{UUID_ONE}:wdvpn-tun0:tun:wdvpn-tun0\n", stderr=""
            )
            self.assertTrue(record_active_tun_connection())

        self.assertEqual(target_file.read_text(encoding="ascii"), "do-not-touch\n")
        self.assertEqual(self.registry_path.read_text(encoding="ascii"), f"{UUID_ONE}\n")

    def test_main_dispatches_explicit_register_mode(self) -> None:
        with patch.object(nm_tun_cleanup.sys, "argv", ["python-module-wrapper", "register"]), patch(
            "drivers.networkmanager_tun_cleanup.record_active_tun_connection", return_value=True
        ) as register, patch(
            "drivers.networkmanager_tun_cleanup.remove_stale_tun_connections"
        ) as cleanup:
            self.assertEqual(nm_tun_cleanup.main(), 0)

        register.assert_called_once_with()
        cleanup.assert_not_called()

    def test_main_dispatches_explicit_cleanup_mode(self) -> None:
        with patch.object(nm_tun_cleanup.sys, "argv", ["python-module-wrapper", "cleanup"]), patch(
            "drivers.networkmanager_tun_cleanup.record_active_tun_connection"
        ) as register, patch(
            "drivers.networkmanager_tun_cleanup.remove_stale_tun_connections", return_value=False
        ) as cleanup:
            self.assertEqual(nm_tun_cleanup.main(), 0)

        register.assert_not_called()
        cleanup.assert_called_once_with()

    def test_main_rejects_unknown_explicit_mode(self) -> None:
        with patch.object(nm_tun_cleanup.sys, "argv", ["python-module-wrapper", "unexpected"]):
            self.assertEqual(nm_tun_cleanup.main(), 1)

    def test_listing_or_delete_failure_is_not_reported_as_clean(self) -> None:
        for side_effect in (
            [subprocess.CompletedProcess([], 1, stdout="", stderr="denied")],
            [
                subprocess.CompletedProcess([], 0, stdout=f"{UUID_ONE}:wdvpn-tun0:tun\n", stderr=""),
                subprocess.CompletedProcess([], 1, stdout="", stderr="failed"),
            ],
        ):
            self.registry_dir.mkdir(mode=0o700, exist_ok=True)
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

    def test_main_register_without_adoption_exits_nonzero_without_registry(self) -> None:
        # T-PR23-12: a helper that could not confirm NetworkManager adoption
        # must not report success, and must not create or keep a registry.
        with self._patched_registry(), patch.object(
            nm_tun_cleanup.sys, "argv", ["python-module-wrapper", "register"]
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            self.assertEqual(nm_tun_cleanup.main(), 1)

        self.assertFalse(self.registry_path.exists())

    def test_main_register_with_confirmed_adoption_exits_zero_and_records(self) -> None:
        listing = f"{UUID_ONE}:wdvpn-tun0:tun:wdvpn-tun0\n"

        with self._patched_registry(), patch.object(
            nm_tun_cleanup.sys, "argv", ["python-module-wrapper", "register"]
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
            self.assertEqual(nm_tun_cleanup.main(), 0)

        self.assertEqual(self.registry_path.read_text(encoding="ascii"), f"{UUID_ONE}\n")

    def test_ambiguous_adoption_fails_closed_and_drops_registry(self) -> None:
        listing = "\n".join((
            f"{UUID_ONE}:wdvpn-tun0:tun:wdvpn-tun0",
            f"{UUID_TWO}:wdvpn-tun0:tun:wdvpn-tun0",
        ))
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o600)

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
            with self.assertRaises(NetworkManagerTunCleanupError):
                record_active_tun_connection()

        self.assertFalse(self.registry_path.exists())
        self.assertFalse(
            any("delete" in call.args[0] for call in run.call_args_list)
        )

    def test_corrupt_registry_is_rejected_without_any_nm_delete(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text("not-a-uuid\n", encoding="ascii")
        self.registry_path.chmod(0o600)

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            with self.assertRaises(NetworkManagerTunCleanupError):
                remove_stale_tun_connections()

        self.assertEqual(run.call_count, 0)

    def test_delete_failure_preserves_registry_for_retry(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o600)
        listing = f"{UUID_ONE}:wdvpn-tun0:tun\n"

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout=listing, stderr=""),
                subprocess.CompletedProcess([], 1, stdout="", stderr="failed"),
            ]
            with self.assertRaises(NetworkManagerTunCleanupError):
                remove_stale_tun_connections()

        self.assertTrue(self.registry_path.exists())

    def test_created_registry_parent_clears_inherited_setgid(self) -> None:
        # The shared state directory is setgid (2770), so a subdirectory created
        # under it inherits the group and the setgid bit. The registry directory
        # must end up exactly root-owned 0700 or the cleanup path rightly refuses
        # it. Reproduced on the real nls1 host.
        base = Path(self.tmpdir.name) / "setgid-state"
        base.mkdir(mode=0o700)
        os.chmod(base, 0o2770)
        registry_path = base / "nm-tun" / "owned-uuid"

        with patch.multiple(
            "drivers.networkmanager_tun_cleanup",
            OWNED_UUIDS_PATH=registry_path,
            EXPECTED_REGISTRY_UID=os.getuid(),
            EXPECTED_REGISTRY_GID=os.getgid(),
            EXPECTED_REGISTRY_DIR_MODE=0o700,
            EXPECTED_REGISTRY_FILE_MODE=0o600,
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                [], 0, stdout=f"{UUID_ONE}:wdvpn-tun0:tun:wdvpn-tun0\n", stderr=""
            )
            nm_tun_cleanup._write_owned_uuid_registry(UUID_ONE)

        parent_mode = (base / "nm-tun").stat().st_mode & 0o7777
        self.assertEqual(parent_mode, 0o700)

    def test_owned_uuid_path_is_durable_outside_run(self) -> None:
        self.assertEqual(
            str(nm_tun_cleanup.OWNED_UUIDS_PATH),
            "/var/lib/watchdogvpn/nm-tun/owned-uuid",
        )
        self.assertFalse(str(nm_tun_cleanup.OWNED_UUIDS_PATH).startswith("/run/"))

    def _patched_registry(self):
        return patch.multiple(
            "drivers.networkmanager_tun_cleanup",
            OWNED_UUIDS_PATH=self.registry_path,
            EXPECTED_REGISTRY_UID=os.getuid(),
            EXPECTED_REGISTRY_GID=os.getgid(),
            EXPECTED_REGISTRY_DIR_MODE=0o700,
            EXPECTED_REGISTRY_FILE_MODE=0o600,
        )


if __name__ == "__main__":
    unittest.main()
