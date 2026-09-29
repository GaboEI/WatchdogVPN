from __future__ import annotations

import subprocess
import tempfile
import unittest
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import drivers.networkmanager_tun_cleanup as nm_tun_cleanup
import privileged_state
from drivers.networkmanager_tun_cleanup import (
    NetworkManagerTunCleanupError,
    migrate_legacy_owned_uuid_registry,
    record_active_tun_connection,
    remove_stale_tun_connections,
)


UUID_ONE = "11111111-1111-1111-1111-111111111111"
UUID_TWO = "22222222-2222-2222-2222-222222222222"
UUID_ALPHA = "abcdef01-2345-6789-abcd-ef0123456789"


class NetworkManagerTunCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.registry_dir = Path(self.tmpdir.name) / "root-owned-registry"
        self.registry_path = self.registry_dir / "owned-uuids"

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_absent_registry_without_candidate_is_reconciled_success(self) -> None:
        # No ownership authority and no product-shaped residual: nothing to do.
        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            self.assertTrue(remove_stale_tun_connections())

        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 1)
        self.assertFalse(any("delete" in command for command in commands))

    def test_absent_registry_with_residual_candidate_is_not_reported_clean(self) -> None:
        # T-PR23-08 durable residual: a product-shaped profile may exist while
        # the authority is gone. Never delete by name, but never claim success.
        listing = f"{UUID_ONE}:wdvpn-tun0:tun\n"
        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
            self.assertFalse(remove_stale_tun_connections())

        commands = [call.args[0] for call in run.call_args_list]
        self.assertFalse(any("delete" in command for command in commands))

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

    def test_registered_uuid_absent_profile_is_reconciled_without_deleting(self) -> None:
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
            self.assertTrue(remove_stale_tun_connections())

        commands = [call.args[0] for call in run.call_args_list]
        self.assertFalse(any("delete" in command for command in commands))
        self.assertFalse(self.registry_path.exists())

    def test_foreign_same_name_is_not_deleted_without_registered_identity(self) -> None:
        listing = f"{UUID_ONE}:wdvpn-tun0:tun\n"

        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
            self.assertFalse(remove_stale_tun_connections())

        commands = [call.args[0] for call in run.call_args_list]
        self.assertFalse(any("delete" in command for command in commands))

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
            "drivers.networkmanager_tun_cleanup.remove_stale_tun_connections", return_value=True
        ) as cleanup:
            self.assertEqual(nm_tun_cleanup.main(), 0)

        register.assert_not_called()
        cleanup.assert_called_once_with()

    def test_main_cleanup_unresolved_returns_nonzero(self) -> None:
        with patch.object(
            nm_tun_cleanup.sys, "argv", ["python-module-wrapper", "cleanup"]
        ), patch(
            "drivers.networkmanager_tun_cleanup.remove_stale_tun_connections", return_value=False
        ) as cleanup:
            self.assertEqual(nm_tun_cleanup.main(), 1)

        cleanup.assert_called_once_with()

    def test_main_cleanup_absent_registry_without_candidate_returns_zero(self) -> None:
        with self._patched_registry(), patch.object(
            nm_tun_cleanup.sys, "argv", ["wrapper", "cleanup"]
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            self.assertEqual(nm_tun_cleanup.main(), 0)
        self.assertFalse(self.registry_path.exists())
        self.assertFalse(any("delete" in call.args[0] for call in run.call_args_list))

    def test_main_cleanup_absent_registry_with_residual_returns_nonzero(self) -> None:
        listing = f"{UUID_ONE}:wdvpn-tun0:tun\n"
        with self._patched_registry(), patch.object(
            nm_tun_cleanup.sys, "argv", ["wrapper", "cleanup"]
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
            self.assertEqual(nm_tun_cleanup.main(), 1)
        self.assertFalse(any("delete" in call.args[0] for call in run.call_args_list))

    def test_main_cleanup_corrupt_registry_returns_nonzero_without_nmcli(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text("not-a-uuid\n", encoding="ascii")
        self.registry_path.chmod(0o600)
        with self._patched_registry(), patch.object(
            nm_tun_cleanup.sys, "argv", ["wrapper", "cleanup"]
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            self.assertEqual(nm_tun_cleanup.main(), 1)
        self.assertEqual(run.call_count, 0)
        self.assertTrue(self.registry_path.exists())

    def test_main_cleanup_symlink_registry_returns_nonzero_without_nmcli(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
        target = Path(self.tmpdir.name) / "target-file"
        target.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.symlink_to(target)
        with self._patched_registry(), patch.object(
            nm_tun_cleanup.sys, "argv", ["wrapper", "cleanup"]
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            self.assertEqual(nm_tun_cleanup.main(), 1)
        self.assertEqual(run.call_count, 0)

    def test_main_cleanup_valid_uuid_without_profile_reconciles(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o600)
        with self._patched_registry(), patch.object(
            nm_tun_cleanup.sys, "argv", ["wrapper", "cleanup"]
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            self.assertEqual(nm_tun_cleanup.main(), 0)
        self.assertFalse(self.registry_path.exists())
        self.assertFalse(any("delete" in call.args[0] for call in run.call_args_list))

    def test_main_cleanup_valid_uuid_with_own_profile_deletes(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o600)
        listing = f"{UUID_ONE}:wdvpn-tun0:tun\n"
        with self._patched_registry(), patch.object(
            nm_tun_cleanup.sys, "argv", ["wrapper", "cleanup"]
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout=listing, stderr=""),
                subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ]
            self.assertEqual(nm_tun_cleanup.main(), 0)
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["nmcli", "connection", "delete", "uuid", UUID_ONE],
        )
        self.assertFalse(self.registry_path.exists())

    def test_main_cleanup_delete_failure_returns_nonzero_and_keeps_registry(self) -> None:
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text(f"{UUID_ONE}\n", encoding="ascii")
        self.registry_path.chmod(0o600)
        listing = f"{UUID_ONE}:wdvpn-tun0:tun\n"
        with self._patched_registry(), patch.object(
            nm_tun_cleanup.sys, "argv", ["wrapper", "cleanup"]
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout=listing, stderr=""),
                subprocess.CompletedProcess([], 1, stdout="", stderr="failed"),
            ]
            self.assertEqual(nm_tun_cleanup.main(), 1)
        self.assertTrue(self.registry_path.exists())

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

    def test_write_registry_fails_closed_when_parent_is_swapped(self) -> None:
        # F-S2-01: a swap of the TUN registry directory for a symlink after it
        # is created must be rejected by the no-follow re-open before any
        # registry read/write, and the symlink target must stay untouched.
        sentinel = Path(self.tmpdir.name) / "tun-sentinel"
        sentinel.mkdir(mode=0o700)
        (sentinel / "marker").write_text("untouched\n", encoding="ascii")

        def meta() -> tuple:
            info = sentinel.lstat()
            return (info.st_mode & 0o777, info.st_uid, info.st_gid, info.st_mtime_ns)

        before = meta()
        real_open = privileged_state.open_state_directory

        def swapping_open(directory, **kwargs):
            descriptor = real_open(directory, **kwargs)
            os.rename(directory, str(directory) + ".moved")
            os.symlink(sentinel, directory)
            return descriptor

        with self._patched_registry(), patch(
            "privileged_state.open_state_directory", side_effect=swapping_open
        ):
            with self.assertRaises(NetworkManagerTunCleanupError):
                nm_tun_cleanup._write_owned_uuid_registry(UUID_ONE)
        self.assertEqual(meta(), before)

    def test_owned_uuid_path_is_durable_outside_run(self) -> None:
        self.assertEqual(
            str(nm_tun_cleanup.OWNED_UUIDS_PATH),
            "/var/lib/watchdogvpn/nm-tun/owned-uuid",
        )
        self.assertFalse(str(nm_tun_cleanup.OWNED_UUIDS_PATH).startswith("/run/"))

    def test_legacy_owned_uuid_path_is_the_established_volatile_location(self) -> None:
        self.assertEqual(
            str(nm_tun_cleanup.LEGACY_OWNED_UUIDS_PATH),
            "/run/watchdogvpn-nm-tun/owned-uuid",
        )

    # --- S.1: legacy /run UUID migration and cleanup authority -------------

    def test_migrate_trusted_legacy_registry_promotes_into_durable_authority(self) -> None:
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")

        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ):
            self.assertTrue(migrate_legacy_owned_uuid_registry())

        self.assertEqual(self.registry_path.read_text(encoding="ascii"), f"{UUID_ONE}\n")
        self.assertEqual(self.registry_path.stat().st_mode & 0o777, 0o600)
        # The recoverable trusted source is preserved, not consumed.
        self.assertEqual(legacy_path.read_text(encoding="ascii"), f"{UUID_ONE}\n")

    def test_migrated_legacy_authority_deletes_only_its_uuid(self) -> None:
        # Requirement 1: trusted legacy state migrates before cleanup and the
        # cleanup deletes only the migrated UUID, never a foreign same-name one.
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")
        listing = "\n".join((
            f"{UUID_ONE}:wdvpn-tun0:tun",
            f"{UUID_TWO}:wdvpn-tun0:tun",
        ))

        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ):
            self.assertTrue(migrate_legacy_owned_uuid_registry())

        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout=listing, stderr=""),
                subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ]
            self.assertTrue(remove_stale_tun_connections())

        delete_commands = [
            call.args[0] for call in run.call_args_list if "delete" in call.args[0]
        ]
        self.assertEqual(
            delete_commands,
            [["nmcli", "connection", "delete", "uuid", UUID_ONE]],
        )
        self.assertFalse(self.registry_path.exists())

    def test_migrate_is_noop_when_valid_durable_registry_exists(self) -> None:
        # Requirement 3: a valid durable state stays valid without legacy input.
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text(f"{UUID_TWO}\n", encoding="ascii")
        self.registry_path.chmod(0o600)
        absent_legacy = Path(self.tmpdir.name) / "absent-legacy" / "owned-uuid"

        with self._patched_registry_and_legacy(absent_legacy), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ):
            self.assertFalse(migrate_legacy_owned_uuid_registry())
            self.assertEqual(nm_tun_cleanup._read_owned_uuid_registry(), UUID_TWO)

        self.assertEqual(self.registry_path.read_text(encoding="ascii"), f"{UUID_TWO}\n")

    def test_migrate_absent_legacy_is_noop_without_authority(self) -> None:
        absent_legacy = Path(self.tmpdir.name) / "absent-legacy" / "owned-uuid"
        with self._patched_registry_and_legacy(absent_legacy), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ):
            self.assertFalse(migrate_legacy_owned_uuid_registry())
        self.assertFalse(self.registry_path.exists())

    def test_migrate_requires_root(self) -> None:
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")
        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=1000
        ):
            with self.assertRaises(NetworkManagerTunCleanupError):
                migrate_legacy_owned_uuid_registry()
        self.assertFalse(self.registry_path.exists())

    def test_migrate_rejects_malformed_or_ambiguous_legacy_content(self) -> None:
        # Requirement 4: malformed, duplicate and multiline legacy input must
        # never be promoted into cleanup authority.
        for content in ("not-a-uuid\n", "\n", "  \n", f"{UUID_ONE}\n{UUID_TWO}\n"):
            with self.subTest(content=content):
                legacy_path = self._write_legacy_registry(content)
                with self._patched_registry_and_legacy(legacy_path), patch(
                    "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
                ):
                    self.assertFalse(migrate_legacy_owned_uuid_registry())
                self.assertFalse(self.registry_path.exists())

    def test_migrate_rejects_unsafe_legacy_file_permissions(self) -> None:
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")
        legacy_path.chmod(0o644)
        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ):
            self.assertFalse(migrate_legacy_owned_uuid_registry())
        self.assertFalse(self.registry_path.exists())

    def test_migrate_rejects_unsafe_legacy_ownership(self) -> None:
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")
        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.EXPECTED_REGISTRY_UID", os.getuid() + 1
        ), patch("drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0):
            self.assertFalse(migrate_legacy_owned_uuid_registry())
        self.assertFalse(self.registry_path.exists())

    def test_migrate_rejects_non_regular_legacy_entry(self) -> None:
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")
        legacy_path.unlink()
        legacy_path.mkdir(mode=0o700)
        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ):
            self.assertFalse(migrate_legacy_owned_uuid_registry())
        self.assertFalse(self.registry_path.exists())

    def test_migrate_rejects_symlink_legacy_entry(self) -> None:
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")
        target = Path(self.tmpdir.name) / "legacy-target"
        legacy_path.rename(target)
        legacy_path.symlink_to(target)
        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ):
            self.assertFalse(migrate_legacy_owned_uuid_registry())
        self.assertFalse(self.registry_path.exists())

    def test_migrate_rejects_unsafe_legacy_directory(self) -> None:
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")
        legacy_path.parent.chmod(0o755)
        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ):
            self.assertFalse(migrate_legacy_owned_uuid_registry())
        self.assertFalse(self.registry_path.exists())

    def test_rejected_legacy_never_authorizes_a_deletion(self) -> None:
        # Requirement 4 (deletion half): an untrusted legacy source, even with a
        # product-shaped residual present, must issue no nmcli delete.
        legacy_path = self._write_legacy_registry("not-a-uuid\n")
        listing = f"{UUID_ONE}:wdvpn-tun0:tun\n"
        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
            self.assertFalse(migrate_legacy_owned_uuid_registry())
            self.assertFalse(remove_stale_tun_connections())

        self.assertFalse(any("delete" in call.args[0] for call in run.call_args_list))

    def test_migrate_write_failure_keeps_source_without_creating_authority(self) -> None:
        # Requirement 5: a failed durable write leaves no authority and does not
        # consume the still-recoverable trusted legacy source.
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")
        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ), patch(
            "drivers.networkmanager_tun_cleanup.os.link", side_effect=OSError("boom")
        ):
            with self.assertRaises(NetworkManagerTunCleanupError):
                migrate_legacy_owned_uuid_registry()

        self.assertFalse(self.registry_path.exists())
        self.assertFalse(
            any(
                path.name.startswith(f".{self.registry_path.name}")
                for path in self.registry_dir.glob(".*")
            )
        )
        self.assertEqual(legacy_path.read_text(encoding="ascii"), f"{UUID_ONE}\n")

    def test_migrate_never_replaces_registry_created_after_migration_begins(self) -> None:
        # PR25-F3: presence is decided and published atomically, so a live
        # registration created after the migration's presence check wins and the
        # stale legacy UUID is never published over it.
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")

        def interleaved_legacy_read():
            # Deterministic interleave: the live registry appears between the
            # presence check and the publication.
            self.registry_dir.mkdir(mode=0o700, exist_ok=True)
            self.registry_path.write_text(f"{UUID_TWO}\n", encoding="ascii")
            self.registry_path.chmod(0o600)
            return UUID_ONE

        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ), patch(
            "drivers.networkmanager_tun_cleanup._read_legacy_owned_uuid_registry",
            side_effect=interleaved_legacy_read,
        ):
            self.assertFalse(migrate_legacy_owned_uuid_registry())

        self.assertEqual(self.registry_path.read_text(encoding="ascii"), f"{UUID_TWO}\n")
        self.assertEqual(self.registry_path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(
            any(
                path.name.startswith(f".{self.registry_path.name}")
                for path in self.registry_dir.glob(".*")
            )
        )
        self.assertEqual(legacy_path.read_text(encoding="ascii"), f"{UUID_ONE}\n")

    def test_no_replace_publish_keeps_an_existing_registry_byte_identical(self) -> None:
        # PR25-F3 primitive: the no-replace publication used by migration never
        # overwrites an existing entry; the live-registration path still may.
        self.registry_dir.mkdir(mode=0o700)
        self.registry_path.write_text(f"{UUID_TWO}\n", encoding="ascii")
        self.registry_path.chmod(0o600)

        with self._patched_registry():
            self.assertFalse(
                nm_tun_cleanup._write_owned_uuid_registry(UUID_ONE, replace=False)
            )
            self.assertEqual(self.registry_path.read_text(encoding="ascii"), f"{UUID_TWO}\n")

            self.assertTrue(
                nm_tun_cleanup._write_owned_uuid_registry(UUID_ONE, replace=True)
            )
            self.assertEqual(self.registry_path.read_text(encoding="ascii"), f"{UUID_ONE}\n")

    def test_publication_fails_closed_when_the_directory_is_replaced(self) -> None:
        # PR25-F5: after publication the required pathname must still resolve to
        # the validated registry. Replacing the directory during publication
        # means the authority is not durable there, so registration fails closed
        # instead of reporting success.
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")
        moved_dir = self.registry_dir.with_name("root-owned-registry.moved")
        real_link = os.link

        def link_then_replace_directory(source, target, *args, **kwargs):
            result = real_link(source, target, *args, **kwargs)
            self.registry_dir.rename(moved_dir)
            self.registry_dir.mkdir(mode=0o700)
            self.registry_dir.chmod(0o700)
            return result

        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ), patch(
            "drivers.networkmanager_tun_cleanup.os.link", side_effect=link_then_replace_directory
        ):
            with self.assertRaises(NetworkManagerTunCleanupError):
                migrate_legacy_owned_uuid_registry()

        # The publication really happened (in the replaced directory) but it is
        # not reachable at the required pathname, and no success was reported.
        self.assertTrue((moved_dir / self.registry_path.name).exists())
        self.assertFalse(self.registry_path.exists())

    def test_publication_fails_closed_when_a_live_registration_entry_is_replaced(self) -> None:
        # PR25-F5: the live-registration path has the same postcondition; an
        # entry replaced by a different validated registry is not reported as a
        # successful registration of the UUID that was written.
        real_rename = os.rename

        def rename_then_replace_entry(source, target, *args, **kwargs):
            result = real_rename(source, target, *args, **kwargs)
            replacement = self.registry_dir / "replacement.tmp"
            replacement.write_text(f"{UUID_TWO}\n", encoding="ascii")
            replacement.chmod(0o600)
            os.replace(replacement, self.registry_path)
            return result

        self.registry_dir.mkdir(mode=0o700)
        with self._patched_registry(), patch(
            "drivers.networkmanager_tun_cleanup.os.rename", side_effect=rename_then_replace_entry
        ):
            with self.assertRaises(NetworkManagerTunCleanupError):
                nm_tun_cleanup._write_owned_uuid_registry(UUID_ONE, replace=True)

    def test_migrated_authority_never_removes_foreign_same_name_profile(self) -> None:
        # Requirement 6: only the migrated UUID authorises a deletion; a foreign
        # profile that merely shares the fixed name is never removed.
        legacy_path = self._write_legacy_registry(f"{UUID_ONE}\n")
        listing = f"{UUID_TWO}:wdvpn-tun0:tun\n"
        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
        ):
            self.assertTrue(migrate_legacy_owned_uuid_registry())
        with self._patched_registry_and_legacy(legacy_path), patch(
            "drivers.networkmanager_tun_cleanup.subprocess.run"
        ) as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
            self.assertTrue(remove_stale_tun_connections())

        self.assertFalse(any("delete" in call.args[0] for call in run.call_args_list))

    def test_main_dispatches_migrate_mode(self) -> None:
        with patch.object(nm_tun_cleanup.sys, "argv", ["wrapper", "migrate"]), patch(
            "drivers.networkmanager_tun_cleanup.migrate_legacy_owned_uuid_registry",
            return_value=True,
        ) as migrate:
            self.assertEqual(nm_tun_cleanup.main(), 0)
        migrate.assert_called_once_with()

    def test_migrate_rejects_non_canonical_legacy_payloads(self) -> None:
        # F-S1-01: only the exact historical payload "<canonical-uuid>\n" is
        # trusted. Whitespace, tabs, extra lines, a missing newline, uppercase,
        # a carriage return, non-ASCII bytes and overlong content must create no
        # authority and must never authorize a delete.
        non_canonical = (
            f" {UUID_ONE}\n",
            f"{UUID_ONE} \n",
            f"\t{UUID_ONE}\t\n",
            f"{UUID_ONE}\n\n",
            UUID_ONE,
            f"{UUID_ONE}\n{UUID_ONE}\n",
            f"{UUID_ALPHA.upper()}\n",
            f"{UUID_ONE}\r\n",
            f"{UUID_ONE}0\n",
            f"{'a' * 200}\n",
            b"\xc2\xa0" + UUID_ONE.encode("ascii") + b"\n",
            b"",
        )
        for content in non_canonical:
            with self.subTest(content=content):
                legacy_path = self._write_legacy_registry(content)
                listing = f"{UUID_ONE}:wdvpn-tun0:tun\n"
                with self._patched_registry_and_legacy(legacy_path), patch(
                    "drivers.networkmanager_tun_cleanup.os.geteuid", return_value=0
                ), patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
                    run.return_value = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
                    self.assertFalse(migrate_legacy_owned_uuid_registry())
                    self.assertFalse(self.registry_path.exists())
                    self.assertFalse(remove_stale_tun_connections())
                self.assertFalse(any("delete" in call.args[0] for call in run.call_args_list))

    def _write_legacy_registry(self, content: str | bytes) -> Path:
        legacy_dir = Path(self.tmpdir.name) / "run-watchdogvpn-nm-tun"
        legacy_dir.mkdir(mode=0o700, exist_ok=True)
        legacy_path = legacy_dir / "owned-uuid"
        if legacy_path.exists() or legacy_path.is_symlink():
            legacy_path.unlink()
        if isinstance(content, bytes):
            legacy_path.write_bytes(content)
        else:
            legacy_path.write_text(content, encoding="ascii")
        legacy_path.chmod(0o600)
        return legacy_path

    def _patched_registry_and_legacy(self, legacy_path: Path):
        return patch.multiple(
            "drivers.networkmanager_tun_cleanup",
            OWNED_UUIDS_PATH=self.registry_path,
            LEGACY_OWNED_UUIDS_PATH=legacy_path,
            EXPECTED_REGISTRY_UID=os.getuid(),
            EXPECTED_REGISTRY_GID=os.getgid(),
            EXPECTED_REGISTRY_DIR_MODE=0o700,
            EXPECTED_REGISTRY_FILE_MODE=0o600,
        )

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
