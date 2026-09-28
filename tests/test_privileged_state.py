from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import privileged_state
from privileged_state import PrivilegedStateError, prepare_state_directory


def _stat_snapshot(path: Path) -> tuple:
    info = os.lstat(path)
    if stat.S_ISDIR(info.st_mode):
        content = None
    else:
        content = path.read_bytes()
    return (info.st_mode, info.st_uid, info.st_gid, info.st_mtime_ns, content)


class PrivilegedStateDirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self._tmp.name) / "watchdogvpn"
        self.parent.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _patched_identity(self):
        return mock.patch.multiple(
            privileged_state,
            EXPECTED_STATE_UID=os.getuid(),
            EXPECTED_STATE_GID=os.getgid(),
        )

    def test_absent_directory_is_created_root_only(self) -> None:
        target = self.parent / "nm-tun"
        with self._patched_identity():
            prepare_state_directory(target)
        info = target.lstat()
        self.assertTrue(stat.S_ISDIR(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
        self.assertEqual((info.st_uid, info.st_gid), (os.getuid(), os.getgid()))

    def test_valid_existing_directory_is_accepted_idempotently(self) -> None:
        target = self.parent / "nm-dns-restore"
        target.mkdir(mode=0o700)
        before = _stat_snapshot(target)
        with self._patched_identity():
            prepare_state_directory(target)
            prepare_state_directory(target)
        self.assertEqual(_stat_snapshot(target), before)

    def test_valid_existing_state_file_retains_metadata(self) -> None:
        target = self.parent / "nm-tun"
        target.mkdir(mode=0o700)
        state = target / "owned-uuid"
        state.write_text("11111111-1111-1111-1111-111111111111\n", encoding="ascii")
        state.chmod(0o600)
        before = _stat_snapshot(state)
        with self._patched_identity():
            prepare_state_directory(target, "owned-uuid")
        self.assertEqual(_stat_snapshot(state), before)

    def test_absent_state_file_is_not_required(self) -> None:
        target = self.parent / "nm-dns-restore"
        with self._patched_identity():
            prepare_state_directory(target, "snapshot.json")
        self.assertTrue(target.is_dir())
        self.assertFalse((target / "snapshot.json").exists())

    # --- negative cases -----------------------------------------------------

    def _assert_rejected_without_touching(self, target: Path) -> None:
        before = _stat_snapshot(target)
        with self._patched_identity():
            with self.assertRaises(PrivilegedStateError):
                prepare_state_directory(target)
        self.assertEqual(_stat_snapshot(target), before)

    def test_symlinked_directory_is_rejected_and_sentinel_untouched(self) -> None:
        sentinel = Path(self._tmp.name) / "sentinel-dir"
        sentinel.mkdir(mode=0o700)
        (sentinel / "marker").write_text("untouched\n", encoding="ascii")
        before = _stat_snapshot(sentinel)
        target = self.parent / "nm-tun"
        target.symlink_to(sentinel, target_is_directory=True)
        with self._patched_identity():
            with self.assertRaises(PrivilegedStateError):
                prepare_state_directory(target)
        self.assertEqual(_stat_snapshot(sentinel), before)
        self.assertEqual(before, _stat_snapshot(sentinel))

    def test_non_directory_existing_entry_is_rejected(self) -> None:
        target = self.parent / "nm-dns-restore"
        target.write_text("not-a-directory\n", encoding="ascii")
        self._assert_rejected_without_touching(target)

    def test_incompatible_existing_mode_is_rejected(self) -> None:
        target = self.parent / "nm-tun"
        target.mkdir(mode=0o755)
        os.chmod(target, 0o755)
        self._assert_rejected_without_touching(target)

    def test_incompatible_existing_ownership_is_rejected(self) -> None:
        target = self.parent / "nm-tun"
        target.mkdir(mode=0o700)
        before = _stat_snapshot(target)
        with mock.patch.multiple(
            privileged_state,
            EXPECTED_STATE_UID=os.getuid() + 1,
            EXPECTED_STATE_GID=os.getgid(),
        ):
            with self.assertRaises(PrivilegedStateError):
                prepare_state_directory(target)
        self.assertEqual(_stat_snapshot(target), before)

    def test_symlinked_parent_is_rejected(self) -> None:
        real_parent = Path(self._tmp.name) / "real-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent = Path(self._tmp.name) / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self._patched_identity():
            with self.assertRaises(PrivilegedStateError):
                prepare_state_directory(linked_parent / "nm-tun")
        self.assertFalse((real_parent / "nm-tun").exists())

    def test_identity_change_after_open_is_rejected(self) -> None:
        target = self.parent / "nm-tun"
        target.mkdir(mode=0o700)
        swapped = os.stat_result((stat.S_IFDIR | 0o700, 424242, 424242, 1, os.getuid(), os.getgid(), 0, 0, 0, 0))
        with self._patched_identity(), mock.patch("privileged_state.os.stat", return_value=swapped):
            with self.assertRaises(PrivilegedStateError):
                prepare_state_directory(target)

    def test_symlinked_state_file_is_rejected_and_sentinel_untouched(self) -> None:
        target = self.parent / "nm-dns-restore"
        target.mkdir(mode=0o700)
        sentinel = Path(self._tmp.name) / "sentinel-file"
        sentinel.write_text("untouched\n", encoding="ascii")
        sentinel.chmod(0o600)
        before = _stat_snapshot(sentinel)
        (target / "snapshot.json").symlink_to(sentinel)
        with self._patched_identity():
            with self.assertRaises(PrivilegedStateError):
                prepare_state_directory(target, "snapshot.json")
        self.assertEqual(_stat_snapshot(sentinel), before)

    def test_state_file_with_unsafe_mode_is_rejected(self) -> None:
        target = self.parent / "nm-tun"
        target.mkdir(mode=0o700)
        state = target / "owned-uuid"
        state.write_text("11111111-1111-1111-1111-111111111111\n", encoding="ascii")
        os.chmod(state, 0o644)
        before = _stat_snapshot(state)
        with self._patched_identity():
            with self.assertRaises(PrivilegedStateError):
                prepare_state_directory(target, "owned-uuid")
        self.assertEqual(_stat_snapshot(state), before)

    def test_non_regular_state_file_is_rejected(self) -> None:
        target = self.parent / "nm-tun"
        target.mkdir(mode=0o700)
        (target / "owned-uuid").mkdir(mode=0o700)
        with self._patched_identity():
            with self.assertRaises(PrivilegedStateError):
                prepare_state_directory(target, "owned-uuid")

    # --- CLI ----------------------------------------------------------------

    def test_main_prepares_and_rejects(self) -> None:
        good_parent = Path(self._tmp.name) / "cli-parent"
        good_parent.mkdir(mode=0o700)
        good = good_parent / "nm-tun"
        with self._patched_identity():
            self.assertEqual(privileged_state.main(["prepare", str(good)]), 0)
            self.assertTrue(good.is_dir())

        bad_parent = Path(self._tmp.name) / "bad-parent"
        bad_parent.mkdir(mode=0o700)
        sentinel = Path(self._tmp.name) / "cli-sentinel"
        sentinel.mkdir(mode=0o700)
        bad = bad_parent / "nm-tun"
        bad.symlink_to(sentinel, target_is_directory=True)
        with self._patched_identity():
            self.assertEqual(privileged_state.main(["prepare", str(bad)]), 1)
        self.assertEqual(privileged_state.main(["nonsense"]), 2)


if __name__ == "__main__":
    unittest.main()
