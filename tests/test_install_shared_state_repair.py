"""Regression: the shared-state permission repair is race-safe and no-follow.

`/var/lib/watchdogvpn` is group-writable, so a member of the `watchdogvpn`
group can plant an entry there. A pathname-based `chown`/`chmod` would follow an
entry swapped for a symlink between classification and the change and alter
whatever it points at outside the tree.

These tests exercise the shipped descriptor-relative primitive
(`privileged_state.repair_shared_state_permissions`) and the guard CLI mode:

* a legitimate shared entry is still widened;
* the `private`, `nm-dns-restore` and `nm-tun` subtrees stay pruned and
  untouched;
* a pre-existing symlink entry is never followed, and its external target keeps
  its owner, group, mode and content;
* an entry swapped for an external symlink *between classification and the
  ownership/mode operation* cannot change the external target either, and the
  swap is reported as skipped.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import privileged_state  # noqa: E402
from privileged_state import PrivilegedStateError, repair_shared_state_permissions  # noqa: E402


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


class SharedStateRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.root = base / "watchdogvpn-shared"
        self.outside = base / "outside-tree"
        self.root.mkdir(mode=0o2770)
        self.root.chmod(0o2770)
        self.outside.mkdir(mode=0o755)

        # Ordinary shared entries: these are the ones the repair should widen.
        (self.root / "sub").mkdir(mode=0o755)
        (self.root / "sub").chmod(0o755)
        self.shared_file = self.root / "sub" / "plain.txt"
        self.shared_file.write_text("shared\n", encoding="utf-8")
        self.shared_file.chmod(0o644)

        # An external target reachable through a symlink placed in the tree.
        self.sentinel = self.outside / "sentinel.txt"
        self.sentinel.write_text("sentinel-content\n", encoding="utf-8")
        self.sentinel.chmod(0o604)
        self.sentinel_link = self.outside / "sentinel-link-dir"

        # Root-only privileged subtrees: pruned by the repair, never widened.
        for name in ("private", "nm-dns-restore", "nm-tun"):
            directory = self.root / name
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            entry = directory / "state.txt"
            entry.write_text("privileged\n", encoding="utf-8")
            entry.chmod(0o600)

        # The primitive targets the service account; tests run unprivileged, so
        # the expected owner/group are the current user's.
        self._owner_patch = mock.patch.multiple(
            privileged_state,
            SHARED_STATE_OWNER=pwd_name(),
            SHARED_STATE_GROUP=grp_name(),
        )
        self._owner_patch.start()

    def tearDown(self) -> None:
        self._owner_patch.stop()
        self.tmp.cleanup()

    def _expected_identity(self) -> tuple[int, int]:
        info = os.stat(self.shared_file)
        return (info.st_uid, info.st_gid)

    def test_repair_widens_shared_entries_and_prunes_privileged_subtrees(self) -> None:
        skipped = repair_shared_state_permissions(self.root)

        self.assertEqual(skipped, ())
        uid, gid = self._expected_identity()
        for path, expected_mode in (
            (self.root, privileged_state.SHARED_STATE_DIRECTORY_MODE),
            (self.root / "sub", privileged_state.SHARED_STATE_DIRECTORY_MODE),
            (self.shared_file, privileged_state.SHARED_STATE_FILE_MODE),
        ):
            info = os.lstat(path)
            self.assertEqual((info.st_uid, info.st_gid), (uid, gid), path)
            self.assertEqual(_mode(path), expected_mode, path)

        for name in ("private", "nm-dns-restore", "nm-tun"):
            directory = self.root / name
            self.assertEqual(_mode(directory), 0o700, directory)
            self.assertEqual(_mode(directory / "state.txt"), 0o600, directory)

    def test_repair_never_follows_a_preexisting_symlink_entry(self) -> None:
        link = self.root / "link-to-sentinel"
        link.symlink_to(self.sentinel)
        before = os.lstat(self.sentinel)
        content_before = self.sentinel.read_bytes()

        skipped = repair_shared_state_permissions(self.root)

        self.assertIn(str(link), skipped)
        after = os.lstat(self.sentinel)
        self.assertEqual(
            (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
            (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)),
        )
        self.assertEqual(self.sentinel.read_bytes(), content_before)
        self.assertTrue(link.is_symlink())

    def test_repair_skips_an_entry_swapped_before_the_operation(self) -> None:
        # Deterministic adversarial interleave: the entry is classified as a
        # regular file and only then replaced by a symlink to an external target
        # before the ownership/mode operation runs.
        victim = self.root / "swapme.txt"
        victim.write_text("victim\n", encoding="utf-8")
        victim.chmod(0o644)
        sentinel_before = os.lstat(self.sentinel)
        content_before = self.sentinel.read_bytes()
        victim_display = str(victim)

        real_stat = os.stat
        swapped = {"done": False}

        def stat_with_swap(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if not swapped["done"] and kwargs.get("dir_fd") is not None and path == "swapme.txt":
                swapped["done"] = True
                os.unlink(victim)
                victim.symlink_to(self.sentinel)
            return result

        with mock.patch.object(privileged_state.os, "stat", side_effect=stat_with_swap):
            skipped = repair_shared_state_permissions(self.root)

        self.assertTrue(swapped["done"], "the adversarial swap did not run")
        self.assertIn(victim_display, skipped)
        sentinel_after = os.lstat(self.sentinel)
        self.assertEqual(
            (
                sentinel_after.st_uid,
                sentinel_after.st_gid,
                stat.S_IMODE(sentinel_after.st_mode),
            ),
            (
                sentinel_before.st_uid,
                sentinel_before.st_gid,
                stat.S_IMODE(sentinel_before.st_mode),
            ),
        )
        self.assertEqual(self.sentinel.read_bytes(), content_before)
        # The replacement symlink itself is left untouched as well.
        self.assertTrue(victim.is_symlink())
        self.assertEqual(stat.S_IMODE(os.lstat(victim).st_mode), 0o777)

    def test_repair_rejects_a_non_directory_target(self) -> None:
        not_a_directory = Path(self.tmp.name) / "plain-file"
        not_a_directory.write_text("x\n", encoding="utf-8")
        with self.assertRaises(PrivilegedStateError):
            repair_shared_state_permissions(not_a_directory)


class SharedStateRepairGuardCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "shared"
        self.root.mkdir(mode=0o2770)
        self.root.chmod(0o2770)
        self.sentinel = Path(self.tmp.name) / "sentinel.txt"
        self.sentinel.write_text("sentinel\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run_guard(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "privileged_state.py"), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_guard_cli_warns_about_an_untouched_symlink_entry(self) -> None:
        # The CLI runs against the real service account, so a non-root caller
        # cannot widen ownership; the entry classification and the symlink
        # decision are still observable.
        link = self.root / "link"
        link.symlink_to(self.sentinel)
        result = self._run_guard("repair-shared", str(self.root))
        self.assertIn(result.returncode, (0, 1))
        if result.returncode == 0:
            self.assertIn("left untouched", result.stderr)
            self.assertIn(str(link), result.stderr)
        self.assertEqual(self.sentinel.read_text(encoding="utf-8"), "sentinel\n")

    def test_guard_cli_rejects_unknown_mode(self) -> None:
        result = self._run_guard("unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("repair-shared", result.stderr)


def pwd_name() -> str:
    import pwd

    return pwd.getpwuid(os.getuid()).pw_name


def grp_name() -> str:
    import grp

    return grp.getgrgid(os.getgid()).gr_name


if __name__ == "__main__":
    unittest.main()
