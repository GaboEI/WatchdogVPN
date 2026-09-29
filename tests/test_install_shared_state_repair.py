"""Regression: the shared-state permission repair never follows a symlink.

The repair runs over `/var/lib/watchdogvpn`, which is group-writable, so a group
member can place a symlink there. `chown`/`chmod` follow a symlink given by
name, so the repair must never hand a symlink entry to them.

This module executes the exact `find` expressions shipped in
`repair_watchdogvpn_shared_state_permissions()` (extracted from `lib/runtime.sh`
so the test cannot drift from the implementation) against an isolated temporary
tree that contains symlinks pointing outside it, and proves:

* the external sentinel target's ownership and mode are unchanged;
* the symlink entries are never passed to chown (logged by a shim) and never
  have their targets chmod'ed (the real chmod runs against the temporary tree);
* the intended widening still happens for ordinary shared entries;
* the root-only privileged subtrees stay pruned and untouched.
"""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_SH = REPO_ROOT / "lib" / "runtime.sh"
REPAIR_FUNCTION = "repair_watchdogvpn_shared_state_permissions() {"


def extract_shared_state_find_commands() -> list[str]:
    """Return the three `find` commands the repair function runs, verbatim."""
    text = RUNTIME_SH.read_text(encoding="utf-8")
    start = text.index(REPAIR_FUNCTION)
    end = text.index("\n}\n", start)
    body_lines = text[start:end].splitlines()
    commands: list[str] = []
    index = 0
    while index < len(body_lines):
        stripped = body_lines[index].strip()
        index += 1
        if not stripped.startswith("run_step sudo find "):
            continue
        collected = [stripped]
        while collected[-1].rstrip().endswith("\\"):
            collected.append(body_lines[index].strip())
            index += 1
        joined = " ".join(part.rstrip().rstrip("\\").strip() for part in collected)
        commands.append(joined[len("run_step sudo ") :])
    return commands


class SharedStateRepairSymlinkTests(unittest.TestCase):
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
        self.shared_file = self.root / "sub" / "plain.txt"
        self.shared_file.write_text("shared\n", encoding="utf-8")
        self.shared_file.chmod(0o644)

        # A file and a directory outside the tree, reachable through symlinks
        # placed inside the group-writable tree.
        self.sentinel_file = self.outside / "sentinel.txt"
        self.sentinel_file.write_text("sentinel\n", encoding="utf-8")
        self.sentinel_file.chmod(0o604)
        self.sentinel_dir = self.outside / "sentinel-dir"
        self.sentinel_dir.mkdir(mode=0o705)

        self.link_file = self.root / "link-to-sentinel"
        self.link_file.symlink_to(self.sentinel_file)
        self.link_dir = self.root / "link-to-dir"
        self.link_dir.symlink_to(self.sentinel_dir)

        # Root-only privileged subtrees: pruned by the repair, never widened.
        for name in ("private", "nm-dns-restore", "nm-tun"):
            directory = self.root / name
            directory.mkdir(mode=0o700)
            # The setgid parent makes mkdir inherit 2700; the privileged
            # subtrees are intentionally plain 0700.
            directory.chmod(0o700)
            entry = directory / "state.txt"
            entry.write_text("privileged\n", encoding="utf-8")
            entry.chmod(0o600)

        # chown cannot change ownership as an unprivileged test user, so it is
        # shimmed to log what it was asked to change. chmod runs for real.
        self.stub_bin = base / "stub-bin"
        self.stub_bin.mkdir()
        self.chown_log = base / "chown.log"
        chown_shim = self.stub_bin / "chown"
        chown_shim.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f"printf '%s\\n' \"$@\" >> {shlex.quote(str(self.chown_log))}\n",
            encoding="utf-8",
        )
        chown_shim.chmod(0o755)

    def tearDown(self) -> None:
        shutil.rmtree(self.stub_bin, ignore_errors=True)
        self.tmp.cleanup()

    def _run_repair_commands(self) -> list[subprocess.CompletedProcess[str]]:
        env = dict(os.environ)
        env["PATH"] = f"{self.stub_bin}:{env['PATH']}"
        prefix = (
            f"target_dir={shlex.quote(str(self.root))}; "
            f"private_dir={shlex.quote(str(self.root / 'private'))}; "
            f"dns_restore_dir={shlex.quote(str(self.root / 'nm-dns-restore'))}; "
            f"tun_dir={shlex.quote(str(self.root / 'nm-tun'))}; "
        )
        results = []
        for command in extract_shared_state_find_commands():
            results.append(
                subprocess.run(
                    ["bash", "-c", prefix + command],
                    capture_output=True,
                    text=True,
                    env=env,
                    check=False,
                )
            )
        return results

    def test_repair_excludes_symlinks_and_preserves_external_targets(self) -> None:
        commands = extract_shared_state_find_commands()
        self.assertEqual(len(commands), 3, commands)

        sentinel_file_before = self.sentinel_file.stat()
        sentinel_dir_before = self.sentinel_dir.stat()

        results = self._run_repair_commands()
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)

        logged = (
            self.chown_log.read_text(encoding="utf-8").split("\n")
            if self.chown_log.exists()
            else []
        )
        logged_args = [line for line in logged if line]

        # The symlink entries (and therefore their external targets) are never
        # named to chown, and the real chmod never reached the sentinel either.
        self.assertFalse([arg for arg in logged_args if "link-to-sentinel" in arg], logged_args)
        self.assertFalse([arg for arg in logged_args if "link-to-dir" in arg], logged_args)
        sentinel_file_after = self.sentinel_file.stat()
        self.assertEqual(
            stat.S_IMODE(sentinel_file_after.st_mode),
            stat.S_IMODE(sentinel_file_before.st_mode),
        )
        self.assertEqual(sentinel_file_after.st_uid, sentinel_file_before.st_uid)
        self.assertEqual(sentinel_file_after.st_gid, sentinel_file_before.st_gid)
        sentinel_dir_after = self.sentinel_dir.stat()
        self.assertEqual(
            stat.S_IMODE(sentinel_dir_after.st_mode),
            stat.S_IMODE(sentinel_dir_before.st_mode),
        )
        # The symlinks themselves are left in place, untouched.
        self.assertTrue(self.link_file.is_symlink())
        self.assertTrue(self.link_dir.is_symlink())

        # The intended widening still happens for ordinary shared entries.
        self.assertIn(str(self.shared_file), logged_args)
        self.assertEqual(stat.S_IMODE(self.shared_file.stat().st_mode), 0o660)
        self.assertEqual(stat.S_IMODE((self.root / "sub").stat().st_mode), 0o2770)

        # The privileged subtrees stay pruned: neither chown nor chmod saw them.
        for name in ("private", "nm-dns-restore", "nm-tun"):
            directory = self.root / name
            entry = directory / "state.txt"
            self.assertNotIn(str(entry), logged_args)
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
