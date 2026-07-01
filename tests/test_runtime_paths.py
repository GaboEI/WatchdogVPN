from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from drivers import runtime_paths


class RuntimePathsTests(unittest.TestCase):
    def test_make_runtime_dir_writes_owner_pid_and_private_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                runtime_dir = runtime_paths.make_runtime_dir("watchdogvpn-test-")
                config_path = runtime_dir / "config.txt"
                runtime_paths.write_private_file(config_path, "secret")

                self.assertEqual((runtime_dir / runtime_paths.OWNER_PID_NAME).read_text(encoding="utf-8"), str(runtime_paths.os.getpid()))
                self.assertEqual(config_path.read_text(encoding="utf-8"), "secret")
                self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)

    def test_cleanup_stale_runtime_dirs_preserves_live_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(runtime_paths.os.environ, {"WATCHDOGVPN_RUNTIME_DIR": tmp}):
                live_dir = Path(tmp) / "watchdogvpn-test-live"
                stale_dir = Path(tmp) / "watchdogvpn-test-stale"
                live_dir.mkdir()
                stale_dir.mkdir()
                runtime_paths.write_private_file(live_dir / runtime_paths.OWNER_PID_NAME, str(runtime_paths.os.getpid()))
                runtime_paths.write_private_file(stale_dir / runtime_paths.OWNER_PID_NAME, "999999999")

                runtime_paths.cleanup_stale_runtime_dirs("watchdogvpn-test-")

                self.assertTrue(live_dir.exists())
                self.assertFalse(stale_dir.exists())


if __name__ == "__main__":
    unittest.main()
