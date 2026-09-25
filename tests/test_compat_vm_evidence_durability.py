"""Regression test for VM evidence durability.

Task 23.7.5.10b checkpoint failure root cause: Evidence.flush() in the
transactional-provisioning VM harness wrote evidence JSON with
Path.write_text() but never called os.fsync() or fsync'd the parent
directory. After a hard VM reset the prepare evidence file was lost, so
the recover-after-reboot verification failed with FileNotFoundError.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# tests/vm/ is not a Python package, so import the harness by path.
_HARNESS_DIR = Path(__file__).resolve().parent / "vm"
sys.path.insert(0, str(_HARNESS_DIR))
import phase23_7_5_6a_transactional_provisioning_validation as harness
sys.path.pop(0)


class EvidenceDurabilityTest(unittest.TestCase):
    def test_flush_fsyncs_file_and_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            evidence = harness.Evidence(path)
            evidence.record("boot_id_before_reboot", boot_id="boot-a")

            fsync_calls = []

            def tracking_fsync(fd):
                fsync_calls.append(fd)

            with mock.patch("os.fsync", side_effect=tracking_fsync):
                evidence.flush()

            self.assertEqual(
                len(fsync_calls), 2,
                "Evidence.flush() must fsync the file and its parent directory",
            )

    def test_flush_writes_readable_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            evidence = harness.Evidence(path)
            evidence.record("phase", value=42)
            evidence.flush()
            data = path.read_text(encoding="utf-8")
            self.assertIn('"phase": "phase"', data)
            self.assertIn('"value": 42', data)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
