from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import cli.main
from config.profile_store import ProfileStore


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"

STUB_DOCTOR = (
    "#!/usr/bin/env bash\n"
    'printf \'doctor-ok count=%s\\n\' "${WATCHDOGVPN_AWG_PROFILE_COUNT:-unset}"\n'
)

READABLE_PROFILES = [
    {"id": "awg-1", "name": "WG server", "protocol": "amneziawg", "config": {}, "source": "manual"},
    {"id": "vless-1", "name": "VLESS server", "protocol": "vless", "config": {}, "source": "manual"},
]


class Task2375R6DoctorResilienceTests(unittest.TestCase):
    """T-PR23-07: doctor.sh must run even when the profile store cannot be read.

    The profile-store read only computes the AmneziaWG profile count, so a
    store failure must never block doctor.sh, must never report the count as 0,
    and must never surface a traceback.
    """

    def _env(self, tmp: str) -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", ""),
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_CONFIG_FILE": str(Path(tmp) / "config.toml"),
            "WATCHDOGVPN_STATE_FILE": str(Path(tmp) / "state.toml"),
            "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
            "PYTHONPATH": str(ROOT_DIR),
        }

    def _stub(self, tmp: Path, *, sentinel: bool = False) -> Path:
        script = tmp / "doctor.sh"
        body = STUB_DOCTOR
        if sentinel:
            body += 'touch "$DOCTOR_SENTINEL"\n'
        script.write_text(body, encoding="utf-8")
        script.chmod(0o755)
        return script

    def _run_watchdog(self, tmp: str, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(WATCHDOG), *args],
            text=True,
            capture_output=True,
            env=self._env(tmp),
            check=False,
        )

    def _run_main(self, args: list[str]) -> tuple[int, str, str]:
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def _assert_doctor_ran_without_traceback(
        self,
        stdout: str,
        stderr: str,
        returncode: int,
    ) -> None:
        self.assertIn("doctor-ok count=", stdout)
        self.assertNotIn("Traceback", stdout)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(returncode, 0)

    def test_doctor_human_readable_store_preserves_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._stub(tmp)
            (tmp / "profiles.json").write_text(json.dumps(READABLE_PROFILES), encoding="utf-8")
            result = self._run_watchdog(tmp_name, ["doctor", "--doctor-script", str(script)])
        self._assert_doctor_ran_without_traceback(result.stdout, result.stderr, result.returncode)
        self.assertIn("doctor-ok count=1", result.stdout)
        self.assertNotIn("Warning:", result.stderr)

    def test_doctor_json_readable_store_preserves_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._stub(tmp)
            (tmp / "profiles.json").write_text(json.dumps(READABLE_PROFILES), encoding="utf-8")
            result = self._run_watchdog(
                tmp_name, ["doctor", "--doctor-script", str(script), "--json"]
            )
        self._assert_doctor_ran_without_traceback(result.stdout, result.stderr, result.returncode)
        data = json.loads(result.stdout)
        self.assertEqual(data["doctor_exit_code"], 0)
        self.assertIn("doctor-ok count=1", data["doctor_stdout"])
        self.assertEqual(data["amneziawg_profile_count"], 1)
        self.assertEqual(data["profile_inventory"], "verified")
        self.assertNotIn("warnings", data)
        self.assertTrue(data["read_only"])
        self.assertFalse(data["mutates_runtime"])

    def test_doctor_human_corrupt_store_still_runs_doctor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._stub(tmp)
            (tmp / "profiles.json").write_text("{not-json", encoding="utf-8")
            result = self._run_watchdog(tmp_name, ["doctor", "--doctor-script", str(script)])
        self._assert_doctor_ran_without_traceback(result.stdout, result.stderr, result.returncode)
        self.assertIn("doctor-ok count=unknown", result.stdout)
        self.assertIn("Warning:", result.stderr)
        self.assertIn("could not be inspected", result.stderr)
        self.assertIn("inconclusive", result.stderr)
        self.assertIn("unknown, not zero", result.stderr)

    def test_doctor_json_corrupt_store_still_runs_doctor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._stub(tmp)
            (tmp / "profiles.json").write_text("{not-json", encoding="utf-8")
            result = self._run_watchdog(
                tmp_name, ["doctor", "--doctor-script", str(script), "--json"]
            )
        self._assert_doctor_ran_without_traceback(result.stdout, result.stderr, result.returncode)
        data = json.loads(result.stdout)
        self.assertEqual(data["doctor_exit_code"], 0)
        self.assertIn("doctor-ok count=unknown", data["doctor_stdout"])
        self.assertEqual(data["amneziawg_profile_count"], "unknown")
        self.assertNotEqual(data["amneziawg_profile_count"], 0)
        self.assertNotEqual(data["amneziawg_profile_count"], "0")
        self.assertEqual(data["profile_inventory"], "unverified")
        warnings = data["warnings"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("could not be inspected", warnings[0])
        self.assertIn("PersistentStoreError", warnings[0])
        self.assertIn("inconclusive", warnings[0])
        self.assertIn("unknown, not zero", warnings[0])

    def test_doctor_permission_error_store_still_runs_doctor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._stub(tmp)
            with patch.object(
                ProfileStore,
                "list",
                side_effect=PermissionError("synthetic unreadable profile store"),
            ):
                code, stdout, stderr = self._run_main(
                    ["doctor", "--doctor-script", str(script), "--json"]
                )
        self._assert_doctor_ran_without_traceback(stdout, stderr, code)
        data = json.loads(stdout)
        self.assertEqual(data["doctor_exit_code"], 0)
        self.assertIn("doctor-ok count=unknown", data["doctor_stdout"])
        self.assertEqual(data["amneziawg_profile_count"], "unknown")
        self.assertEqual(data["profile_inventory"], "unverified")
        self.assertIn("PermissionError", data["warnings"][0])
        self.assertIn("inconclusive", data["warnings"][0])

    def test_doctor_permission_error_store_human_warns_on_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._stub(tmp, sentinel=True)
            sentinel = tmp / "doctor-ran"
            with (
                patch.object(
                    ProfileStore,
                    "list",
                    side_effect=PermissionError("synthetic unreadable profile store"),
                ),
                patch.dict(os.environ, {"DOCTOR_SENTINEL": str(sentinel)}),
            ):
                code, stdout, stderr = self._run_main(["doctor", "--doctor-script", str(script)])
            self.assertTrue(sentinel.exists(), "doctor.sh must still be launched")
        self.assertNotIn("Traceback", stdout)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(code, 0)
        self.assertIn("Warning:", stderr)
        self.assertIn("could not be inspected", stderr)

    def test_doctor_corrupt_profile_item_still_runs_doctor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._stub(tmp)
            (tmp / "profiles.json").write_text(
                json.dumps([{"protocol": "amneziawg", "name": "broken", "source": "manual"}]),
                encoding="utf-8",
            )
            result = self._run_watchdog(
                tmp_name, ["doctor", "--doctor-script", str(script), "--json"]
            )
        self._assert_doctor_ran_without_traceback(result.stdout, result.stderr, result.returncode)
        data = json.loads(result.stdout)
        self.assertEqual(data["amneziawg_profile_count"], "unknown")
        self.assertEqual(data["profile_inventory"], "unverified")
        self.assertIn("KeyError", data["warnings"][0])

    def test_doctor_unreadable_profile_item_type_error_still_runs_doctor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script = self._stub(tmp)
            (tmp / "profiles.json").write_text(json.dumps(["not-a-profile"]), encoding="utf-8")
            result = self._run_watchdog(
                tmp_name, ["doctor", "--doctor-script", str(script), "--json"]
            )
        self._assert_doctor_ran_without_traceback(result.stdout, result.stderr, result.returncode)
        data = json.loads(result.stdout)
        self.assertEqual(data["amneziawg_profile_count"], "unknown")
        self.assertEqual(data["profile_inventory"], "unverified")


if __name__ == "__main__":
    unittest.main()
