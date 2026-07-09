from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from config.profile_store import ProfileStore
from models.profile import Profile, ProfileSource, ProtocolType


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliBackupCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
            "PYTHONPATH": str(ROOT_DIR),
        }
        result = subprocess.run(
            [str(WATCHDOG), *args],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        if check and result.returncode != 0:
            self.fail(f"command failed: {result.stderr}\nstdout={result.stdout}")
        return result

    def seed_profile(self, tmp: str) -> None:
        ProfileStore(Path(tmp) / "profiles.json").add(
            Profile(
                id="backup-profile",
                name="Backup Profile",
                protocol=ProtocolType.TROJAN,
                config={"host": "example.com", "password": "secret"},
                source=ProfileSource.MANUAL,
            )
        )

    def test_backup_create_json_writes_selected_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_profile(tmp)
            backup = Path(tmp) / "profiles.zip"

            result = self.run_watchdog(
                [
                    "backup",
                    "create",
                    "--output",
                    str(backup),
                    "--section",
                    "profiles",
                    "--json",
                ],
                tmp,
            )

            data = json.loads(result.stdout)
            self.assertEqual(data["path"], str(backup))
            self.assertEqual(data["sections"], ["profiles"])
            self.assertTrue(data["normal_backup"])
            self.assertFalse(data["support_export"])
            self.assertFalse(data["redacted_export"])
            self.assertTrue(backup.exists())

    def test_backup_inspect_json_validates_manifest_without_dumping_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_profile(tmp)
            backup = Path(tmp) / "profiles.zip"
            self.run_watchdog(
                ["backup", "export", "--output", str(backup), "--section", "profiles"],
                tmp,
            )

            result = self.run_watchdog(["backup", "inspect", str(backup), "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertTrue(data["valid"])
        self.assertEqual(data["sections"], ["profiles"])
        self.assertNotIn("backup-profile", result.stdout)
        self.assertNotIn("secret", result.stdout)

    def test_backup_restore_dry_run_validates_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = Path(tmp) / "target"
            source.mkdir()
            target.mkdir()
            self.seed_profile(str(source))
            backup = Path(tmp) / "profiles.zip"
            self.run_watchdog(
                ["backup", "create", "--output", str(backup), "--section", "profiles"],
                str(source),
            )

            result = self.run_watchdog(
                [
                    "backup",
                    "restore",
                    str(backup),
                    "--section",
                    "profiles",
                    "--dry-run",
                    "--json",
                ],
                str(target),
            )

            data = json.loads(result.stdout)
            self.assertTrue(data["dry_run"])
            self.assertFalse(data["restore_would_write"])
            self.assertIsNone(data["pre_restore_backup"])
            self.assertFalse((target / "profiles.json").exists())

    def test_backup_restore_replace_requires_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.seed_profile(tmp)
            backup = Path(tmp) / "profiles.zip"
            self.run_watchdog(
                ["backup", "create", "--output", str(backup), "--section", "profiles"],
                tmp,
            )

            result = self.run_watchdog(
                ["backup", "import", str(backup), "--section", "profiles"],
                tmp,
                check=False,
            )

        self.assertEqual(result.returncode, 70)
        self.assertIn("RESTORE-WATCHDOGVPN-BACKUP", result.stderr)


if __name__ == "__main__":
    unittest.main()
