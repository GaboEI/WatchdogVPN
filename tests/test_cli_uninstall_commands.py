from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

import cli.main
from config.app_config import AppConfig
from config.backup_manager import BACKUP_ENCRYPTION_SUPPORTED, BackupManager, BackupValidationError
from config.profile_store import ProfileStore
from models.profile import Profile, ProfileSource, ProtocolType


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliUninstallCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: Path,
        script: Path,
        *,
        check: bool = True,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": str(tmp / "config"),
            "WATCHDOGVPN_UNINSTALL_SCRIPT": str(script),
            "PYTHONPATH": str(ROOT_DIR),
        }
        if extra_env:
            env.update(extra_env)
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

    def make_script(self, tmp: Path) -> tuple[Path, Path]:
        script = tmp / "uninstall.sh"
        log = tmp / "uninstall-args.json"
        script.write_text(
            "\n".join(
                [
                    "#!/usr/bin/env bash",
                    "set -euo pipefail",
                    f"export WATCHDOGVPN_TEST_UNINSTALL_ARG_LOG={str(log)!r}",
                    "python3 - \"$@\" <<'PY'",
                    "import json",
                    "import os",
                    "import sys",
                    "with open(os.environ['WATCHDOGVPN_TEST_UNINSTALL_ARG_LOG'], 'w', encoding='utf-8') as handle:",
                    "    handle.write(json.dumps(sys.argv[1:]))",
                    "PY",
                    "printf 'uninstall args: %s\\n' \"$*\"",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script, log

    def seed_config(self, config_dir: Path) -> None:
        config_dir.mkdir(parents=True, exist_ok=True)
        AppConfig(config_dir / "config.toml").save(
            AppConfig(config_dir / "config.toml").load()
        )
        ProfileStore(config_dir / "profiles.json").add(
            Profile(
                id="uninstall-profile",
                name="Uninstall Profile",
                protocol=ProtocolType.TROJAN,
                config={"host": "example.com", "port": 443, "password": "secret"},
                source=ProfileSource.MANUAL,
            )
        )

    def test_uninstall_requires_explicit_mode_when_noninteractive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script, log = self.make_script(tmp)

            result = self.run_watchdog(["uninstall", "--yes"], tmp, script, check=False)

            self.assertEqual(result.returncode, 65)
            self.assertIn("--keep-data", result.stderr)
            self.assertFalse(log.exists())

    def test_keep_data_calls_uninstaller_without_purge_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script, log = self.make_script(tmp)

            result = self.run_watchdog(
                ["uninstall", "--keep-data", "--yes", "--dry-run"],
                tmp,
                script,
            )

            self.assertIn("Mode: keep-data", result.stdout)
            self.assertFalse(log.exists())

    def test_real_uninstall_requires_yes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script, log = self.make_script(tmp)

            result = self.run_watchdog(
                ["uninstall", "--keep-data"],
                tmp,
                script,
                check=False,
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("requires --yes", result.stderr)
            self.assertFalse(log.exists())

    def test_json_output_remains_single_valid_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script, _log = self.make_script(tmp)

            result = self.run_watchdog(
                ["uninstall", "--keep-data", "--yes", "--dry-run", "--json"],
                tmp,
                script,
            )

            data = json.loads(result.stdout)
            self.assertEqual(data["mode"], "keep-data")
            self.assertIsNone(data["uninstall_exit_code"])
            self.assertEqual(data["uninstall_stdout"], "")
            self.assertIn("product_managed_files", data["contract"])
            self.assertEqual(data["contract"]["backups"], "internal recovery backups preserved")

    def test_uninstall_resolves_installed_runtime_without_cwd_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            runtime_root = tmp / "runtime"
            (runtime_root / "cli").mkdir(parents=True)
            script = runtime_root / "uninstall.sh"
            script.write_text("#!/usr/bin/env bash\nprintf 'installed uninstall ok\\n'\n", encoding="utf-8")
            script.chmod(0o755)
            unrelated_cwd = tmp / "home"
            unrelated_cwd.mkdir()

            env = {
                "PATH": os.environ.get("PATH", ""),
                "WATCHDOGVPN_CONFIG_DIR": str(tmp / "config"),
            }
            with (
                patch.dict(os.environ, env, clear=True),
                patch.object(cli.main, "__file__", str(runtime_root / "cli" / "main.py")),
                patch("pathlib.Path.cwd", return_value=unrelated_cwd),
                redirect_stdout(StringIO()) as stdout,
            ):
                result = cli.main.main(["uninstall", "--keep-data", "--dry-run", "--json"])

        self.assertEqual(result, 0)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["command"], [str(script), "--dry-run"])
        self.assertIsNone(data["uninstall_exit_code"])

    def test_backup_first_exports_backup_before_uninstall(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script, log = self.make_script(tmp)
            config_dir = tmp / "config"
            self.seed_config(config_dir)
            backup = tmp / "uninstall-backup.zip"

            self.run_watchdog(
                [
                    "uninstall",
                    "--backup-first",
                    "--yes",
                    "--backup-output",
                    str(backup),
                ],
                tmp,
                script,
            )

            self.assertEqual(json.loads(log.read_text(encoding="utf-8")), ["--yes"])
            with ZipFile(backup) as archive:
                self.assertIn("manifest.json", archive.namelist())
                self.assertIn("profiles.json", archive.namelist())

    def test_delete_all_data_requires_delete_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script, log = self.make_script(tmp)

            result = self.run_watchdog(
                ["uninstall", "--delete-all-data", "--yes"],
                tmp,
                script,
                check=False,
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("--confirm-delete DELETE", result.stderr)
            self.assertFalse(log.exists())

    def test_delete_all_data_exports_pre_delete_backup_and_passes_purge_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script, log = self.make_script(tmp)
            config_dir = tmp / "config"
            self.seed_config(config_dir)
            backup = tmp / "pre-delete.zip"

            self.run_watchdog(
                [
                    "uninstall",
                    "--delete-all-data",
                    "--yes",
                    "--confirm-delete",
                    "DELETE",
                    "--backup-output",
                    str(backup),
                ],
                tmp,
                script,
            )

            self.assertEqual(
                json.loads(log.read_text(encoding="utf-8")),
                [
                    "--yes",
                    "--purge-config",
                    "--purge-logs",
                    "--purge-state",
                    "--confirm-delete",
                    "DELETE",
                ],
            )
            dry_run = self.run_watchdog(
                [
                    "uninstall",
                    "--delete-all-data",
                    "--dry-run",
                    "--json",
                ],
                tmp,
                script,
            )
            contract = json.loads(dry_run.stdout)["contract"]
            self.assertIn("explicit pre-delete export preserved", contract["backups"])
            self.assertIn("internal /var/backups/watchdogvpn copies removed", contract["backups"])
            with ZipFile(backup) as archive:
                manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest["reason"], "pre-uninstall-delete")

    def test_rejects_backup_output_inside_watchdogvpn_data_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script, log = self.make_script(tmp)
            inside_config = tmp / "config" / "backup.zip"

            result = self.run_watchdog(
                [
                    "uninstall",
                    "--backup-first",
                    "--yes",
                    "--backup-output",
                    str(inside_config),
                ],
                tmp,
                script,
                check=False,
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("outside WatchdogVPN-owned paths", result.stderr)
            self.assertFalse(log.exists())

    def test_rejects_explicit_export_inside_internal_backup_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script, log = self.make_script(tmp)

            result = self.run_watchdog(
                [
                    "uninstall",
                    "--delete-all-data",
                    "--yes",
                    "--confirm-delete",
                    "DELETE",
                    "--backup-output",
                    "/var/backups/watchdogvpn/pre-delete.zip",
                ],
                tmp,
                script,
                check=False,
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("outside WatchdogVPN-owned paths", result.stderr)
            self.assertFalse(log.exists())

    @unittest.skipUnless(BACKUP_ENCRYPTION_SUPPORTED, "cryptography dependency unavailable")
    def test_backup_first_can_encrypt_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            script, _log = self.make_script(tmp)
            config_dir = tmp / "config"
            self.seed_config(config_dir)
            backup = tmp / "encrypted-uninstall.zip"

            self.run_watchdog(
                [
                    "uninstall",
                    "--backup-first",
                    "--yes",
                    "--backup-output",
                    str(backup),
                    "--encrypt-backup",
                    "--backup-password-env",
                    "WATCHDOGVPN_TEST_BACKUP_PASSWORD",
                ],
                tmp,
                script,
                extra_env={"WATCHDOGVPN_TEST_BACKUP_PASSWORD": "secret-passphrase"},
            )

            manager = BackupManager(config_dir=config_dir)
            with self.assertRaisesRegex(BackupValidationError, "password"):
                manager.inspect_backup(backup)
            parsed = manager.inspect_backup(backup, password="secret-passphrase")
            self.assertIn("profiles.json", parsed.sections)


if __name__ == "__main__":
    unittest.main()
