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

import cli.main
from app_policy.store import AppPolicyStore
from config.app_config import AppConfig
from config.dns_policy_store import DNSPolicyStore
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.state_manager import StateManager


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliSetupDoctorCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        *,
        check: bool = True,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_CONFIG_FILE": str(Path(tmp) / "config.toml"),
            "WATCHDOGVPN_STATE_FILE": str(Path(tmp) / "state.toml"),
            "WATCHDOGVPN_DNS_POLICY_FILE": str(Path(tmp) / "dns-policy.json"),
            "WATCHDOGVPN_APP_POLICY_FILE": str(Path(tmp) / "app-policy.json"),
            "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
            "WATCHDOGVPN_PROVIDERS_FILE": str(Path(tmp) / "providers.json"),
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

    def test_setup_dry_run_does_not_write_profile_or_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                [
                    "setup",
                    "--dry-run",
                    "--json",
                    "--language",
                    "es",
                    "--profile-uri",
                    "vless://uuid@example.com:443?encryption=none#demo",
                    "--provider-url",
                    "https://example.com/sub",
                    "--provider-name",
                    "demo-provider",
                    "--dns-mode",
                    "off",
                ],
                tmp,
            )

            data = json.loads(result.stdout)
            self.assertTrue(data["dry_run"])
            self.assertTrue(data["has_changes"])
            self.assertFalse(data["applied"])
            self.assertEqual(data["outcome"], "dry_run")
            self.assertFalse(data["network_fetch_performed"])
            self.assertFalse(data["runtime_action_executed"])
            self.assertFalse((Path(tmp) / "profiles.json").exists())
            self.assertFalse((Path(tmp) / "providers.json").exists())

    def test_setup_profile_file_imports_one_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_file = Path(tmp) / "profile.conf"
            profile_file.write_text(
                "[Interface]\nPrivateKey = test-private-key\nAddress = 10.8.1.5/32\n"
                "\n[Peer]\nPublicKey = test-public-key\nEndpoint = wg.example.com:51820\n"
                "AllowedIPs = 0.0.0.0/0\n",
                encoding="utf-8",
            )
            result = self.run_watchdog(
                [
                    "setup",
                    "--yes",
                    "--acknowledge-backup-warning",
                    "--profile-file",
                    str(profile_file),
                    "--json",
                ],
                tmp,
            )

            data = json.loads(result.stdout)
            self.assertEqual(data["operations"][0]["action"], "import-profile-file")
            self.assertEqual(len(ProfileStore(Path(tmp) / "profiles.json").list()), 1)
            self.assertNotIn("test-private-key", result.stdout)

    def test_setup_amneziawg_file_reports_missing_runtime_in_dry_run(self) -> None:
        raw_profile = """[Interface]
PrivateKey = test-private-key
Address = 10.8.1.5/32
Jc = 4
Jmin = 10
Jmax = 20

[Peer]
PublicKey = test-public-key
Endpoint = awg.example.com:51820
AllowedIPs = 0.0.0.0/0
"""
        guidance = {
            "available": False,
            "blocked": False,
            "distro": "arch",
            "distro_adapter": "arch",
            "tools_available": False,
            "kernel_module_available": False,
            "userspace_fallback_available": False,
            "commands": [{"command": "safe-command", "purpose": "safe"}],
            "script": "safe-command",
            "certified_on_opensuse_leap": False,
            "compatibility": {"status": "not_verified", "note": "not verified"},
            "releases": [],
            "sources": ["https://example.invalid/tools", "https://example.invalid/go"],
            "message": "AmneziaWG profile saved, but its local runtime is not ready yet.",
            "executed_by_watchdogvpn": False,
        }
        with tempfile.TemporaryDirectory() as tmp:
            profile_file = Path(tmp) / "amneziawg.conf"
            profile_file.write_text(raw_profile, encoding="utf-8")
            env = {
                "WATCHDOGVPN_CONFIG_DIR": tmp,
                "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
            }
            with patch.dict(os.environ, env, clear=False), patch(
                "cli.main.import_guidance_payload", return_value=guidance
            ) as guidance_check, redirect_stdout(StringIO()) as stdout:
                rc = cli.main.main(
                    ["setup", "--dry-run", "--profile-file", str(profile_file), "--json"]
                )

        self.assertEqual(rc, 0)
        guidance_check.assert_called_once_with()
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["amneziawg_dependency"]["commands"], [{"command": "safe-command", "purpose": "safe"}])
        self.assertNotIn("test-private-key", stdout.getvalue())

    def test_setup_apply_writes_local_state_and_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                [
                    "setup",
                    "--yes",
                    "--acknowledge-backup-warning",
                    "--json",
                    "--language",
                    "es",
                    "--autostart",
                    "enable",
                    "--autoconnect",
                    "enable",
                    "--kill-switch",
                    "enable",
                    "--dns-mode",
                    "off",
                    "--app-policy",
                    "enable",
                    "--app-policy-mode",
                    "whitelist",
                    "--app-policy-default-action",
                    "block",
                    "--profile-uri",
                    "trojan://secret@example.com:443#demo",
                    "--provider-url",
                    "https://example.com/sub",
                    "--provider-name",
                    "demo-provider",
                ],
                tmp,
            )

            data = json.loads(result.stdout)
            self.assertTrue(data["has_changes"])
            self.assertTrue(data["applied"])
            self.assertEqual(data["outcome"], "applied")
            self.assertTrue(Path(data["backup_path"]).exists())
            state = StateManager(Path(tmp) / "state.toml").load()
            self.assertEqual(state["selected_language"], "es")
            self.assertTrue(state["app_autostart_enabled"])
            self.assertTrue(state["vpn_autoconnect_enabled"])
            self.assertTrue(AppConfig(Path(tmp) / "config.toml").load()["kill_switch"]["enabled"])
            self.assertEqual(DNSPolicyStore(Path(tmp) / "dns-policy.json").load().mode.value, "off")
            policy = AppPolicyStore(Path(tmp) / "app-policy.json").load()
            self.assertTrue(policy.enabled)
            self.assertEqual(policy.mode.value, "whitelist")
            self.assertEqual(policy.default_action.value, "block")
            self.assertEqual(len(ProfileStore(Path(tmp) / "profiles.json").list()), 1)
            providers = ProviderStore(Path(tmp) / "providers.json").list()
            self.assertEqual(len(providers), 1)
            self.assertEqual(providers[0].name, "demo-provider")
            self.assertEqual(providers[0].profiles, [])

    def test_setup_exact_repeat_is_noop_without_backup_or_store_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            requested = [
                "--json",
                "--language",
                "es",
                "--autostart",
                "enable",
                "--autoconnect",
                "enable",
                "--kill-switch",
                "enable",
                "--dns-mode",
                "off",
                "--app-policy",
                "enable",
                "--app-policy-mode",
                "whitelist",
                "--app-policy-default-action",
                "block",
                "--profile-uri",
                "trojan://secret@example.com:443#demo",
                "--provider-url",
                "https://example.com/sub",
                "--provider-name",
                "demo-provider",
            ]
            first = self.run_watchdog(
                ["setup", "--yes", "--acknowledge-backup-warning", *requested],
                tmp,
            )
            first_data = json.loads(first.stdout)
            self.assertEqual(first_data["outcome"], "applied")

            provider_store = ProviderStore(Path(tmp) / "providers.json")
            provider = provider_store.list()[0]
            provider.rotation_enabled = True
            provider.metadata = {"quota_bytes": 1024}
            provider_store.update(provider)

            store_paths = [
                Path(tmp) / "state.toml",
                Path(tmp) / "config.toml",
                Path(tmp) / "dns-policy.json",
                Path(tmp) / "app-policy.json",
                Path(tmp) / "profiles.json",
                Path(tmp) / "providers.json",
            ]
            before = {
                path: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in store_paths
            }
            backups_before = sorted((Path(tmp) / "backups").glob("watchdogvpn-pre-setup-*.zip"))

            repeated = self.run_watchdog(["setup", *requested], tmp)

            repeated_data = json.loads(repeated.stdout)
            self.assertFalse(repeated_data["has_changes"])
            self.assertFalse(repeated_data["applied"])
            self.assertEqual(repeated_data["outcome"], "no_changes")
            self.assertIsNone(repeated_data["backup_path"])
            self.assertEqual(repeated_data["operations"], [])
            self.assertEqual(repeated_data["sections"], [])
            self.assertEqual(
                sorted((Path(tmp) / "backups").glob("watchdogvpn-pre-setup-*.zip")),
                backups_before,
            )
            for path, (content, mtime_ns) in before.items():
                self.assertEqual(path.read_bytes(), content)
                self.assertEqual(path.stat().st_mtime_ns, mtime_ns)
            preserved_provider = provider_store.list()[0]
            self.assertTrue(preserved_provider.rotation_enabled)
            self.assertEqual(preserved_provider.metadata, {"quota_bytes": 1024})

    def test_setup_partial_repeat_reports_only_effective_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(
                [
                    "setup",
                    "--yes",
                    "--acknowledge-backup-warning",
                    "--json",
                    "--language",
                    "es",
                    "--autostart",
                    "enable",
                ],
                tmp,
            )

            result = self.run_watchdog(
                [
                    "setup",
                    "--yes",
                    "--acknowledge-backup-warning",
                    "--json",
                    "--language",
                    "es",
                    "--autostart",
                    "disable",
                ],
                tmp,
            )

            data = json.loads(result.stdout)
            self.assertEqual(data["outcome"], "applied")
            self.assertEqual(data["sections"], ["selection-state"])
            self.assertEqual(
                data["operations"],
                [
                    {
                        "target": "selection-state",
                        "key": "app_autostart_enabled",
                        "value": False,
                    }
                ],
            )
            state = StateManager(Path(tmp) / "state.toml").load()
            self.assertEqual(state["selected_language"], "es")
            self.assertFalse(state["app_autostart_enabled"])

    def test_setup_rejects_non_https_provider_before_backup_or_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                [
                    "setup",
                    "--yes",
                    "--acknowledge-backup-warning",
                    "--provider-url",
                    "file:///etc/passwd",
                ],
                tmp,
                check=False,
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("https required", result.stderr)
            self.assertFalse((Path(tmp) / "providers.json").exists())
            self.assertFalse((Path(tmp) / "backups").exists())

    def test_setup_requires_yes_and_backup_ack_for_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_yes = self.run_watchdog(
                ["setup", "--language", "es"],
                tmp,
                check=False,
            )
            missing_ack = self.run_watchdog(
                ["setup", "--yes", "--language", "es"],
                tmp,
                check=False,
            )

        self.assertEqual(missing_yes.returncode, 65)
        self.assertIn("requires --yes", missing_yes.stderr)
        self.assertEqual(missing_ack.returncode, 65)
        self.assertIn("acknowledge-backup-warning", missing_ack.stderr)

    def test_doctor_json_wraps_script_without_shell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "doctor.sh"
            script.write_text("#!/usr/bin/env bash\nprintf 'doctor ok\\n'\n", encoding="utf-8")
            script.chmod(0o755)

            result = self.run_watchdog(
                ["doctor", "--doctor-script", str(script), "--json"],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["doctor_exit_code"], 0)
        self.assertEqual(data["doctor_stdout"], "doctor ok\n")
        self.assertTrue(data["read_only"])
        self.assertFalse(data["mutates_runtime"])

    def test_doctor_resolves_installed_runtime_without_cwd_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            runtime_root = tmp / "runtime"
            (runtime_root / "cli").mkdir(parents=True)
            script = runtime_root / "doctor.sh"
            script.write_text("#!/usr/bin/env bash\nprintf 'installed doctor ok\\n'\n", encoding="utf-8")
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
                result = cli.main.main(["doctor", "--json"])

        self.assertEqual(result, 0)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["command"], [str(script)])
        self.assertEqual(data["doctor_stdout"], "installed doctor ok\n")


if __name__ == "__main__":
    unittest.main()
