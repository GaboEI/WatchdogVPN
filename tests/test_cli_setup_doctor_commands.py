from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

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
            self.assertFalse(data["applied"])
            self.assertFalse(data["network_fetch_performed"])
            self.assertFalse(data["runtime_action_executed"])
            self.assertFalse((Path(tmp) / "profiles.json").exists())
            self.assertFalse((Path(tmp) / "providers.json").exists())

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
            self.assertTrue(data["applied"])
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


if __name__ == "__main__":
    unittest.main()
