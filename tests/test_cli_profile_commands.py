from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import cli.main
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider

ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliProfileCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        input_text: str | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
            "PYTHONPATH": str(ROOT_DIR),
        }
        result = subprocess.run(
            [str(WATCHDOG), *args],
            input=input_text,
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        if check and result.returncode != 0:
            self.fail(f"command failed: {result.stderr}\nstdout={result.stdout}")
        return result

    def test_profile_add_uri_and_list_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(
                ["profile", "add", "--uri", "vless://uuid@example.com:443?encryption=none#demo"],
                tmp,
            )

            result = self.run_watchdog(["profile", "list", "--json"], tmp)

            profiles = json.loads(result.stdout)
            self.assertEqual(len(profiles), 1)
            self.assertEqual(profiles[0]["id"], "demo")
            self.assertEqual(profiles[0]["protocol"], "vless")
            self.assertEqual(profiles[0]["resilience_category"], "resilient")
            self.assertFalse(profiles[0]["in_rotation_pool"])
            self.assertFalse(profiles[0]["config_included"])
            self.assertNotIn("config", profiles[0])
            self.assertNotIn("uuid", result.stdout)

    def test_profile_list_human_groups_by_source_and_summarizes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_store = ProfileStore(Path(tmp) / "profiles.json")
            provider_store = ProviderStore(Path(tmp) / "providers.json")
            provider_store.add(
                Provider(
                    id="provider-one",
                    name="Provider One",
                    url="https://provider.example/token",
                    profiles=["provider-one:very-long-provider-node-id-that-should-truncate"],
                )
            )
            profile_store.add(
                Profile(
                    id="manual-profile",
                    name="Manual Profile",
                    protocol=ProtocolType.VLESS,
                    config={"host": "manual.example.com", "port": 443, "uuid": "manual-uuid"},
                    source=ProfileSource.MANUAL,
                    health_status="ok",
                )
            )
            profile_store.add(
                Profile(
                    id="provider-one:very-long-provider-node-id-that-should-truncate",
                    name="Provider Node",
                    protocol=ProtocolType.TROJAN,
                    config={"host": "provider.example.com", "port": 443, "password": "secret"},
                    source=ProfileSource.SUBSCRIPTION,
                    provider_id="provider-one",
                    in_rotation_pool=True,
                    health_status="unknown",
                )
            )

            result = self.run_watchdog(["profile", "list"], tmp)
            json_result = self.run_watchdog(["profile", "list", "--json"], tmp)

            self.assertIn("Profiles (all saved profiles)", result.stdout)
            self.assertIn("Total: 2 | Manual: 1 | Provider-owned: 1 | Enabled: 2 | Rotation: 1", result.stdout)
            self.assertIn("Health: ok=1 unknown=1 down=0 degraded=0", result.stdout)
            self.assertIn("Manual profiles", result.stdout)
            self.assertIn("Provider: Provider One (provider-one)", result.stdout)
            self.assertIn("Name", result.stdout)
            self.assertIn("Protocol", result.stdout)
            self.assertIn("ID", result.stdout)
            self.assertIn("Manual Profile", result.stdout)
            self.assertIn("Provider Node", result.stdout)
            self.assertIn("provider-one:very-long-provider...", result.stdout)
            self.assertNotIn("very-long-provider-node-id-that-should-truncate", result.stdout)
            profiles = json.loads(json_result.stdout)
            self.assertEqual(
                profiles[1]["id"],
                "provider-one:very-long-provider-node-id-that-should-truncate",
            )
            self.assertNotIn("secret", json_result.stdout)

    def test_profile_list_wide_keeps_full_human_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_store = ProfileStore(Path(tmp) / "profiles.json")
            profile_store.add(
                Profile(
                    id="manual-profile-with-a-very-long-id",
                    name="Manual",
                    protocol=ProtocolType.VLESS,
                    config={"host": "manual.example.com", "port": 443, "uuid": "manual-uuid"},
                    source=ProfileSource.MANUAL,
                )
            )

            result = self.run_watchdog(["profile", "list", "--wide"], tmp)

            self.assertIn("manual-profile-with-a-very-long-id", result.stdout)

    def test_profile_add_file_and_list_pool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_file = Path(tmp) / "profile.txt"
            profile_file.write_text("trojan://secret@example.com:443#trojan-demo", encoding="utf-8")
            self.run_watchdog(["profile", "add", "--file", str(profile_file)], tmp)
            self.run_watchdog(["profile", "rotation", "trojan-demo", "--enable"], tmp)

            result = self.run_watchdog(["profile", "list", "--pool", "--json"], tmp)

            profiles = json.loads(result.stdout)
            self.assertEqual([profile["id"] for profile in profiles], ["trojan-demo"])
            self.assertTrue(profiles[0]["in_rotation_pool"])
            self.assertEqual(profiles[0]["resilience_category"], "resilient")

    def test_profile_add_text_from_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["profile", "add", "--text"],
                tmp,
                input_text="hy2://password@example.com:443?sni=example.com#hy2-demo",
            )

            self.assertIn("Imported 1 profile(s).", result.stdout)
            listed = self.run_watchdog(["profile", "list", "--json"], tmp)
            self.assertEqual(json.loads(listed.stdout)[0]["protocol"], "hysteria2")
            self.assertNotIn("password", listed.stdout)

    def test_profile_add_empty_uri_reports_parse_error_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["profile", "add", "--uri", ""], tmp, check=False)

            self.assertEqual(result.stdout, "")
            self.assertEqual(result.returncode, 65)
            self.assertIn("unsupported URI scheme: missing", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_profile_add_duplicate_uri_fails_without_secret_leak(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            uri = "vless://secret-uuid@example.com:443?encryption=none#demo"
            self.run_watchdog(["profile", "add", "--uri", uri], tmp)

            result = self.run_watchdog(["profile", "add", "--uri", uri], tmp, check=False)

            self.assertEqual(result.stdout, "")
            self.assertEqual(result.returncode, 65)
            self.assertIn("profile already exists: demo", result.stderr)
            self.assertNotIn("secret-uuid", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_profile_enable_disable_rotation_and_remove(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(
                ["profile", "add", "--uri", "vless://uuid@example.com:443?encryption=none#demo"],
                tmp,
            )
            self.run_watchdog(["profile", "disable", "demo"], tmp)
            self.run_watchdog(["profile", "rotation", "demo", "--on"], tmp)

            profiles = json.loads(self.run_watchdog(["profile", "list", "--json"], tmp).stdout)
            self.assertFalse(profiles[0]["enabled"])
            self.assertTrue(profiles[0]["in_rotation_pool"])

            self.run_watchdog(["profile", "enable", "demo"], tmp)
            self.run_watchdog(["profile", "rotation", "demo", "--off"], tmp)
            profiles = json.loads(self.run_watchdog(["profile", "list", "--json"], tmp).stdout)
            self.assertTrue(profiles[0]["enabled"])
            self.assertFalse(profiles[0]["in_rotation_pool"])

            removed = self.run_watchdog(["profile", "remove", "demo", "--json"], tmp)
            removed_data = json.loads(removed.stdout)
            self.assertEqual(removed_data["removed"]["id"], "demo")
            self.assertFalse(removed_data["rollback_point"]["raw_profile_config_included"])
            self.assertEqual(json.loads(self.run_watchdog(["profile", "list", "--json"], tmp).stdout), [])

    def test_profile_mutations_json_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            added = self.run_watchdog(
                ["profile", "add", "--uri", "trojan://secret-password@example.com:443#trojan-demo", "--json"],
                tmp,
            )
            disabled = self.run_watchdog(["profile", "disable", "trojan-demo", "--json"], tmp)
            rotation = self.run_watchdog(["profile", "rotation", "trojan-demo", "--enable", "--json"], tmp)

            for result in (added, disabled, rotation):
                self.assertNotIn("secret-password", result.stdout)
                self.assertNotIn('"config":', result.stdout)
            self.assertEqual(json.loads(added.stdout)["profiles"][0]["resilience_category"], "resilient")
            self.assertFalse(json.loads(disabled.stdout)["profile"]["enabled"])
            self.assertTrue(json.loads(rotation.stdout)["profile"]["in_rotation_pool"])

    def test_profile_add_json_does_not_prompt_for_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "WATCHDOGVPN_CONFIG_DIR": tmp,
                "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
            }
            with patch.dict("os.environ", env, clear=False), patch(
                "cli.main._prompt_rotation_pool",
                side_effect=AssertionError("json profile add must not prompt"),
            ), redirect_stdout(StringIO()) as stdout:
                rc = cli.main.main([
                    "profile",
                    "add",
                    "--uri",
                    "vless://uuid@example.com:443?encryption=none#json-demo",
                    "--json",
                ])

            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["profiles"][0]["id"], "json-demo")
            self.assertFalse(payload["profiles"][0]["in_rotation_pool"])

    def test_profile_missing_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["profile", "enable", "missing"], tmp, check=False)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("profile not found: missing", result.stderr)
            self.assertIn("watchdog profile list", result.stderr)

    def test_profile_list_persistent_validation_error_has_no_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profiles_file = Path(tmp) / "profiles.json"
            profiles_file.write_text(
                json.dumps(
                    [
                        {
                            "id": "bad",
                            "name": "bad",
                            "protocol": "vless",
                            "config": {},
                            "source": "manual",
                            "failure_count": 1,
                        }
                    ]
                ),
                encoding="utf-8",
            )

            result = self.run_watchdog(["profile", "list", "--json"], tmp, check=False)

            self.assertEqual(result.returncode, 70)
            self.assertIn("profile contains unsupported fields: failure_count", result.stdout)
            self.assertNotIn("Traceback", result.stdout)
            self.assertNotIn("Traceback", result.stderr)

    def test_profile_add_clipboard_uses_manual_provider(self) -> None:
        profile = Profile(
            id="clip-demo",
            name="clip-demo",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
        )
        with patch("cli.main.ManualProvider") as provider_cls:
            provider = provider_cls.return_value
            provider.from_clipboard.return_value = profile
            provider.last_imported = [profile]

            with redirect_stdout(StringIO()):
                result = cli.main.main(["profile", "add", "--clipboard"])

        self.assertEqual(result, 0)
        provider.from_clipboard.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
