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
from models.profile import Profile, ProfileSource, ProtocolType

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
            self.assertFalse(profiles[0]["in_rotation_pool"])

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

    def test_profile_enable_disable_rotation_and_remove(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(
                ["profile", "add", "--uri", "vless://uuid@example.com:443?encryption=none#demo"],
                tmp,
            )
            self.run_watchdog(["profile", "disable", "demo"], tmp)
            self.run_watchdog(["profile", "rotation", "demo", "--enable"], tmp)

            profiles = json.loads(self.run_watchdog(["profile", "list", "--json"], tmp).stdout)
            self.assertFalse(profiles[0]["enabled"])
            self.assertTrue(profiles[0]["in_rotation_pool"])

            self.run_watchdog(["profile", "enable", "demo"], tmp)
            self.run_watchdog(["profile", "rotation", "demo", "--disable"], tmp)
            profiles = json.loads(self.run_watchdog(["profile", "list", "--json"], tmp).stdout)
            self.assertTrue(profiles[0]["enabled"])
            self.assertFalse(profiles[0]["in_rotation_pool"])

            self.run_watchdog(["profile", "remove", "demo"], tmp)
            self.assertEqual(json.loads(self.run_watchdog(["profile", "list", "--json"], tmp).stdout), [])

    def test_profile_missing_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["profile", "enable", "missing"], tmp, check=False)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("profile not found: missing", result.stderr)

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

            self.assertEqual(result.stdout, "")
            self.assertEqual(result.returncode, 70)
            self.assertIn("profile contains unsupported fields: failure_count", result.stderr)
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
