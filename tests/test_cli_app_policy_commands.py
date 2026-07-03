from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliAppPolicyCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_APP_POLICY_FILE": str(Path(tmp) / "app-policy.json"),
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

    def test_status_json_shows_default_disabled_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["app-policy", "status", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertTrue(data["valid"])
        self.assertFalse(data["policy"]["enabled"])
        self.assertEqual(data["policy"]["mode"], "blacklist")
        self.assertEqual(data["rule_count"], 0)

    def test_enable_disable_and_mode_persist_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["app-policy", "enable"], tmp)
            self.run_watchdog(["app-policy", "mode", "whitelist"], tmp)
            result = self.run_watchdog(["app-policy", "status", "--json"], tmp)

            data = json.loads(result.stdout)
            self.assertTrue(data["policy"]["enabled"])
            self.assertEqual(data["policy"]["mode"], "whitelist")

            self.run_watchdog(["app-policy", "disable"], tmp)
            result = self.run_watchdog(["app-policy", "status", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertFalse(data["policy"]["enabled"])
        self.assertEqual(data["policy"]["mode"], "whitelist")

    def test_add_process_name_rule_and_remove_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                [
                    "app-policy",
                    "add",
                    "--process-name",
                    "curl",
                    "--action",
                    "block",
                    "--json",
                ],
                tmp,
            )
            added = json.loads(result.stdout)["added"]
            rule_id = added["id"]
            self.assertEqual(added["action"], "block")
            self.assertEqual(added["match"], {"process_name": ["curl"]})

            status = self.run_watchdog(["app-policy", "status", "--json"], tmp)
            status_data = json.loads(status.stdout)
            self.assertEqual(status_data["rule_count"], 1)
            self.assertEqual(status_data["rules"][0]["match_confidence"], "low")

            self.run_watchdog(["app-policy", "remove", rule_id], tmp)
            status = self.run_watchdog(["app-policy", "status", "--json"], tmp)

        self.assertEqual(json.loads(status.stdout)["rule_count"], 0)

    def test_add_process_path_rule_with_custom_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                [
                    "app-policy",
                    "add",
                    "--process-path",
                    "/usr/bin/firefox",
                    "--action",
                    "direct",
                    "--id",
                    "firefox-direct",
                    "--json",
                ],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["added"]["id"], "firefox-direct")
        self.assertEqual(data["added"]["match"], {"process_path": ["/usr/bin/firefox"]})
        self.assertEqual(data["policy"]["rules"][0]["match_confidence"], "high")

    def test_rejects_auto_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                [
                    "app-policy",
                    "add",
                    "--process-name",
                    "curl",
                    "--action",
                    "auto",
                ],
                tmp,
                check=False,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)

    def test_status_json_reports_invalid_policy_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "app-policy.json"
            policy_path.write_text("{", encoding="utf-8")

            result = self.run_watchdog(["app-policy", "status", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertFalse(data["valid"])
        self.assertIn("invalid JSON", data["error"])
        self.assertEqual(data["policy"]["default_action"], "block")


if __name__ == "__main__":
    unittest.main()
