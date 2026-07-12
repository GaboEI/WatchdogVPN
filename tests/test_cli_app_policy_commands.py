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

    def test_mutations_return_backup_and_rollback_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["app-policy", "enable", "--json"], tmp)
            data = json.loads(result.stdout)
            backup_exists = Path(data["backup_path"]).exists()

        self.assertTrue(backup_exists)
        self.assertEqual(data["rollback_point"]["kind"], "section-backup")
        self.assertEqual(data["rollback_point"]["section"], "app-policy")

    def test_default_action_persists_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["app-policy", "default-action", "direct", "--json"],
                tmp,
            )
            data = json.loads(result.stdout)
            self.assertEqual(data["policy"]["default_action"], "direct")

            result = self.run_watchdog(["app-policy", "status", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertEqual(data["policy"]["default_action"], "direct")

    def test_default_action_rejects_invalid_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["app-policy", "default-action", "auto"],
                tmp,
                check=False,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)

    def test_default_direct_plus_app_current_can_be_configured_with_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["app-policy", "enable"], tmp)
            self.run_watchdog(["app-policy", "mode", "blacklist"], tmp)
            self.run_watchdog(["app-policy", "default-action", "direct"], tmp)
            self.run_watchdog(
                [
                    "app-policy",
                    "add",
                    "--process-path",
                    "/usr/bin/python3.14",
                    "--action",
                    "current",
                    "--id",
                    "python-current",
                ],
                tmp,
            )
            result = self.run_watchdog(["app-policy", "status", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertTrue(data["policy"]["enabled"])
        self.assertEqual(data["policy"]["mode"], "blacklist")
        self.assertEqual(data["policy"]["default_action"], "direct")
        self.assertEqual(data["rules"][0]["id"], "python-current")
        self.assertEqual(data["rules"][0]["action"], "current")
        self.assertEqual(data["rules"][0]["match"], {"process_path": ["/usr/bin/python3.14"]})

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
            added_data = json.loads(result.stdout)
            rule_id = added["id"]
            added_backup_exists = Path(added_data["backup_path"]).exists()
            self.assertEqual(added["action"], "block")
            self.assertEqual(added["match"], {"process_name": ["curl"]})

            status = self.run_watchdog(["app-policy", "status", "--json"], tmp)
            status_data = json.loads(status.stdout)
            self.assertEqual(status_data["rule_count"], 1)
            self.assertEqual(status_data["rules"][0]["match_confidence"], "low")

            removed = self.run_watchdog(["app-policy", "remove", rule_id, "--json"], tmp)
            removed_data = json.loads(removed.stdout)
            removed_backup_exists = Path(removed_data["backup_path"]).exists()
            status = self.run_watchdog(["app-policy", "status", "--json"], tmp)

        self.assertTrue(added_backup_exists)
        self.assertTrue(removed_backup_exists)
        self.assertEqual(json.loads(status.stdout)["rule_count"], 0)

    def test_duplicate_rule_id_returns_recovery_hint_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(
                [
                    "app-policy",
                    "add",
                    "--process-name",
                    "curl",
                    "--action",
                    "block",
                    "--id",
                    "curl-block",
                ],
                tmp,
            )
            result = self.run_watchdog(
                [
                    "app-policy",
                    "add",
                    "--process-name",
                    "curl",
                    "--action",
                    "block",
                    "--id",
                    "curl-block",
                ],
                tmp,
                check=False,
            )

        self.assertEqual(result.returncode, 65)
        self.assertIn("watchdog app-policy status", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_add_group_action_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                [
                    "app-policy",
                    "add",
                    "--process-name",
                    "curl",
                    "--action",
                    "group:phase14-vm",
                    "--id",
                    "curl-phase14",
                    "--json",
                ],
                tmp,
            )

            added = json.loads(result.stdout)["added"]
            self.assertEqual(added["id"], "curl-phase14")
            self.assertEqual(added["action"], "group:phase14-vm")

    def test_add_group_action_rule_human_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                [
                    "app-policy",
                    "add",
                    "--process-name",
                    "curl",
                    "--action",
                    "group:phase14-vm",
                    "--id",
                    "curl-phase14",
                ],
                tmp,
            )

        self.assertIn("Added app policy rule: curl-phase14", result.stdout)
        self.assertIn("Action: group:phase14-vm", result.stdout)

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

        self.assertEqual(result.returncode, 70)
        self.assertIn("rule.action action 'auto' is scheduled for later multi-outbound support", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_status_json_reports_invalid_policy_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "app-policy.json"
            policy_path.write_text("{", encoding="utf-8")

            result = self.run_watchdog(["app-policy", "status", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertFalse(data["valid"])
        self.assertIn("invalid JSON", data["error"])
        self.assertEqual(data["policy"]["default_action"], "block")

    def test_add_process_path_regex_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                [
                    "app-policy",
                    "add",
                    "--process-path-regex",
                    r"^/usr/bin/(curl|wget)$",
                    "--action",
                    "block",
                    "--json",
                ],
                tmp,
            )

            data = json.loads(result.stdout)
            added = data["added"]
            self.assertEqual(added["match"], {"process_path_regex": [r"^/usr/bin/(curl|wget)$"]})
            self.assertEqual(data["policy"]["rules"][0]["match_confidence"], "medium")

    def test_add_rejects_invalid_process_path_regex_without_mutating_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["app-policy", "add", "--process-path-regex", "[", "--action", "block"],
                tmp,
                check=False,
            )

            self.assertEqual(result.returncode, 70)
            self.assertIn("invalid regex", result.stderr)

            status = self.run_watchdog(["app-policy", "status", "--json"], tmp)
            self.assertEqual(json.loads(status.stdout)["rule_count"], 0)

    def test_add_user_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["app-policy", "add", "--user", "vpnuser", "--action", "block", "--json"],
                tmp,
            )

            data = json.loads(result.stdout)
            added = data["added"]
            self.assertEqual(added["match"], {"user": ["vpnuser"]})
            self.assertEqual(data["policy"]["rules"][0]["match_confidence"], "medium")

    def test_add_user_id_rule_accepts_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["app-policy", "add", "--user-id", "0", "--action", "block", "--json"],
                tmp,
            )

            data = json.loads(result.stdout)
            added = data["added"]
            self.assertEqual(added["match"], {"user_id": [0]})
            self.assertEqual(data["policy"]["rules"][0]["match_confidence"], "high")

    def test_enable_disable_rule_toggles_single_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            added = self.run_watchdog(
                [
                    "app-policy",
                    "add",
                    "--process-name",
                    "curl",
                    "--action",
                    "block",
                    "--id",
                    "curl-block",
                ],
                tmp,
            )

            disabled = self.run_watchdog(
                ["app-policy", "disable-rule", "curl-block", "--json"], tmp
            )
            disabled_data = json.loads(disabled.stdout)
            self.assertFalse(disabled_data["policy"]["rules"][0]["enabled"])
            self.assertTrue(Path(disabled_data["backup_path"]).exists())

            enabled = self.run_watchdog(
                ["app-policy", "enable-rule", "curl-block", "--json"], tmp
            )
            enabled_data = json.loads(enabled.stdout)
            self.assertTrue(enabled_data["policy"]["rules"][0]["enabled"])

    def test_disable_rule_missing_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["app-policy", "disable-rule", "missing"], tmp, check=False
            )
            self.assertEqual(result.returncode, 65)
            self.assertIn("app policy rule not found: missing", result.stderr)


if __name__ == "__main__":
    unittest.main()
