from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import cli.main
from config.provider_store import ProviderStore
from daemon.protocol import Response
from models.provider import Provider


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliNodeGroupCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
            "WATCHDOGVPN_NODE_GROUPS_FILE": str(Path(tmp) / "node_groups.json"),
            "WATCHDOGVPN_PROVIDERS_FILE": str(Path(tmp) / "providers.json"),
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

    def test_create_add_profile_select_and_list_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(
                ["profile", "add", "--uri", "vless://uuid@example.com:443?encryption=none#demo"],
                tmp,
            )
            created = self.run_watchdog(["node-group", "create", "paris", "--json"], tmp)
            added = self.run_watchdog(
                ["node-group", "add-profile", "paris", "demo", "--json"],
                tmp,
            )
            selected = self.run_watchdog(
                ["node-group", "select", "paris", "demo", "--json"],
                tmp,
            )

            data = json.loads(
                self.run_watchdog(["node-group", "list", "--json"], tmp).stdout
            )

            self.assertTrue(Path(json.loads(created.stdout)["backup_path"]).exists())
            self.assertEqual(json.loads(added.stdout)["rollback_point"]["section"], "node-groups")
            self.assertEqual(json.loads(selected.stdout)["selected_profile_id"], "demo")
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["name"], "paris")
            self.assertEqual(data[0]["member_profile_ids"], ["demo"])
            self.assertEqual(data[0]["selection_mode"], "manual")
            self.assertEqual(data[0]["manual_profile_id"], "demo")

    def test_select_auto_clears_manual_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(
                ["profile", "add", "--uri", "trojan://secret@example.com:443#demo"],
                tmp,
            )
            self.run_watchdog(["node-group", "create", "paris"], tmp)
            self.run_watchdog(["node-group", "select", "paris", "demo"], tmp)
            auto = self.run_watchdog(["node-group", "select", "paris", "auto", "--json"], tmp)

            data = json.loads(
                self.run_watchdog(["node-group", "list", "--json"], tmp).stdout
            )

            self.assertEqual(json.loads(auto.stdout)["selection"], "auto")
            self.assertTrue(Path(json.loads(auto.stdout)["backup_path"]).exists())
            self.assertEqual(data[0]["selection_mode"], "auto")
            self.assertIsNone(data[0]["manual_profile_id"])

    def test_create_rejects_existing_group_without_overwriting_membership(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(
                ["profile", "add", "--uri", "vless://uuid@example.com:443?encryption=none#demo"],
                tmp,
            )
            self.run_watchdog(["node-group", "create", "paris"], tmp)
            self.run_watchdog(["node-group", "add-profile", "paris", "demo"], tmp)

            result = self.run_watchdog(["node-group", "create", "paris"], tmp, check=False)
            data = json.loads(
                self.run_watchdog(["node-group", "list", "--json"], tmp).stdout
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("watchdog node-group list", result.stderr)
            self.assertEqual(data[0]["member_profile_ids"], ["demo"])

    def test_add_profile_rejects_missing_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["node-group", "create", "paris"], tmp)

            result = self.run_watchdog(
                ["node-group", "add-profile", "paris", "missing"], tmp, check=False
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("profile not found: missing", result.stderr)

    def test_auto_test_uses_ipc_client_and_prints_payload_json(self) -> None:
        response = Response(
            ok=True,
            payload={
                "group_name": "paris",
                "result": "selected",
                "selected_profile_id": "p1",
                "tested": [],
                "candidates": [],
            },
        )
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.node_group_auto_test.return_value = response
            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(["node-group", "auto-test", "paris", "--json"])

        self.assertEqual(result, 0)
        client_cls.return_value.node_group_auto_test.assert_called_once_with("paris")
        self.assertEqual(json.loads(stdout.getvalue())["selected_profile_id"], "p1")

    def test_auto_test_daemon_error_returns_70(self) -> None:
        response = Response(ok=False, error="node-group auto-test requires standby/disconnected state")
        with patch("cli.main.WatchdogIPCClient") as client_cls:
            client_cls.return_value.node_group_auto_test.return_value = response
            with redirect_stderr(StringIO()) as stderr:
                result = cli.main.main(["node-group", "auto-test", "paris"])

        self.assertEqual(result, 70)
        self.assertIn("requires standby", stderr.getvalue())

    def test_add_remove_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ProviderStore(Path(tmp) / "providers.json").add(
                Provider(id="netz.tg", name="netz", url="https://netz.tg/token")
            )
            self.run_watchdog(["node-group", "create", "paris"], tmp)

            added = self.run_watchdog(
                ["node-group", "add-provider", "paris", "netz.tg", "--json"], tmp
            )
            data = json.loads(
                self.run_watchdog(["node-group", "list", "--json"], tmp).stdout
            )
            self.assertEqual(data[0]["member_provider_ids"], ["netz.tg"])
            self.assertEqual(json.loads(added.stdout)["added_provider_id"], "netz.tg")

            self.run_watchdog(["node-group", "remove-provider", "paris", "netz.tg"], tmp)
            data = json.loads(
                self.run_watchdog(["node-group", "list", "--json"], tmp).stdout
            )
            self.assertEqual(data[0]["member_provider_ids"], [])

    def test_add_provider_rejects_missing_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["node-group", "create", "paris"], tmp)

            result = self.run_watchdog(
                ["node-group", "add-provider", "paris", "missing"], tmp, check=False
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("provider not found: missing", result.stderr)

    def test_exclude_unexclude_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(
                ["profile", "add", "--uri", "vless://uuid@example.com:443?encryption=none#demo"],
                tmp,
            )
            self.run_watchdog(["node-group", "create", "paris"], tmp)

            excluded = self.run_watchdog(
                ["node-group", "exclude", "paris", "demo", "--json"], tmp
            )
            data = json.loads(
                self.run_watchdog(["node-group", "list", "--json"], tmp).stdout
            )
            self.assertEqual(data[0]["exclude_profile_ids"], ["demo"])
            self.assertEqual(json.loads(excluded.stdout)["excluded_profile_id"], "demo")

            self.run_watchdog(["node-group", "unexclude", "paris", "demo"], tmp)
            data = json.loads(
                self.run_watchdog(["node-group", "list", "--json"], tmp).stdout
            )
            self.assertEqual(data[0]["exclude_profile_ids"], [])

    def test_set_resilience_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["node-group", "create", "paris"], tmp)

            result = self.run_watchdog(
                ["node-group", "resilience", "paris", "resilient_only", "--json"], tmp
            )
            data = json.loads(
                self.run_watchdog(["node-group", "list", "--json"], tmp).stdout
            )

            self.assertEqual(data[0]["resilience_policy"], "resilient_only")
            self.assertEqual(
                json.loads(result.stdout)["group"]["resilience_policy"], "resilient_only"
            )

    def test_set_resilience_policy_rejects_unknown_choice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["node-group", "create", "paris"], tmp)

            result = self.run_watchdog(
                ["node-group", "resilience", "paris", "bogus"], tmp, check=False
            )

            self.assertNotEqual(result.returncode, 0)

    def test_enable_disable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["node-group", "create", "paris"], tmp)

            self.run_watchdog(["node-group", "disable", "paris"], tmp)
            data = json.loads(
                self.run_watchdog(["node-group", "list", "--json"], tmp).stdout
            )
            self.assertFalse(data[0]["enabled"])

            self.run_watchdog(["node-group", "enable", "paris"], tmp)
            data = json.loads(
                self.run_watchdog(["node-group", "list", "--json"], tmp).stdout
            )
            self.assertTrue(data[0]["enabled"])


if __name__ == "__main__":
    unittest.main()
