from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliConfigCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_STATE_FILE": str(Path(tmp) / "state.toml"),
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

    def test_set_mode_persists_to_state_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["config", "set", "mode", "tun"], tmp)

            state_path = Path(tmp) / "state.toml"
            content = state_path.read_text(encoding="utf-8")
            self.assertIn('active_mode = "tun"', content)
            self.assertIn('routing_state_version = "1"', content)
            self.assertIn('routing_policy = "global"', content)
            self.assertIn('capture_modes = "local_proxy,tun"', content)
            self.assertIn('default_route_action = "current"', content)

    def test_set_mode_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["config", "set", "mode", "global", "--json"], tmp)
            data = json.loads(result.stdout)
            self.assertEqual(
                {
                    key: data[key]
                    for key in (
                        "active_mode",
                        "routing_state_version",
                        "routing_policy",
                        "capture_modes",
                        "default_route_action",
                    )
                },
                {
                    "active_mode": "global",
                    "routing_state_version": "1",
                    "routing_policy": "global",
                    "capture_modes": ["local_proxy"],
                    "default_route_action": "current",
                },
            )
            self.assertTrue(data["connectable"])
            self.assertEqual(data["runtime_status"], "connectable")

    def test_set_mode_text_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["config", "set", "mode", "direct"], tmp)
            self.assertIn("Active mode set to: direct", result.stdout)
            self.assertIn(
                "Compatibility alias: routing_policy=global capture_modes=local_proxy "
                "default_route_action=direct",
                result.stdout,
            )

    def test_set_mode_accepts_all_allowed_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for mode in ("global", "rules", "direct", "tun", "proxy"):
                self.run_watchdog(["config", "set", "mode", mode], tmp)
                state_path = Path(tmp) / "state.toml"
                self.assertIn(f'active_mode = "{mode}"', state_path.read_text(encoding="utf-8"))

    def test_set_mode_rejects_invalid_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["config", "set", "mode", "bogus"], tmp, check=False)
            self.assertEqual(result.returncode, 65)
            self.assertIn("mode must be one of", result.stderr)

    def test_set_routing_policy_capture_modes_and_default_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = self.run_watchdog(["config", "set", "routing-policy", "global", "--json"], tmp)
            capture = self.run_watchdog(["config", "set", "capture-modes", "local_proxy,tun", "--json"], tmp)
            action = self.run_watchdog(["config", "set", "default-route-action", "direct", "--json"], tmp)

            state_content = (Path(tmp) / "state.toml").read_text(encoding="utf-8")

        self.assertEqual(json.loads(policy.stdout)["routing_policy"], "global")
        self.assertEqual(json.loads(capture.stdout)["capture_modes"], ["local_proxy", "tun"])
        self.assertEqual(json.loads(action.stdout)["default_route_action"], "direct")
        self.assertIn('routing_policy = "global"', state_content)
        self.assertIn('capture_modes = "local_proxy,tun"', state_content)
        self.assertIn('default_route_action = "direct"', state_content)

    def test_set_capture_modes_rejects_no_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["config", "set", "capture-modes", ""], tmp, check=False)

        self.assertEqual(result.returncode, 70)
        self.assertIn("capture_modes must include at least one capture mode", result.stderr)

    def test_set_system_proxy_capture_is_representable_but_not_connectable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["config", "set", "capture-modes", "local_proxy,system_proxy", "--json"],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["capture_modes"], ["local_proxy", "system_proxy"])
        self.assertFalse(data["connectable"])
        self.assertEqual(data["runtime_status"], "representable-fail-closed")

    def test_routing_contract_reports_capture_coexistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["config", "routing-contract", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertEqual(data["current"]["routing_policy"], "rule")
        capture_modes = {
            tuple(item["capture_modes"]): item
            for item in data["contract"]["capture_modes"]
        }
        self.assertTrue(capture_modes[("local_proxy",)]["connectable"])
        self.assertTrue(capture_modes[("local_proxy", "tun")]["connectable"])
        self.assertFalse(capture_modes[("local_proxy", "system_proxy")]["connectable"])
        invalid = {tuple(item["capture_modes"]): item["reason"] for item in data["contract"]["invalid_capture_modes"]}
        self.assertIn((), invalid)
        self.assertIn(("system_proxy",), invalid)

    def test_set_mode_preserves_other_state_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["config", "set", "mode", "tun"], tmp)
            state_path = Path(tmp) / "state.toml"
            content = state_path.read_text(encoding="utf-8")
            self.assertIn('vpn_desired_state = "off"', content)
            self.assertIn('selected_language = "en"', content)

    def test_set_watchdog_interval_persists_to_config_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["config", "set", "watchdog.check_interval_seconds", "60"], tmp)

            config_path = Path(tmp) / "config.toml"
            self.assertIn("check_interval_seconds = 60", config_path.read_text(encoding="utf-8"))

    def test_set_scheduled_rotation_off_persists_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.run_watchdog(["config", "set", "rotation.scheduled_interval_hours", "off"], tmp)

            config_path = Path(tmp) / "config.toml"
            self.assertIn("scheduled_interval_hours = 0", config_path.read_text(encoding="utf-8"))

    def test_set_rotation_test_url_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["config", "set", "rotation.test_url", "https://example.net/probe", "--json"],
                tmp,
            )

            data = json.loads(result.stdout)
            self.assertEqual(
                data,
                {"key": "rotation.test_url", "value": "https://example.net/probe"},
            )

    def test_set_rejects_unsupported_config_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["config", "set", "kill_switch.enabled", "true"], tmp, check=False
            )

            self.assertEqual(result.returncode, 65)
            self.assertIn("unsupported config key: kill_switch.enabled", result.stderr)

    def test_set_rejects_invalid_watchdog_interval_via_app_config_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(
                ["config", "set", "watchdog.check_interval_seconds", "1"], tmp, check=False
            )

            self.assertEqual(result.returncode, 70)
            self.assertIn("watchdog.check_interval_seconds must be at least", result.stderr)


if __name__ == "__main__":
    unittest.main()
