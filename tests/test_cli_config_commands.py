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
            self.assertIn('active_mode = "tun"', state_path.read_text(encoding="utf-8"))

    def test_set_mode_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["config", "set", "mode", "global", "--json"], tmp)
            data = json.loads(result.stdout)
            self.assertEqual(data, {"active_mode": "global"})

    def test_set_mode_text_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_watchdog(["config", "set", "mode", "direct"], tmp)
            self.assertIn("Active mode set to: direct", result.stdout)

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
