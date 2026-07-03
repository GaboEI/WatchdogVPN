from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cli.main import _dns_snapshot_path
from config.app_config import AppConfig
from config.dns_policy_store import DNSPolicyStore
from config.paths import MIGRATION_MARKER, resolve_config_dir
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.state_manager import StateManager
from dns.state_manager import default_snapshot_path
from rules.rule_store import RuleStore


class ConfigPathResolutionTests(unittest.TestCase):
    def test_env_override_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            override = Path(tmp) / "override"
            system_dir = Path(tmp) / "system"
            user_dir = Path(tmp) / "user"
            system_dir.mkdir()
            (system_dir / MIGRATION_MARKER).touch()

            with self._patched_dirs(system_dir, user_dir), patch.dict(
                "os.environ",
                {"WATCHDOGVPN_CONFIG_DIR": str(override)},
                clear=True,
            ), patch("config.paths._running_as_service_user", return_value=True):
                self.assertEqual(resolve_config_dir(), override)

    def test_service_user_uses_system_dir_without_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            system_dir = Path(tmp) / "system"
            user_dir = Path(tmp) / "user"

            with self._patched_dirs(system_dir, user_dir), patch.dict(
                "os.environ",
                {},
                clear=True,
            ), patch("config.paths._running_as_service_user", return_value=True):
                self.assertEqual(resolve_config_dir(), system_dir)

    def test_migration_marker_uses_system_dir_for_regular_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            system_dir = Path(tmp) / "system"
            user_dir = Path(tmp) / "user"
            system_dir.mkdir()
            (system_dir / MIGRATION_MARKER).touch()

            with self._patched_dirs(system_dir, user_dir), patch.dict(
                "os.environ",
                {},
                clear=True,
            ), patch("config.paths._running_as_service_user", return_value=False):
                self.assertEqual(resolve_config_dir(), system_dir)

    def test_inaccessible_migration_marker_reports_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            system_dir = Path(tmp) / "system"
            user_dir = Path(tmp) / "user"

            with self._patched_dirs(system_dir, user_dir), patch.dict(
                "os.environ",
                {},
                clear=True,
            ), patch("config.paths._running_as_service_user", return_value=False), patch.object(
                Path,
                "exists",
                side_effect=PermissionError("denied"),
            ):
                with self.assertRaises(PermissionError) as ctx:
                    resolve_config_dir()

            self.assertIn("watchdogvpn' group", str(ctx.exception))
            self.assertIn("./install.sh", str(ctx.exception))

    def test_empty_system_dir_does_not_shadow_user_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            system_dir = Path(tmp) / "system"
            user_dir = Path(tmp) / "user"
            system_dir.mkdir()
            user_dir.mkdir()
            (user_dir / "profiles.json").write_text("[]\n", encoding="utf-8")

            with self._patched_dirs(system_dir, user_dir), patch.dict(
                "os.environ",
                {},
                clear=True,
            ), patch("config.paths._running_as_service_user", return_value=False):
                self.assertEqual(resolve_config_dir(), user_dir)

    def test_unknown_uid_falls_back_to_user_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            system_dir = Path(tmp) / "system"
            user_dir = Path(tmp) / "user"

            with self._patched_dirs(system_dir, user_dir), patch.dict(
                "os.environ",
                {},
                clear=True,
            ), patch("config.paths.os.getuid", return_value=123456), patch(
                "config.paths.pwd.getpwuid",
                side_effect=KeyError,
            ):
                self.assertEqual(resolve_config_dir(), user_dir)

    def test_service_user_detection_uses_account_name(self) -> None:
        with patch("config.paths.os.getuid", return_value=123), patch(
            "config.paths.pwd.getpwuid",
            return_value=SimpleNamespace(pw_name="watchdogvpn"),
        ):
            with patch.dict("os.environ", {}, clear=True):
                self.assertTrue(resolve_config_dir().is_absolute())

    def test_store_defaults_use_resolved_config_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "config"
            env = {"WATCHDOGVPN_CONFIG_DIR": str(config_dir)}

            with patch.dict("os.environ", env, clear=True):
                self.assertEqual(ProfileStore().path, config_dir / "profiles.json")
                self.assertEqual(ProviderStore().path, config_dir / "providers.json")
                self.assertEqual(StateManager().path, config_dir / "state.toml")
                self.assertEqual(AppConfig().path, config_dir / "config.toml")
                self.assertEqual(DNSPolicyStore().path, config_dir / "dns-policy.json")
                self.assertEqual(RuleStore().path, config_dir / "rules")
                self.assertEqual(default_snapshot_path(), config_dir / "dns-state.json")
                self.assertEqual(_dns_snapshot_path(SimpleNamespace()), config_dir / "dns-state.json")

    def test_state_dir_override_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "config"
            state_dir = Path(tmp) / "state"

            with patch.dict(
                "os.environ",
                {
                    "WATCHDOGVPN_CONFIG_DIR": str(config_dir),
                    "WATCHDOGVPN_STATE_DIR": str(state_dir),
                },
                clear=True,
            ):
                self.assertEqual(StateManager().path, state_dir / "state.toml")

    def _patched_dirs(self, system_dir: Path, user_dir: Path):
        return patch.multiple(
            "config.paths",
            SYSTEM_CONFIG_DIR=system_dir,
            _user_config_dir=lambda: user_dir,
        )


if __name__ == "__main__":
    unittest.main()
