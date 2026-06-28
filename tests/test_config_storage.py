from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from config.app_config import AppConfig, DEFAULT_CONFIG
from config.profile_store import ProfileStore
from config.provider_store import ProviderLimitError, ProviderStore
from config.state_manager import DEFAULT_STATE, StateManager
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider


class ConfigStorageTests(unittest.TestCase):
    def test_state_manager_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.toml"
            manager = StateManager(path)
            state = dict(DEFAULT_STATE)
            state["vpn_desired_state"] = "on"
            state["selected_language"] = "es"
            manager.save(state)

            restored = manager.load()
            self.assertEqual(restored["vpn_desired_state"], "on")
            self.assertEqual(restored["selected_language"], "es")
            self.assertEqual(manager.get("vpn_desired_state"), "on")

    def test_app_config_load_and_save(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            config = AppConfig(path)
            loaded = config.load()
            self.assertEqual(loaded["watchdog"]["check_interval_seconds"], 30)
            self.assertEqual(loaded["adguard"]["legacy_mode"], True)

            loaded["watchdog"]["check_interval_seconds"] = 45
            config.save(loaded)
            restored = config.load()
            self.assertEqual(restored["watchdog"]["check_interval_seconds"], 45)

    def test_config_paths_follow_environment_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "cfg"
            env = {
                "WATCHDOGVPN_CONFIG_DIR": str(config_dir),
                "WATCHDOGVPN_STATE_FILE": str(Path(tmp) / "state.toml"),
                "WATCHDOGVPN_PROFILES_FILE": str(Path(tmp) / "profiles.json"),
                "WATCHDOGVPN_PROVIDERS_FILE": str(Path(tmp) / "providers.json"),
                "WATCHDOGVPN_CONFIG_FILE": str(Path(tmp) / "config.toml"),
            }
            with patch.dict("os.environ", env, clear=False):
                state_manager = StateManager()
                app_config = AppConfig()
                profile_store = ProfileStore()
                provider_store = ProviderStore()

            self.assertEqual(state_manager.path, Path(env["WATCHDOGVPN_STATE_FILE"]))
            self.assertEqual(app_config.path, Path(env["WATCHDOGVPN_CONFIG_FILE"]))
            self.assertEqual(profile_store.path, Path(env["WATCHDOGVPN_PROFILES_FILE"]))
            self.assertEqual(provider_store.path, Path(env["WATCHDOGVPN_PROVIDERS_FILE"]))

    def test_profile_store_crud_and_rotation_pool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            store = ProfileStore(path)
            profile = Profile(
                id="p1",
                name="Paris",
                protocol=ProtocolType.VLESS,
                config={"server": "example.com"},
                source=ProfileSource.MANUAL,
                in_rotation_pool=True,
                enabled=True,
                created_at=datetime(2026, 6, 1, 12, 0, 0),
            )
            store.add(profile)
            self.assertEqual(store.get("p1"), profile)
            self.assertEqual(store.get_rotation_pool(), [profile])

            profile.enabled = False
            store.update(profile)
            self.assertEqual(store.get_rotation_pool(), [])

            store.remove("p1")
            self.assertIsNone(store.get("p1"))

    def test_provider_store_enforces_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "providers.json"
            store = ProviderStore(path)
            p1 = Provider(id="a", name="A", url="https://a.example/sub")
            p2 = Provider(id="b", name="B", url="https://b.example/sub")
            p3 = Provider(id="c", name="C", url="https://c.example/sub")
            store.add(p1)
            store.add(p2)
            with self.assertRaises(ProviderLimitError):
                store.add(p3)
            self.assertEqual(store.list(), [p1, p2])
            store.remove("a")
            self.assertIsNone(store.get("a"))


if __name__ == "__main__":
    unittest.main()
