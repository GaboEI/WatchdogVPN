from __future__ import annotations

import tempfile
import unittest
import os
import stat
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from config.app_config import AppConfig, DEFAULT_CONFIG
from config.dns_policy_store import DNSPolicyStore
from config.persistence import (
    PersistentStoreError,
    PersistentValidationError,
    atomic_write_bytes,
    atomic_write_text,
)
from config.profile_store import ProfileStore
from config.provider_store import ProviderLimitError, ProviderStore
from config.state_manager import (
    DEFAULT_STATE,
    StateManager,
    rollback_active_mode_for_routing_state,
)
from dns.models import DNSPolicy
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

    def test_state_manager_migrates_legacy_active_modes(self) -> None:
        cases = {
            "rules": ("rule", "local_proxy", "current"),
            "global": ("global", "local_proxy", "current"),
            "direct": ("global", "local_proxy", "direct"),
            "tun": ("global", "local_proxy,tun", "current"),
            "proxy": ("global", "local_proxy", "current"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            for legacy_mode, expected in cases.items():
                path = Path(tmp) / f"{legacy_mode}.toml"
                path.write_text(f'active_mode = "{legacy_mode}"\n', encoding="utf-8")

                state = StateManager(path).load()

                self.assertEqual(state["routing_state_version"], "1")
                self.assertEqual(
                    (
                        state["routing_policy"],
                        state["capture_modes"],
                        state["default_route_action"],
                    ),
                    expected,
                )

    def test_state_manager_set_active_mode_updates_routing_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.toml"
            manager = StateManager(path)

            manager.set("active_mode", "tun")

            state = manager.load()
            self.assertEqual(state["active_mode"], "tun")
            self.assertEqual(state["routing_policy"], "global")
            self.assertEqual(state["capture_modes"], "local_proxy,tun")
            self.assertEqual(state["default_route_action"], "current")

    def test_state_manager_versioned_shape_wins_over_stale_active_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.toml"
            path.write_text(
                "\n".join(
                    [
                        'active_mode = "tun"',
                        'routing_state_version = "1"',
                        'routing_policy = "global"',
                        'capture_modes = "local_proxy"',
                        'default_route_action = "direct"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            state = StateManager(path).load()

            self.assertEqual(state["active_mode"], "direct")

    def test_state_manager_rejects_invalid_routing_state_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.toml"
            path.write_text('routing_state_version = "2"\n', encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                StateManager(path).load()

    def test_state_manager_rejects_invalid_routing_fields(self) -> None:
        invalid_docs = [
            'routing_policy = "maybe"\n',
            'capture_modes = ""\n',
            'capture_modes = "local_proxy,unknown"\n',
            'capture_modes = "local_proxy,local_proxy"\n',
            'capture_modes = "system_proxy"\n',
            'capture_modes = "tun"\n',
            'capture_modes = "tun,system_proxy"\n',
            'default_route_action = "group:alpha"\n',
            'default_route_action = "chain:primary"\n',
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for index, content in enumerate(invalid_docs):
                path = Path(tmp) / f"invalid-{index}.toml"
                path.write_text(content, encoding="utf-8")

                with self.assertRaises(PersistentValidationError):
                    StateManager(path).load()

    def test_state_manager_accepts_system_proxy_only_with_local_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.toml"
            path.write_text(
                "\n".join(
                    [
                        'routing_state_version = "1"',
                        'routing_policy = "global"',
                        'capture_modes = "local_proxy,system_proxy"',
                        'default_route_action = "current"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            state = StateManager(path).load()

            self.assertEqual(state["capture_modes"], "local_proxy,system_proxy")

    def test_state_manager_accepts_tun_with_local_and_system_proxy_intent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.toml"
            path.write_text(
                "\n".join(
                    [
                        'routing_state_version = "1"',
                        'routing_policy = "rule"',
                        'capture_modes = "local_proxy,tun,system_proxy"',
                        'default_route_action = "current"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            state = StateManager(path).load()

            self.assertEqual(state["capture_modes"], "local_proxy,tun,system_proxy")

    def test_rollback_active_mode_refuses_non_equivalent_shape(self) -> None:
        with self.assertRaises(PersistentValidationError):
            rollback_active_mode_for_routing_state(
                {
                    "routing_policy": "global",
                    "capture_modes": "local_proxy",
                    "default_route_action": "block",
                }
            )

    def test_state_manager_rejects_invalid_desired_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.toml"
            path.write_text('vpn_desired_state = "maybe"\n', encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                StateManager(path).load()

    def test_state_manager_reports_corrupt_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.toml"
            path.write_text("vpn_desired_state = [\n", encoding="utf-8")

            with self.assertRaises(PersistentStoreError):
                StateManager(path).load()

    def test_app_config_load_and_save(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            config = AppConfig(path)
            loaded = config.load()
            self.assertEqual(loaded["watchdog"]["check_interval_seconds"], 30)
            self.assertEqual(loaded["rotation"]["enabled"], False)

            loaded["watchdog"]["check_interval_seconds"] = 45
            config.save(loaded)
            restored = config.load()
            self.assertEqual(restored["watchdog"]["check_interval_seconds"], 45)

    def test_app_config_rejects_string_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text('[kill_switch]\nenabled = "false"\n', encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                AppConfig(path).load()

    def test_app_config_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text("[watchdog]\nfuture_setting = true\n", encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                AppConfig(path).load()

    def test_app_config_rejects_check_interval_below_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text("[watchdog]\ncheck_interval_seconds = 1\n", encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                AppConfig(path).load()

    def test_app_config_accepts_check_interval_at_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text("[watchdog]\ncheck_interval_seconds = 5\n", encoding="utf-8")

            loaded = AppConfig(path).load()
            self.assertEqual(loaded["watchdog"]["check_interval_seconds"], 5)

    def test_app_config_default_rotation_test_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            loaded = AppConfig(Path(tmp) / "config.toml").load()

            self.assertEqual(loaded["rotation"]["test_url"], "https://example.com")
            self.assertEqual(loaded["rotation"]["test_timeout_seconds"], 5)
            self.assertEqual(loaded["rotation"]["latency_max_stale_seconds"], 300)

    def test_app_config_rejects_test_url_without_scheme(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text('[rotation]\ntest_url = "example.com"\n', encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                AppConfig(path).load()

    def test_app_config_accepts_custom_test_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text('[rotation]\ntest_url = "https://custom.example/probe"\n', encoding="utf-8")

            loaded = AppConfig(path).load()

            self.assertEqual(loaded["rotation"]["test_url"], "https://custom.example/probe")

    def test_app_config_rejects_test_timeout_below_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text("[rotation]\ntest_timeout_seconds = 0\n", encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                AppConfig(path).load()

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

    def test_shared_state_writes_ignore_restrictive_umask(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared_dir = Path(tmp) / "watchdogvpn"
            target = shared_dir / "rules" / "custom.json"
            old_umask = os.umask(0o077)
            try:
                with patch("config.paths.SYSTEM_CONFIG_DIR", shared_dir):
                    atomic_write_text(target, "{}\n")
            finally:
                os.umask(old_umask)

            self.assertEqual(stat.S_IMODE(shared_dir.stat().st_mode), 0o2770)
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o2770)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o660)

    def test_atomic_write_bytes_ignores_restrictive_umask(self) -> None:
        # Regression coverage for the Phase 18 Task 18.4 shared-state audit:
        # config.backup_manager's restore-rollback path used to write bytes
        # directly (path.write_bytes()), bypassing this shared-permission
        # normalization entirely. Under the daemon's real UMask=0077, a raw
        # write would land as 0600 (unreadable/unwritable by the watchdogvpn
        # group) - the same bug class as the historical Phase 2.6 incident.
        with tempfile.TemporaryDirectory() as tmp:
            shared_dir = Path(tmp) / "watchdogvpn"
            target = shared_dir / "rules" / "restored.json"
            old_umask = os.umask(0o077)
            try:
                with patch("config.paths.SYSTEM_CONFIG_DIR", shared_dir):
                    atomic_write_bytes(target, b'{"restored": true}\n')
            finally:
                os.umask(old_umask)

            self.assertEqual(stat.S_IMODE(shared_dir.stat().st_mode), 0o2770)
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o2770)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o660)
            self.assertEqual(target.read_bytes(), b'{"restored": true}\n')

    def test_profile_store_crud(self) -> None:
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

            profile.enabled = False
            store.update(profile)
            self.assertEqual(store.get("p1").enabled, False)

            store.remove("p1")
            self.assertIsNone(store.get("p1"))

    def test_profile_store_reports_corrupt_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text("[", encoding="utf-8")

            with self.assertRaises(PersistentStoreError):
                ProfileStore(path).list()

    def test_profile_store_rejects_non_array_top_level(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text("{}", encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                ProfileStore(path).list()

    def test_profile_store_rejects_string_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(
                """[
  {
    "id": "p1",
    "name": "Paris",
    "protocol": "vless",
    "config": {},
    "source": "manual",
    "enabled": "false"
  }
]
""",
                encoding="utf-8",
            )

            with self.assertRaises(PersistentValidationError):
                ProfileStore(path).list()

    def test_profile_store_rejects_unknown_profile_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            path.write_text(
                """[
  {
    "id": "p1",
    "name": "Paris",
    "protocol": "vless",
    "config": {},
    "source": "manual",
    "future": true
  }
]
""",
                encoding="utf-8",
            )

            with self.assertRaises(PersistentValidationError):
                ProfileStore(path).list()

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

    def test_provider_store_rejects_string_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "providers.json"
            path.write_text(
                """[
  {
    "id": "a",
    "name": "A",
    "url": "https://a.example/sub",
    "rotation_enabled": "false"
  }
]
""",
                encoding="utf-8",
            )

            with self.assertRaises(PersistentValidationError):
                ProviderStore(path).list()

    def test_dns_policy_store_rejects_corrupt_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns-policy.json"
            path.write_text("{", encoding="utf-8")

            with self.assertRaises(PersistentStoreError):
                DNSPolicyStore(path).load()

    def test_dns_policy_store_rejects_string_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns-policy.json"
            path.write_text('{"tun_hijack": "false"}', encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                DNSPolicyStore(path).load()

    def test_dns_policy_store_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns-policy.json"
            path.write_text('{"future": true}', encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                DNSPolicyStore(path).load()

    def test_atomic_save_does_not_leave_temp_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns-policy.json"

            DNSPolicyStore(path).save(DNSPolicy())

            self.assertTrue(path.exists())
            self.assertEqual(list(Path(tmp).glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
