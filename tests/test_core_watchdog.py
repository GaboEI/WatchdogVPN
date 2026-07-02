from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

from core.watchdog import WatchdogRuntime, build_watchdog, select_driver
from config.dns_policy_store import DNSPolicyStore
from config.profile_store import ProfileStore
from config.state_manager import StateManager
from dns.models import DNSMode, DNSPolicy
from dns.state_manager import SystemDNSStateManager
from drivers.amneziawg_driver import AmneziaWGDriver
from drivers.base import BaseDriver
from drivers.legacy.adguard_driver import AdGuardDriver
from drivers.openvpn_cloak_driver import OpenVPNCloakDriver
from drivers.openvpn_driver import OpenVPNDriver
from drivers.singbox_driver import SingBoxDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType


class FakeDriver(BaseDriver):
    def __init__(self) -> None:
        self.connect_mock = Mock(return_value=True)
        self.disconnect_mock = Mock(return_value=True)
        self.health_check_mock = Mock(return_value="ok")
        self.status_mock = Mock(return_value=ConnectionState(status="connected", mode="rules"))
        self.is_available_mock = Mock(return_value=True)
        self.last_dns_policy: DNSPolicy | None = "unset"

    def connect(self, profile: Profile, dns_policy: DNSPolicy | None = None) -> bool:
        self.last_dns_policy = dns_policy
        return bool(self.connect_mock(profile))

    def disconnect(self) -> bool:
        return bool(self.disconnect_mock())

    def health_check(self) -> str:
        return str(self.health_check_mock())

    def status(self) -> ConnectionState:
        return self.status_mock()

    def is_available(self) -> bool:
        return bool(self.is_available_mock())


class FakeKillSwitch:
    def __init__(self, active: bool = False, enable_result: bool = True) -> None:
        self.active = active
        self.enable_result = enable_result
        self.enable_mock = Mock(side_effect=self._enable)
        self.disable_mock = Mock(return_value=True)
        self.is_active_mock = Mock(side_effect=lambda: self.active)
        self.status_mock = Mock(return_value={})
        self.tunnel_interface = "tun0"
        self.block_ipv6 = True
        self.allow_lan = True

    def _enable(self) -> bool:
        if self.enable_result:
            self.active = True
        return self.enable_result

    def enable(self) -> bool:
        return bool(self.enable_mock())

    def disable(self) -> bool:
        return bool(self.disable_mock())

    def is_active(self) -> bool:
        return bool(self.is_active_mock())

    def status(self) -> dict:
        return self.status_mock()


class FakeDNSRunner:
    def __init__(self, active_services: set[str] | None = None) -> None:
        self.active_services = active_services or set()
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> str:
        self.commands.append(command)
        if command[:2] == ["systemctl", "is-active"] and len(command) == 3:
            return "active" if command[2] in self.active_services else "inactive"
        if command == ["nmcli", "-t", "-f", "NAME", "con", "show", "--active"]:
            return ""
        return ""


class WatchdogCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = Profile(
            id="ad1",
            name="DK",
            protocol=ProtocolType.ADGUARD,
            config={"location": "DK"},
            source=ProfileSource.MANUAL,
        )
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state_manager = StateManager(Path(self.tmpdir.name) / "state.toml")
        self.profile_store = ProfileStore(Path(self.tmpdir.name) / "profiles.json")

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def set_desired_state(self, desired_state: str) -> None:
        self.state_manager.set("vpn_desired_state", desired_state)

    def test_select_driver_routes_to_adguard(self) -> None:
        driver = select_driver(self.profile)
        self.assertIsInstance(driver, AdGuardDriver)

    def test_select_driver_routes_to_amneziawg(self) -> None:
        profile = Profile(
            id="awg1",
            name="AWG",
            protocol=ProtocolType.AMNEZIAWG,
            config={},
            source=ProfileSource.MANUAL,
        )
        driver = select_driver(profile)
        self.assertIsInstance(driver, AmneziaWGDriver)

    def test_select_driver_routes_to_openvpn(self) -> None:
        profile = Profile(
            id="ovpn1",
            name="OVPN",
            protocol=ProtocolType.OPENVPN,
            config={},
            source=ProfileSource.MANUAL,
        )
        driver = select_driver(profile)
        self.assertIsInstance(driver, OpenVPNDriver)

    def test_select_driver_routes_to_openvpn_cloak(self) -> None:
        profile = Profile(
            id="ovpncloak1",
            name="OVPN+Cloak",
            protocol=ProtocolType.OPENVPN_CLOAK,
            config={},
            source=ProfileSource.MANUAL,
        )
        driver = select_driver(profile)
        self.assertIsInstance(driver, OpenVPNCloakDriver)

    def test_select_driver_routes_to_singbox_by_default(self) -> None:
        profile = Profile(
            id="vless1",
            name="VLESS",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
        )
        driver = select_driver(profile)
        self.assertIsInstance(driver, SingBoxDriver)

    def test_select_driver_routes_to_singbox_when_no_profile(self) -> None:
        driver = select_driver(None)
        self.assertIsInstance(driver, SingBoxDriver)

    @patch.object(AdGuardDriver, "connect", return_value=True)
    @patch.object(AdGuardDriver, "disconnect", return_value=True)
    @patch.object(AdGuardDriver, "health_check", return_value="ok")
    @patch.object(AdGuardDriver, "status", return_value=None)
    def test_runtime_delegates_to_driver_interface(self, status_mock, health_mock, disconnect_mock, connect_mock) -> None:
        self.set_desired_state("on")
        runtime = WatchdogRuntime(driver=AdGuardDriver(), state_manager=self.state_manager)
        self.assertTrue(runtime.connect(self.profile))
        self.assertEqual(runtime.health_check(), "ok")
        self.assertTrue(runtime.disconnect())

    def test_run_iteration_stands_by_when_user_disabled_vpn(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        with self.assertLogs("core.watchdog", level="INFO") as logs:
            state = runtime.run_iteration()

        self.assertEqual(state.status, "standby")
        self.assertIn("standby mode - user disabled VPN", "\n".join(logs.output))
        driver.health_check_mock.assert_not_called()
        driver.status_mock.assert_not_called()

    def test_run_iteration_stands_by_when_state_file_is_invalid(self) -> None:
        self.state_manager.path.write_text('vpn_desired_state = "maybe"\n', encoding="utf-8")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        with self.assertLogs("core.watchdog", level="ERROR") as logs:
            state = runtime.run_iteration()

        self.assertEqual(state.status, "standby")
        self.assertIn("invalid persistent state", "\n".join(logs.output))
        driver.health_check_mock.assert_not_called()

    def test_run_iteration_checks_health_when_user_enabled_vpn(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        state = runtime.run_iteration()

        self.assertEqual(state.status, "connected")
        driver.health_check_mock.assert_called_once_with()
        driver.status_mock.assert_called_once_with()

    def test_health_check_returns_standby_when_user_disabled_vpn(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        self.assertEqual(runtime.health_check(), "standby")
        driver.health_check_mock.assert_not_called()

    def test_startup_stands_by_when_user_disabled_vpn(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "off",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": self.profile.id,
            }
        )
        self.profile_store.add(self.profile)
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
        )

        state = runtime.startup()

        self.assertEqual(state.status, "standby")
        driver.connect_mock.assert_not_called()

    def test_startup_stands_by_when_state_file_is_invalid(self) -> None:
        self.state_manager.path.write_text('vpn_desired_state = "maybe"\n', encoding="utf-8")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        with self.assertLogs("core.watchdog", level="ERROR") as logs:
            state = runtime.startup()

        self.assertEqual(state.status, "standby")
        self.assertIn("invalid persistent state", "\n".join(logs.output))
        driver.connect_mock.assert_not_called()

    def test_startup_stands_by_when_autoconnect_disabled(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": False,
                "active_profile_id": self.profile.id,
            }
        )
        self.profile_store.add(self.profile)
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
        )

        state = runtime.startup()

        self.assertEqual(state.status, "standby")
        driver.connect_mock.assert_not_called()

    def test_startup_autoconnects_last_active_profile(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": self.profile.id,
            }
        )
        self.profile_store.add(self.profile)
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
        )

        state = runtime.startup()

        self.assertEqual(state.status, "connected")
        driver.connect_mock.assert_called_once_with(self.profile)
        driver.status_mock.assert_called_once_with()

    def test_startup_stands_by_when_active_profile_missing(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": "missing",
            }
        )
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
        )

        with self.assertLogs("core.watchdog", level="WARNING"):
            state = runtime.startup()

        self.assertEqual(state.status, "standby")
        driver.connect_mock.assert_not_called()

    def test_build_watchdog_returns_runtime(self) -> None:
        runtime = build_watchdog(self.profile)
        self.assertIsInstance(runtime.driver, AdGuardDriver)

    def test_disconnect_calls_driver_disconnect(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        self.assertTrue(runtime.disconnect())
        driver.disconnect_mock.assert_called_once_with()

    def test_disconnect_persists_desired_state_off(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        runtime.disconnect()

        rebooted_state_manager = StateManager(self.state_manager.path)
        self.assertEqual(rebooted_state_manager.get("vpn_desired_state"), "off")

    def test_disconnect_logs_manual_disable_message(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        with self.assertLogs("core.watchdog", level="INFO") as logs:
            runtime.disconnect()

        self.assertIn("VPN manually disabled. Will not auto-reconnect.", "\n".join(logs.output))

    def test_disconnect_disables_active_kill_switch_by_default(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        kill_switch = FakeKillSwitch(active=True)
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            kill_switch=kill_switch,
        )

        runtime.disconnect()

        kill_switch.disable_mock.assert_called_once_with()

    def test_disconnect_keeps_active_kill_switch_when_configured(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        kill_switch = FakeKillSwitch(active=True)
        app_config = Mock()
        app_config.load.return_value = {
            "kill_switch": {"on_manual_disconnect": "keep"},
        }
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            app_config=app_config,
            kill_switch=kill_switch,
        )

        runtime.disconnect()

        kill_switch.disable_mock.assert_not_called()

    def test_disconnect_ignores_kill_switch_when_inactive(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        kill_switch = FakeKillSwitch(active=False)
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            kill_switch=kill_switch,
        )

        runtime.disconnect()

        kill_switch.disable_mock.assert_not_called()

    def test_disconnect_invalid_kill_switch_policy_defaults_to_disable(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        kill_switch = FakeKillSwitch(active=True)
        app_config = Mock()
        app_config.load.return_value = {
            "kill_switch": {"on_manual_disconnect": "invalid"},
        }
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            app_config=app_config,
            kill_switch=kill_switch,
        )

        runtime.disconnect()

        kill_switch.disable_mock.assert_called_once_with()

    def test_disconnect_restores_dns_snapshot_when_present(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        resolv_conf = Path(self.tmpdir.name) / "resolv.conf"
        resolv_conf.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
        runner = FakeDNSRunner(active_services={"systemd-resolved.service"})
        dns_state_manager = SystemDNSStateManager(resolv_conf_path=resolv_conf, runner=runner)
        snapshot = dns_state_manager.save_state(systemd_link="tun0")
        snapshot_path = Path(self.tmpdir.name) / "dns-state.json"
        snapshot_path.write_text(json.dumps(snapshot.to_dict()), encoding="utf-8")
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            dns_state_manager=dns_state_manager,
            dns_snapshot_path=snapshot_path,
        )

        runtime.disconnect()

        self.assertIn(["resolvectl", "revert", "tun0"], runner.commands)
        self.assertFalse(snapshot_path.exists())

    def test_disconnect_does_nothing_when_no_dns_snapshot(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        runner = FakeDNSRunner()
        dns_state_manager = SystemDNSStateManager(
            resolv_conf_path=Path(self.tmpdir.name) / "resolv.conf",
            runner=runner,
        )
        snapshot_path = Path(self.tmpdir.name) / "missing-dns-state.json"
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            dns_state_manager=dns_state_manager,
            dns_snapshot_path=snapshot_path,
        )

        runtime.disconnect()

        self.assertEqual(runner.commands, [])

    def test_disconnect_survives_dns_restore_failure(self) -> None:
        self.set_desired_state("on")
        driver = FakeDriver()
        snapshot_path = Path(self.tmpdir.name) / "corrupt-dns-state.json"
        snapshot_path.write_text("not valid json", encoding="utf-8")
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            dns_snapshot_path=snapshot_path,
        )

        with self.assertLogs("core.watchdog", level="WARNING"):
            result = runtime.disconnect()

        self.assertTrue(result)
        self.assertTrue(snapshot_path.exists())

    def test_connect_calls_driver_connect_with_profile(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        self.assertTrue(runtime.connect(self.profile))
        driver.connect_mock.assert_called_once_with(self.profile)

    def test_connect_forwards_the_stored_dns_policy_to_the_driver(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        dns_policy_path = Path(self.tmpdir.name) / "dns-policy.json"
        dns_policy_store = DNSPolicyStore(dns_policy_path)
        policy = DNSPolicy(mode=DNSMode.CUSTOM)
        dns_policy_store.save(policy)
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            dns_policy_store=dns_policy_store,
        )

        runtime.connect(self.profile)

        self.assertEqual(driver.last_dns_policy.mode, DNSMode.CUSTOM)

    def test_startup_forwards_the_stored_dns_policy_to_the_driver(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": self.profile.id,
            }
        )
        self.profile_store.add(self.profile)
        driver = FakeDriver()
        dns_policy_path = Path(self.tmpdir.name) / "dns-policy.json"
        dns_policy_store = DNSPolicyStore(dns_policy_path)
        dns_policy_store.save(DNSPolicy(mode=DNSMode.CUSTOM))
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            dns_policy_store=dns_policy_store,
        )

        runtime.startup()

        self.assertEqual(driver.last_dns_policy.mode, DNSMode.CUSTOM)

    def test_connect_persists_desired_state_on(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        runtime.connect(self.profile)

        rebooted_state_manager = StateManager(self.state_manager.path)
        self.assertEqual(rebooted_state_manager.get("vpn_desired_state"), "on")

    def test_connect_persists_desired_state_on_even_if_driver_connect_fails(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        driver.connect_mock.return_value = False
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        self.assertFalse(runtime.connect(self.profile))
        self.assertEqual(self.state_manager.get("vpn_desired_state"), "on")

    def test_connect_persists_active_profile_id(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        runtime.connect(self.profile)

        rebooted_state_manager = StateManager(self.state_manager.path)
        self.assertEqual(rebooted_state_manager.get("active_profile_id"), self.profile.id)

    def test_connect_persists_active_profile_id_even_if_driver_connect_fails(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        driver.connect_mock.return_value = False
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        self.assertFalse(runtime.connect(self.profile))
        self.assertEqual(self.state_manager.get("active_profile_id"), self.profile.id)

    def test_connect_then_startup_reconnects_after_simulated_reboot(self) -> None:
        self.profile_store.add(self.profile)
        self.state_manager.set("vpn_autoconnect_enabled", True)
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
        )

        runtime.connect(self.profile)

        rebooted_driver = FakeDriver()
        rebooted_runtime = WatchdogRuntime(
            driver=rebooted_driver,
            state_manager=StateManager(self.state_manager.path),
            profile_store=self.profile_store,
        )

        state = rebooted_runtime.startup()

        self.assertNotEqual(state.status, "standby")
        rebooted_driver.connect_mock.assert_called_once_with(self.profile)

    def test_connect_enables_automatic_actions_for_session(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        runtime.connect(self.profile)

        self.assertEqual(runtime.health_check(), "ok")
        driver.health_check_mock.assert_called_once_with()


class WatchdogIntegrationTests(unittest.TestCase):
    """Task 8.5 — integration of pool_builder, rotation_engine, health_checker, recovery."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state_manager = StateManager(Path(self.tmpdir.name) / "state.toml")
        self.state_manager.set("vpn_desired_state", "on")
        self.profile_store = ProfileStore(Path(self.tmpdir.name) / "profiles.json")
        self.profile = Profile(
            id="vless1",
            name="VLESS",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
            in_rotation_pool=True,
            enabled=True,
        )

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _make_runtime(self, driver: BaseDriver) -> WatchdogRuntime:
        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine

        clock_value = [0.0]
        clock = lambda: clock_value[0]
        return WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=FakeKillSwitch(),
        )

    def test_run_iteration_healthy_resets_recovery_and_returns_connected(self) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "ok"
        runtime = self._make_runtime(driver)

        result = runtime.run_iteration()

        self.assertEqual(result.status, "connected")

    def test_run_iteration_standby_when_gate_off(self) -> None:
        self.state_manager.set("vpn_desired_state", "off")
        driver = FakeDriver()
        runtime = self._make_runtime(driver)

        result = runtime.run_iteration()

        self.assertEqual(result.status, "standby")
        driver.health_check_mock.assert_not_called()

    @patch("core.watchdog.health_checker.check", return_value="ok")
    def test_run_iteration_reconnects_current_profile_on_failure(self, _hc) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)
        runtime = self._make_runtime(driver)

        result = runtime.run_iteration()

        self.assertEqual(result.status, "recovered")
        driver.connect_mock.assert_called_with(self.profile)

    @patch("core.watchdog.health_checker.check", return_value="down")
    def test_run_iteration_returns_reconnecting_below_attempt_threshold(self, _hc) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {"watchdog": {"reconnect_attempts": 3}, "kill_switch": {"enabled": False}, "rotation": {}, "adguard": {}}

        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine
        clock_value = [0.0]
        clock = lambda: clock_value[0]
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=FakeKillSwitch(),
        )

        result = runtime.run_iteration()

        self.assertEqual(result.status, "reconnecting")
        self.assertEqual(runtime._reconnect_failures, 1)

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    def test_run_iteration_rotates_after_threshold_crossed(self, mock_pool, mock_sel_driver) -> None:
        alt_profile = Profile(
            id="alt1", name="Alt", protocol=ProtocolType.VLESS,
            config={}, source=ProfileSource.MANUAL, in_rotation_pool=True, enabled=True,
        )
        driver = FakeDriver()
        mock_pool.return_value = [alt_profile]
        mock_sel_driver.return_value = driver

        driver.health_check_mock.return_value = "down"
        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1},
            "kill_switch": {"enabled": False},
            "rotation": {"enabled": True},
            "adguard": {},
        }

        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine
        clock_value = [0.0]
        clock = lambda: clock_value[0]
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            rotation_engine=RotationEngine(
                clock=clock, sleep=lambda s: None, warmup_seconds=0.0,
                max_fails_before_rollback=99,
            ),
            recovery=Recovery(clock=clock),
            kill_switch=FakeKillSwitch(),
        )

        def health_check_by_profile(profile, drv):
            return "ok" if profile.id == alt_profile.id else "down"

        with patch("core.watchdog.health_checker.check", side_effect=health_check_by_profile):
            result = runtime.run_iteration()

        self.assertEqual(result.status, "recovered")
        self.assertEqual(self.state_manager.get("active_profile_id"), alt_profile.id)

    @patch("core.watchdog.pool_builder.build_pool", return_value=[])
    @patch("core.watchdog.health_checker.check", return_value="down")
    def test_run_iteration_reports_rotation_unavailable_when_pool_empty(self, _hc, _pool) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1},
            "kill_switch": {"enabled": False},
            "rotation": {"enabled": True},
            "adguard": {},
        }

        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine
        clock_value = [0.0]
        clock = lambda: clock_value[0]
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=FakeKillSwitch(),
        )

        result = runtime.run_iteration()

        self.assertEqual(result.status, "rotation_unavailable")

    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check", return_value="down")
    def test_run_iteration_does_not_rotate_when_rotation_disabled(self, _hc, pool_mock) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1},
            "kill_switch": {"enabled": False},
            "rotation": {"enabled": False},
            "adguard": {},
        }

        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine
        clock_value = [0.0]
        clock = lambda: clock_value[0]
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=FakeKillSwitch(),
        )

        result = runtime.run_iteration()

        self.assertEqual(result.status, "rotation_unavailable")
        pool_mock.assert_not_called()

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check", return_value="down")
    def test_run_iteration_reports_all_failed_when_candidates_fail(self, _hc, mock_pool, mock_sel_driver) -> None:
        alt_profile = Profile(
            id="alt-down", name="Alt down", protocol=ProtocolType.VLESS,
            config={}, source=ProfileSource.MANUAL, in_rotation_pool=True, enabled=True,
        )
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        mock_pool.return_value = [alt_profile]
        mock_sel_driver.return_value = driver

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1},
            "kill_switch": {"enabled": False},
            "rotation": {"enabled": True},
            "adguard": {},
        }

        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine
        clock_value = [0.0]
        clock = lambda: clock_value[0]
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=FakeKillSwitch(),
        )

        result = runtime.run_iteration()

        self.assertEqual(result.status, "all_failed")

    def test_run_iteration_applies_recovery_backoff_config(self) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1, "reconnect_backoff_seconds": 7},
            "kill_switch": {"enabled": False},
            "rotation": {"enabled": False, "max_backoff_interval_seconds": 8},
            "adguard": {},
        }

        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine
        clock_value = [0.0]
        clock = lambda: clock_value[0]
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=FakeKillSwitch(),
        )

        runtime.run_iteration()
        runtime.run_iteration()

        self.assertEqual(runtime.recovery.base_interval_seconds, 7.0)
        self.assertEqual(runtime.recovery.max_interval_seconds, 8.0)
        self.assertEqual(runtime.recovery.backoff_interval(2), 8.0)

    @patch("core.watchdog.pool_builder.build_pool", return_value=[])
    @patch("core.watchdog.health_checker.check", return_value="down")
    def test_run_iteration_enables_kill_switch_when_configured_and_all_fail(self, _hc, _pool) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        kill_switch = FakeKillSwitch(active=False)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1},
            "kill_switch": {"enabled": True},
            "rotation": {"enabled": True},
            "adguard": {},
        }

        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine
        clock_value = [0.0]
        clock = lambda: clock_value[0]
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=kill_switch,
        )

        result = runtime.run_iteration()

        self.assertEqual(result.status, "kill_switch_active")
        kill_switch.enable_mock.assert_called_once_with()

    @patch("core.watchdog.pool_builder.build_pool", return_value=[])
    @patch("core.watchdog.health_checker.check", return_value="down")
    def test_run_iteration_keeps_existing_kill_switch_active_when_all_fail(self, _hc, _pool) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        kill_switch = FakeKillSwitch(active=True)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1},
            "kill_switch": {"enabled": False},
            "rotation": {"enabled": True},
            "adguard": {},
        }

        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine
        clock_value = [0.0]
        clock = lambda: clock_value[0]
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=kill_switch,
        )

        result = runtime.run_iteration()

        self.assertEqual(result.status, "kill_switch_active")
        kill_switch.enable_mock.assert_not_called()

    @patch("core.watchdog.pool_builder.build_pool", return_value=[])
    @patch("core.watchdog.health_checker.check", return_value="down")
    def test_run_iteration_falls_back_when_configured_kill_switch_fails_to_enable(self, _hc, _pool) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        kill_switch = FakeKillSwitch(active=False, enable_result=False)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1},
            "kill_switch": {"enabled": True},
            "rotation": {"enabled": True},
            "adguard": {},
        }

        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine
        clock_value = [0.0]
        clock = lambda: clock_value[0]
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=kill_switch,
        )

        result = runtime.run_iteration()

        self.assertEqual(result.status, "rotation_unavailable")
        kill_switch.enable_mock.assert_called_once_with()

    def test_rotate_now_standby_when_gate_off(self) -> None:
        self.state_manager.set("vpn_desired_state", "off")
        runtime = self._make_runtime(FakeDriver())

        result = runtime.rotate_now()

        self.assertEqual(result.status, "standby")

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check", return_value="ok")
    def test_rotate_now_returns_recovered_on_success(self, _hc, mock_pool, mock_sel_driver) -> None:
        alt_profile = Profile(
            id="alt2", name="Alt2", protocol=ProtocolType.VLESS,
            config={}, source=ProfileSource.MANUAL, in_rotation_pool=True, enabled=True,
        )
        driver = FakeDriver()
        mock_pool.return_value = [alt_profile]
        mock_sel_driver.return_value = driver

        runtime = self._make_runtime(driver)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        runtime.app_config = MagicMock(spec=AppConfig)
        runtime.app_config.load.return_value = {
            "watchdog": {}, "kill_switch": {"enabled": False},
            "rotation": {"enabled": True}, "adguard": {},
        }

        result = runtime.rotate_now(force=True)

        self.assertEqual(result.status, "recovered")
        self.assertEqual(self.state_manager.get("active_profile_id"), alt_profile.id)

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check", return_value="ok")
    def test_successful_rotation_restores_existing_kill_switch(self, _hc, mock_pool, mock_sel_driver) -> None:
        alt_profile = Profile(
            id="alt3", name="Alt3", protocol=ProtocolType.VLESS,
            config={}, source=ProfileSource.MANUAL, in_rotation_pool=True, enabled=True,
        )
        driver = FakeDriver()
        kill_switch = FakeKillSwitch(active=True)
        mock_pool.return_value = [alt_profile]
        mock_sel_driver.return_value = driver

        runtime = self._make_runtime(driver)
        runtime.kill_switch = kill_switch

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        runtime.app_config = MagicMock(spec=AppConfig)
        runtime.app_config.load.return_value = {
            "watchdog": {},
            "kill_switch": {
                "enabled": True,
                "tunnel_interface": "wg0",
                "block_ipv6": False,
                "allow_lan": False,
            },
            "rotation": {"enabled": True},
            "adguard": {},
        }

        result = runtime.rotate_now(force=True)

        self.assertEqual(result.status, "recovered")
        self.assertTrue(result.kill_switch_active)
        self.assertEqual(kill_switch.tunnel_interface, "wg0")
        self.assertFalse(kill_switch.block_ipv6)
        self.assertFalse(kill_switch.allow_lan)
        kill_switch.enable_mock.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
