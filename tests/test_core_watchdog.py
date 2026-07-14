from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

from app_policy.models import AppPolicy, AppPolicyAction, AppPolicyMode, AppPolicyRule
from app_policy.store import AppPolicyStore
from config.app_config import AppConfig
from core.watchdog import WatchdogRuntime, build_watchdog, select_driver

from core.kill_switch import KillSwitch
from core.runtime_observation import EffectiveRuntimeObservation
from config.dns_policy_store import DNSPolicyStore
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.state_manager import StateManager
from dns.models import DNSChannel, DNSChannelName, DNSMode, DNSPolicy, Resolver
from dns.state_manager import SystemDNSStateManager
from drivers.amneziawg_driver import AmneziaWGDriver
from drivers.base import BaseDriver
from drivers.openvpn_cloak_driver import OpenVPNCloakDriver
from drivers.openvpn_driver import OpenVPNDriver
from drivers.singbox_driver import SingBoxDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType
from rotation import pool_builder
from rotation.health_checker import HealthCheckResult
from route_chains.models import ChainHop, RouteChain, RouteChainDocument
from route_chains.store import RouteChainStore
from rules.models import Rule, RuleGroup
from rules.rule_store import RuleStore
from rules.ruleset_lifecycle import RuleSetLifecycleManager
from rules.ruleset_trust_store import RuleSetTrustStore


class FakeDriver(BaseDriver):
    def __init__(self) -> None:
        self.connect_mock = Mock(return_value=True)
        self.disconnect_mock = Mock(return_value=True)
        self.health_check_mock = Mock(return_value="ok")
        self.status_mock = Mock(return_value=ConnectionState(status="connected", mode="rules"))
        self.is_available_mock = Mock(return_value=True)
        self.last_dns_policy: DNSPolicy | None = "unset"
        self.last_mode: str | None = None
        self.last_groups = "unset"
        self.last_app_policy = "unset"
        self.last_final_policy: str | None = None
        self.last_rule_set_tags = "unset"
        self.last_rule_set_declarations = "unset"
        self.last_chain_runtime_plans = "unset"
        self.last_lan_proxy = "unset"
        self.last_lan_gateway = "unset"
        self.last_capture_modes = "unset"

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups=None,
        app_policy=None,
        final_policy: str = "current_profile",
        rule_set_tags=None,
        rule_set_declarations=None,
        chain_runtime_plans=None,
        lan_proxy=None,
        lan_gateway=None,
        capture_modes=None,
    ) -> bool:
        self.last_dns_policy = dns_policy
        self.last_mode = mode
        self.last_groups = groups
        self.last_app_policy = app_policy
        self.last_final_policy = final_policy
        self.last_rule_set_tags = rule_set_tags
        self.last_rule_set_declarations = rule_set_declarations
        self.last_chain_runtime_plans = chain_runtime_plans
        self.last_lan_proxy = lan_proxy
        self.last_lan_gateway = lan_gateway
        self.last_capture_modes = capture_modes
        return bool(self.connect_mock(profile))

    def disconnect(self) -> bool:
        return bool(self.disconnect_mock())

    def health_check(self) -> str:
        return str(self.health_check_mock())

    def status(self) -> ConnectionState:
        return self.status_mock()

    def is_available(self) -> bool:
        return bool(self.is_available_mock())


class FakeSingBoxDriver(FakeDriver):
    pass


class FakeAWGDriver(FakeDriver):
    pass


class EventDriver(FakeDriver):
    def __init__(self, name: str, events: list[str]) -> None:
        super().__init__()
        self.name = name
        self.events = events

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups=None,
        app_policy=None,
        final_policy: str = "current_profile",
        rule_set_tags=None,
        rule_set_declarations=None,
        chain_runtime_plans=None,
        lan_proxy=None,
        lan_gateway=None,
        capture_modes=None,
    ) -> bool:
        self.events.append(f"{self.name}:connect:{profile.id}")
        return super().connect(
            profile,
            dns_policy=dns_policy,
            mode=mode,
            groups=groups,
            app_policy=app_policy,
            final_policy=final_policy,
            rule_set_tags=rule_set_tags,
            rule_set_declarations=rule_set_declarations,
            chain_runtime_plans=chain_runtime_plans,
            lan_proxy=lan_proxy,
            lan_gateway=lan_gateway,
            capture_modes=capture_modes,
        )

    def disconnect(self) -> bool:
        self.events.append(f"{self.name}:disconnect")
        return super().disconnect()


class EventSingBoxDriver(EventDriver):
    pass


class EventAWGDriver(EventDriver):
    pass


class FakeKillSwitch:
    def __init__(self, active: bool = False, enable_result: bool = True) -> None:
        self.active = active
        self.enable_result = enable_result
        self.enable_mock = Mock(side_effect=self._enable)
        self.apply_atomic_mock = Mock(side_effect=self._enable)
        self.disable_mock = Mock(return_value=True)
        self.is_active_mock = Mock(side_effect=lambda: self.active)
        self.status_mock = Mock(return_value={})
        self.tunnel_interface = "tun0"
        self.block_ipv6 = True
        self.allow_lan = True
        self.allowed_endpoints: tuple[str, ...] = ()

    def _enable(self) -> bool:
        if self.enable_result:
            self.active = True
        return self.enable_result

    def enable(self) -> bool:
        return bool(self.enable_mock())

    def apply_atomic(self) -> bool:
        return bool(self.apply_atomic_mock())

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
            protocol=ProtocolType.VLESS,
            config={"location": "DK"},
            source=ProfileSource.MANUAL,
        )
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state_manager = StateManager(Path(self.tmpdir.name) / "state.toml")
        self.profile_store = ProfileStore(Path(self.tmpdir.name) / "profiles.json")
        self.kill_switch_apply_patch = patch.object(KillSwitch, "apply_atomic", return_value=True)
        self.kill_switch_apply_patch.start()
        self.addCleanup(self.kill_switch_apply_patch.stop)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def set_desired_state(self, desired_state: str) -> None:
        self.state_manager.set("vpn_desired_state", desired_state)

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

    @patch.object(SingBoxDriver, "connect", return_value=True)
    @patch.object(SingBoxDriver, "disconnect", return_value=True)
    @patch.object(SingBoxDriver, "health_check", return_value="ok")
    @patch.object(SingBoxDriver, "status", return_value=None)
    def test_runtime_delegates_to_driver_interface(self, status_mock, health_mock, disconnect_mock, connect_mock) -> None:
        self.set_desired_state("on")
        runtime = WatchdogRuntime(driver=SingBoxDriver(), state_manager=self.state_manager)
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


    def test_restart_startup_installs_barrier_before_connecting(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": self.profile.id,
            }
        )
        self.profile_store.add(self.profile)
        events: list[str] = []
        driver = FakeDriver()
        driver.connect_mock.side_effect = lambda _profile: events.append("connect") or True
        kill_switch = FakeKillSwitch()
        kill_switch.apply_atomic_mock.side_effect = (
            lambda: events.append("barrier") or kill_switch._enable()
        )
        app_config = Mock(spec=AppConfig)
        app_config.load.return_value = {"kill_switch": {"enabled": False}}
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            kill_switch=kill_switch,
        )

        state = runtime.startup(require_restart_protection=True)

        self.assertEqual(state.status, "connected")
        self.assertEqual(events, ["barrier", "connect"])
        kill_switch.disable_mock.assert_not_called()
        self.assertTrue(runtime._desired_on_kill_switch_forced)

    def test_restart_startup_refuses_driver_spawn_when_barrier_fails(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": self.profile.id,
            }
        )
        self.profile_store.add(self.profile)
        driver = FakeDriver()
        app_config = Mock(spec=AppConfig)
        app_config.load.return_value = {"kill_switch": {"enabled": False}}
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            kill_switch=FakeKillSwitch(enable_result=False),
        )

        state = runtime.startup(require_restart_protection=True)

        self.assertEqual(state.status, "kill_switch_failed")
        runtime.kill_switch.apply_atomic_mock.assert_called_once_with()
        driver.connect_mock.assert_not_called()


    def test_restart_startup_keeps_barrier_during_failed_autoconnect(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": self.profile.id,
            }
        )
        self.profile_store.add(self.profile)
        driver = FakeDriver()
        driver.connect_mock.return_value = False
        kill_switch = FakeKillSwitch()
        app_config = Mock(spec=AppConfig)
        app_config.load.return_value = {"kill_switch": {"enabled": False}}
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            kill_switch=kill_switch,
        )

        runtime.startup(require_restart_protection=True)

        kill_switch.apply_atomic_mock.assert_called_once_with()
        kill_switch.disable_mock.assert_not_called()
        self.assertTrue(runtime._desired_on_kill_switch_forced)

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
        self.assertIsInstance(runtime.driver, SingBoxDriver)

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

        runtime._desired_on_kill_switch_forced = True
        runtime.disconnect()

        kill_switch.disable_mock.assert_called_once_with()

        self.assertFalse(runtime._desired_on_kill_switch_forced)

    def test_shutdown_preserves_desired_on_and_keeps_fail_closed_barrier(self) -> None:
        self.set_desired_state("on")
        self.profile_store.add(self.profile)
        self.state_manager.set("active_profile_id", self.profile.id)
        driver = FakeDriver()
        kill_switch = FakeKillSwitch(active=True)
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            kill_switch=kill_switch,
        )

        self.assertTrue(runtime.shutdown())

        self.assertEqual(self.state_manager.get("vpn_desired_state"), "on")
        kill_switch.apply_atomic_mock.assert_called_once_with()
        kill_switch.disable_mock.assert_not_called()
        driver.disconnect_mock.assert_called_once_with()

    def test_shutdown_desired_off_removes_active_product_firewall(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        kill_switch = FakeKillSwitch(active=True)
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager, kill_switch=kill_switch)

        self.assertTrue(runtime.shutdown())

        self.assertEqual(self.state_manager.get("vpn_desired_state"), "off")
        kill_switch.apply_atomic_mock.assert_not_called()
        kill_switch.disable_mock.assert_called_once_with()
        driver.disconnect_mock.assert_called_once_with()

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
        events: list[str] = []
        driver = FakeDriver()
        driver.connect_mock.side_effect = lambda _profile: events.append("connect") or True
        kill_switch = FakeKillSwitch()
        kill_switch.apply_atomic_mock.side_effect = (
            lambda: events.append("barrier") or kill_switch._enable()
        )
        app_config = Mock(spec=AppConfig)
        app_config.load.return_value = {"kill_switch": {"enabled": False}}
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            app_config=app_config,
            kill_switch=kill_switch,
        )

        self.assertTrue(runtime.connect(self.profile))
        driver.connect_mock.assert_called_once_with(self.profile)
        self.assertEqual(events, ["barrier", "connect"])
        self.assertTrue(runtime._desired_on_kill_switch_forced)

    def test_connect_fails_closed_before_driver_spawn_when_atomic_kill_switch_fails(self) -> None:
        self.set_desired_state("off")
        driver = FakeDriver()
        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {"kill_switch": {"enabled": True}}

        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            app_config=app_config,
            kill_switch=FakeKillSwitch(enable_result=False),
        )

        self.assertFalse(runtime.connect(self.profile))
        runtime.kill_switch.apply_atomic_mock.assert_called_once_with()
        driver.connect_mock.assert_not_called()
        self.assertEqual(self.state_manager.get("vpn_desired_state"), "off")
        self.assertEqual(self.state_manager.get("active_profile_id", ""), "")

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

    def test_connect_forwards_the_stored_active_mode_to_the_driver(self) -> None:
        self.set_desired_state("off")
        self.state_manager.set("active_mode", "tun")
        driver = FakeDriver()
        runtime = WatchdogRuntime(driver=driver, state_manager=self.state_manager)

        runtime.connect(self.profile)

        self.assertEqual(driver.last_mode, "tun")
        self.assertEqual(driver.last_final_policy, "current_profile")

    def test_connect_forwards_persisted_rule_groups_when_rules_mode(self) -> None:
        self.set_desired_state("off")
        self.state_manager.set("active_mode", "rules")
        rule_store = RuleStore(Path(self.tmpdir.name) / "rules")
        group = RuleGroup(
            name="block",
            rules=[Rule(id="ads", action="block", conditions={"domain_suffix": [".ads.example"]})],
        )
        rule_store.add_group(group)
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            rule_store=rule_store,
        )

        runtime.connect(self.profile)

        self.assertEqual(driver.last_mode, "rules")
        self.assertEqual(driver.last_groups, [group])
        self.assertEqual(driver.last_final_policy, "current_profile")

    def test_connect_forwards_app_policy_when_rules_mode(self) -> None:
        self.set_desired_state("off")
        self.state_manager.set("active_mode", "rules")
        app_policy_store = AppPolicyStore(Path(self.tmpdir.name) / "app-policy.json")
        policy = AppPolicy(
            enabled=True,
            mode="blacklist",
            rules=[
                AppPolicyRule(
                    id="curl",
                    action="block",
                    match={"process_path": ["/usr/bin/curl"]},
                )
            ],
        )
        app_policy_store.save(policy)
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            app_policy_store=app_policy_store,
        )

        runtime.connect(self.profile)

        self.assertEqual(driver.last_mode, "rules")
        self.assertEqual(driver.last_app_policy, policy)

    def test_connect_resolves_chain_runtime_plan_for_rule_action(self) -> None:
        self.set_desired_state("off")
        self.state_manager.set("active_mode", "rules")
        self.profile_store.add(self.profile)
        dns_policy_store = DNSPolicyStore(Path(self.tmpdir.name) / "dns-policy.json")
        dns_policy_store.save(
            DNSPolicy(
                channels={
                    DNSChannelName.PROXY: DNSChannel(
                        name=DNSChannelName.PROXY,
                        resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                    )
                }
            )
        )
        rule_store = RuleStore(Path(self.tmpdir.name) / "rules")
        rule_store.add_group(
            RuleGroup(
                name="custom",
                rules=[
                    Rule(
                        id="chain",
                        action="chain:work-safe",
                        conditions={"domain": ["example.com"]},
                    )
                ],
            )
        )
        route_chain_store = RouteChainStore(Path(self.tmpdir.name) / "chains.json")
        route_chain_store.save(
            RouteChainDocument(
                chains=[
                    RouteChain(
                        id="work-safe",
                        enabled=True,
                        hops=[ChainHop(type="profile", target=self.profile.id)],
                    )
                ]
            )
        )
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            dns_policy_store=dns_policy_store,
            rule_store=rule_store,
            route_chain_store=route_chain_store,
        )

        runtime.connect(self.profile)

        plan = driver.last_chain_runtime_plans["chain:work-safe"]
        self.assertTrue(plan.resolved)
        self.assertEqual(plan.route_outbound_tag, "watchdogvpn-chain-work-safe-hop-1")

    def test_connect_fails_closed_when_app_policy_is_invalid(self) -> None:
        self.set_desired_state("off")
        self.state_manager.set("active_mode", "rules")
        app_policy_path = Path(self.tmpdir.name) / "app-policy.json"
        app_policy_path.write_text("{", encoding="utf-8")
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            app_policy_store=AppPolicyStore(app_policy_path),
        )

        with self.assertLogs("core.watchdog", level="ERROR") as logs:
            runtime.connect(self.profile)

        self.assertIn("app_policy_invalid action=fail_closed", "\n".join(logs.output))
        self.assertTrue(driver.last_app_policy.enabled)
        self.assertEqual(driver.last_app_policy.mode, AppPolicyMode.WHITELIST)
        self.assertEqual(driver.last_app_policy.default_action, AppPolicyAction.BLOCK)
        self.assertEqual(driver.last_app_policy.rules, [])

    def test_connect_does_not_forward_rule_groups_outside_rules_mode(self) -> None:
        self.set_desired_state("off")
        self.state_manager.set("active_mode", "global")
        rule_store = RuleStore(Path(self.tmpdir.name) / "rules")
        rule_store.add_group(
            RuleGroup(
                name="block",
                rules=[Rule(id="ads", action="block", conditions={"domain_suffix": [".ads.example"]})],
            )
        )
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            rule_store=rule_store,
        )

        runtime.connect(self.profile)

        # "global" legacy mode now migrates to capture_modes="local_proxy,tun"
        # (Phase 23 Task 23.3.4), so _connect_options() correctly derives
        # the more specific "tun" mode label rather than "global" - the
        # point of this test is that rule groups/app policy are not
        # forwarded outside "rules" mode, not the exact label.
        self.assertEqual(driver.last_mode, "tun")
        self.assertIsNone(driver.last_groups)
        self.assertIsNone(driver.last_app_policy)

    def test_connect_maps_global_block_routing_shape_without_rule_policy(self) -> None:
        self.set_desired_state("off")
        self.state_manager.save(
            {
                "routing_state_version": "1",
                "routing_policy": "global",
                "capture_modes": "local_proxy",
                "default_route_action": "block",
                "active_mode": "global",
            }
        )
        rule_store = RuleStore(Path(self.tmpdir.name) / "rules")
        rule_store.add_group(
            RuleGroup(
                name="block",
                rules=[Rule(id="ads", action="block", conditions={"domain_suffix": [".ads.example"]})],
            )
        )
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            rule_store=rule_store,
        )

        runtime.connect(self.profile)

        self.assertEqual(driver.last_mode, "rules")
        self.assertEqual(driver.last_final_policy, "block")
        self.assertIsNone(driver.last_groups)
        self.assertIsNone(driver.last_app_policy)

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

    def test_startup_forwards_the_stored_active_mode_to_the_driver(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": self.profile.id,
                "active_mode": "tun",
            }
        )
        self.profile_store.add(self.profile)
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
        )

        runtime.startup()

        self.assertEqual(driver.last_mode, "tun")

    def test_startup_forwards_persisted_rule_groups_when_rules_mode(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": self.profile.id,
                "active_mode": "rules",
            }
        )
        self.profile_store.add(self.profile)
        rule_store = RuleStore(Path(self.tmpdir.name) / "rules")
        group = RuleGroup(
            name="app",
            rules=[Rule(id="steam", action="direct", conditions={"process_name": ["steam"]})],
        )
        rule_store.add_group(group)
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            rule_store=rule_store,
        )

        runtime.startup()

        self.assertEqual(driver.last_mode, "rules")
        self.assertEqual(driver.last_groups, [group])

    def test_startup_forwards_app_policy_when_rules_mode(self) -> None:
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": self.profile.id,
                "active_mode": "rules",
            }
        )
        self.profile_store.add(self.profile)
        app_policy_store = AppPolicyStore(Path(self.tmpdir.name) / "app-policy.json")
        policy = AppPolicy(
            enabled=True,
            mode="blacklist",
            rules=[
                AppPolicyRule(
                    id="browser",
                    action="direct",
                    match={"process_name": ["firefox"]},
                )
            ],
        )
        app_policy_store.save(policy)
        driver = FakeDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_policy_store=app_policy_store,
        )

        runtime.startup()

        self.assertEqual(driver.last_app_policy, policy)

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "health_check", return_value="ok")
    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    @patch.object(SingBoxDriver, "_ip_rule_lines", return_value=())
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_runtime_rules_mode_groups_reach_generated_singbox_config(
        self, popen_mock, ip_rule_mock, bind_mock, binary_mock, health_mock, write_mock
    ) -> None:
        process = popen_mock.return_value
        process.poll.return_value = None
        process.pid = 4321
        self.set_desired_state("off")
        self.state_manager.set("active_mode", "rules")
        profile = Profile(
            id="vless-runtime",
            name="Runtime VLESS",
            protocol=ProtocolType.VLESS,
            config={
                "server": "vless.example.com",
                "port": 443,
                "uuid": "00000000-0000-4000-8000-000000000001",
                "security": "none",
            },
            source=ProfileSource.MANUAL,
        )
        rule_store = RuleStore(Path(self.tmpdir.name) / "rules")
        rule_store.add_group(
            RuleGroup(
                name="block",
                rules=[Rule(id="ads", action="block", conditions={"domain_suffix": [".ads.example"]})],
            )
        )
        app_policy_store = AppPolicyStore(Path(self.tmpdir.name) / "app-policy.json")
        dns_policy_store = DNSPolicyStore(Path(self.tmpdir.name) / "dns-policy.json")
        dns_policy_store.save(DNSPolicy(mode=DNSMode.OFF))
        driver = SingBoxDriver()
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            rule_store=rule_store,
            app_policy_store=app_policy_store,
            dns_policy_store=dns_policy_store,
        )

        self.assertTrue(runtime.connect(profile))

        config = write_mock.call_args.args[0]
        self.assertEqual(
            config["route"]["rules"],
            [
                {"domain_suffix": [".ads.example"], "action": "reject"},
                {"action": "route", "outbound": "Runtime VLESS"},
            ],
        )

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

    def test_connect_switches_driver_when_profile_requires_different_driver_type(self) -> None:
        self.set_desired_state("off")
        current_driver = FakeSingBoxDriver()
        next_driver = FakeAWGDriver()
        awg_profile = Profile(
            id="awg1",
            name="AWG",
            protocol=ProtocolType.AMNEZIAWG,
            config={},
            source=ProfileSource.MANUAL,
        )

        def selector(profile: Profile | None = None) -> BaseDriver:
            return next_driver if profile and profile.id == awg_profile.id else current_driver

        runtime = WatchdogRuntime(
            driver=current_driver,
            state_manager=self.state_manager,
            driver_selector=selector,
        )

        self.assertTrue(runtime.connect(awg_profile))

        current_driver.disconnect_mock.assert_called_once_with()
        next_driver.connect_mock.assert_called_once_with(awg_profile)
        self.assertIs(runtime.driver, next_driver)
        self.assertEqual(self.state_manager.get("active_profile_id"), awg_profile.id)

    def test_connect_reuses_current_driver_for_same_driver_type(self) -> None:
        self.set_desired_state("off")
        current_driver = FakeSingBoxDriver()
        replacement_same_type = FakeSingBoxDriver()
        profile = Profile(
            id="vless1",
            name="VLESS",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
        )

        runtime = WatchdogRuntime(
            driver=current_driver,
            state_manager=self.state_manager,
            driver_selector=lambda _profile=None: replacement_same_type,
        )

        self.assertTrue(runtime.connect(profile))

        current_driver.disconnect_mock.assert_called_once()
        current_driver.connect_mock.assert_called_once_with(profile)
        replacement_same_type.connect_mock.assert_not_called()
        self.assertIs(runtime.driver, current_driver)

    def test_startup_switches_to_driver_for_active_profile(self) -> None:
        awg_profile = Profile(
            id="awg-start",
            name="AWG",
            protocol=ProtocolType.AMNEZIAWG,
            config={},
            source=ProfileSource.MANUAL,
        )
        self.state_manager.save(
            {
                "vpn_desired_state": "on",
                "vpn_autoconnect_enabled": True,
                "active_profile_id": awg_profile.id,
            }
        )
        self.profile_store.add(awg_profile)
        current_driver = FakeSingBoxDriver()
        next_driver = FakeAWGDriver()
        runtime = WatchdogRuntime(
            driver=current_driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            driver_selector=lambda _profile=None: next_driver,
        )

        state = runtime.startup()

        self.assertEqual(state.status, "connected")
        current_driver.disconnect_mock.assert_called_once_with()
        next_driver.connect_mock.assert_called_once_with(awg_profile)
        self.assertIs(runtime.driver, next_driver)

    def test_status_uses_current_driver_after_driver_switch(self) -> None:
        self.set_desired_state("off")
        current_driver = FakeSingBoxDriver()
        current_driver.status_mock.return_value = ConnectionState(status="connected", mode="old-driver")
        next_driver = FakeAWGDriver()
        next_driver.status_mock.return_value = ConnectionState(status="recovered", mode="new-driver")
        awg_profile = Profile(
            id="awg-status",
            name="AWG",
            protocol=ProtocolType.AMNEZIAWG,
            config={},
            source=ProfileSource.MANUAL,
        )
        runtime = WatchdogRuntime(
            driver=current_driver,
            state_manager=self.state_manager,
            driver_selector=lambda _profile=None: next_driver,
        )

        runtime.connect(awg_profile)

        state = runtime.status()
        self.assertEqual(state.status, "recovered")
        self.assertEqual(state.mode, "new-driver")
        current_driver.status_mock.assert_not_called()
        next_driver.status_mock.assert_called_once_with()


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

        self.kill_switch_apply_patch = patch.object(KillSwitch, "apply_atomic", return_value=True)
        self.kill_switch_apply_patch.start()
        self.addCleanup(self.kill_switch_apply_patch.stop)
    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _make_runtime(self, driver: BaseDriver, rule_store: RuleStore | None = None) -> WatchdogRuntime:
        from config.app_config import AppConfig
        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine

        clock_value = [0.0]
        clock = lambda: clock_value[0]
        return WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            # AppConfig defaults to the real user config dir - pin it to the
            # tmpdir so any self.app_config.load() call (_checked_and_recorded,
            # Task 14.7) never touches real filesystem state in tests.
            app_config=AppConfig(Path(self.tmpdir.name) / "config.toml"),
            rotation_engine=RotationEngine(clock=clock, sleep=lambda s: None, warmup_seconds=0.0),
            recovery=Recovery(clock=clock),
            kill_switch=FakeKillSwitch(),
            rule_store=rule_store or RuleStore(Path(self.tmpdir.name) / "rules"),
            rule_set_lifecycle=RuleSetLifecycleManager(
                store=RuleSetTrustStore(Path(self.tmpdir.name) / "ruleset-trust.json"),
                cache_dir=Path(self.tmpdir.name) / "rulesets" / "cache",
            ),
        )

    def test_run_iteration_healthy_resets_recovery_and_returns_connected(self) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "ok"
        runtime = self._make_runtime(driver)

        result = runtime.run_iteration()

        self.assertEqual(result.status, "connected")

    def test_run_iteration_persists_health_status_on_happy_path(self) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "ok"
        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)
        runtime = self._make_runtime(driver)

        runtime.run_iteration()

        persisted = self.profile_store.get(self.profile.id)
        self.assertEqual(persisted.health_status, "ok")
        self.assertIsNotNone(persisted.last_health_check)

    def test_run_iteration_standby_when_gate_off(self) -> None:
        self.state_manager.set("vpn_desired_state", "off")
        driver = FakeDriver()
        runtime = self._make_runtime(driver)

        result = runtime.run_iteration()

        self.assertEqual(result.status, "standby")
        driver.health_check_mock.assert_not_called()

    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="ok"))
    def test_run_iteration_reconnects_current_profile_on_failure(self, _hc) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)
        runtime = self._make_runtime(driver)

        result = runtime.run_iteration()

        self.assertEqual(result.status, "recovered")
        # Assert by id, not full object equality: _try_reconnect fetches
        # its own fresh copy via _active_profile() (a different Profile
        # instance from self.profile) and Task 14.5 now mutates it in
        # place with the real health check result after connect() records
        # it, which would otherwise make a full-object comparison flaky.
        connected_profile = driver.connect_mock.call_args.args[0]
        self.assertEqual(connected_profile.id, self.profile.id)

    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="ok"))
    def test_successful_reconnect_persists_health_status_to_the_real_store(self, _hc) -> None:
        # AUD-P14-001 / Task 14.5: the persisted copy must reflect the real
        # health_checker.check() result the reconnect path just produced,
        # even though _try_reconnect operates on its own fresh Profile
        # instance (fetched via _active_profile()), not self.profile.
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)
        runtime = self._make_runtime(driver)

        runtime.run_iteration()

        persisted = self.profile_store.get(self.profile.id)
        self.assertEqual(persisted.health_status, "ok")
        self.assertIsNotNone(persisted.last_health_check)

    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="ok"))
    def test_reconnect_forwards_persisted_rule_groups_when_rules_mode(self, _hc) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        self.state_manager.set("active_profile_id", self.profile.id)
        self.state_manager.set("active_mode", "rules")
        self.profile_store.add(self.profile)
        rule_store = RuleStore(Path(self.tmpdir.name) / "rules")
        group = RuleGroup(
            name="custom",
            rules=[Rule(id="site", action="current_profile", conditions={"domain": ["example.com"]})],
        )
        rule_store.add_group(group)
        runtime = self._make_runtime(driver, rule_store=rule_store)

        result = runtime.run_iteration()

        self.assertEqual(result.status, "recovered")
        self.assertEqual(driver.last_mode, "rules")
        self.assertEqual(driver.last_groups, [group])

    def test_connect_forwards_verified_ruleset_runtime_plan(self) -> None:
        payload = json.dumps({"version": 1, "rules": [{"domain": ["example.com"]}]}).encode("utf-8")
        source = Path(self.tmpdir.name) / "builtin.json"
        source.write_bytes(payload)
        trust_store = RuleSetTrustStore(Path(self.tmpdir.name) / "ruleset-trust.json")
        from rules.ruleset_trust import RuleSetTrustPolicy, RuleSetTrustRegistry

        policy = RuleSetTrustPolicy(
            id="builtin-example",
            kind="built-in",
            source=str(source),
            critical=True,
            update_interval_seconds=3600,
            max_stale_seconds=7200,
        )
        trust_store.save(RuleSetTrustRegistry(policies={policy.id: policy}))
        driver = FakeDriver()
        self.state_manager.set("active_mode", "rules")
        rule_store = RuleStore(Path(self.tmpdir.name) / "rules")
        group = RuleGroup(
            name="custom",
            rules=[
                Rule(
                    id="rs",
                    action="block",
                    conditions={"ruleset_builtin": [policy.id]},
                )
            ],
        )
        rule_store.add_group(group)
        runtime = WatchdogRuntime(
            driver=driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            rule_store=rule_store,
            rule_set_lifecycle=RuleSetLifecycleManager(
                store=trust_store,
                cache_dir=Path(self.tmpdir.name) / "rulesets" / "cache",
            ),
        )

        runtime.connect(self.profile)

        self.assertEqual(driver.last_mode, "rules")
        self.assertIn(policy.id, driver.last_rule_set_tags)
        self.assertEqual(driver.last_rule_set_declarations[0]["type"], "local")

    def test_connect_refuses_ruleset_without_trust_policy(self) -> None:
        driver = FakeDriver()
        self.state_manager.set("active_mode", "rules")
        rule_store = RuleStore(Path(self.tmpdir.name) / "rules")
        rule_store.add_group(
            RuleGroup(
                name="custom",
                rules=[
                    Rule(
                        id="rs",
                        action="block",
                        conditions={"ruleset_remote": ["missing-policy"]},
                    )
                ],
            )
        )
        runtime = self._make_runtime(driver, rule_store=rule_store)

        with self.assertRaisesRegex(RuntimeError, "referenced rule-set has no trust policy"):
            runtime.connect(self.profile)
        driver.connect_mock.assert_not_called()

    def test_connect_refuses_unimplemented_system_proxy_capture(self) -> None:
        driver = FakeDriver()
        self.state_manager.save(
            {
                **self.state_manager.load(),
                "routing_state_version": "1",
                "routing_policy": "global",
                "capture_modes": "local_proxy,system_proxy",
                "default_route_action": "current",
            }
        )
        runtime = self._make_runtime(driver)

        with self.assertRaisesRegex(RuntimeError, "system_proxy capture is not implemented yet"):
            runtime.connect(self.profile)
        driver.connect_mock.assert_not_called()

    def test_connect_options_cover_capture_coexistence_contract(self) -> None:
        cases = [
            (
                "rule-local-proxy",
                {
                    "routing_policy": "rule",
                    "capture_modes": "local_proxy",
                    "default_route_action": "current",
                },
                "rules",
                "current_profile",
            ),
            (
                "rule-tun",
                {
                    "routing_policy": "rule",
                    "capture_modes": "local_proxy,tun",
                    "default_route_action": "current",
                },
                "rules",
                "current_profile",
            ),
            (
                "global-local-proxy",
                {
                    "routing_policy": "global",
                    "capture_modes": "local_proxy",
                    "default_route_action": "current",
                },
                "global",
                "current_profile",
            ),
            (
                "global-tun",
                {
                    "routing_policy": "global",
                    "capture_modes": "local_proxy,tun",
                    "default_route_action": "current",
                },
                "tun",
                "current_profile",
            ),
            (
                "local-proxy-direct-action",
                {
                    "routing_policy": "global",
                    "capture_modes": "local_proxy",
                    "default_route_action": "direct",
                },
                "direct",
                "direct",
            ),
            (
                "local-proxy-block-action",
                {
                    "routing_policy": "global",
                    "capture_modes": "local_proxy",
                    "default_route_action": "block",
                },
                "rules",
                "block",
            ),
        ]
        runtime = self._make_runtime(FakeDriver())
        for name, routing_shape, expected_mode, expected_final_policy in cases:
            with self.subTest(name=name):
                self.state_manager.save(
                    {
                        **self.state_manager.load(),
                        "routing_state_version": "1",
                        **routing_shape,
                    }
                )

                options = runtime._connect_options()

                self.assertEqual(options["mode"], expected_mode)
                self.assertEqual(options["final_policy"], expected_final_policy)

    def test_connect_refuses_tun_system_proxy_until_system_proxy_runtime_exists(self) -> None:
        driver = FakeDriver()
        self.state_manager.save(
            {
                **self.state_manager.load(),
                "routing_state_version": "1",
                "routing_policy": "global",
                "capture_modes": "local_proxy,tun,system_proxy",
                "default_route_action": "current",
            }
        )
        runtime = self._make_runtime(driver)

        with self.assertRaisesRegex(RuntimeError, "system_proxy capture is not implemented yet"):
            runtime.connect(self.profile)
        driver.connect_mock.assert_not_called()

    def test_connect_forwards_enabled_lan_proxy_runtime_config(self) -> None:
        driver = FakeDriver()
        config_path = Path(self.tmpdir.name) / "config.toml"
        app_config = AppConfig(config_path)
        config = app_config.load()
        config["lan_sharing"].update(
            {
                "enabled": True,
                "mode": "proxy",
                "bind_address": "192.168.0.228",
                "socks_port": 2080,
                "http_port": 2081,
                "authentication_required": True,
                "firewall_managed": False,
            }
        )
        app_config.save(config)
        runtime = self._make_runtime(driver)
        runtime.app_config = app_config
        runtime._local_ip_addresses = Mock(return_value={"192.168.0.228"})

        runtime.connect(self.profile)

        self.assertEqual(driver.last_lan_proxy.bind_address, "192.168.0.228")
        self.assertEqual(driver.last_lan_proxy.socks_port, 2080)
        self.assertEqual(driver.last_lan_proxy.http_port, 2081)
        self.assertEqual(driver.last_lan_proxy.username, "watchdogvpn")
        self.assertTrue(driver.last_lan_proxy.password)
        self.assertFalse(driver.last_lan_proxy.firewall_managed)

    def test_connect_refuses_lan_proxy_bind_not_assigned_to_host(self) -> None:
        driver = FakeDriver()
        config_path = Path(self.tmpdir.name) / "config.toml"
        app_config = AppConfig(config_path)
        config = app_config.load()
        config["lan_sharing"].update(
            {
                "enabled": True,
                "mode": "proxy",
                "bind_address": "192.168.0.228",
                "authentication_required": True,
            }
        )
        app_config.save(config)
        runtime = self._make_runtime(driver)
        runtime.app_config = app_config
        runtime._local_ip_addresses = Mock(return_value={"10.0.0.5"})

        with self.assertRaisesRegex(RuntimeError, "not assigned to this host"):
            runtime.connect(self.profile)
        driver.connect_mock.assert_not_called()

    def test_connect_forwards_enabled_lan_gateway_runtime_config(self) -> None:
        driver = FakeDriver()
        config_path = Path(self.tmpdir.name) / "config.toml"
        app_config = AppConfig(config_path)
        config = app_config.load()
        config["lan_sharing"].update(
            {
                "enabled": True,
                "mode": "gateway",
                "firewall_managed": True,
                "gateway_interface": "enp0s8",
                "gateway_client_cidr": "192.168.50.0/24",
                "gateway_dns_mode": "manual",
            }
        )
        app_config.save(config)
        self.state_manager.save(
            {
                **self.state_manager.load(),
                "routing_state_version": "1",
                "routing_policy": "global",
                "capture_modes": "local_proxy,tun",
                "default_route_action": "current",
            }
        )
        runtime = self._make_runtime(driver)
        runtime.app_config = app_config
        runtime._local_interface_ipv4_addresses = Mock(return_value={"enp0s8": {"192.168.50.1"}})

        runtime.connect(self.profile)

        self.assertEqual(driver.last_lan_gateway.lan_interface, "enp0s8")
        self.assertEqual(driver.last_lan_gateway.client_cidr, "192.168.50.0/24")
        self.assertEqual(driver.last_lan_gateway.dns_mode, "manual")
        self.assertTrue(driver.last_lan_gateway.firewall_managed)
        self.assertEqual(driver.last_lan_gateway.tunnel_interface, "wdvpn-tun0")

    def test_connect_refuses_lan_gateway_without_tun_capture(self) -> None:
        driver = FakeDriver()
        config_path = Path(self.tmpdir.name) / "config.toml"
        app_config = AppConfig(config_path)
        config = app_config.load()
        config["lan_sharing"].update(
            {
                "enabled": True,
                "mode": "gateway",
                "firewall_managed": True,
                "gateway_interface": "enp0s8",
                "gateway_client_cidr": "192.168.50.0/24",
            }
        )
        app_config.save(config)
        runtime = self._make_runtime(driver)
        runtime.app_config = app_config
        # Explicit proxy-only capture (Task 23.3.4 made "rules"/"global"
        # default to capture_modes including "tun"; this test needs the
        # no-tun precondition it's actually testing).
        self.state_manager.set("active_mode", "proxy")

        with self.assertRaisesRegex(RuntimeError, "requires capture_modes to include tun"):
            runtime.connect(self.profile)
        driver.connect_mock.assert_not_called()

    def test_status_reports_lan_gateway_disabled(self) -> None:
        driver = FakeDriver()
        runtime = self._make_runtime(driver)

        state = runtime.status()

        self.assertEqual(state.lan_gateway_status, "disabled")
        self.assertFalse(state.lan_gateway_active)

    def test_status_reports_firewall_kill_switch_activity(self) -> None:
        driver = FakeDriver()
        driver.status_mock.return_value = ConnectionState(status="standby")
        runtime = self._make_runtime(driver)
        runtime.kill_switch = FakeKillSwitch(active=True)
        runtime.kill_switch.status_mock.return_value = {
            "active": True,
            "artifacts_present": True,
            "consistent": True,
            "method": "nftables",
            "mismatch_reasons": [],
        }

        with patch(
            "core.watchdog.observe_effective_runtime",
            return_value=EffectiveRuntimeObservation(),
        ):
            state = runtime.status()

        self.assertTrue(state.kill_switch_active)
        self.assertEqual(state.kill_switch_status, "applied")
        self.assertEqual(state.kill_switch_method, "nftables")
        self.assertEqual(state.status, "kill_switch_active")

    def test_status_reports_partial_kill_switch_as_critical_mismatch(self) -> None:
        driver = FakeDriver()
        driver.status_mock.return_value = ConnectionState(status="standby")
        runtime = self._make_runtime(driver)
        runtime.kill_switch = FakeKillSwitch(active=False)
        runtime.kill_switch.status_mock.return_value = {
            "active": False,
            "artifacts_present": True,
            "consistent": False,
            "method": "nftables",
            "mismatch_reasons": ["missing_terminal_drop"],
        }

        with patch(
            "core.watchdog.observe_effective_runtime",
            return_value=EffectiveRuntimeObservation(),
        ):
            state = runtime.status()

        self.assertEqual(state.status, "runtime_mismatch")
        self.assertEqual(state.runtime_mismatch_severity, "critical")
        self.assertEqual(state.kill_switch_status, "partial")
        self.assertFalse(state.kill_switch_consistent)
        self.assertIn(
            "kill_switch_mismatch:missing_terminal_drop", state.runtime_artifacts
        )

    def test_status_reports_owned_proxy_listener_when_driver_claims_standby(self) -> None:
        driver = FakeDriver()
        driver.status_mock.return_value = ConnectionState(status="standby")
        runtime = self._make_runtime(driver)
        observation = EffectiveRuntimeObservation(
            processes=("sing-box",),
            listener_ports=(2080,),
        )

        with patch(
            "core.watchdog.observe_effective_runtime", return_value=observation
        ):
            state = runtime.status()

        self.assertEqual(state.status, "runtime_mismatch")
        self.assertEqual(state.runtime_mismatch_severity, "critical")
        self.assertTrue(state.proxy_active)
        self.assertIn("owned_listener:tcp/2080", state.runtime_artifacts)

    def test_status_reports_lan_gateway_configured(self) -> None:
        driver = FakeDriver()
        config_path = Path(self.tmpdir.name) / "config.toml"
        app_config = AppConfig(config_path)
        config = app_config.load()
        config["lan_sharing"].update(
            {
                "enabled": True,
                "mode": "gateway",
                "firewall_managed": True,
                "gateway_interface": "enp0s8",
                "gateway_client_cidr": "192.168.50.0/24",
            }
        )
        app_config.save(config)
        runtime = self._make_runtime(driver)
        runtime.app_config = app_config

        state = runtime.status()

        self.assertEqual(state.lan_gateway_status, "configured")
        self.assertFalse(state.lan_gateway_active)
        self.assertEqual(state.lan_gateway_interface, "enp0s8")
        self.assertEqual(state.lan_gateway_client_cidr, "192.168.50.0/24")
        self.assertEqual(state.lan_gateway_dns_mode, "manual")

    def test_status_reports_lan_gateway_applied(self) -> None:
        driver = FakeDriver()
        driver.status_mock.return_value = ConnectionState(
            status="connected",
            mode="sing-box",
            tun_active=True,
            proxy_active=True,
            lan_gateway_active=True,
            lan_gateway_interface="enp0s8",
            lan_gateway_client_cidr="192.168.50.0/24",
            lan_gateway_dns_mode="manual",
        )
        runtime = self._make_runtime(driver)

        state = runtime.status()

        self.assertEqual(state.lan_gateway_status, "applied")

    def test_status_reports_lan_gateway_degraded(self) -> None:
        driver = FakeDriver()
        driver.status_mock.return_value = ConnectionState(
            status="connected",
            mode="sing-box",
            tun_active=False,
            proxy_active=True,
            lan_gateway_active=True,
            lan_gateway_interface="enp0s8",
            lan_gateway_client_cidr="192.168.50.0/24",
            lan_gateway_dns_mode="manual",
        )
        runtime = self._make_runtime(driver)

        state = runtime.status()

        self.assertEqual(state.lan_gateway_status, "degraded")

    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
    def test_run_iteration_returns_reconnecting_below_attempt_threshold(self, _hc) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {"watchdog": {"reconnect_attempts": 3}, "kill_switch": {"enabled": False}, "rotation": {}}

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

    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
    def test_run_iteration_disconnects_reconnect_runtime_when_deep_check_fails(self, _hc) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        driver.connect_mock.return_value = True
        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 3},
            "kill_switch": {"enabled": False},
            "rotation": {},
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

        self.assertEqual(result.status, "reconnecting")
        self.assertEqual(driver.disconnect_mock.call_count, 2)

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

        def health_check_by_profile(profile, drv, **kwargs):
            status = "ok" if profile.id == alt_profile.id else "down"
            return HealthCheckResult(status=status)

        with patch("core.watchdog.health_checker.check_with_latency", side_effect=health_check_by_profile):
            result = runtime.run_iteration()

        self.assertEqual(result.status, "recovered")
        self.assertEqual(self.state_manager.get("active_profile_id"), alt_profile.id)

    @patch("core.watchdog.pool_builder.build_pool")
    def test_run_iteration_rotates_across_driver_type_boundary(self, mock_pool) -> None:
        alt_profile = Profile(
            id="awg-alt",
            name="AWG Alt",
            protocol=ProtocolType.AMNEZIAWG,
            config={},
            source=ProfileSource.MANUAL,
            in_rotation_pool=True,
            enabled=True,
        )
        events: list[str] = []
        current_driver = EventSingBoxDriver("singbox", events)
        current_driver.health_check_mock.return_value = "down"
        next_driver = EventAWGDriver("awg", events)
        mock_pool.return_value = [alt_profile]

        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1},
            "kill_switch": {"enabled": False},
            "rotation": {"enabled": True},
        }

        from rotation.recovery import Recovery
        from rotation.rotation_engine import RotationEngine
        clock_value = [0.0]
        clock = lambda: clock_value[0]

        def selector(profile: Profile | None = None) -> BaseDriver:
            return next_driver if profile and profile.id == alt_profile.id else current_driver

        runtime = WatchdogRuntime(
            driver=current_driver,
            state_manager=self.state_manager,
            profile_store=self.profile_store,
            app_config=app_config,
            rotation_engine=RotationEngine(
                clock=clock,
                sleep=lambda s: None,
                warmup_seconds=0.0,
                max_fails_before_rollback=99,
            ),
            recovery=Recovery(clock=clock),
            kill_switch=FakeKillSwitch(),
            driver_selector=selector,
        )

        def health_check_by_profile(profile: Profile, driver: BaseDriver, **kwargs) -> HealthCheckResult:
            status = "ok" if profile.id == alt_profile.id else "down"
            return HealthCheckResult(status=status)

        with patch("core.watchdog.health_checker.check_with_latency", side_effect=health_check_by_profile):
            result = runtime.run_iteration()

        self.assertEqual(result.status, "recovered")
        self.assertEqual(self.state_manager.get("active_profile_id"), alt_profile.id)
        self.assertIs(runtime.driver, next_driver)
        self.assertIn("singbox:disconnect", events)
        self.assertIn("awg:connect:awg-alt", events)
        self.assertLess(events.index("singbox:disconnect"), events.index("awg:connect:awg-alt"))

    @patch("core.watchdog.pool_builder.build_pool", return_value=[])
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
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
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
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
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
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

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
    def test_status_surfaces_last_failure_after_all_failed_until_reconnect(
        self, _hc, mock_pool, mock_sel_driver
    ) -> None:
        # Regression guard for WDCLI-003: an all_failed rotation must not
        # vanish from watchdog status() a moment later - it has to persist
        # until a confirmed reconnect, not just live in a log line.
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

        # driver.status() itself would say "standby" - status() must still
        # surface the persisted failure on top of that. A fresh
        # ConnectionState per call (not a shared return_value) - status()
        # mutates the instance it's given, so reusing one across calls
        # would leak the first call's mutation into the second.
        driver.status_mock.side_effect = lambda: ConnectionState(status="standby", mode="standby")
        status_after = runtime.status()
        self.assertEqual(status_after.last_failure_reason, "all_failed")
        self.assertIsNotNone(status_after.last_failure_at)

        self.assertTrue(runtime.connect(self.profile))
        status_after_reconnect = runtime.status()
        self.assertEqual(status_after_reconnect.last_failure_reason, "")
        self.assertIsNone(status_after_reconnect.last_failure_at)

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
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
    def test_run_iteration_enables_kill_switch_when_configured_and_all_fail(self, _hc, _pool) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        kill_switch = FakeKillSwitch(active=False)
        self.profile.config["host"] = "203.0.113.10"
        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1},
            "kill_switch": {"enabled": True},
            "rotation": {"enabled": True},
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
        self.assertEqual(kill_switch.apply_atomic_mock.call_count, 2)
        self.assertEqual(kill_switch.allowed_endpoints, ("203.0.113.10",))

    @patch("core.watchdog.pool_builder.build_pool", return_value=[])
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
    def test_run_iteration_does_not_allow_hostname_endpoint_without_literal_ip(self, _hc, _pool) -> None:
        driver = FakeDriver()
        driver.health_check_mock.return_value = "down"
        kill_switch = FakeKillSwitch(active=False)
        self.profile.config["host"] = "vpn.example.test"
        self.state_manager.set("active_profile_id", self.profile.id)
        self.profile_store.add(self.profile)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        app_config = MagicMock(spec=AppConfig)
        app_config.load.return_value = {
            "watchdog": {"reconnect_attempts": 1},
            "kill_switch": {"enabled": True},
            "rotation": {"enabled": True},
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
        self.assertEqual(kill_switch.allowed_endpoints, ())

    @patch("core.watchdog.pool_builder.build_pool", return_value=[])
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
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
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
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

        self.assertEqual(result.status, "kill_switch_failed")
        kill_switch.apply_atomic_mock.assert_called_once_with()

    def test_rotate_now_standby_when_gate_off(self) -> None:
        self.state_manager.set("vpn_desired_state", "off")
        runtime = self._make_runtime(FakeDriver())

        result = runtime.rotate_now()

        self.assertEqual(result.status, "standby")

    def test_scheduled_rotate_standby_when_gate_off(self) -> None:
        self.state_manager.set("vpn_desired_state", "off")
        runtime = self._make_runtime(FakeDriver())

        result = runtime.scheduled_rotate()

        self.assertEqual(result.status, "standby")

    def test_scheduled_rotate_noop_when_interval_is_zero(self) -> None:
        driver = FakeDriver()
        runtime = self._make_runtime(driver)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        runtime.app_config = MagicMock(spec=AppConfig)
        runtime.app_config.load.return_value = {
            "watchdog": {},
            "kill_switch": {"enabled": False},
            "rotation": {"enabled": True, "scheduled_interval_hours": 0},
        }

        result = runtime.scheduled_rotate()

        self.assertEqual(result.status, "connected")
        driver.connect_mock.assert_not_called()
        driver.disconnect_mock.assert_not_called()

    @patch("core.watchdog.pool_builder.build_pool", return_value=[])
    def test_scheduled_rotate_skips_quietly_when_pool_empty_no_kill_switch(self, _pool) -> None:
        driver = FakeDriver()
        kill_switch = FakeKillSwitch(active=False)
        runtime = self._make_runtime(driver)
        runtime.kill_switch = kill_switch

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        runtime.app_config = MagicMock(spec=AppConfig)
        runtime.app_config.load.return_value = {
            "watchdog": {},
            "kill_switch": {"enabled": True},
            "rotation": {"scheduled_interval_hours": 6},
        }

        result = runtime.scheduled_rotate()

        # An empty rotation pool means "nothing configured to rotate over",
        # not a network failure - it must not be treated like an all-failed
        # rotation attempt (which would enable the kill switch and record a
        # recovery failure over a config gap, not a real outage).
        self.assertEqual(result.status, "connected")
        kill_switch.enable_mock.assert_not_called()
        self.assertEqual(runtime.recovery.consecutive_failures, 0)

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="ok"))
    def test_scheduled_rotate_rotates_through_the_same_pool_and_engine(
        self, _hc, mock_pool, mock_sel_driver
    ) -> None:
        alt_profile = Profile(
            id="alt-scheduled", name="AltScheduled", protocol=ProtocolType.VLESS,
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
            "watchdog": {},
            "kill_switch": {"enabled": False},
            # rotation.enabled is False (reactive off) - scheduled rotation
            # has its own independent gate and must still proceed.
            "rotation": {"enabled": False, "scheduled_interval_hours": 6},
        }

        result = runtime.scheduled_rotate()

        self.assertEqual(result.status, "recovered")
        self.assertEqual(self.state_manager.get("active_profile_id"), alt_profile.id)
        mock_pool.assert_called_with(self.profile_store, runtime.provider_store, runtime.app_config.load.return_value)

    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="down"))
    def test_scheduled_rotate_applies_kill_switch_when_real_candidates_all_fail(
        self, _hc, mock_pool
    ) -> None:
        alt_profile = Profile(
            id="alt-scheduled-fail", name="AltFail", protocol=ProtocolType.VLESS,
            config={}, source=ProfileSource.MANUAL, in_rotation_pool=True, enabled=True,
        )
        mock_pool.return_value = [alt_profile]
        driver = FakeDriver()
        driver.connect_mock.return_value = True
        kill_switch = FakeKillSwitch(active=False)
        runtime = self._make_runtime(driver)
        runtime.kill_switch = kill_switch

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        runtime.app_config = MagicMock(spec=AppConfig)
        runtime.app_config.load.return_value = {
            "watchdog": {},
            "kill_switch": {"enabled": True},
            "rotation": {"enabled": False, "scheduled_interval_hours": 6},
        }

        result = runtime.scheduled_rotate()

        # Unlike the empty-pool case: real candidates were tried and really
        # failed, so this is a genuine connectivity finding and must escalate
        # exactly like a reactive/manual rotation would.
        self.assertEqual(result.status, "kill_switch_active")
        kill_switch.apply_atomic_mock.assert_called_once_with()

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="ok"))
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
            "rotation": {"enabled": True},
        }

        result = runtime.rotate_now(force=True)

        self.assertEqual(result.status, "recovered")
        self.assertEqual(self.state_manager.get("active_profile_id"), alt_profile.id)

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    def test_rotation_persists_health_status_for_every_attempted_candidate(
        self, mock_pool, mock_sel_driver
    ) -> None:
        # AUD-P14-001 / Task 14.5: RotationEngine threads the injected
        # health_check callable through its main loop unchanged - a failed
        # candidate and the eventual winner must both end up persisted,
        # proving the wrapper covers real multi-candidate rotation, not
        # just the single-profile reconnect path.
        failing = Profile(
            id="fails-first", name="Fails", protocol=ProtocolType.VLESS,
            config={}, source=ProfileSource.MANUAL, in_rotation_pool=True, enabled=True,
        )
        winner = Profile(
            id="wins-second", name="Wins", protocol=ProtocolType.VLESS,
            config={}, source=ProfileSource.MANUAL, in_rotation_pool=True, enabled=True,
        )
        self.profile_store.add(failing)
        self.profile_store.add(winner)
        mock_pool.return_value = [failing, winner]
        driver = FakeDriver()
        mock_sel_driver.return_value = driver

        def health_check_side_effect() -> str:
            return "down" if driver.connect_mock.call_count == 1 else "ok"

        driver.health_check_mock.side_effect = health_check_side_effect
        runtime = self._make_runtime(driver)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        runtime.app_config = MagicMock(spec=AppConfig)
        runtime.app_config.load.return_value = {
            "watchdog": {}, "kill_switch": {"enabled": False},
            "rotation": {"enabled": True},
        }

        with patch(
            "core.watchdog.health_checker.check_with_latency",
            side_effect=lambda profile, driver, **kwargs: HealthCheckResult(status=driver.health_check()),
        ):
            result = runtime.rotate_now(force=True)

        self.assertEqual(result.status, "recovered")
        self.assertEqual(self.profile_store.get("fails-first").health_status, "down")
        self.assertEqual(self.profile_store.get("wins-second").health_status, "ok")

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="ok"))
    def test_rotate_now_forwards_the_stored_active_mode_to_the_driver(self, _hc, mock_pool, mock_sel_driver) -> None:
        alt_profile = Profile(
            id="alt-tun",
            name="Alt Tun",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
            in_rotation_pool=True,
            enabled=True,
        )
        driver = FakeDriver()
        mock_pool.return_value = [alt_profile]
        mock_sel_driver.return_value = driver
        self.state_manager.set("active_mode", "tun")

        runtime = self._make_runtime(driver)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        runtime.app_config = MagicMock(spec=AppConfig)
        runtime.app_config.load.return_value = {
            "watchdog": {},
            "kill_switch": {"enabled": False},
            "rotation": {"enabled": True},
        }

        runtime.rotate_now(force=True)

        self.assertEqual(driver.last_mode, "tun")

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="ok"))
    def test_rotate_now_forwards_persisted_rule_groups_when_rules_mode(
        self, _hc, mock_pool, mock_sel_driver
    ) -> None:
        alt_profile = Profile(
            id="alt-rules",
            name="Alt Rules",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
            in_rotation_pool=True,
            enabled=True,
        )
        driver = FakeDriver()
        mock_pool.return_value = [alt_profile]
        mock_sel_driver.return_value = driver
        self.state_manager.set("active_mode", "rules")
        rule_store = RuleStore(Path(self.tmpdir.name) / "rules")
        group = RuleGroup(
            name="direct",
            rules=[Rule(id="apt", action="direct", conditions={"process_name": ["apt"]})],
        )
        rule_store.add_group(group)

        runtime = self._make_runtime(driver, rule_store=rule_store)

        from config.app_config import AppConfig
        from unittest.mock import MagicMock
        runtime.app_config = MagicMock(spec=AppConfig)
        runtime.app_config.load.return_value = {
            "watchdog": {},
            "kill_switch": {"enabled": False},
            "rotation": {"enabled": True},
        }

        runtime.rotate_now(force=True)

        self.assertEqual(driver.last_mode, "rules")
        self.assertEqual(driver.last_groups, [group])

    @patch("core.watchdog.select_driver")
    @patch("core.watchdog.pool_builder.build_pool")
    @patch("core.watchdog.health_checker.check_with_latency", return_value=HealthCheckResult(status="ok"))
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
        }

        result = runtime.rotate_now(force=True)

        self.assertEqual(result.status, "recovered")
        self.assertTrue(result.kill_switch_active)
        self.assertEqual(kill_switch.tunnel_interface, "wg0")
        self.assertFalse(kill_switch.block_ipv6)
        self.assertFalse(kill_switch.allow_lan)
        kill_switch.apply_atomic_mock.assert_called_once_with()

        kill_switch.enable_mock.assert_not_called()
    def test_end_to_end_failed_node_excluded_then_reeligible_after_cooldown(self) -> None:
        """Closes AUD-P14-001 with evidence, not just a lone field write:
        a real health check finding a node down is persisted, a real
        build_pool() call excludes it while the cooldown is active, and the
        same real call includes it again once the cooldown window has
        passed. Uses real ProfileStore reads/writes throughout - no mocked
        field, no stubbed pool_builder.
        """
        profile = Profile(
            id="flaky",
            name="Flaky",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
            in_rotation_pool=True,
            enabled=True,
        )
        self.profile_store.add(profile)
        driver = FakeDriver()
        runtime = self._make_runtime(driver)  # already uses a tmpdir-scoped AppConfig
        provider_store = ProviderStore(Path(self.tmpdir.name) / "providers.json")
        config = {"rotation": {"health_status_cooldown_seconds": 300}}

        # 1. A real health check finds it down; the result is persisted.
        with patch(
            "core.watchdog.health_checker.check_with_latency",
            return_value=HealthCheckResult(status="down"),
        ):
            status = runtime._checked_and_recorded(profile, driver)
        self.assertEqual(status, "down")
        persisted = self.profile_store.get("flaky")
        self.assertEqual(persisted.health_status, "down")
        self.assertIsNotNone(persisted.last_health_check)

        # 2. A real build_pool() call excludes it - cooldown active.
        pool = pool_builder.build_pool(self.profile_store, provider_store, config)
        self.assertEqual(pool, [])

        # 3. Simulate the cooldown window passing (same backdating
        #    technique tests.test_pool_builder already uses).
        stale = self.profile_store.get("flaky")
        stale.last_health_check = datetime.now(timezone.utc) - timedelta(seconds=600)
        self.profile_store.update(stale)

        # 4. The same real build_pool() call now includes it again.
        pool_after_cooldown = pool_builder.build_pool(self.profile_store, provider_store, config)
        self.assertEqual([p.id for p in pool_after_cooldown], ["flaky"])


if __name__ == "__main__":
    unittest.main()
