from __future__ import annotations

import logging
from dataclasses import dataclass, field

from config.app_config import AppConfig
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.state_manager import StateManager
from core.kill_switch import KillSwitch
from drivers.amneziawg_driver import AmneziaWGDriver
from drivers.base import BaseDriver
from drivers.legacy.adguard_driver import AdGuardDriver
from drivers.openvpn_cloak_driver import OpenVPNCloakDriver
from drivers.openvpn_driver import OpenVPNDriver
from drivers.singbox_driver import SingBoxDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType
from rotation import health_checker, pool_builder
from rotation.recovery import Recovery
from rotation.rotation_engine import RotationEngine


LOGGER = logging.getLogger(__name__)


@dataclass
class WatchdogRuntime:
    driver: BaseDriver
    state_manager: StateManager = field(default_factory=StateManager)
    profile_store: ProfileStore = field(default_factory=ProfileStore)
    provider_store: ProviderStore = field(default_factory=ProviderStore)
    app_config: AppConfig = field(default_factory=AppConfig)
    rotation_engine: RotationEngine = field(default_factory=RotationEngine)
    recovery: Recovery = field(default_factory=Recovery)
    kill_switch: KillSwitch = field(default_factory=KillSwitch)

    _reconnect_failures: int = field(default=0, init=False, repr=False)

    def automatic_actions_enabled(self) -> bool:
        desired_state = self.state_manager.get("vpn_desired_state", "off")
        if desired_state == "off":
            LOGGER.info("standby mode - user disabled VPN")
            return False
        return True

    def standby_state(self) -> ConnectionState:
        return ConnectionState(status="standby", mode="standby")

    def run_iteration(self) -> ConnectionState:
        if not self.automatic_actions_enabled():
            return self.standby_state()
        if self.driver.health_check() == "ok":
            self.recovery.record_success()
            return self.driver.status()
        return self._recover_from_failure()

    def rotate_now(self, force: bool = False) -> ConnectionState:
        if not self.automatic_actions_enabled():
            return self.standby_state()
        config = self.app_config.load()
        return self._attempt_rotation(config, force=force)

    def startup(self) -> ConnectionState:
        state = self.state_manager.load()
        if state.get("vpn_desired_state", "off") == "off":
            LOGGER.info("standby mode - user disabled VPN")
            return self.standby_state()

        if not state.get("vpn_autoconnect_enabled", False):
            LOGGER.info("standby mode - autoconnect disabled")
            return self.standby_state()

        active_profile_id = str(state.get("active_profile_id", ""))
        if not active_profile_id:
            LOGGER.warning("standby mode - no active profile configured")
            return self.standby_state()

        profile = self.profile_store.get(active_profile_id)
        if profile is None:
            LOGGER.warning("standby mode - active profile not found: %s", active_profile_id)
            return self.standby_state()

        self.driver.connect(profile)
        return self.driver.status()

    def connect(self, profile: Profile) -> bool:
        self.state_manager.set("vpn_desired_state", "on")
        self.state_manager.set("active_profile_id", profile.id)
        return self.driver.connect(profile)

    def disconnect(self) -> bool:
        result = self.driver.disconnect()
        self.state_manager.set("vpn_desired_state", "off")
        LOGGER.info("VPN manually disabled. Will not auto-reconnect.")
        return result

    def health_check(self) -> str:
        if not self.automatic_actions_enabled():
            return "standby"
        return self.driver.health_check()

    def status(self) -> ConnectionState:
        return self.driver.status()

    def _active_profile(self) -> Profile | None:
        active_profile_id = str(self.state_manager.get("active_profile_id", ""))
        if not active_profile_id:
            return None
        return self.profile_store.get(active_profile_id)

    def _try_reconnect(self, profile: Profile) -> bool:
        LOGGER.info("watchdog_reconnect_attempt profile_id=%s", profile.id)
        self.driver.disconnect()
        if not self.driver.connect(profile):
            return False
        return health_checker.check(profile, self.driver) == "ok"

    def _recover_from_failure(self) -> ConnectionState:
        if not self.recovery.can_retry_now():
            LOGGER.info("watchdog_recovery_skip reason=backoff_window")
            return ConnectionState(status="waiting_retry", mode=self.driver.status().mode)

        current_profile = self._active_profile()
        if current_profile is not None and self._try_reconnect(current_profile):
            self._reconnect_failures = 0
            self.recovery.record_success()
            config = self.app_config.load()
            return self._recovered_state_after_stable_connection(config)

        self._reconnect_failures += 1
        config = self.app_config.load()
        reconnect_attempts = int(config.get("watchdog", {}).get("reconnect_attempts", 3))
        if self._reconnect_failures < reconnect_attempts:
            LOGGER.info(
                "watchdog_reconnect_retry attempt=%d/%d",
                self._reconnect_failures,
                reconnect_attempts,
            )
            return ConnectionState(status="reconnecting", mode=self.driver.status().mode)

        self._reconnect_failures = 0
        exclude_id = current_profile.id if current_profile is not None else None
        return self._attempt_rotation(config, exclude_profile_id=exclude_id)

    def _attempt_rotation(
        self,
        config: dict,
        force: bool = False,
        exclude_profile_id: str | None = None,
    ) -> ConnectionState:
        pool = self._compatible_pool(config)
        if exclude_profile_id:
            pool = [p for p in pool if p.id != exclude_profile_id]
        result = self.rotation_engine.rotate(pool, self.driver, health_checker.check, force=force)

        if result.success and result.profile is not None:
            self._reconnect_failures = 0
            self.recovery.record_success()
            self.state_manager.set("active_profile_id", result.profile.id)
            LOGGER.info(
                "watchdog_rotation_recovered profile_id=%s rolled_back=%s",
                result.profile.id,
                result.rolled_back,
            )
            return self._recovered_state_after_stable_connection(config)

        kill_switch_active = self._apply_all_failed_kill_switch(config)
        action = self.recovery.handle_all_failed(kill_switch_active=kill_switch_active)
        status = "kill_switch_active" if action.kill_switch_active else "normal_network_temp"
        LOGGER.error(
            "watchdog_all_failed kill_switch=%s consecutive_failures=%d",
            "on" if action.kill_switch_active else "off",
            self.recovery.consecutive_failures,
        )
        return ConnectionState(status=status, mode=self.driver.status().mode)

    def _compatible_pool(self, config: dict) -> list[Profile]:
        full_pool = pool_builder.build_pool(self.profile_store, self.provider_store, config)
        driver_type = type(self.driver)
        return [p for p in full_pool if type(select_driver(p)) is driver_type]

    def _apply_all_failed_kill_switch(self, config: dict) -> bool:
        self._configure_kill_switch(config)
        configured = bool(config.get("kill_switch", {}).get("enabled", False))
        if self.kill_switch.is_active():
            LOGGER.warning("watchdog_all_failed_kill_switch action=keep_active")
            return True
        if not configured:
            return False
        if self.kill_switch.enable():
            LOGGER.warning("watchdog_all_failed_kill_switch action=enabled")
            return True
        LOGGER.error("watchdog_all_failed_kill_switch action=enable_failed")
        return False

    def _recovered_state_after_stable_connection(self, config: dict) -> ConnectionState:
        kill_switch_active = self._restore_kill_switch_after_recovery(config)
        return self._as_recovered(self.driver.status(), kill_switch_active=kill_switch_active)

    def _restore_kill_switch_after_recovery(self, config: dict) -> bool:
        self._configure_kill_switch(config)
        if not self.kill_switch.is_active():
            return False
        if self.kill_switch.enable():
            LOGGER.info("watchdog_kill_switch_restored_after_recovery")
            return True
        LOGGER.error("watchdog_kill_switch_restore_failed_after_recovery")
        return False

    def _configure_kill_switch(self, config: dict) -> None:
        kill_switch_config = config.get("kill_switch", {})
        if hasattr(self.kill_switch, "tunnel_interface"):
            self.kill_switch.tunnel_interface = str(kill_switch_config.get("tunnel_interface", "tun0"))
        if hasattr(self.kill_switch, "block_ipv6"):
            self.kill_switch.block_ipv6 = bool(kill_switch_config.get("block_ipv6", True))
        if hasattr(self.kill_switch, "allow_lan"):
            self.kill_switch.allow_lan = bool(kill_switch_config.get("allow_lan", True))

    @staticmethod
    def _as_recovered(
        state: ConnectionState,
        kill_switch_active: bool | None = None,
    ) -> ConnectionState:
        return ConnectionState(
            active_profile_id=state.active_profile_id,
            connected_at=state.connected_at,
            mode=state.mode,
            tun_active=state.tun_active,
            proxy_active=state.proxy_active,
            kill_switch_active=(
                state.kill_switch_active if kill_switch_active is None else kill_switch_active
            ),
            status="recovered",
        )


def select_driver(profile: Profile | None = None) -> BaseDriver:
    if profile is None:
        return SingBoxDriver()
    if profile.protocol is ProtocolType.AMNEZIAWG:
        return AmneziaWGDriver()
    if profile.protocol is ProtocolType.ADGUARD:
        return AdGuardDriver()
    if profile.protocol is ProtocolType.OPENVPN:
        return OpenVPNDriver()
    if profile.protocol is ProtocolType.OPENVPN_CLOAK:
        return OpenVPNCloakDriver()
    return SingBoxDriver()


def build_watchdog(profile: Profile | None = None) -> WatchdogRuntime:
    return WatchdogRuntime(driver=select_driver(profile))
