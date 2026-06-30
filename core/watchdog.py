from __future__ import annotations

import logging
from dataclasses import dataclass, field

from config.profile_store import ProfileStore
from config.state_manager import StateManager
from drivers.amneziawg_driver import AmneziaWGDriver
from drivers.base import BaseDriver
from drivers.legacy.adguard_driver import AdGuardDriver
from drivers.openvpn_cloak_driver import OpenVPNCloakDriver
from drivers.openvpn_driver import OpenVPNDriver
from drivers.singbox_driver import SingBoxDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class WatchdogRuntime:
    driver: BaseDriver
    state_manager: StateManager = field(default_factory=StateManager)
    profile_store: ProfileStore = field(default_factory=ProfileStore)

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
        self.driver.health_check()
        return self.driver.status()

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
