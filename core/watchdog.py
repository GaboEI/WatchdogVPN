from __future__ import annotations

import logging
from dataclasses import dataclass, field

from config.state_manager import StateManager
from drivers.base import BaseDriver
from drivers.legacy.adguard_driver import AdGuardDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class WatchdogRuntime:
    driver: BaseDriver
    state_manager: StateManager = field(default_factory=StateManager)

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

    def connect(self, profile: Profile) -> bool:
        return self.driver.connect(profile)

    def disconnect(self) -> bool:
        return self.driver.disconnect()

    def health_check(self) -> str:
        if not self.automatic_actions_enabled():
            return "standby"
        return self.driver.health_check()

    def status(self) -> ConnectionState:
        return self.driver.status()


def select_driver(profile: Profile | None = None) -> BaseDriver:
    if profile is not None and profile.protocol is ProtocolType.ADGUARD:
        return AdGuardDriver()
    return AdGuardDriver()


def build_watchdog(profile: Profile | None = None) -> WatchdogRuntime:
    return WatchdogRuntime(driver=select_driver(profile))
