from __future__ import annotations

from dataclasses import dataclass

from drivers.base import BaseDriver
from drivers.legacy.adguard_driver import AdGuardDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType


@dataclass(slots=True)
class WatchdogRuntime:
    driver: BaseDriver

    def connect(self, profile: Profile) -> bool:
        return self.driver.connect(profile)

    def disconnect(self) -> bool:
        return self.driver.disconnect()

    def health_check(self) -> str:
        return self.driver.health_check()

    def status(self) -> ConnectionState:
        return self.driver.status()


def select_driver(profile: Profile | None = None) -> BaseDriver:
    if profile is not None and profile.protocol is ProtocolType.ADGUARD:
        return AdGuardDriver()
    return AdGuardDriver()


def build_watchdog(profile: Profile | None = None) -> WatchdogRuntime:
    return WatchdogRuntime(driver=select_driver(profile))

