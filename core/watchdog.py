from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app_policy.models import AppPolicy, AppPolicyAction, AppPolicyMode
from app_policy.store import AppPolicyStore
from config.app_config import AppConfig
from config.dns_policy_store import DNSPolicyStore
from config.persistence import PersistentStoreError, PersistentValidationError, strict_bool
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.state_manager import ALLOWED_ACTIVE_MODES, StateManager
from core.kill_switch import KillSwitch
from drivers.amneziawg_driver import AmneziaWGDriver
from drivers.base import BaseDriver
from drivers.openvpn_cloak_driver import OpenVPNCloakDriver
from drivers.openvpn_driver import OpenVPNDriver
from drivers.singbox_driver import SingBoxDriver
from dns.models import DNSPolicy
from dns.state_manager import SystemDNSStateManager, default_snapshot_path, load_snapshot
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType
from rotation import health_checker, pool_builder
from rotation.recovery import Recovery
from rotation.rotation_engine import RotationEngine
from rules.rule_store import RuleStore


LOGGER = logging.getLogger(__name__)
MANAGED_DRIVER_TYPES = (
    AmneziaWGDriver,
    OpenVPNCloakDriver,
    OpenVPNDriver,
    SingBoxDriver,
)


def select_driver(profile: Profile | None = None) -> BaseDriver:
    if profile is None:
        return SingBoxDriver()
    if profile.protocol is ProtocolType.AMNEZIAWG:
        return AmneziaWGDriver()
    if profile.protocol is ProtocolType.OPENVPN:
        return OpenVPNDriver()
    if profile.protocol is ProtocolType.OPENVPN_CLOAK:
        return OpenVPNCloakDriver()
    return SingBoxDriver()


ORIGINAL_SELECT_DRIVER = select_driver
DriverSelector = Callable[[Profile | None], BaseDriver]


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
    dns_policy_store: DNSPolicyStore = field(default_factory=DNSPolicyStore)
    dns_state_manager: SystemDNSStateManager = field(default_factory=SystemDNSStateManager)
    dns_snapshot_path: Path = field(default_factory=default_snapshot_path)
    rule_store: RuleStore = field(default_factory=RuleStore)
    app_policy_store: AppPolicyStore = field(default_factory=AppPolicyStore)
    driver_selector: DriverSelector = field(default_factory=lambda: select_driver)

    _reconnect_failures: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.driver_selector is ORIGINAL_SELECT_DRIVER and type(self.driver) not in MANAGED_DRIVER_TYPES:
            self.driver_selector = lambda _profile=None: self.driver

    def automatic_actions_enabled(self) -> bool:
        try:
            desired_state = self.state_manager.get("vpn_desired_state", "off")
        except (PersistentStoreError, PersistentValidationError):
            LOGGER.error("standby mode - invalid persistent state", exc_info=True)
            return False
        if desired_state == "off":
            LOGGER.info("standby mode - user disabled VPN")
            return False
        if desired_state != "on":
            LOGGER.error("standby mode - invalid vpn_desired_state: %r", desired_state)
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
        try:
            state = self.state_manager.load()
        except (PersistentStoreError, PersistentValidationError):
            LOGGER.error("standby mode - invalid persistent state", exc_info=True)
            return self.standby_state()
        if state.get("vpn_desired_state", "off") == "off":
            LOGGER.info("standby mode - user disabled VPN")
            return self.standby_state()
        if state.get("vpn_desired_state") != "on":
            LOGGER.error("standby mode - invalid vpn_desired_state: %r", state.get("vpn_desired_state"))
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

        self._driver_for_profile(profile).connect(
            profile,
            dns_policy=self.dns_policy_store.load(),
            **self._connect_options(),
        )
        return self.driver.status()

    def connect(self, profile: Profile) -> bool:
        self.state_manager.set("vpn_desired_state", "on")
        self.state_manager.set("active_profile_id", profile.id)
        return self._driver_for_profile(profile).connect(
            profile,
            dns_policy=self.dns_policy_store.load(),
            **self._connect_options(),
        )

    def disconnect(self) -> bool:
        result = self.driver.disconnect()
        self._handle_manual_disconnect_kill_switch()
        self._restore_dns_snapshot_if_present()
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

    def _active_mode(self) -> str:
        mode = str(self.state_manager.get("active_mode", "rules"))
        if mode not in ALLOWED_ACTIVE_MODES:
            raise PersistentValidationError("active_mode must be one of: rules, global, direct, tun, proxy")
        return mode

    def _connect_options(self) -> dict[str, object]:
        mode = self._active_mode()
        options: dict[str, object] = {"mode": mode}
        if mode == "rules":
            options["groups"] = self.rule_store.list_groups()
            options["app_policy"] = self._runtime_app_policy()
        return options

    def _runtime_app_policy(self) -> AppPolicy:
        result = self.app_policy_store.load_or_disabled()
        if result.valid:
            return result.policy
        LOGGER.error("app_policy_invalid action=fail_closed error=%s", result.error)
        return AppPolicy(
            enabled=True,
            mode=AppPolicyMode.WHITELIST,
            default_action=AppPolicyAction.BLOCK,
            rules=[],
        )

    def _try_reconnect(self, profile: Profile) -> bool:
        LOGGER.info("watchdog_reconnect_attempt profile_id=%s", profile.id)
        driver = self._driver_for_profile(profile)
        driver.disconnect()
        if not driver.connect(
            profile,
            dns_policy=self.dns_policy_store.load(),
            **self._connect_options(),
        ):
            return False
        return health_checker.check(profile, driver) == "ok"

    def _recover_from_failure(self) -> ConnectionState:
        config = self.app_config.load()
        self._configure_recovery(config)
        if not self.recovery.can_retry_now():
            LOGGER.info("watchdog_recovery_skip reason=backoff_window")
            return ConnectionState(status="waiting_retry", mode=self.driver.status().mode)

        current_profile = self._active_profile()
        if current_profile is not None and self._try_reconnect(current_profile):
            self._reconnect_failures = 0
            self.recovery.record_success()
            return self._recovered_state_after_stable_connection(config)

        self._reconnect_failures += 1
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
        self._configure_recovery(config)
        if not force and not self._rotation_enabled(config):
            LOGGER.warning("rotation_unavailable reason=disabled")
            return self._handle_rotation_unavailable(config, reason="disabled")

        pool = self._compatible_pool(config)
        if exclude_profile_id:
            pool = [p for p in pool if p.id != exclude_profile_id]
        rotation_driver = _RuntimeDriverRouter(self)
        result = self.rotation_engine.rotate(
            pool,
            rotation_driver,
            health_checker.check,
            force=force,
            dns_policy=self.dns_policy_store.load(),
        )

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

        if result.category == "unavailable" or result.attempts == 0:
            return self._handle_rotation_unavailable(config, reason=result.category)

        kill_switch_active = self._apply_all_failed_kill_switch(config)
        action = self.recovery.handle_all_failed(kill_switch_active=kill_switch_active)
        status = "kill_switch_active" if action.kill_switch_active else "all_failed"
        LOGGER.error(
            "watchdog_all_failed kill_switch=%s consecutive_failures=%d",
            "on" if action.kill_switch_active else "off",
            self.recovery.consecutive_failures,
        )
        return ConnectionState(status=status, mode=self.driver.status().mode)

    def _rotation_enabled(self, config: dict) -> bool:
        return strict_bool(config.get("rotation", {}).get("enabled", False), "rotation.enabled")

    def _handle_rotation_unavailable(self, config: dict, reason: str) -> ConnectionState:
        kill_switch_active = self._apply_all_failed_kill_switch(config)
        action = self.recovery.handle_rotation_unavailable(
            kill_switch_active=kill_switch_active,
            reason=reason,
        )
        status = "kill_switch_active" if action.kill_switch_active else "rotation_unavailable"
        LOGGER.error(
            "watchdog_rotation_unavailable reason=%s kill_switch=%s consecutive_failures=%d",
            reason,
            "on" if action.kill_switch_active else "off",
            self.recovery.consecutive_failures,
        )
        return ConnectionState(status=status, mode=self.driver.status().mode)

    def _compatible_pool(self, config: dict) -> list[Profile]:
        return pool_builder.build_pool(self.profile_store, self.provider_store, config)

    def _driver_for_profile(self, profile: Profile, disconnect_current: bool = True) -> BaseDriver:
        selected_driver = self.driver_selector(profile)
        if type(selected_driver) is type(self.driver):
            return self.driver
        if disconnect_current:
            self.driver.disconnect()
        self.driver = selected_driver
        return self.driver

    def _configure_recovery(self, config: dict) -> None:
        watchdog_config = config.get("watchdog", {})
        rotation_config = config.get("rotation", {})
        if "reconnect_backoff_seconds" in watchdog_config:
            self.recovery.base_interval_seconds = float(watchdog_config["reconnect_backoff_seconds"])
        if "max_backoff_interval_seconds" in rotation_config:
            self.recovery.max_interval_seconds = float(rotation_config["max_backoff_interval_seconds"])

    def _apply_all_failed_kill_switch(self, config: dict) -> bool:
        self._configure_kill_switch(config)
        configured = strict_bool(config.get("kill_switch", {}).get("enabled", False), "kill_switch.enabled")
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
            self.kill_switch.tunnel_interface = str(
                kill_switch_config.get("tunnel_interface", "wdvpn-tun0")
            )
        if hasattr(self.kill_switch, "block_ipv6"):
            self.kill_switch.block_ipv6 = strict_bool(
                kill_switch_config.get("block_ipv6", True),
                "kill_switch.block_ipv6",
            )
        if hasattr(self.kill_switch, "allow_lan"):
            self.kill_switch.allow_lan = strict_bool(
                kill_switch_config.get("allow_lan", True),
                "kill_switch.allow_lan",
            )

    def _handle_manual_disconnect_kill_switch(self) -> None:
        config = self.app_config.load()
        self._configure_kill_switch(config)
        if not self.kill_switch.is_active():
            return

        policy = str(
            config.get("kill_switch", {}).get("on_manual_disconnect", "disable")
        ).strip().lower()
        if policy == "keep":
            LOGGER.warning("watchdog_manual_disconnect_kill_switch action=keep_active")
            return
        if policy != "disable":
            LOGGER.warning(
                "watchdog_manual_disconnect_kill_switch action=disable reason=invalid_policy policy=%s",
                policy,
            )
        if self.kill_switch.disable():
            LOGGER.info("watchdog_manual_disconnect_kill_switch action=disabled")
            return
        LOGGER.error("watchdog_manual_disconnect_kill_switch action=disable_failed")

    def _restore_dns_snapshot_if_present(self) -> None:
        try:
            snapshot = load_snapshot(self.dns_snapshot_path)
        except Exception:
            LOGGER.warning("watchdog_dns_restore_on_disconnect status=load_failed", exc_info=True)
            return
        if snapshot is None:
            return
        try:
            self.dns_state_manager.restore_state(snapshot)
            self.dns_snapshot_path.unlink()
        except Exception:
            LOGGER.warning("watchdog_dns_restore_on_disconnect status=restore_failed", exc_info=True)
            return
        LOGGER.info("watchdog_dns_restore_on_disconnect status=restored")

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


class _RuntimeDriverRouter(BaseDriver):
    def __init__(self, runtime: WatchdogRuntime) -> None:
        self.runtime = runtime

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups=None,
        app_policy=None,
        final_policy: str = "current_profile",
    ) -> bool:
        driver = self.runtime._driver_for_profile(profile, disconnect_current=False)
        return driver.connect(
            profile,
            dns_policy=dns_policy,
            **self.runtime._connect_options(),
            final_policy=final_policy,
        )

    def disconnect(self) -> bool:
        return self.runtime.driver.disconnect()

    def health_check(self) -> str:
        return self.runtime.driver.health_check()

    def status(self) -> ConnectionState:
        return self.runtime.driver.status()

    def is_available(self) -> bool:
        return self.runtime.driver.is_available()


def build_watchdog(profile: Profile | None = None) -> WatchdogRuntime:
    return WatchdogRuntime(driver=select_driver(profile))
