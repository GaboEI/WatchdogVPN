from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Callable

from app_policy.models import AppPolicy, AppPolicyAction, AppPolicyMode
from app_policy.store import AppPolicyStore
from config.app_config import AppConfig
from config.dns_policy_store import DNSPolicyStore
from config.lan_sharing import (
    LANGatewayRuntimeConfig,
    LANProxyRuntimeConfig,
    lan_sharing_credentials_path,
    load_or_create_lan_sharing_credentials,
)
from config.persistence import PersistentStoreError, PersistentValidationError, strict_bool, strict_int
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.state_manager import ALLOWED_ACTIVE_MODES, StateManager, parse_capture_modes
from core.kill_switch import KillSwitch
from core.runtime_observation import observe_effective_runtime
from drivers.amneziawg_driver import AmneziaWGDriver
from drivers.base import (
    BaseDriver,
    ManagementPathSafetyError,
    TeardownBarrierError,
    UnsupportedDriverPolicyError,
)
from drivers.openvpn_cloak_driver import OpenVPNCloakDriver
from drivers.openvpn_driver import OpenVPNDriver
from drivers.native_policy_driver import NativePolicyDriver
from drivers.singbox_driver import SingBoxDriver
from dns.models import DNSPolicy
from dns.state_manager import SystemDNSStateManager, default_snapshot_path, load_snapshot
from dns.resolver_inventory import ResolverManager
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType
from parsers.endpoint_policy import (
    EndpointPolicyError,
    EndpointResolutionCache,
    profile_endpoint_host,
    validate_profile_endpoint,
)
from node_groups.models import NodeGroup, NodeGroupSelectionMode, group_target
from node_groups.resolver import resolve_candidates as resolve_node_group_candidates
from node_groups.scoring import rank_candidates
from node_groups.store import NodeGroupStore
from route_chains.models import chain_target
from route_chains.runtime import ChainRuntimePlan, ChainRuntimeResolver
from route_chains.store import RouteChainStore
from rotation import health_checker, pool_builder
from rotation.recovery import Recovery
from rotation.rotation_engine import RotationEngine
from rules.rule_engine import PRIORITY_TIER_ORDER, group_by_tier
from rules.rule_store import RuleStore
from rules.ruleset_lifecycle import RuleSetLifecycleManager


LOGGER = logging.getLogger(__name__)


class EndpointPolicyConnectionError(RuntimeError):
    """A profile endpoint failed mandatory pre-connection validation."""
MANAGED_DRIVER_TYPES = (
    AmneziaWGDriver,
    OpenVPNCloakDriver,
    OpenVPNDriver,
    NativePolicyDriver,
    SingBoxDriver,
)

# Sentinel distinct from None: "this call site never attempted a latency
# measurement" vs. "it attempted one and the node was unreachable". See
# WatchdogRuntime._record_health_result for why conflating the two would
# silently erase a real measurement.
_LATENCY_NOT_MEASURED = object()

# A native transport can report its interface and policy companion ready just
# before the first real packets traverse the newly installed routes. Retrying
# one failed startup probe avoids treating that short convergence window as a
# proven outage; the second probe still uses the full configured target quorum.
NATIVE_EGRESS_STARTUP_RETRY_DELAY_SECONDS = 1.0


def driver_type_for_profile(profile: Profile | None = None) -> type[BaseDriver]:
    if profile is None:
        return SingBoxDriver
    if profile.protocol in {ProtocolType.AMNEZIAWG, ProtocolType.OPENVPN, ProtocolType.OPENVPN_CLOAK}:
        return NativePolicyDriver
    return SingBoxDriver


def select_driver(profile: Profile | None = None) -> BaseDriver:
    if profile is not None and profile.protocol is ProtocolType.AMNEZIAWG:
        return NativePolicyDriver(AmneziaWGDriver())
    if profile is not None and profile.protocol is ProtocolType.OPENVPN:
        return NativePolicyDriver(OpenVPNDriver())
    if profile is not None and profile.protocol is ProtocolType.OPENVPN_CLOAK:
        return NativePolicyDriver(OpenVPNCloakDriver())
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
    rule_set_lifecycle: RuleSetLifecycleManager = field(default_factory=RuleSetLifecycleManager)
    app_policy_store: AppPolicyStore = field(default_factory=AppPolicyStore)
    node_group_store: NodeGroupStore = field(default_factory=NodeGroupStore)
    route_chain_store: RouteChainStore = field(default_factory=RouteChainStore)
    driver_selector: DriverSelector = field(default_factory=lambda: select_driver)

    _reconnect_failures: int = field(default=0, init=False, repr=False)

    _desired_on_kill_switch_forced: bool = field(default=False, init=False, repr=False)

    _cleanup_barrier_failed: bool = field(default=False, init=False, repr=False)

    # Deep egress checks deliberately return a small, safe classification
    # instead of a target URL, profile field, or subprocess output. Keep that
    # diagnosis at the runtime layer: a failed gate is not a driver startup
    # error, and assigning it to a driver would make it leak into the next
    # unrelated connection attempt.
    _health_error_detail: str = field(default="", init=False, repr=False)

    endpoint_resolution_cache: EndpointResolutionCache = field(
        default_factory=EndpointResolutionCache
    )

    def __post_init__(self) -> None:
        if self.driver_selector is ORIGINAL_SELECT_DRIVER and type(self.driver) not in MANAGED_DRIVER_TYPES:
            self.driver_selector = lambda _profile=None: self.driver

    def automatic_actions_enabled(self, *, require_autoconnect: bool = False) -> bool:
        try:
            state = self.state_manager.load()
        except (PersistentStoreError, PersistentValidationError):
            LOGGER.error("standby mode - invalid persistent state", exc_info=True)
            return False
        desired_state = state.get("vpn_desired_state", "off")
        if desired_state == "off":
            LOGGER.info("standby mode - user disabled VPN")
            return False
        if desired_state != "on":
            LOGGER.error("standby mode - invalid vpn_desired_state: %r", desired_state)
            return False
        # Automatic ticks are not the same as explicit CLI requests.  When a
        # boot with autoconnect disabled cannot prove clean direct networking
        # (for example DNS restore or kill-switch disable failed), the state is
        # deliberately left diagnostic/fail-closed with desired_state=on.  That
        # must not authorize the background loop to reconnect behind the user's
        # autoconnect=false setting; manual connect/rotate paths do not pass
        # require_autoconnect and keep their explicit behavior.
        if require_autoconnect and not bool(state.get("vpn_autoconnect_enabled", False)):
            LOGGER.info("automatic actions disabled - autoconnect disabled")
            return False
        return True

    def standby_state(self) -> ConnectionState:
        return ConnectionState(status="standby", mode="standby")

    def _automatic_disabled_state(self) -> ConnectionState:
        try:
            last_failure_reason = str(self.state_manager.get("last_failure_reason", ""))
        except (PersistentStoreError, PersistentValidationError):
            return self.standby_state()
        if last_failure_reason in {"dns_restore_failed", "kill_switch_disable_failed"}:
            return ConnectionState(status=last_failure_reason, mode="standby")
        return self.standby_state()

    def _autoconnect_enabled(self) -> bool:
        try:
            return bool(self.state_manager.get("vpn_autoconnect_enabled", False))
        except (PersistentStoreError, PersistentValidationError):
            return False

    @staticmethod
    def _runtime_state_active(state: ConnectionState) -> bool:
        return state.status == "connected" or state.tun_active or state.proxy_active or state.mode != "standby"

    def run_iteration(self) -> ConnectionState:
        if not self.automatic_actions_enabled():
            return self.standby_state()
        autoconnect_enabled = self._autoconnect_enabled()
        current_state = self.driver.status()
        if not autoconnect_enabled and not self._runtime_state_active(current_state):
            return self._automatic_disabled_state()
        # Autoconnect only gates creating/recovering a runtime. A manually
        # connected runtime still needs health and kill-switch supervision.
        if not self._maintain_kill_switch_for_active_runtime():
            self._record_last_failure("kill_switch_failed")
            return ConnectionState(status="kill_switch_failed", mode=current_state.mode)
        active_profile = self._active_profile()
        if active_profile is not None and getattr(self.driver, "requires_profile_egress_check", False):
            status = self._checked_and_recorded(active_profile, self.driver)
        else:
            status = self.driver.health_check()
            if active_profile is not None:
                self._record_health_result(active_profile, status)
        if status == "ok":
            self.recovery.record_success()
            return self.driver.status()
        if not autoconnect_enabled:
            self._record_last_failure("recovery_disabled")
            state = self.driver.status()
            state.status = "recovery_disabled"
            return state
        return self._recover_from_failure()

    def _record_health_result(
        self,
        profile: Profile,
        status: str,
        latency_ms: float | None = _LATENCY_NOT_MEASURED,  # type: ignore[assignment]
    ) -> None:
        """Persist the result of a real health check (Task 14.5, AUD-P14-001;
        latency extended in Task 14.7).

        health_status and last_health_check are written together, in the
        same profile_store.update() call, so they can never disagree on
        disk - Profile is serialized whole, there is no way to write one
        field without the other. last_health_check updates on every check
        (including "ok"), not only on failure: it means "when this profile
        was last verified", not "when it last failed" - otherwise a node
        that stays healthy for hours would have a permanently None
        timestamp, and the cooldown could never reason about a profile
        that failed once and later recovered.

        `latency_ms` defaults to the `_LATENCY_NOT_MEASURED` sentinel, not
        `None`: run_iteration()'s happy path (bare driver.health_check())
        never attempts a latency measurement at all and must leave
        `latency_ms`/`last_latency_check` untouched, whereas
        `_checked_and_recorded`'s deep check always passes a real value -
        possibly a legitimate `None` when the node was unreachable. Using
        `None` as the "didn't measure" default would silently erase a
        freshly-measured latency on the very next unrelated happy-path
        tick - the same class of bug AUD-P14-001 was about, in the other
        direction (overwriting a real value instead of never writing one).
        `last_latency_check` is a separate timestamp from `last_health_check`
        on purpose: the two check depths update `last_health_check` at
        different rates, but only the deep check ever refreshes latency -
        collapsing them under one timestamp would make a stale latency
        reading look fresh whenever a shallow check merely ran.

        Design note: `health_status` itself still collapses two different
        check depths into one status value - run_iteration()'s happy path
        calls the lighter driver.health_check(), while the rotation path
        calls the deeper health_checker.check() (real connect + external
        reachability verification). health_status="ok" does not record
        which depth produced it. This is fine for the cooldown (it only
        distinguishes down vs not-down), but a future factor that wants to
        weigh check depth would need to extend this - a known extension
        point, not a bug.
        """
        now = datetime.now(timezone.utc)
        profile.health_status = status
        profile.last_health_check = now
        if latency_ms is not _LATENCY_NOT_MEASURED:
            profile.latency_ms = latency_ms
            profile.last_latency_check = now
        self.profile_store.update(profile)

    def _configured_verify(self, config: dict) -> health_checker.VerifyFn:
        rotation_config = config.get("rotation", {})
        targets = tuple(rotation_config.get("health_targets", health_checker.DEFAULT_HEALTH_TARGETS))
        success_quorum = int(
            rotation_config.get("health_success_quorum", health_checker.DEFAULT_SUCCESS_QUORUM)
        )
        timeout = float(
            rotation_config.get("test_timeout_seconds", health_checker.DEFAULT_TIMEOUT_SECONDS)
        )
        return lambda via_proxy: health_checker.verify_health_targets(
            via_proxy, timeout=timeout, targets=targets, success_quorum=success_quorum
        )

    def _checked_and_recorded(
        self,
        profile: Profile,
        driver: BaseDriver,
        *,
        retry_startup_failure: bool = False,
    ) -> str:
        """HealthCheckFn-compatible wrapper: real check, then persist.

        Passed as the health_check callable into RotationEngine.rotate()
        (see _attempt_rotation), which threads it, unchanged, through its
        main candidate loop, _rollback(), and _single_node_check() - all
        three paths get persistence for free, with zero changes to
        rotation/rotation_engine.py, which stays store-agnostic by design.

        Uses the configured multi-target rotation health policy and timeout
        for every candidate and every call site. A shared quorum policy keeps
        latency and failure interpretation comparable across profiles.
        """
        config = self.app_config.load()
        verify = self._configured_verify(config)
        result = health_checker.check_with_latency(profile, driver, verify=verify)
        if (
            retry_startup_failure
            and getattr(driver, "requires_profile_egress_check", False)
            and result.status != "ok"
        ):
            LOGGER.info(
                "egress_startup_check_retry profile_id=%s status=%s classification=%s",
                profile.id,
                result.status,
                result.classification,
            )
            time.sleep(NATIVE_EGRESS_STARTUP_RETRY_DELAY_SECONDS)
            result = health_checker.check_with_latency(profile, driver, verify=verify)
        self._record_health_result(profile, result.status, latency_ms=result.latency_ms)
        if result.status == "ok":
            self._health_error_detail = ""
        else:
            endpoint_host = profile_endpoint_host(profile)
            if endpoint_host is not None:
                self.endpoint_resolution_cache.invalidate(endpoint_host)
            classification = result.classification
            if not isinstance(classification, str) or not classification.replace("_", "").isalpha():
                classification = "unknown"
            self._health_error_detail = (
                f"selected egress health check failed: {classification}"
            )
        return result.status

    def rotate_now(self, force: bool = False) -> ConnectionState:
        if not self.automatic_actions_enabled():
            return self.standby_state()
        config = self.app_config.load()
        return self._attempt_rotation(config, force=force)

    def scheduled_rotate(self) -> ConnectionState:
        """Proactive rotation trigger (Task 14.2), independent of health.

        Gated by rotation.scheduled_interval_hours (0 = disabled), separate
        from rotation.enabled (which only gates reactive rotation-on-failure).
        Peeks at the same pool_builder.build_pool() result _attempt_rotation
        would use before committing to a real attempt: an empty pool here
        means "nothing configured to rotate over", not a network failure, so
        it must not trip the same kill-switch/all-failed handling a real
        rotation attempt would - that would let an optional, unattended timer
        block traffic over a simple configuration gap.
        """
        if not self.automatic_actions_enabled(require_autoconnect=True):
            return self._automatic_disabled_state()
        config = self.app_config.load()
        if not self._scheduled_rotation_enabled(config):
            return self.status()
        if not self._compatible_pool(config):
            LOGGER.info("scheduled_rotation_skipped reason=pool_empty")
            return self.status()
        return self._attempt_rotation(config, force=True)

    def node_group_auto_test(self, group_name: str) -> dict[str, object]:
        """Sequentially measure one group's currently eligible candidates.

        This is the explicit CLI consumer anticipated by Task 14.7. It is
        intentionally a RuntimeWorker/IPC action, not a direct store mutation:
        each candidate requires a real connect + deep health check, so the
        work must be serialized with manual connect/disconnect/rotate and the
        autonomous timers on the single runtime worker thread.

        It does not use RotationEngine and does not write active_profile_id:
        this is an operator validation command, not a request to change the
        active exit node or trigger kill-switch/all-failed recovery policy.
        """
        state = self.status()
        if state.kill_switch_active or state.kill_switch_status != "inactive":
            raise RuntimeError("node-group auto-test requires the kill switch to be inactive")
        if (
            state.active_profile_id
            or state.tun_active
            or state.proxy_active
            or state.status != "standby"
        ):
            raise RuntimeError("node-group auto-test requires standby/disconnected state")

        group = self.node_group_store.get(group_name)
        if group is None:
            raise RuntimeError(f"node group not found: {group_name}")
        if not group.enabled:
            raise RuntimeError(f"node group is disabled: {group_name}")

        config = self.app_config.load()
        candidates = resolve_node_group_candidates(
            group, self.profile_store, self.provider_store, config
        )
        requested_capabilities = self._requested_policy_capabilities()
        for profile in candidates:
            driver_name, policy_capabilities = self._driver_policy_contract_for_profile(profile)
            unsupported = requested_capabilities - policy_capabilities
            if unsupported:
                raise UnsupportedDriverPolicyError(driver_name, unsupported)

        options = self._connect_options()
        dns_policy = self.dns_policy_store.load()
        test_results: list[dict[str, object]] = []
        ok_profile_ids: set[str] = set()
        for profile in candidates:
            # The standby assertion above covers the first iteration and the
            # loop disconnects unconditionally before advancing.
            driver = self._activate_driver(
                self._candidate_driver_for_profile(profile), disconnect_current=False
            )
            connected = driver.connect(
                profile,
                dns_policy=dns_policy,
                **options,
            )
            if not connected:
                self._record_health_result(profile, "down", latency_ms=None)
                test_results.append(
                    {
                        "profile_id": profile.id,
                        "connected": False,
                        "health_status": "down",
                        "latency_ms": None,
                    }
                )
                if not driver.disconnect():
                    raise RuntimeError(
                        f"node-group auto-test failed to disconnect profile: {profile.id}"
                    )
                continue
            try:
                if self.rotation_engine.warmup_seconds > 0:
                    self.rotation_engine.sleep(self.rotation_engine.warmup_seconds)
                status = self._checked_and_recorded(
                    profile,
                    driver,
                    retry_startup_failure=True,
                )
                if status == "ok":
                    ok_profile_ids.add(profile.id)
                refreshed = self.profile_store.get(profile.id) or profile
                test_results.append(
                    {
                        "profile_id": profile.id,
                        "connected": True,
                        "health_status": status,
                        "latency_ms": refreshed.latency_ms,
                    }
                )
            finally:
                if not driver.disconnect():
                    raise RuntimeError(
                        f"node-group auto-test failed to disconnect profile: {profile.id}"
                    )

        refreshed_group = self.node_group_store.get(group_name) or group
        refreshed_candidates = resolve_node_group_candidates(
            refreshed_group, self.profile_store, self.provider_store, config
        )
        refreshed_candidates = [
            profile for profile in refreshed_candidates if profile.id in ok_profile_ids
        ]
        ranked = rank_candidates(refreshed_candidates, refreshed_group.resilience_policy, config)
        selected_profile_id = ranked[0].profile_id if ranked else None
        return {
            "group_name": group_name,
            "result": "selected" if selected_profile_id else "unavailable",
            "selected_profile_id": selected_profile_id,
            "tested": test_results,
            "candidates": [score.to_dict() for score in ranked],
        }

    def _scheduled_rotation_enabled(self, config: dict) -> bool:
        hours = strict_int(
            config.get("rotation", {}).get("scheduled_interval_hours", 0),
            "rotation.scheduled_interval_hours",
        )
        return hours > 0

    def startup(self, *, require_restart_protection: bool = False) -> ConnectionState:
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

        active_profile_id = str(state.get("active_profile_id", ""))
        profile = self.profile_store.get(active_profile_id) if active_profile_id else None
        if not state.get("vpn_autoconnect_enabled", False):
            LOGGER.info("standby mode - autoconnect disabled")
            if not self._restore_dns_snapshot_if_present():
                self._record_last_failure("dns_restore_failed")
                return ConnectionState(status="dns_restore_failed", mode="standby")
            if self.kill_switch.is_active():
                if not self.kill_switch.disable() or self.kill_switch.is_active():
                    self._record_last_failure("kill_switch_disable_failed")
                    LOGGER.error("watchdog_startup_autoconnect_disabled_kill_switch_disable_failed")
                    return ConnectionState(status="kill_switch_disable_failed", mode="standby")
            self.state_manager.set("vpn_desired_state", "off")
            self.state_manager.set("active_profile_id", "")
            self._desired_on_kill_switch_forced = False
            self._clear_last_failure()
            return self.standby_state()

        if require_restart_protection and not self._apply_desired_on_protection(profile):
            self._record_last_failure("kill_switch_failed")
            return ConnectionState(status="kill_switch_failed", mode="standby")

        if not active_profile_id:
            LOGGER.warning("standby mode - no active profile configured")
            return self.standby_state()
        if profile is None:
            LOGGER.warning("standby mode - active profile not found: %s", active_profile_id)
            return self.standby_state()
        try:
            driver, options = self._prepare_driver_for_connection(profile)
        except UnsupportedDriverPolicyError as exc:
            LOGGER.error("watchdog_startup_policy_unsupported error=%s", exc)
            self._record_last_failure("unsupported_policy")
            return ConnectionState(status="unsupported_policy", mode="standby")
        except ManagementPathSafetyError as exc:
            LOGGER.error("watchdog_startup_management_path_unsafe error=%s", exc)
            self._record_last_failure("management_path_unprotected")
            return ConnectionState(status="standby", mode="standby")
        except EndpointPolicyConnectionError as exc:
            LOGGER.error("watchdog_startup_endpoint_resolution_failed error=%s", exc)
            self._record_last_failure("endpoint_resolution_failed")
            return self.standby_state()
        try:
            active_driver = self._activate_driver(driver)
        except TeardownBarrierError:
            return self._cleanup_failure_state()
        if not require_restart_protection and not self._protect_connection_attempt(profile):
            return ConnectionState(status="kill_switch_failed", mode="standby")

        connected = active_driver.connect(
            profile,
            dns_policy=self.dns_policy_store.load(),
            **options,
        )
        if connected:
            if not getattr(self.driver, "requires_profile_egress_check", False) or self._checked_and_recorded(
                profile,
                self.driver,
                retry_startup_failure=True,
            ) == "ok":
                self._clear_last_failure()
                self.rotation_engine.record_successful_profile(profile.id)
            else:
                if not self._teardown_active_driver():
                    return self._cleanup_failure_state()
        return self.driver.status()

    def connect(self, profile: Profile) -> bool:
        self._health_error_detail = ""
        driver, options = self._prepare_driver_for_connection(profile)
        active_driver = self._activate_driver(driver)
        if not self._protect_connection_attempt(profile):
            return False
        self.state_manager.set("vpn_desired_state", "on")
        self.state_manager.set("active_profile_id", profile.id)
        connected = active_driver.connect(
            profile,
            dns_policy=self.dns_policy_store.load(),
            **options,
        )
        if not connected:
            return self._fail_manual_connect()
        if (
            getattr(self.driver, "requires_profile_egress_check", False)
            and self._checked_and_recorded(
                profile,
                self.driver,
                retry_startup_failure=True,
            )
            != "ok"
        ):
            return self._fail_manual_connect()
        self._clear_last_failure()
        self.rotation_engine.record_successful_profile(profile.id)
        return True

    def _fail_manual_connect(self) -> bool:
        """Return a failed manual connect to an explicit clean standby state.

        A manual request is not permission to keep retrying indefinitely.  If
        teardown is provably complete, disable temporary protection and clear
        the requested profile so a failed handshake or egress gate cannot turn
        into a background reconnect loop.  A failed teardown remains
        fail-closed and is recorded by the teardown barrier.
        """
        if not self._teardown_active_driver():
            return False
        self._handle_manual_disconnect_kill_switch()
        self._restore_dns_snapshot_if_present()
        self.state_manager.set("vpn_desired_state", "off")
        self.state_manager.set("active_profile_id", "")
        self._record_last_failure("connect_failed")
        return False

    @property
    def last_error(self) -> str:
        return self._health_error_detail or str(getattr(self.driver, "last_error", "") or "")

    def disconnect(self) -> bool:
        if not self._teardown_active_driver():
            LOGGER.error("watchdog_manual_disconnect_blocked reason=cleanup_failed")
            return False
        self._handle_manual_disconnect_kill_switch()
        self._restore_dns_snapshot_if_present()
        self.state_manager.set("vpn_desired_state", "off")
        self.state_manager.set("active_profile_id", "")
        self._health_error_detail = ""
        self._clear_last_failure()
        LOGGER.info("VPN manually disabled. Will not auto-reconnect.")
        return True

    def shutdown(self) -> bool:
        """Tear down runtime state without changing the user's desired state."""
        desired_on = True
        try:
            desired_on = self.state_manager.get("vpn_desired_state", "off") == "on"
        except (PersistentStoreError, PersistentValidationError):
            LOGGER.error("watchdog_shutdown_desired_state_unreadable", exc_info=True)

        protection_ok = True
        if desired_on:
            try:
                protection_ok = self._apply_desired_on_protection(self._active_profile())
            except Exception:
                protection_ok = False
                LOGGER.error("watchdog_shutdown_protection_failed", exc_info=True)

        disconnected = False
        try:
            disconnected = self.driver.disconnect()
        except Exception:
            LOGGER.error("watchdog_shutdown_driver_cleanup_failed", exc_info=True)
        finally:
            self._restore_dns_snapshot_if_present()
            if not desired_on:
                self._handle_manual_disconnect_kill_switch()

        if desired_on:
            if not protection_ok:
                LOGGER.error("watchdog_shutdown_fail_closed_barrier_unavailable")
                return False
            if not disconnected:
                # La proteccion fail-closed ya esta aplicada (kill switch activo),
                # por lo que no hay fuga de trafico posible. Durante un shutdown
                # del sistema (SIGTERM con red colapsando) el driver puede no
                # terminar su runtime a tiempo (p.ej. proceso en D-state que ni
                # SIGKILL resuelve en el timeout 5+5s). El kernel limpia en el
                # reboot y el siguiente arranque reconcilia; se registra para
                # trazabilidad, pero no se reporta FAILURE.
                LOGGER.error(
                    "watchdog_shutdown_driver_cleanup_incomplete_protection_active"
                )
            return True
        return disconnected

    def health_check(self) -> str:
        if not self.automatic_actions_enabled():
            return "standby"
        return self.driver.health_check()

    def status(self) -> ConnectionState:
        state = self._with_effective_runtime_status(self.driver.status())
        return self._with_last_failure(
            self._with_lan_gateway_status(self._with_kill_switch_status(state))
        )

    def _with_effective_runtime_status(self, state: ConnectionState) -> ConnectionState:
        observation = observe_effective_runtime()
        artifacts = list(state.runtime_artifacts)
        artifacts.extend(observation.artifacts)
        if observation.processes and not observation.listener_observable:
            artifacts.append("observation:owned-listeners-unavailable")
        state.runtime_artifacts = tuple(sorted(set(artifacts)))
        state.tun_active = state.tun_active or bool(observation.interfaces)
        state.proxy_active = state.proxy_active or bool(
            {2080, 2081}.intersection(observation.listener_ports)
        )
        if state.status == "standby" and state.runtime_artifacts:
            state.status = "runtime_mismatch"
        if state.status == "runtime_mismatch":
            state.runtime_mismatch_severity = "critical"
        return state

    def _with_last_failure(self, state: ConnectionState) -> ConnectionState:
        # Explicitly owns both fields - always sets them from the persisted
        # record (clearing to the dataclass defaults when there is none),
        # rather than trusting the passed-in state to already be clean.
        reason = str(self.state_manager.get("last_failure_reason", "") or "")
        state.last_failure_reason = reason
        if reason == "cleanup_failed":
            state.status = "cleanup_failed"
        at_raw = str(self.state_manager.get("last_failure_at", "") or "") if reason else ""
        state.last_failure_at = None
        if at_raw:
            try:
                state.last_failure_at = datetime.fromisoformat(at_raw)
            except ValueError:
                pass
        return state

    def _record_last_failure(self, reason: str) -> None:
        self.state_manager.set("last_failure_reason", reason)
        self.state_manager.set("last_failure_at", datetime.now(timezone.utc).isoformat())

    def _clear_last_failure(self) -> None:
        self.state_manager.set("last_failure_reason", "")
        self.state_manager.set("last_failure_at", "")

    def _with_kill_switch_status(self, state: ConnectionState) -> ConnectionState:
        try:
            config = self.app_config.load()
            self._configure_kill_switch(config, self._active_profile())
        except (PersistentStoreError, PersistentValidationError, ValueError):
            LOGGER.error("kill_switch_status_config_invalid", exc_info=True)

        raw_status = self.kill_switch.status()
        active = bool(
            raw_status["active"]
            if "active" in raw_status
            else self.kill_switch.is_active()
        )
        artifacts_present = bool(raw_status.get("artifacts_present", active))
        consistent = bool(raw_status.get("consistent", True))
        method = str(raw_status.get("method") or "")
        reasons_raw = raw_status.get("mismatch_reasons", ())
        reasons = (
            tuple(str(reason) for reason in reasons_raw)
            if isinstance(reasons_raw, (list, tuple))
            else ()
        )

        state.kill_switch_active = state.kill_switch_active or active
        state.kill_switch_method = method
        state.kill_switch_consistent = consistent
        if artifacts_present and consistent and active:
            state.kill_switch_status = "applied"
            if state.status == "standby":
                state.status = "kill_switch_active"
        elif artifacts_present:
            state.kill_switch_status = "partial"
            artifacts = list(state.runtime_artifacts)
            artifacts.append(f"kill_switch:{method or 'unknown'}/partial")
            artifacts.extend(f"kill_switch_mismatch:{reason}" for reason in reasons)
            state.runtime_artifacts = tuple(sorted(set(artifacts)))
            state.status = "runtime_mismatch"
            state.runtime_mismatch_severity = "critical"
        else:
            state.kill_switch_status = "inactive"
        return state

    def _with_lan_gateway_status(self, state: ConnectionState) -> ConnectionState:
        config_gateway = False
        try:
            config = self.app_config.load()
            lan_config = config.get("lan_sharing", {})
            config_gateway = bool(lan_config.get("enabled", False)) and lan_config.get("mode") == "gateway"
        except (PersistentStoreError, PersistentValidationError):
            lan_config = {}

        if state.lan_gateway_active:
            state.lan_gateway_status = "applied" if state.tun_active else "degraded"
            return state
        if config_gateway:
            state.lan_gateway_status = "configured"
            state.lan_gateway_interface = str(lan_config.get("gateway_interface", ""))
            state.lan_gateway_client_cidr = str(lan_config.get("gateway_client_cidr", ""))
            state.lan_gateway_dns_mode = str(lan_config.get("gateway_dns_mode", "manual"))
            return state
        state.lan_gateway_status = "disabled"
        return state

    def _requested_policy_capabilities(self) -> frozenset[str]:
        """Return every WatchdogVPN policy requested by persistent state.

        This read-only preflight intentionally runs before _connect_options(),
        whose rule-set and LAN helpers can create runtime state. Native drivers
        must never reach those helpers while unable to enforce the policy.
        """
        state = self.state_manager.load()
        config = self.app_config.load()
        capabilities = {"dns", "routing", "capture"}
        if state.get("routing_policy") == "rule":
            app_policy = self._runtime_app_policy()
            if app_policy.enabled:
                capabilities.add("app_policy")
            chain_actions = _chain_actions_from_rule_groups(self.rule_store.list_groups())
            chain_actions.update(_chain_actions_from_app_policy(app_policy))
            if chain_actions:
                capabilities.add("chains")
        if chain_target(str(state.get("default_route_action", "current"))) is not None:
            capabilities.add("chains")
        lan_config = config.get("lan_sharing", {})
        if isinstance(lan_config, dict) and lan_config.get("enabled") is True:
            if lan_config.get("mode") == "proxy":
                capabilities.add("lan_proxy")
            elif lan_config.get("mode") == "gateway":
                capabilities.add("lan_gateway")
        return frozenset(capabilities)

    def _driver_policy_contract_for_profile(
        self, profile: Profile
    ) -> tuple[str, frozenset[str]]:
        if self.driver_selector is ORIGINAL_SELECT_DRIVER:
            driver_type = driver_type_for_profile(profile)
            return driver_type.__name__, driver_type.policy_capabilities
        driver = self._candidate_driver_for_profile(profile)
        return type(driver).__name__, driver.policy_capabilities

    def _candidate_driver_for_profile(self, profile: Profile) -> BaseDriver:
        if self.driver_selector is ORIGINAL_SELECT_DRIVER:
            candidate = select_driver(profile)
            if type(candidate) is not type(self.driver):
                return candidate
            if isinstance(candidate, NativePolicyDriver) and isinstance(self.driver, NativePolicyDriver):
                return self.driver if type(candidate.native) is type(self.driver.native) else candidate
            return self.driver
        selected_driver = self.driver_selector(profile)
        return self.driver if type(selected_driver) is type(self.driver) else selected_driver

    def _teardown_active_driver(self) -> bool:
        """Stop the current runtime or retain it as a hard lifecycle barrier."""
        try:
            disconnected = self.driver.disconnect()
        except Exception:
            LOGGER.error("watchdog_cleanup_barrier_exception driver=%s", type(self.driver).__name__, exc_info=True)
            disconnected = False
        if disconnected:
            self._cleanup_barrier_failed = False
            return True
        self._cleanup_barrier_failed = True
        self._record_last_failure("cleanup_failed")
        LOGGER.error("watchdog_cleanup_barrier_failed driver=%s", type(self.driver).__name__)
        return False

    def _cleanup_failure_state(self) -> ConnectionState:
        state = self.status()
        state.status = "cleanup_failed"
        return state

    def _activate_driver(
        self, selected_driver: BaseDriver, *, disconnect_current: bool = True
    ) -> BaseDriver:
        if disconnect_current and not self._teardown_active_driver():
            raise TeardownBarrierError(type(self.driver).__name__)
        if selected_driver is not self.driver:
            self.driver = selected_driver
        return self.driver

    def _prepare_driver_for_connection(
        self,
        profile: Profile,
    ) -> tuple[BaseDriver, dict[str, object]]:
        driver_name, policy_capabilities = self._driver_policy_contract_for_profile(profile)
        unsupported = self._requested_policy_capabilities() - policy_capabilities
        if unsupported:
            raise UnsupportedDriverPolicyError(driver_name, unsupported)
        try:
            endpoint_host = profile_endpoint_host(profile)
            if endpoint_host is not None:
                validate_profile_endpoint(
                    profile,
                    require_resolution=True,
                    allow_captured_fakeip_ranges=self._endpoint_policy_fakeip_allowlist(),
                    resolution_cache=self.endpoint_resolution_cache,
                    allow_live_resolution=self._active_profile() is None,
                )
        except (EndpointPolicyError, ValueError) as exc:
            raise EndpointPolicyConnectionError(f"endpoint policy rejected connection: {exc}") from exc
        driver = self._candidate_driver_for_profile(profile)
        options = self._connect_options()
        management_preflight = getattr(driver, "preflight_management_path", None)
        if callable(management_preflight):
            peers = management_preflight(
                profile,
                mode=str(options["mode"]),
                capture_modes=options["capture_modes"],
            )
            # An empty result is still a successful fail-closed preflight.
            # It must happen before desired state, kill switch, process,
            # route, or DNS mutation.
            options["management_peers"] = peers
        return driver, options

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
        state = self.state_manager.load()
        routing_policy = str(state.get("routing_policy", "rule"))
        capture_modes = parse_capture_modes(str(state.get("capture_modes", "local_proxy")))
        default_action = str(state.get("default_route_action", "current"))

        if not capture_modes:
            raise RuntimeError("no usable capture mode is configured")
        if "system_proxy" in capture_modes:
            raise RuntimeError(
                "system_proxy capture is not implemented yet; use local_proxy or tun"
            )

        if chain_target(default_action) is not None:
            final_policy = default_action
        else:
            final_policy = {
                "current": "current_profile",
                "direct": "direct",
                "block": "block",
            }.get(default_action)
        if final_policy is None:
            raise PersistentValidationError(
                "default_route_action must be one of: current, direct, block, or chain:<id>"
            )

        if routing_policy == "rule":
            mode = "rules"
        elif "tun" in capture_modes and default_action == "current":
            mode = "tun"
        elif default_action == "direct" and capture_modes == ("local_proxy",):
            mode = "direct"
        elif default_action == "block" and capture_modes == ("local_proxy",):
            mode = "rules"
        else:
            mode = "global"

        options: dict[str, object] = {
            "mode": mode,
            "final_policy": final_policy,
            "capture_modes": capture_modes,
        }
        runtime_config = self.app_config.load()
        dns_policy = self.dns_policy_store.load()
        chain_actions = {default_action} if chain_target(default_action) is not None else set()
        lan_proxy = self._lan_proxy_runtime_config()
        if lan_proxy is not None:
            LOGGER.warning(
                "lan_sharing_enabled bind_address=%s socks_port=%s http_port=%s firewall_managed=%s",
                lan_proxy.bind_address,
                lan_proxy.socks_port,
                lan_proxy.http_port,
                lan_proxy.firewall_managed,
            )
            options["lan_proxy"] = lan_proxy
        lan_gateway = self._lan_gateway_runtime_config(capture_modes)
        if lan_gateway is not None:
            LOGGER.warning(
                "lan_gateway_enabled interface=%s client_cidr=%s dns_mode=%s firewall_managed=%s",
                lan_gateway.lan_interface,
                lan_gateway.client_cidr,
                lan_gateway.dns_mode,
                lan_gateway.firewall_managed,
            )
            options["lan_gateway"] = lan_gateway
        if routing_policy == "rule":
            groups = self.rule_store.list_groups()
            app_policy = self._runtime_app_policy()
            chain_actions.update(_chain_actions_from_rule_groups(groups))
            chain_actions.update(_chain_actions_from_app_policy(app_policy))
            runtime_plan = self.rule_set_lifecycle.runtime_plan(groups)
            if runtime_plan.results:
                LOGGER.info(
                    "rule_set_refresh_before_connect results=%s",
                    [result.to_dict() for result in runtime_plan.results],
                )
            options["groups"] = groups
            options["app_policy"] = app_policy
            options["rule_set_tags"] = runtime_plan.tags
            options["rule_set_declarations"] = runtime_plan.declarations
        chain_runtime_plans = self._chain_runtime_plans(
            chain_actions,
            dns_policy=dns_policy,
            config=runtime_config,
        )
        if chain_runtime_plans:
            options["chain_runtime_plans"] = chain_runtime_plans
        return options

    def _endpoint_policy_fakeip_allowlist(self) -> tuple[str, ...]:
        try:
            state = self.driver.status()
        except Exception:
            return ()
        if not (state.tun_active or state.proxy_active or state.runtime_artifacts):
            return ()
        try:
            policy = self.dns_policy_store.load()
        except Exception:
            return ()
        return (policy.fakeip_inet4_range, policy.fakeip_inet6_range)

    def _profile_with_cached_endpoint(self, profile: Profile) -> Profile:
        """Use a validated dial address without changing the logical profile."""
        host = profile_endpoint_host(profile)
        if host is None:
            return profile
        lease = self.endpoint_resolution_cache.get(host)
        if lease is None:
            return profile
        dial_address = lease.addresses[0]
        config = dict(profile.config)
        if "host" in config:
            config["host"] = dial_address
        elif "server" in config:
            config["server"] = dial_address
        elif isinstance(config.get("endpoint"), str):
            endpoint = str(config["endpoint"])
            separator = endpoint.rfind(":")
            dial_endpoint = f"[{dial_address}]" if ":" in dial_address else dial_address
            config["endpoint"] = (
                f"{dial_endpoint}{endpoint[separator:]}" if separator > 0 else dial_endpoint
            )
        if profile.protocol in {
            ProtocolType.VLESS,
            ProtocolType.VMESS,
            ProtocolType.TROJAN,
            ProtocolType.HYSTERIA2,
            ProtocolType.TUIC,
        }:
            config.setdefault("sni", host)
        return replace(profile, config=config)

    def _chain_runtime_plans(
        self,
        actions: set[str],
        *,
        dns_policy: DNSPolicy,
        config: dict,
    ) -> dict[str, ChainRuntimePlan]:
        if not actions:
            return {}
        resolver = ChainRuntimeResolver(
            chain_store=self.route_chain_store,
            profile_store=self.profile_store,
            node_group_store=self.node_group_store,
            provider_store=self.provider_store,
        )
        plans: dict[str, ChainRuntimePlan] = {}
        for action in sorted(actions):
            plan = resolver.resolve_action(action, dns_policy=dns_policy, config=config)
            if plan is not None:
                plans[action] = plan
        return plans

    def _lan_proxy_runtime_config(self) -> LANProxyRuntimeConfig | None:
        config = self.app_config.load()
        lan_config = config.get("lan_sharing", {})
        if not lan_config.get("enabled", False) or lan_config.get("mode") != "proxy":
            return None

        bind_address = str(lan_config["bind_address"])
        if bind_address not in self._local_ip_addresses():
            raise RuntimeError(
                f"lan_sharing.bind_address is not assigned to this host: {bind_address}"
            )
        credentials = load_or_create_lan_sharing_credentials(
            lan_sharing_credentials_path(self.app_config.path)
        )
        return LANProxyRuntimeConfig(
            bind_address=bind_address,
            socks_port=int(lan_config["socks_port"]),
            http_port=int(lan_config["http_port"]),
            username=credentials["username"],
            password=credentials["password"],
            firewall_managed=bool(lan_config["firewall_managed"]),
        )

    def _lan_gateway_runtime_config(
        self,
        capture_modes: tuple[str, ...],
    ) -> LANGatewayRuntimeConfig | None:
        config = self.app_config.load()
        lan_config = config.get("lan_sharing", {})
        if not lan_config.get("enabled", False) or lan_config.get("mode") != "gateway":
            return None
        if "tun" not in capture_modes:
            raise RuntimeError("lan_sharing gateway mode requires capture_modes to include tun")

        interface_name = str(lan_config["gateway_interface"])
        interfaces = self._local_interface_ipv4_addresses()
        if interface_name not in interfaces:
            raise RuntimeError(
                f"lan_sharing.gateway_interface is not assigned to this host: {interface_name}"
            )
        if interface_name == "lo":
            raise RuntimeError("lan_sharing.gateway_interface must be non-loopback")
        if not interfaces[interface_name]:
            raise RuntimeError(
                f"lan_sharing.gateway_interface has no IPv4 address: {interface_name}"
            )
        return LANGatewayRuntimeConfig(
            lan_interface=interface_name,
            client_cidr=str(lan_config["gateway_client_cidr"]),
            dns_mode=str(lan_config["gateway_dns_mode"]),
            firewall_managed=bool(lan_config["firewall_managed"]),
            tunnel_interface=str(config.get("kill_switch", {}).get("tunnel_interface", "wdvpn-tun0")),
        )

    def _local_ip_addresses(self) -> set[str]:
        return {
            address
            for addresses in self._local_interface_addresses().values()
            for address in addresses
        }

    def _local_interface_ipv4_addresses(self) -> dict[str, set[str]]:
        return self._local_interface_addresses(family="inet")

    def _local_interface_addresses(self, family: str | None = None) -> dict[str, set[str]]:
        try:
            result = subprocess.run(
                ["ip", "-j", "addr", "show"],
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            raise RuntimeError("cannot verify LAN sharing interface state: ip command unavailable") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            message = "cannot verify LAN sharing interface state"
            if detail:
                message += f": {detail}"
            raise RuntimeError(message)
        try:
            interfaces = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise RuntimeError("cannot verify LAN sharing interface state: invalid ip output") from exc
        addresses: dict[str, set[str]] = {}
        if not isinstance(interfaces, list):
            return addresses
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            name = interface.get("ifname")
            if not isinstance(name, str):
                continue
            interface_addresses = addresses.setdefault(name, set())
            for item in interface.get("addr_info", []):
                if (
                    isinstance(item, dict)
                    and (family is None or item.get("family") == family)
                    and isinstance(item.get("local"), str)
                ):
                    interface_addresses.add(item["local"])
        return addresses

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
        try:
            selected_driver, options = self._prepare_driver_for_connection(profile)
        except UnsupportedDriverPolicyError as exc:
            LOGGER.error("watchdog_reconnect_policy_unsupported error=%s", exc)
            self._record_last_failure("unsupported_policy")
            return False
        except ManagementPathSafetyError as exc:
            LOGGER.error("watchdog_reconnect_management_path_unsafe error=%s", exc)
            self._record_last_failure("management_path_unprotected")
            return False
        except EndpointPolicyConnectionError as exc:
            LOGGER.error("watchdog_reconnect_endpoint_policy_rejected error=%s", exc)
            self._record_last_failure("endpoint_policy_rejected")
            return False
        try:
            driver = self._activate_driver(selected_driver)
        except TeardownBarrierError:
            return False
        if not self._protect_connection_attempt(profile):
            return False
        if not driver.connect(
            profile,
            dns_policy=self.dns_policy_store.load(),
            **options,
        ):
            return False
        if self._checked_and_recorded(profile, driver, retry_startup_failure=True) == "ok":
            self.rotation_engine.record_successful_profile(profile.id)
            return True
        self._teardown_active_driver()
        return False

    def _recover_from_failure(self) -> ConnectionState:
        self._cleanup_barrier_failed = False
        config = self.app_config.load()
        self._configure_recovery(config)
        if not self.recovery.can_retry_now():
            LOGGER.info("watchdog_recovery_skip reason=backoff_window")
            # watchdog status must not keep reporting a stale "connected,
            # failure_or_degraded: false" while a background tick has
            # already detected a failed egress probe and is sitting in its
            # backoff window - previously last_failure_reason was only ever
            # set once every retry was exhausted, leaving up to one full
            # reconnect_attempts cycle where status() had no way to know
            # anything was wrong.
            self._record_last_failure("waiting_retry")
            return ConnectionState(status="waiting_retry", mode=self.driver.status().mode)

        current_profile = self._active_profile()
        if current_profile is not None and self._try_reconnect(current_profile):
            self._reconnect_failures = 0
            self.recovery.record_success()
            # The transient "waiting_retry"/"reconnecting" markers recorded
            # below must be cleared here too: this in-place recovery path
            # never escalates to _attempt_rotation() (whose own success path
            # already clears last_failure), so without this a machine that
            # self-heals within the same backoff window would be left
            # showing a permanently stale failure_or_degraded: true.
            self._clear_last_failure()
            return self._recovered_state_after_stable_connection(config)
        if self._cleanup_barrier_failed:
            return self._cleanup_failure_state()

        self._reconnect_failures += 1
        reconnect_attempts = int(config.get("watchdog", {}).get("reconnect_attempts", 3))
        if self._reconnect_failures < reconnect_attempts:
            LOGGER.info(
                "watchdog_reconnect_retry attempt=%d/%d",
                self._reconnect_failures,
                reconnect_attempts,
            )
            self._record_last_failure("reconnecting")
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
        self._cleanup_barrier_failed = False
        self._configure_recovery(config)
        if not force and not self._rotation_enabled(config):
            LOGGER.warning("rotation_unavailable reason=disabled")
            return self._handle_rotation_unavailable(config, reason="disabled")

        pool = self._compatible_pool(config)
        if exclude_profile_id:
            pool = [p for p in pool if p.id != exclude_profile_id]
        try:
            requested_capabilities = self._requested_policy_capabilities()
            for profile in pool:
                driver_name, policy_capabilities = self._driver_policy_contract_for_profile(profile)
                unsupported = requested_capabilities - policy_capabilities
                if unsupported:
                    raise UnsupportedDriverPolicyError(driver_name, unsupported)
        except UnsupportedDriverPolicyError as exc:
            LOGGER.error("watchdog_rotation_policy_unsupported error=%s", exc)
            self._record_last_failure("unsupported_policy")
            return ConnectionState(status="unsupported_policy", mode=self.driver.status().mode)
        rotation_driver = _RuntimeDriverRouter(self)
        result = self.rotation_engine.rotate(
            pool,
            rotation_driver,
            lambda checked_profile, checked_driver: self._checked_and_recorded(
                checked_profile,
                checked_driver,
                retry_startup_failure=True,
            ),
            force=force,
            dns_policy=self.dns_policy_store.load(),
        )

        if result.cleanup_failed or self._cleanup_barrier_failed:
            return self._cleanup_failure_state()

        if result.success and result.profile is not None:
            self._reconnect_failures = 0
            self.recovery.record_success()
            self.state_manager.set("active_profile_id", result.profile.id)
            self._clear_last_failure()
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
        status = (
            "all_failed"
            if self._desired_on_kill_switch_forced
            else ("kill_switch_active" if action.kill_switch_active else "all_failed")
        )
        LOGGER.error(
            "watchdog_all_failed kill_switch=%s consecutive_failures=%d",
            "on" if action.kill_switch_active else "off",
            self.recovery.consecutive_failures,
        )
        self._record_last_failure(status)
        return ConnectionState(status=status, mode=self.driver.status().mode)

    def _rotation_enabled(self, config: dict) -> bool:
        return strict_bool(config.get("rotation", {}).get("enabled", False), "rotation.enabled")

    def _handle_rotation_unavailable(self, config: dict, reason: str) -> ConnectionState:
        kill_switch_active = self._apply_all_failed_kill_switch(config)
        action = self.recovery.handle_rotation_unavailable(
            kill_switch_active=kill_switch_active,
            reason=reason,
        )
        status = (
            "rotation_unavailable"
            if self._desired_on_kill_switch_forced
            else ("kill_switch_active" if action.kill_switch_active else "rotation_unavailable")
        )
        LOGGER.error(
            "watchdog_rotation_unavailable reason=%s kill_switch=%s consecutive_failures=%d",
            reason,
            "on" if action.kill_switch_active else "off",
            self.recovery.consecutive_failures,
        )
        self._record_last_failure(status)
        return ConnectionState(status=status, mode=self.driver.status().mode)

    def _compatible_pool(self, config: dict) -> list[Profile]:
        """The candidate pool RotationEngine rotates over.

        Task 14.6: the node-group selector does not compete with
        RotationEngine for "which profile is active" - it only changes
        which candidate list feeds it. RotationEngine itself, Recovery,
        and the kill-switch/all-failed pipeline are all unchanged; this is
        the single point where the source of candidates is decided.
        """
        target_name, target_group = self._effective_node_group()
        if target_name is None:
            return pool_builder.build_pool(self.profile_store, self.provider_store, config)
        if target_group is None:
            # Fail-closed, deliberately: an enabled rule/app-policy action
            # references a node group that does not exist (deleted, or the
            # rule was written before the group was created). This is a
            # broken routing reference, not "nothing configured" - for a
            # resilience product it must not silently degrade to "use any
            # node" by falling back to the legacy pool. An empty pool here
            # flows into the same unavailable/kill-switch path as any other
            # exhausted pool (RotationEngine.pool_size_category() ==
            # "unavailable" -> _handle_rotation_unavailable), so no new
            # safety code is needed - only correct sourcing.
            LOGGER.error("node_group_target_missing name=%s", target_name)
            return []
        if not target_group.enabled:
            LOGGER.error("node_group_target_disabled name=%s", target_name)
            return []
        return self._group_scoped_pool(target_group, config)

    def _effective_node_group(self) -> tuple[str | None, NodeGroup | None]:
        """Which node group, if any, currently governs the active connection.

        Scans enabled rules/app-policy in the same priority order RuleEngine
        already uses for matching real traffic (block -> custom -> app ->
        imported -> recommended), reusing that order rather than inventing a
        second precedence system: the first `group:<id>` action found, in
        that order, is the group that governs. Returns (None, None) when no
        enabled rule/app-policy targets any group - the legacy pool applies.
        Returns (name, None) when a group is targeted but does not exist
        (name, group) when it does.
        """
        tiers = group_by_tier(self.rule_store.list_groups())
        app_policy = self._runtime_app_policy()
        for tier in PRIORITY_TIER_ORDER:
            if tier == "app":
                name = self._app_policy_group_target(app_policy)
                if name is not None:
                    return name, self.node_group_store.get(name)
            for rule_group in tiers[tier]:
                if not rule_group.enabled:
                    continue
                for rule in rule_group.rules:
                    if not rule.enabled:
                        continue
                    name = group_target(rule.action)
                    if name is not None:
                        return name, self.node_group_store.get(name)
        return None, None

    def _app_policy_group_target(self, policy: AppPolicy) -> str | None:
        if not policy.enabled:
            return None
        for rule in policy.rules:
            if not rule.enabled:
                continue
            name = group_target(rule.action)
            if name is not None:
                return name
        return group_target(policy.default_action)

    def _group_scoped_pool(self, group: NodeGroup, config: dict) -> list[Profile]:
        candidates = resolve_node_group_candidates(
            group, self.profile_store, self.provider_store, config
        )
        if group.selection_mode is NodeGroupSelectionMode.MANUAL:
            # Hard pin (Task 14.3): never substitute a different profile
            # when the pinned one is unavailable - "decisions are
            # respected," an empty result here is correct, not a bug.
            return [profile for profile in candidates if profile.id == group.manual_profile_id]
        ranked = rank_candidates(candidates, group.resilience_policy, config)
        by_id = {profile.id: profile for profile in candidates}
        return [by_id[score.profile_id] for score in ranked]

    def _driver_for_profile(self, profile: Profile, disconnect_current: bool = True) -> BaseDriver:
        return self._activate_driver(
            self._candidate_driver_for_profile(profile),
            disconnect_current=disconnect_current,
        )

    def _configure_recovery(self, config: dict) -> None:
        watchdog_config = config.get("watchdog", {})
        rotation_config = config.get("rotation", {})
        if "reconnect_backoff_seconds" in watchdog_config:
            self.recovery.base_interval_seconds = float(watchdog_config["reconnect_backoff_seconds"])
        if "max_backoff_interval_seconds" in rotation_config:
            self.recovery.max_interval_seconds = float(rotation_config["max_backoff_interval_seconds"])

    def _apply_all_failed_kill_switch(self, config: dict) -> bool:
        self._configure_kill_switch(config, self._active_profile())
        configured = strict_bool(config.get("kill_switch", {}).get("enabled", False), "kill_switch.enabled")
        if self.kill_switch.is_active():
            LOGGER.warning("watchdog_all_failed_kill_switch action=keep_active")
            return True
        if not configured and not self._desired_on_kill_switch_forced:
            return False
        if self.kill_switch.apply_atomic():
            LOGGER.warning("watchdog_all_failed_kill_switch action=enabled")
            return True
        LOGGER.error("watchdog_all_failed_kill_switch action=enable_failed")
        return False

    def _recovered_state_after_stable_connection(self, config: dict) -> ConnectionState:
        kill_switch_active = self._restore_kill_switch_after_recovery(config)
        return self._as_recovered(self.driver.status(), kill_switch_active=kill_switch_active)

    def _restore_kill_switch_after_recovery(self, config: dict) -> bool:
        configured = strict_bool(
            config.get("kill_switch", {}).get("enabled", False),
            "kill_switch.enabled",
        )
        if not configured and not self._desired_on_kill_switch_forced:
            return self.kill_switch.is_active()

        # enable() removes the active table and then recreates it command by
        # command. Recovery must retain that policy or replace it atomically.
        if self._maintain_kill_switch_for_active_runtime():
            LOGGER.info("watchdog_kill_switch_restored_after_recovery")
            return True
        LOGGER.error("watchdog_kill_switch_restore_failed_after_recovery")
        return False

    def _apply_desired_on_protection(self, profile: Profile | None) -> bool:
        """Install fail-closed protection for the entire desired-on lifecycle."""

        config = self.app_config.load()
        self._configure_kill_switch(config, profile)
        if self.kill_switch.apply_atomic():
            # A desired-on session is never permitted to run without the
            # policy. The setting only records whether the policy was forced
            # by this invariant rather than explicitly requested by the user.
            configured = strict_bool(
                config.get("kill_switch", {}).get("enabled", False),
                "kill_switch.enabled",
            )
            self._desired_on_kill_switch_forced = not configured
            return True
        LOGGER.error("watchdog_desired_on_protection_failed")
        return False

    def _protect_connection_attempt(self, profile: Profile) -> bool:
        """Install the candidate policy before a driver can open a socket."""
        return self._apply_desired_on_protection(profile)

    def _maintain_kill_switch_for_active_runtime(self) -> bool:
        config = self.app_config.load()
        configured = strict_bool(
            config.get("kill_switch", {}).get("enabled", False),
            "kill_switch.enabled",
        )
        if not configured and not self._desired_on_kill_switch_forced:
            return True
        self._configure_kill_switch(config, self._active_profile())
        status = self.kill_switch.status()
        active = (
            bool(status["active"])
            if "active" in status
            else self.kill_switch.is_active()
        )
        if active and bool(status.get("consistent", True)):
            return True
        if self.kill_switch.apply_atomic():
            LOGGER.warning("watchdog_kill_switch_reapplied")
            return True
        LOGGER.error("watchdog_kill_switch_unavailable_for_active_runtime")
        return False

    def _configure_kill_switch(self, config: dict, profile: Profile | None = None) -> None:
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
        if hasattr(self.kill_switch, "allowed_endpoints"):
            self.kill_switch.allowed_endpoints = self._kill_switch_allowed_endpoints(profile)
        if hasattr(self.kill_switch, "direct_egress_uid"):
            # sing-box marks its own physical outbound sockets so they do not
            # re-enter TUN capture.  The mark alone is attacker-controlled
            # firewall input and must never be trusted.  Conjoin it with the
            # exact unprivileged daemon UID for every managed connection: this
            # permits both the selected VPN transport and explicit `direct`
            # policy while retaining the controlled-failure boundary.
            self.kill_switch.direct_egress_uid = os.getuid() if profile is not None else None

    def _kill_switch_allowed_endpoints(self, profile: Profile | None) -> tuple[str, ...]:
        if profile is None:
            return ()
        try:
            host = profile_endpoint_host(profile)
        except ValueError:
            return ()
        if not isinstance(host, str) or not host.strip():
            return ()
        try:
            return (str(ip_address(host.strip())),)
        except ValueError:
            return ()

    def _handle_manual_disconnect_kill_switch(self) -> None:
        config = self.app_config.load()
        self._configure_kill_switch(config, self._active_profile())
        if not self.kill_switch.is_active():
            self._desired_on_kill_switch_forced = False
            return

        policy = str(
            config.get("kill_switch", {}).get("on_manual_disconnect", "disable")
        ).strip().lower()
        if policy == "keep":
            self._desired_on_kill_switch_forced = False
            LOGGER.warning("watchdog_manual_disconnect_kill_switch action=keep_active")
            return
        if policy != "disable":
            LOGGER.warning(
                "watchdog_manual_disconnect_kill_switch action=disable reason=invalid_policy policy=%s",
                policy,
            )
        if self.kill_switch.disable():
            self._desired_on_kill_switch_forced = False
            LOGGER.info("watchdog_manual_disconnect_kill_switch action=disabled")
            return
        LOGGER.error("watchdog_manual_disconnect_kill_switch action=disable_failed")

    def _restore_dns_snapshot_if_present(self) -> bool:
        try:
            snapshot = load_snapshot(self.dns_snapshot_path)
        except Exception:
            LOGGER.warning("watchdog_dns_restore_on_disconnect status=load_failed", exc_info=True)
            return False
        if snapshot is None:
            return True
        try:
            if snapshot.inventory.manager == ResolverManager.NETWORK_MANAGER:
                subprocess.run(
                    ["systemctl", "start", "watchdogvpn-nm-dns-restore.service"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=15,
                )
            else:
                self.dns_state_manager.restore_state(snapshot)
            self.dns_snapshot_path.unlink()
        except Exception:
            LOGGER.warning("watchdog_dns_restore_on_disconnect status=restore_failed", exc_info=True)
            return False
        LOGGER.info("watchdog_dns_restore_on_disconnect status=restored")
        return True

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
            kill_switch_status=state.kill_switch_status,
            kill_switch_method=state.kill_switch_method,
            kill_switch_consistent=state.kill_switch_consistent,
            runtime_mismatch_severity=state.runtime_mismatch_severity,
            runtime_artifacts=state.runtime_artifacts,
            lan_gateway_active=state.lan_gateway_active,
            lan_gateway_interface=state.lan_gateway_interface,
            lan_gateway_client_cidr=state.lan_gateway_client_cidr,
            lan_gateway_dns_mode=state.lan_gateway_dns_mode,
            lan_gateway_status=state.lan_gateway_status,
            status="recovered",
        )


class _RuntimeDriverRouter(BaseDriver):
    def __init__(self, runtime: WatchdogRuntime) -> None:
        self.runtime = runtime
        self._teardown_verified = False
        self._prepared_profile_id: str | None = None
        self._prepared_profile: Profile | None = None
        self._prepared_connection: tuple[BaseDriver, dict[str, object]] | None = None

    @property
    def requires_profile_egress_check(self) -> bool:
        """Expose the active driver's startup-egress contract to rotation."""

        return bool(
            getattr(self.runtime.driver, "requires_profile_egress_check", False)
        )

    def preflight_profile(self, profile: Profile) -> bool:
        """Prepare a candidate completely before tearing down the healthy path."""

        self._prepared_profile_id = None
        self._prepared_profile = None
        self._prepared_connection = None
        try:
            prepared = self.runtime._prepare_driver_for_connection(profile)
        except (
            EndpointPolicyConnectionError,
            ManagementPathSafetyError,
            UnsupportedDriverPolicyError,
        ) as exc:
            LOGGER.warning(
                "watchdog_rotation_candidate_prepare_failed profile_id=%s error_kind=%s error=%s",
                profile.id,
                type(exc).__name__,
                exc,
            )
            return False
        self._prepared_profile_id = profile.id
        self._prepared_profile = self.runtime._profile_with_cached_endpoint(profile)
        self._prepared_connection = prepared
        return True

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups=None,
        app_policy=None,
        final_policy: str = "current_profile",
        lan_proxy=None,
        lan_gateway=None,
        chain_runtime_plans=None,
    ) -> bool:
        if not self._teardown_verified:
            self.runtime._cleanup_barrier_failed = True
            self.runtime._record_last_failure("cleanup_failed")
            LOGGER.error("watchdog_rotation_connect_blocked reason=unverified_teardown")
            return False
        if self._prepared_profile_id == profile.id and self._prepared_connection is not None:
            driver, options = self._prepared_connection
            connection_profile = self._prepared_profile or profile
        else:
            try:
                driver, options = self.runtime._prepare_driver_for_connection(profile)
            except (
                EndpointPolicyConnectionError,
                ManagementPathSafetyError,
                UnsupportedDriverPolicyError,
            ) as exc:
                LOGGER.warning(
                    "watchdog_rotation_candidate_prepare_failed profile_id=%s error_kind=%s error=%s",
                    profile.id,
                    type(exc).__name__,
                    exc,
                )
                return False
            connection_profile = profile
        self._prepared_profile_id = None
        self._prepared_profile = None
        self._prepared_connection = None
        driver = self.runtime._activate_driver(driver, disconnect_current=False)
        if not self.runtime._protect_connection_attempt(connection_profile):
            return False
        self._teardown_verified = False
        options.setdefault("final_policy", final_policy)
        return driver.connect(
            connection_profile,
            dns_policy=dns_policy,
            **options,
        )

    def disconnect(self) -> bool:
        self._teardown_verified = self.runtime._teardown_active_driver()
        return self._teardown_verified

    def health_check(self) -> str:
        return self.runtime.driver.health_check()

    def status(self) -> ConnectionState:
        return self.runtime.driver.status()

    def is_available(self) -> bool:
        return self.runtime.driver.is_available()


def _chain_actions_from_rule_groups(groups: list) -> set[str]:
    actions: set[str] = set()
    for group in groups:
        if not group.enabled:
            continue
        for rule in group.rules:
            if rule.enabled and chain_target(rule.action) is not None:
                actions.add(rule.action)
    return actions


def _chain_actions_from_app_policy(policy: AppPolicy) -> set[str]:
    if not policy.enabled:
        return set()
    actions = {
        str(rule.action)
        for rule in policy.rules
        if rule.enabled and chain_target(rule.action) is not None
    }
    default_action = str(policy.default_action)
    if chain_target(default_action) is not None:
        actions.add(default_action)
    return actions


def build_watchdog(profile: Profile | None = None) -> WatchdogRuntime:
    return WatchdogRuntime(driver=select_driver(profile))
