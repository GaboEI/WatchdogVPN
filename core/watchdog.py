from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
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
from drivers.amneziawg_driver import AmneziaWGDriver
from drivers.base import BaseDriver
from drivers.openvpn_cloak_driver import OpenVPNCloakDriver
from drivers.openvpn_driver import OpenVPNDriver
from drivers.singbox_driver import SingBoxDriver
from dns.models import DNSPolicy
from dns.state_manager import SystemDNSStateManager, default_snapshot_path, load_snapshot
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType
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
MANAGED_DRIVER_TYPES = (
    AmneziaWGDriver,
    OpenVPNCloakDriver,
    OpenVPNDriver,
    SingBoxDriver,
)

# Sentinel distinct from None: "this call site never attempted a latency
# measurement" vs. "it attempted one and the node was unreachable". See
# WatchdogRuntime._record_health_result for why conflating the two would
# silently erase a real measurement.
_LATENCY_NOT_MEASURED = object()


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
    rule_set_lifecycle: RuleSetLifecycleManager = field(default_factory=RuleSetLifecycleManager)
    app_policy_store: AppPolicyStore = field(default_factory=AppPolicyStore)
    node_group_store: NodeGroupStore = field(default_factory=NodeGroupStore)
    route_chain_store: RouteChainStore = field(default_factory=RouteChainStore)
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
        status = self.driver.health_check()
        active_profile = self._active_profile()
        if active_profile is not None:
            self._record_health_result(active_profile, status)
        if status == "ok":
            self.recovery.record_success()
            return self.driver.status()
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
        test_url = str(rotation_config.get("test_url", health_checker.EXTERNAL_CHECK_URL))
        timeout = float(
            rotation_config.get("test_timeout_seconds", health_checker.DEFAULT_TIMEOUT_SECONDS)
        )
        return lambda via_proxy: health_checker.reachable_and_public_ip(
            via_proxy, timeout=timeout, test_url=test_url
        )

    def _checked_and_recorded(self, profile: Profile, driver: BaseDriver) -> str:
        """HealthCheckFn-compatible wrapper: real check, then persist.

        Passed as the health_check callable into RotationEngine.rotate()
        (see _attempt_rotation), which threads it, unchanged, through its
        main candidate loop, _rollback(), and _single_node_check() - all
        three paths get persistence for free, with zero changes to
        rotation/rotation_engine.py, which stays store-agnostic by design.

        Uses the configured rotation.test_url/test_timeout_seconds (Task
        14.7) for every candidate, in every call site - one shared
        reference point is what makes latency comparable across profiles,
        not a per-profile setting.
        """
        config = self.app_config.load()
        verify = self._configured_verify(config)
        result = health_checker.check_with_latency(profile, driver, verify=verify)
        self._record_health_result(profile, result.status, latency_ms=result.latency_ms)
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
        if not self.automatic_actions_enabled():
            return self.standby_state()
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
        if (
            state.active_profile_id
            or state.tun_active
            or state.proxy_active
            or state.status != "standby"
        ):
            raise RuntimeError("node-group auto-test requires standby/disconnected state")
        if self.kill_switch.is_active() or state.kill_switch_active:
            raise RuntimeError("node-group auto-test requires the kill switch to be inactive")

        group = self.node_group_store.get(group_name)
        if group is None:
            raise RuntimeError(f"node group not found: {group_name}")
        if not group.enabled:
            raise RuntimeError(f"node group is disabled: {group_name}")

        config = self.app_config.load()
        candidates = resolve_node_group_candidates(
            group, self.profile_store, self.provider_store, config
        )
        test_results: list[dict[str, object]] = []
        ok_profile_ids: set[str] = set()
        for profile in candidates:
            driver = self._driver_for_profile(profile)
            connected = driver.connect(
                profile,
                dns_policy=self.dns_policy_store.load(),
                **self._connect_options(),
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
                status = self._checked_and_recorded(profile, driver)
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

    @property
    def last_error(self) -> str:
        return str(getattr(self.driver, "last_error", "") or "")

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
        return self._with_lan_gateway_status(self._with_kill_switch_status(self.driver.status()))

    def _with_kill_switch_status(self, state: ConnectionState) -> ConnectionState:
        state.kill_switch_active = state.kill_switch_active or self.kill_switch.is_active()
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

        options: dict[str, object] = {"mode": mode, "final_policy": final_policy}
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
        driver = self._driver_for_profile(profile)
        driver.disconnect()
        if not driver.connect(
            profile,
            dns_policy=self.dns_policy_store.load(),
            **self._connect_options(),
        ):
            return False
        if self._checked_and_recorded(profile, driver) == "ok":
            return True
        driver.disconnect()
        return False

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
            self._checked_and_recorded,
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
        self._configure_kill_switch(config, self._active_profile())
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
        self._configure_kill_switch(config, self._active_profile())
        if not self.kill_switch.is_active():
            return False
        if self.kill_switch.enable():
            LOGGER.info("watchdog_kill_switch_restored_after_recovery")
            return True
        LOGGER.error("watchdog_kill_switch_restore_failed_after_recovery")
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

    def _kill_switch_allowed_endpoints(self, profile: Profile | None) -> tuple[str, ...]:
        if profile is None:
            return ()
        host = profile.config.get("host") or profile.config.get("server")
        if not isinstance(host, str) or not host.strip():
            endpoint = profile.config.get("endpoint")
            if isinstance(endpoint, str):
                host = endpoint.rsplit(":", 1)[0].strip("[]")
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
        driver = self.runtime._driver_for_profile(profile, disconnect_current=False)
        options = self.runtime._connect_options()
        options.setdefault("final_policy", final_policy)
        return driver.connect(
            profile,
            dns_policy=dns_policy,
            **options,
        )

    def disconnect(self) -> bool:
        return self.runtime.driver.disconnect()

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
