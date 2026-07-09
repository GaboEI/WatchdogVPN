from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from config.app_config import AppConfig
from app_policy.models import AppPolicy
from app_policy.store import AppPolicyStore
from config.dns_policy_store import DNSPolicyStore
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.state_manager import StateManager, parse_capture_modes
from diagnostics.chain_routes import diagnose_configured_chains
from dns.models import DNSChannelName, DNSPolicy
from dns.resolver_inventory import ResolverInventory, detect_resolver_manager
from models.connection_state import ConnectionState
from models.profile import Profile
from models.provider import Provider
from network_context.monitor import (
    NetworkContextDecision,
    NetworkContextMonitor,
    NetworkObservation,
    evaluate_network_context,
)
from network_context.models import NetworkContextPolicy
from network_context.store import NetworkContextPolicyStore
from route_chains.models import RouteChainDocument
from route_chains.runtime import ChainRuntimeResolver
from route_chains.store import RouteChainStore
from rules.models import RuleGroup
from rules.rule_store import RuleStore


Runner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True, slots=True)
class RouteTableSnapshot:
    status: str
    default_routes: tuple[dict[str, Any], ...] = ()
    route_count: int = 0
    diagnostics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "default_routes": [dict(item) for item in self.default_routes],
            "route_count": self.route_count,
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True, slots=True)
class ExitIPSnapshot:
    status: str = "not_run"
    public_ip: str = "<not-observed-public-ip>"
    source: str = "not_requested"
    diagnostics: tuple[str, ...] = (
        "public exit IP probing is not run by unified diagnostics by default",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "public_ip": self.public_ip,
            "source": self.source,
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True, slots=True)
class UnifiedDiagnostics:
    schema_version: int
    generated_by: str
    support_export_ready: bool
    routing: dict[str, Any]
    capture: dict[str, Any]
    route_tables: RouteTableSnapshot
    dns: dict[str, Any]
    exit_ip: ExitIPSnapshot
    proxy: dict[str, Any]
    tun: dict[str, Any]
    lan: dict[str, Any]
    network_context: dict[str, Any]
    providers: dict[str, Any]
    recent_failures: dict[str, Any]
    diagnostics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_by": self.generated_by,
            "support_export_ready": self.support_export_ready,
            "routing": dict(self.routing),
            "capture": dict(self.capture),
            "route_tables": self.route_tables.to_dict(),
            "dns": dict(self.dns),
            "exit_ip": self.exit_ip.to_dict(),
            "proxy": dict(self.proxy),
            "tun": dict(self.tun),
            "lan": dict(self.lan),
            "network_context": dict(self.network_context),
            "providers": dict(self.providers),
            "recent_failures": dict(self.recent_failures),
            "diagnostics": list(self.diagnostics),
        }


def collect_unified_diagnostics(
    *,
    app_config: dict[str, Any] | None = None,
    routing_state: dict[str, Any] | None = None,
    dns_policy: DNSPolicy | None = None,
    resolver_inventory: ResolverInventory | None = None,
    providers: Iterable[Provider] | None = None,
    profiles: Iterable[Profile] | None = None,
    rule_groups: Iterable[RuleGroup] | None = None,
    app_policy: AppPolicy | None = None,
    chain_document: RouteChainDocument | None = None,
    chain_resolver: ChainRuntimeResolver | None = None,
    runtime_state: ConnectionState | dict[str, Any] | None = None,
    network_policy: NetworkContextPolicy | None = None,
    network_observation: NetworkObservation | None = None,
    network_decision: NetworkContextDecision | None = None,
    route_table_snapshot: RouteTableSnapshot | None = None,
    exit_ip: ExitIPSnapshot | None = None,
    recent_failure_categories: Iterable[str] | None = None,
    runner: Runner | None = None,
    which: Callable[[str], str | None] | None = None,
    resolv_conf_path: Path = Path("/etc/resolv.conf"),
) -> UnifiedDiagnostics:
    diagnostics: list[str] = []
    runner = runner or subprocess.run
    which = which or shutil.which

    if app_config is None:
        try:
            app_config = AppConfig().load()
        except Exception as exc:
            app_config = {}
            diagnostics.append(f"app config unavailable: {exc}")
    if routing_state is None:
        try:
            routing_state = StateManager().load()
        except Exception as exc:
            routing_state = {}
            diagnostics.append(f"routing state unavailable: {exc}")
    if dns_policy is None:
        try:
            dns_policy = DNSPolicyStore().load()
        except Exception as exc:
            dns_policy = DNSPolicy()
            diagnostics.append(f"dns policy unavailable: {exc}")
    if resolver_inventory is None:
        try:
            resolver_inventory = detect_resolver_manager(resolv_conf_path=resolv_conf_path)
        except Exception as exc:
            resolver_inventory = None
            diagnostics.append(f"resolver inventory unavailable: {exc}")
    if providers is None:
        try:
            providers = ProviderStore().list()
        except Exception as exc:
            providers = []
            diagnostics.append(f"provider state unavailable: {exc}")
    providers = list(providers)
    if profiles is None:
        try:
            profiles = ProfileStore().list()
        except Exception as exc:
            profiles = []
            diagnostics.append(f"profile state unavailable: {exc}")
    profiles = list(profiles)
    if rule_groups is None:
        try:
            rule_groups = RuleStore().list_groups()
        except Exception as exc:
            rule_groups = []
            diagnostics.append(f"rule groups unavailable: {exc}")
    rule_groups = list(rule_groups)
    if app_policy is None:
        try:
            app_policy = AppPolicyStore().load()
        except Exception as exc:
            app_policy = AppPolicy.disabled_due_to_error(str(exc))
            diagnostics.append(f"app policy unavailable: {exc}")
    if chain_document is None:
        try:
            chain_document = RouteChainStore().load()
        except Exception as exc:
            chain_document = RouteChainDocument()
            diagnostics.append(f"route chain state unavailable: {exc}")
    if chain_resolver is None:
        chain_resolver = ChainRuntimeResolver()
    if network_policy is None:
        try:
            network_policy = NetworkContextPolicyStore().load()
        except Exception as exc:
            network_policy = NetworkContextPolicy.disabled_due_to_error(str(exc))
            diagnostics.append(f"network context policy unavailable: {exc}")
    if network_observation is None:
        network_observation = NetworkContextMonitor(runner=runner, which=which).observe()
    if network_decision is None:
        network_decision = evaluate_network_context(network_policy, network_observation)
    if route_table_snapshot is None:
        route_table_snapshot = observe_route_tables(runner=runner, which=which)
    if exit_ip is None:
        exit_ip = ExitIPSnapshot()

    state = _runtime_state(runtime_state)
    routing = _routing_summary(routing_state)
    routing["chain_diagnostics"] = diagnose_configured_chains(
        rule_groups=rule_groups,
        app_policy=app_policy,
        routing_state=routing_state,
        chain_document=chain_document,
        dns_policy=dns_policy,
        resolver=chain_resolver,
        config=app_config,
        matched_route_action=None,
        redact=True,
    )
    capture = _capture_summary(routing, state)
    lan = _lan_summary(app_config, state)
    recent_failures = _recent_failure_summary(state, recent_failure_categories)

    return UnifiedDiagnostics(
        schema_version=1,
        generated_by="watchdogvpn-unified-diagnostics",
        support_export_ready=True,
        routing=routing,
        capture=capture,
        route_tables=route_table_snapshot,
        dns=_dns_summary(dns_policy, resolver_inventory),
        exit_ip=exit_ip,
        proxy=_proxy_summary(capture, state, app_config),
        tun=_tun_summary(capture, state, app_config),
        lan=lan,
        network_context={
            "policy": {
                "enabled": network_policy.enabled,
                "profile_count": len(network_policy.profiles),
                "triggers": {
                    trigger.value: intent.to_dict()
                    for trigger, intent in network_policy.triggers.items()
                },
            },
            "observation": network_observation.to_dict(redact=True),
            "decision": network_decision.to_dict(),
        },
        providers=_provider_summary(providers, profiles),
        recent_failures=recent_failures,
        diagnostics=tuple(diagnostics),
    )


def observe_route_tables(
    *,
    runner: Runner | None = None,
    which: Callable[[str], str | None] | None = None,
) -> RouteTableSnapshot:
    runner = runner or subprocess.run
    which = which or shutil.which
    if which("ip") is None:
        return RouteTableSnapshot(
            status="unsupported",
            diagnostics=("route table monitor unavailable: ip not found",),
        )
    try:
        result = runner(
            ["ip", "-j", "route", "show", "table", "main"],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return RouteTableSnapshot(
            status="error",
            diagnostics=(f"route table monitor failed: {exc}",),
        )
    if result.returncode != 0:
        return RouteTableSnapshot(
            status="error",
            diagnostics=("route table monitor command failed",),
        )
    try:
        routes = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return RouteTableSnapshot(
            status="error",
            diagnostics=("route table monitor returned invalid JSON",),
        )
    if not isinstance(routes, list):
        return RouteTableSnapshot(
            status="error",
            diagnostics=("route table monitor returned invalid shape",),
        )
    default_routes: list[dict[str, Any]] = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        if str(route.get("dst", "")) != "default":
            continue
        default_routes.append(
            {
                "destination": "default",
                "device": _redacted_route_value(route.get("dev"), "interface"),
                "gateway": _redacted_route_value(route.get("gateway"), "gateway"),
                "protocol": str(route.get("protocol", "")) or "unknown",
            }
        )
    return RouteTableSnapshot(
        status="observed",
        default_routes=tuple(default_routes),
        route_count=sum(1 for route in routes if isinstance(route, dict)),
    )


def _runtime_state(value: ConnectionState | dict[str, Any] | None) -> ConnectionState | None:
    if value is None:
        return None
    if isinstance(value, ConnectionState):
        return value
    return ConnectionState.from_dict(value)


def _routing_summary(state: dict[str, Any]) -> dict[str, Any]:
    capture_modes = _safe_capture_modes(str(state.get("capture_modes", "local_proxy")))
    return {
        "status": "configured" if state else "unknown",
        "routing_state_version": str(state.get("routing_state_version", "unknown")),
        "routing_policy": str(state.get("routing_policy", "unknown")),
        "default_route_action": str(state.get("default_route_action", "unknown")),
        "capture_modes": list(capture_modes),
        "active_mode": str(state.get("active_mode", "")) or None,
        "active_mode_role": "compatibility-display-only",
    }


def _safe_capture_modes(value: str) -> tuple[str, ...]:
    try:
        return parse_capture_modes(value)
    except Exception:
        return ()


def _capture_summary(
    routing: dict[str, Any],
    runtime_state: ConnectionState | None,
) -> dict[str, Any]:
    modes = tuple(str(item) for item in routing.get("capture_modes", []))
    return {
        "configured_modes": list(modes),
        "local_proxy": {
            "configured": "local_proxy" in modes,
            "runtime_status": _runtime_bool_status(
                runtime_state.proxy_active if runtime_state else None
            ),
        },
        "tun": {
            "configured": "tun" in modes,
            "runtime_status": _runtime_bool_status(
                runtime_state.tun_active if runtime_state else None
            ),
        },
        "system_proxy": {
            "configured": "system_proxy" in modes,
            "runtime_status": "representable-fail-closed"
            if "system_proxy" in modes
            else "disabled",
        },
    }


def _dns_summary(
    policy: DNSPolicy,
    resolver_inventory: ResolverInventory | None,
) -> dict[str, Any]:
    configured_channels = sorted(name.value for name in policy.channels)
    enabled_resolvers = {
        name.value: sum(1 for resolver in channel.resolvers if resolver.enabled)
        for name, channel in policy.channels.items()
    }
    return {
        "policy": {
            "mode": policy.mode.value,
            "tun_hijack": policy.tun_hijack,
            "resolve_inbound_domains": policy.resolve_inbound_domains,
            "rules_enabled": policy.rules_enabled,
            "static_ip_enabled": policy.static_ip_enabled,
            "proxy_resolution_channel": policy.proxy_resolution_channel,
            "configured_channels": configured_channels,
            "total_channels": len(DNSChannelName),
            "enabled_resolver_counts": enabled_resolvers,
        },
        "resolver_manager": (
            _resolver_inventory_summary(resolver_inventory)
            if resolver_inventory is not None
            else {
                "manager": "unknown",
                "nameservers": [],
                "notes": ["resolver inventory unavailable"],
            }
        ),
    }


def _resolver_inventory_summary(inventory: ResolverInventory) -> dict[str, object]:
    return {
        "manager": inventory.manager.value,
        "resolv_conf_path": str(inventory.resolv_conf_path),
        "resolv_conf_target": inventory.resolv_conf_target,
        "nameservers": [
            _redacted_route_value(item, "dns-server") for item in inventory.nameservers
        ],
        "search_domains": [
            _redacted_route_value(item, "dns-search-domain")
            for item in inventory.search_domains
        ],
        "nameserver_count": len(inventory.nameservers),
        "search_domain_count": len(inventory.search_domains),
        "systemd_resolved_active": inventory.systemd_resolved_active,
        "network_manager_active": inventory.network_manager_active,
        "notes": list(inventory.notes),
    }


def _proxy_summary(
    capture: dict[str, Any],
    runtime_state: ConnectionState | None,
    app_config: dict[str, Any],
) -> dict[str, Any]:
    lan_config = dict(app_config.get("lan_sharing", {}))
    return {
        "local_proxy": capture["local_proxy"],
        "system_proxy": capture["system_proxy"],
        "runtime_mode": runtime_state.mode if runtime_state else "unknown",
        "lan_proxy": {
            "configured": bool(lan_config.get("enabled", False))
            and lan_config.get("mode") == "proxy",
            "authentication_required": bool(
                lan_config.get("authentication_required", True)
            ),
            "bind_address": _redacted_config_value(
                str(lan_config.get("bind_address", "")),
                "lan-bind-address",
            ),
            "socks_port": int(lan_config.get("socks_port", 2080)),
            "http_port": int(lan_config.get("http_port", 2081)),
            "firewall_managed": bool(lan_config.get("firewall_managed", False)),
        },
    }


def _tun_summary(
    capture: dict[str, Any],
    runtime_state: ConnectionState | None,
    app_config: dict[str, Any],
) -> dict[str, Any]:
    kill_switch = dict(app_config.get("kill_switch", {}))
    return {
        "configured": capture["tun"]["configured"],
        "runtime_status": capture["tun"]["runtime_status"],
        "tunnel_interface": _redacted_config_value(
            str(kill_switch.get("tunnel_interface", "")),
            "tunnel-interface",
        ),
        "kill_switch_active": _runtime_bool_status(
            runtime_state.kill_switch_active if runtime_state else None
        ),
    }


def _lan_summary(
    app_config: dict[str, Any],
    runtime_state: ConnectionState | None,
) -> dict[str, Any]:
    lan_config = dict(app_config.get("lan_sharing", {}))
    mode = str(lan_config.get("mode", "disabled"))
    gateway_status = (
        runtime_state.lan_gateway_status if runtime_state else "unknown"
    )
    return {
        "configured": bool(lan_config.get("enabled", False)),
        "mode": mode,
        "proxy": {
            "configured": bool(lan_config.get("enabled", False)) and mode == "proxy",
            "bind_address": _redacted_config_value(
                str(lan_config.get("bind_address", "")),
                "lan-bind-address",
            ),
            "authentication_required": bool(
                lan_config.get("authentication_required", True)
            ),
        },
        "gateway": {
            "configured": bool(lan_config.get("enabled", False)) and mode == "gateway",
            "status": gateway_status,
            "active": bool(runtime_state.lan_gateway_active)
            if runtime_state
            else "unknown",
            "interface": _redacted_config_value(
                runtime_state.lan_gateway_interface
                if runtime_state and runtime_state.lan_gateway_interface
                else str(lan_config.get("gateway_interface", "")),
                "lan-gateway-interface",
            ),
            "client_cidr": str(
                runtime_state.lan_gateway_client_cidr
                if runtime_state and runtime_state.lan_gateway_client_cidr
                else lan_config.get("gateway_client_cidr", "")
            )
            or "unknown",
            "dns_mode": str(
                runtime_state.lan_gateway_dns_mode
                if runtime_state and runtime_state.lan_gateway_dns_mode
                else lan_config.get("gateway_dns_mode", "manual")
            ),
            "dns_honesty": "manual-client-dns-only",
        },
    }


def _provider_summary(providers: list[Provider], profiles: list[Profile]) -> dict[str, Any]:
    provider_items: list[dict[str, Any]] = []
    profiles_by_provider = _profiles_by_provider(profiles)
    for provider in providers:
        metadata_keys = sorted(str(key) for key in provider.metadata)
        provider_profiles = profiles_by_provider.get(provider.id, [])
        health = _provider_health_summary(provider, provider_profiles)
        quota = _provider_quota_summary(provider.metadata)
        expiry = _provider_expiry_summary(provider.metadata)
        provider_items.append(
            {
                "id": provider.id,
                "name": provider.name,
                "last_updated": provider.last_updated.isoformat()
                if provider.last_updated
                else None,
                "last_updated_status": "known" if provider.last_updated else "unknown",
                "profile_count": len(provider.profiles),
                "rotation_enabled": provider.rotation_enabled,
                "auto_update": provider.auto_update,
                "update_interval_hours": provider.update_interval_hours,
                "metadata_keys": metadata_keys,
                "metadata_value_status": "summarized" if metadata_keys else "unknown",
                "quota": quota,
                "expiry": expiry,
                "health": health,
            }
        )
    return {
        "count": len(provider_items),
        "items": provider_items,
        "url_values_included": False,
    }


def _profiles_by_provider(profiles: list[Profile]) -> dict[str, list[Profile]]:
    grouped: dict[str, list[Profile]] = {}
    for profile in profiles:
        if not profile.provider_id:
            continue
        grouped.setdefault(profile.provider_id, []).append(profile)
    return grouped


def _provider_health_summary(
    provider: Provider,
    profiles: list[Profile],
) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    enabled_count = 0
    rotation_count = 0
    last_health_check_values: list[datetime] = []
    for profile in profiles:
        status = str(profile.health_status or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        if profile.enabled:
            enabled_count += 1
        if profile.in_rotation_pool:
            rotation_count += 1
        if profile.last_health_check is not None:
            last_health_check_values.append(profile.last_health_check)
    referenced_profile_count = len(provider.profiles)
    observed_profile_count = len(profiles)
    unknown_count = max(referenced_profile_count - observed_profile_count, 0)
    if unknown_count:
        status_counts["unknown"] = status_counts.get("unknown", 0) + unknown_count
    if not status_counts and referenced_profile_count:
        status_counts["unknown"] = referenced_profile_count
    return {
        "status": _aggregate_health_status(status_counts, referenced_profile_count),
        "profile_count": referenced_profile_count,
        "observed_profile_count": observed_profile_count,
        "enabled_profile_count": enabled_count,
        "rotation_profile_count": rotation_count,
        "status_counts": dict(sorted(status_counts.items())),
        "last_health_check": (
            max(last_health_check_values).isoformat()
            if last_health_check_values
            else None
        ),
        "last_health_check_status": "known" if last_health_check_values else "unknown",
    }


def _aggregate_health_status(status_counts: dict[str, int], profile_count: int) -> str:
    if profile_count == 0:
        return "unknown"
    if any(status in status_counts for status in ("down", "degraded")):
        return "degraded"
    if status_counts.get("ok", 0) == profile_count:
        return "ok"
    return "unknown"


def _provider_quota_summary(metadata: dict[str, Any]) -> dict[str, Any]:
    used = _first_metadata_value(metadata, ("traffic_used", "used", "quota_used"))
    limit = _first_metadata_value(
        metadata,
        ("traffic_limit", "traffic_total", "total", "quota_total", "quota_limit"),
    )
    remaining = _first_metadata_value(
        metadata,
        ("traffic_remaining", "remaining", "quota_remaining"),
    )
    status = "unknown"
    if used is not None or limit is not None or remaining is not None:
        status = "reported"
    return {
        "status": status,
        "used": str(used) if used is not None else None,
        "limit": str(limit) if limit is not None else None,
        "remaining": str(remaining) if remaining is not None else None,
        "unlimited_assumed": False,
    }


def _provider_expiry_summary(metadata: dict[str, Any]) -> dict[str, Any]:
    raw_value = _first_metadata_value(
        metadata,
        ("expires_at", "expire", "expires", "expiry", "valid_until"),
    )
    if raw_value is None:
        return {
            "status": "unknown",
            "expires_at": None,
            "expired": "unknown",
        }
    parsed = _parse_provider_expiry(str(raw_value))
    if parsed is None:
        return {
            "status": "reported-unparsed",
            "expires_at": str(raw_value),
            "expired": "unknown",
        }
    now = datetime.now(timezone.utc)
    return {
        "status": "known",
        "expires_at": parsed.isoformat(),
        "expired": parsed < now,
    }


def _first_metadata_value(metadata: dict[str, Any], keys: tuple[str, ...]) -> Any | None:
    for key in keys:
        value = metadata.get(key)
        if value not in (None, ""):
            return value
    return None


def _parse_provider_expiry(value: str) -> datetime | None:
    normalized = value.strip()
    if not normalized:
        return None
    try:
        if normalized.isdigit():
            number = int(normalized)
            if number > 10_000_000_000:
                number //= 1000
            return datetime.fromtimestamp(number, tz=timezone.utc)
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        try:
            parsed_date = date.fromisoformat(normalized)
        except ValueError:
            return None
        return datetime.combine(parsed_date, datetime.max.time(), tzinfo=timezone.utc)


def _recent_failure_summary(
    runtime_state: ConnectionState | None,
    categories: Iterable[str] | None,
) -> dict[str, Any]:
    normalized = [str(item) for item in (categories or []) if str(item)]
    if runtime_state and runtime_state.status in {
        "all_failed",
        "kill_switch_active",
        "rotation_unavailable",
        "waiting_retry",
        "reconnecting",
    }:
        normalized.append(f"runtime_status:{runtime_state.status}")
    return {
        "status": "observed" if normalized else "none",
        "categories": sorted(set(normalized)),
        "raw_events_included": False,
    }


def _runtime_bool_status(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "active" if value else "inactive"


def _redacted_route_value(value: object, label: str) -> str:
    text = str(value or "").strip()
    return f"<redacted-{label}>" if text else f"<not-observed-{label}>"


def _redacted_config_value(value: str, label: str) -> str:
    text = value.strip()
    return f"<redacted-{label}>" if text else f"<not-configured-{label}>"
