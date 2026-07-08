from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable

from .models import (
    ActionIntent,
    NetworkContextPolicy,
    NetworkContextTrigger,
    NetworkMatchKind,
    NetworkPolicyAction,
    NetworkProfile,
    NetworkTrust,
)


Runner = Callable[..., subprocess.CompletedProcess[str]]


class MonitorStatus(str, Enum):
    OBSERVED = "observed"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class ConnectivityState(str, Enum):
    ONLINE = "online"
    LIMITED = "limited"
    CAPTIVE_PORTAL = "captive_portal"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class ProfileMatchStatus(str, Enum):
    MATCHED = "matched"
    NO_MATCH = "no_match"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class ActiveNetwork:
    source: str
    interface_name: str = ""
    interface_type: str = ""
    ssid: str = ""
    bssid: str = ""
    gateway_identifier: str = ""

    def hashed_values(self) -> dict[NetworkMatchKind, str]:
        values: dict[NetworkMatchKind, str] = {}
        if self.ssid:
            values[NetworkMatchKind.SSID_SHA256] = _sha256(self.ssid)
        if self.bssid:
            values[NetworkMatchKind.BSSID_SHA256] = _sha256(self.bssid)
        if self.interface_name:
            values[NetworkMatchKind.INTERFACE_NAME_SHA256] = _sha256(self.interface_name)
        if self.gateway_identifier:
            values[NetworkMatchKind.GATEWAY_IDENTIFIER_SHA256] = _sha256(
                self.gateway_identifier
            )
        return values

    def raw_values(self) -> dict[NetworkMatchKind, str]:
        values: dict[NetworkMatchKind, str] = {}
        if self.ssid:
            values[NetworkMatchKind.RAW_SSID] = self.ssid
        if self.bssid:
            values[NetworkMatchKind.RAW_BSSID] = self.bssid
        if self.interface_name:
            values[NetworkMatchKind.RAW_INTERFACE_NAME] = self.interface_name
        if self.gateway_identifier:
            values[NetworkMatchKind.RAW_GATEWAY_IDENTIFIER] = self.gateway_identifier
        return values

    def to_dict(self, *, redact: bool = True) -> dict[str, str]:
        if redact:
            return {
                "source": self.source,
                "interface_name": _redacted_marker(self.interface_name, "interface"),
                "interface_type": self.interface_type,
                "ssid": _redacted_marker(self.ssid, "ssid"),
                "bssid": _redacted_marker(self.bssid, "bssid"),
                "gateway_identifier": _redacted_marker(
                    self.gateway_identifier,
                    "gateway",
                ),
            }
        return {
            "source": self.source,
            "interface_name": self.interface_name,
            "interface_type": self.interface_type,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "gateway_identifier": self.gateway_identifier,
        }


@dataclass(frozen=True, slots=True)
class NetworkObservation:
    status: MonitorStatus
    connectivity: ConnectivityState = ConnectivityState.UNKNOWN
    active_networks: tuple[ActiveNetwork, ...] = ()
    default_route_interfaces: tuple[str, ...] = ()
    interface_changed: bool = False
    default_route_changed: bool = False
    diagnostics: tuple[str, ...] = ()

    def is_supported(self) -> bool:
        return self.status in {MonitorStatus.OBSERVED, MonitorStatus.PARTIAL}

    def to_dict(self, *, redact: bool = True) -> dict[str, Any]:
        default_routes: list[str]
        if redact:
            default_routes = [
                _redacted_marker(item, "interface")
                for item in self.default_route_interfaces
            ]
        else:
            default_routes = list(self.default_route_interfaces)
        return {
            "status": self.status.value,
            "connectivity": self.connectivity.value,
            "active_networks": [
                item.to_dict(redact=redact) for item in self.active_networks
            ],
            "default_route_interfaces": default_routes,
            "interface_changed": self.interface_changed,
            "default_route_changed": self.default_route_changed,
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True, slots=True)
class MatchedProfile:
    profile_id: str
    trust: NetworkTrust
    matched_kinds: tuple[NetworkMatchKind, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "trust": self.trust.value,
            "matched_kinds": [item.value for item in self.matched_kinds],
        }


@dataclass(frozen=True, slots=True)
class NetworkContextDecision:
    status: ProfileMatchStatus
    trigger: NetworkContextTrigger | None
    intent: ActionIntent
    matched_profiles: tuple[MatchedProfile, ...] = ()
    diagnostics: tuple[str, ...] = ()

    @property
    def action(self) -> NetworkPolicyAction:
        return self.intent.action

    @property
    def enabled(self) -> bool:
        return self.intent.enabled

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "trigger": self.trigger.value if self.trigger else None,
            "intent": self.intent.to_dict(),
            "matched_profiles": [item.to_dict() for item in self.matched_profiles],
            "diagnostics": list(self.diagnostics),
            "runtime_action_executed": False,
        }


class NetworkContextMonitor:
    def __init__(
        self,
        *,
        runner: Runner | None = None,
        which: Callable[[str], str | None] | None = None,
    ) -> None:
        self.runner = runner or subprocess.run
        self.which = which or shutil.which

    def observe(self, previous: NetworkObservation | None = None) -> NetworkObservation:
        diagnostics: list[str] = []
        if self.which("nmcli") is None and self.which("ip") is None:
            return NetworkObservation(
                status=MonitorStatus.UNSUPPORTED,
                diagnostics=("network monitor unavailable: nmcli and ip not found",),
            )

        networks: list[ActiveNetwork] = []
        connectivity = ConnectivityState.UNKNOWN
        status = MonitorStatus.OBSERVED

        if self.which("nmcli") is None:
            diagnostics.append("NetworkManager monitor unavailable: nmcli not found")
            status = MonitorStatus.PARTIAL
        else:
            nm_observation = self._observe_network_manager()
            networks.extend(nm_observation.active_networks)
            connectivity = nm_observation.connectivity
            diagnostics.extend(nm_observation.diagnostics)
            if nm_observation.status != MonitorStatus.OBSERVED:
                status = MonitorStatus.PARTIAL

        default_routes: tuple[str, ...] = ()
        if self.which("ip") is None:
            diagnostics.append("route monitor unavailable: ip not found")
            status = MonitorStatus.PARTIAL
        else:
            route_observation = self._observe_default_routes()
            default_routes = route_observation.default_route_interfaces
            diagnostics.extend(route_observation.diagnostics)
            if route_observation.status != MonitorStatus.OBSERVED:
                status = MonitorStatus.PARTIAL

        interface_changed = False
        default_route_changed = False
        if previous is not None:
            interface_changed = _interface_fingerprint(networks) != _interface_fingerprint(
                previous.active_networks
            )
            default_route_changed = tuple(default_routes) != tuple(
                previous.default_route_interfaces
            )

        if status == MonitorStatus.OBSERVED and not networks and not default_routes:
            status = MonitorStatus.PARTIAL
            diagnostics.append("network monitor observed no active networks or default routes")

        return NetworkObservation(
            status=status,
            connectivity=connectivity,
            active_networks=tuple(networks),
            default_route_interfaces=default_routes,
            interface_changed=interface_changed,
            default_route_changed=default_route_changed,
            diagnostics=tuple(diagnostics),
        )

    def _observe_network_manager(self) -> NetworkObservation:
        diagnostics: list[str] = []
        connectivity = ConnectivityState.UNKNOWN
        networks: list[ActiveNetwork] = []
        try:
            connectivity_result = self.runner(
                ["nmcli", "-t", "-f", "CONNECTIVITY", "general"],
                text=True,
                capture_output=True,
                check=False,
                timeout=2,
            )
            connection_result = self.runner(
                ["nmcli", "-t", "-f", "NAME,TYPE,DEVICE,STATE", "connection", "show", "--active"],
                text=True,
                capture_output=True,
                check=False,
                timeout=2,
            )
            wifi_result = self.runner(
                ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,DEVICE", "dev", "wifi"],
                text=True,
                capture_output=True,
                check=False,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return NetworkObservation(
                status=MonitorStatus.ERROR,
                diagnostics=(f"NetworkManager monitor failed: {exc}",),
            )

        if connectivity_result.returncode != 0:
            diagnostics.append("NetworkManager connectivity state unavailable")
        else:
            connectivity = _parse_nm_connectivity(connectivity_result.stdout)

        if connection_result.returncode != 0:
            diagnostics.append("NetworkManager active connections unavailable")
        else:
            networks.extend(_parse_nm_active_connections(connection_result.stdout))

        if wifi_result.returncode != 0:
            diagnostics.append("NetworkManager Wi-Fi identifiers unavailable")
        else:
            networks = _merge_wifi_identifiers(networks, wifi_result.stdout)

        status = MonitorStatus.OBSERVED
        if diagnostics:
            status = MonitorStatus.PARTIAL
        return NetworkObservation(
            status=status,
            connectivity=connectivity,
            active_networks=tuple(networks),
            diagnostics=tuple(diagnostics),
        )

    def _observe_default_routes(self) -> NetworkObservation:
        try:
            result = self.runner(
                ["ip", "-j", "route", "show", "default"],
                text=True,
                capture_output=True,
                check=False,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return NetworkObservation(
                status=MonitorStatus.ERROR,
                diagnostics=(f"default route monitor failed: {exc}",),
            )
        if result.returncode != 0:
            return NetworkObservation(
                status=MonitorStatus.ERROR,
                diagnostics=("default route monitor command failed",),
            )
        try:
            routes = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return NetworkObservation(
                status=MonitorStatus.ERROR,
                diagnostics=("default route monitor returned invalid JSON",),
            )
        if not isinstance(routes, list):
            return NetworkObservation(
                status=MonitorStatus.ERROR,
                diagnostics=("default route monitor returned invalid shape",),
            )
        interfaces: list[str] = []
        for route in routes:
            if not isinstance(route, dict):
                continue
            dev = route.get("dev")
            if isinstance(dev, str) and dev and dev not in interfaces:
                interfaces.append(dev)
        return NetworkObservation(
            status=MonitorStatus.OBSERVED,
            default_route_interfaces=tuple(interfaces),
        )


def evaluate_network_context(
    policy: NetworkContextPolicy,
    observation: NetworkObservation,
) -> NetworkContextDecision:
    diagnostics = list(observation.diagnostics)
    if not policy.enabled:
        diagnostics.append("network context policy disabled; manual mode")
        return _manual_decision(ProfileMatchStatus.UNSUPPORTED, diagnostics)
    if not observation.is_supported():
        diagnostics.append("network monitor unsupported; manual mode")
        return _manual_decision(ProfileMatchStatus.UNSUPPORTED, diagnostics)

    matched_profiles = _match_profiles(policy.profiles, observation.active_networks)
    trigger = _select_trigger(observation, matched_profiles)
    if trigger is None:
        diagnostics.append("no network context trigger matched; manual mode")
        return NetworkContextDecision(
            status=ProfileMatchStatus.NO_MATCH,
            trigger=None,
            intent=ActionIntent(),
            matched_profiles=tuple(matched_profiles),
            diagnostics=tuple(diagnostics),
        )

    intent = policy.triggers[trigger]
    if not intent.enabled:
        diagnostics.append(f"{trigger.value} intent disabled; no runtime action")
    else:
        diagnostics.append(
            f"{trigger.value} intent modeled only; no runtime action executed"
        )
    return NetworkContextDecision(
        status=ProfileMatchStatus.MATCHED,
        trigger=trigger,
        intent=intent,
        matched_profiles=tuple(matched_profiles),
        diagnostics=tuple(diagnostics),
    )


def _manual_decision(
    status: ProfileMatchStatus,
    diagnostics: Iterable[str],
) -> NetworkContextDecision:
    return NetworkContextDecision(
        status=status,
        trigger=None,
        intent=ActionIntent(),
        diagnostics=tuple(diagnostics),
    )


def _match_profiles(
    profiles: Iterable[NetworkProfile],
    networks: Iterable[ActiveNetwork],
) -> list[MatchedProfile]:
    matched: list[MatchedProfile] = []
    for profile in profiles:
        if not profile.enabled:
            continue
        matched_kinds: list[NetworkMatchKind] = []
        for match in profile.matches:
            if _match_network(match.kind, match.value, networks):
                matched_kinds.append(match.kind)
        if matched_kinds:
            matched.append(
                MatchedProfile(
                    profile_id=profile.id,
                    trust=profile.trust,
                    matched_kinds=tuple(matched_kinds),
                )
            )
    return matched


def _match_network(
    kind: NetworkMatchKind,
    value: str,
    networks: Iterable[ActiveNetwork],
) -> bool:
    for network in networks:
        if kind == NetworkMatchKind.INTERFACE_TYPE and network.interface_type == value:
            return True
        if kind == NetworkMatchKind.PROFILE_TAG:
            continue
        if kind in network.hashed_values() and network.hashed_values()[kind] == value.lower():
            return True
        if kind in network.raw_values() and network.raw_values()[kind] == value:
            return True
    return False


def _select_trigger(
    observation: NetworkObservation,
    matched_profiles: Iterable[MatchedProfile],
) -> NetworkContextTrigger | None:
    if observation.connectivity == ConnectivityState.OFFLINE:
        return NetworkContextTrigger.OFFLINE
    if observation.connectivity == ConnectivityState.CAPTIVE_PORTAL:
        return NetworkContextTrigger.CAPTIVE_PORTAL
    if observation.interface_changed or observation.default_route_changed:
        return NetworkContextTrigger.INTERFACE_CHANGED
    profiles = list(matched_profiles)
    if any(profile.trust == NetworkTrust.UNTRUSTED for profile in profiles):
        return NetworkContextTrigger.UNTRUSTED_NETWORK
    if any(profile.trust == NetworkTrust.TRUSTED for profile in profiles):
        return NetworkContextTrigger.TRUSTED_NETWORK
    return None


def _parse_nm_connectivity(output: str) -> ConnectivityState:
    value = output.strip().lower()
    if value == "full":
        return ConnectivityState.ONLINE
    if value == "portal":
        return ConnectivityState.CAPTIVE_PORTAL
    if value == "limited":
        return ConnectivityState.LIMITED
    if value == "none":
        return ConnectivityState.OFFLINE
    return ConnectivityState.UNKNOWN


def _parse_nm_active_connections(output: str) -> list[ActiveNetwork]:
    networks: list[ActiveNetwork] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        name, conn_type, device, state = _split_nm_line(line, 4)
        if state and state.lower() not in {"activated", "activating"}:
            continue
        networks.append(
            ActiveNetwork(
                source="networkmanager",
                interface_name=device,
                interface_type=_normalize_interface_type(conn_type),
                ssid=name if _normalize_interface_type(conn_type) == "wifi" else "",
            )
        )
    return networks


def _merge_wifi_identifiers(
    networks: list[ActiveNetwork],
    output: str,
) -> list[ActiveNetwork]:
    wifi_by_device: dict[str, tuple[str, str]] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        active, ssid, bssid, device = _split_nm_line(line, 4)
        if active.lower() in {"yes", "y", "true", "*"} and device:
            wifi_by_device[device] = (ssid, bssid)
    merged: list[ActiveNetwork] = []
    for network in networks:
        ssid, bssid = wifi_by_device.get(network.interface_name, ("", ""))
        merged.append(
            ActiveNetwork(
                source=network.source,
                interface_name=network.interface_name,
                interface_type=network.interface_type,
                ssid=ssid or network.ssid,
                bssid=bssid,
                gateway_identifier=network.gateway_identifier,
            )
        )
    return merged


def _split_nm_line(line: str, expected: int) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == ":" and len(parts) < expected - 1:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    if escaped:
        current.append("\\")
    parts.append("".join(current))
    if len(parts) < expected:
        parts.extend([""] * (expected - len(parts)))
    return [part.strip() for part in parts]


def _normalize_interface_type(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"802-11-wireless", "wifi", "wireless"}:
        return "wifi"
    if normalized in {"802-3-ethernet", "ethernet", "wired"}:
        return "ethernet"
    if normalized in {"tun", "tunnel"}:
        return "tun"
    return normalized or "unknown"


def _interface_fingerprint(networks: Iterable[ActiveNetwork]) -> tuple[str, ...]:
    return tuple(
        sorted(
            f"{network.interface_type}:{_sha256(network.interface_name)}"
            for network in networks
            if network.interface_name or network.interface_type
        )
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _redacted_marker(value: str, label: str) -> str:
    return f"<redacted-{label}>" if value else f"<not-observed-{label}>"
