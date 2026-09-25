from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


ALLOWED_STATUSES = {
    "connected",
    "reconnecting",
    "all_failed",
    "normal_network_temp",
    "kill_switch_active",
    "kill_switch_failed",
    "kill_switch_disable_failed",
    "dns_restore_failed",
    "waiting_retry",
    "rotation_unavailable",
    "recovery_disabled",
    "recovered",
    "standby",
    # Read-only reconciliation found owned OS state that disagrees with the
    # driver's in-memory state: a process, proxy listener, interface, route,
    # nftables state, or a partial kill-switch ruleset. Deliberately distinct
    # from "standby": status() reports evidence but never mutates it; explicit
    # disconnect owns cleanup.
    "runtime_mismatch",
    "unsupported_policy",
    "cleanup_failed",
}

# Terminal/exhausted outcomes - a caller (CLI exit code, status surfacing)
# should treat these as "not a healthy result", distinct from in-progress
# states like "reconnecting" that represent recovery still actively
# happening. Single source of truth shared by cli/main.py and
# daemon/runtime_worker.py so the two layers can't silently drift apart.
FAILURE_STATUSES = frozenset(
    {
        "all_failed",
        "kill_switch_active",
        "kill_switch_failed",
        "kill_switch_disable_failed",
        "dns_restore_failed",
        "normal_network_temp",
        "rotation_unavailable",
        "recovery_disabled",
        "waiting_retry",
        "runtime_mismatch",
        "unsupported_policy",
        "cleanup_failed",
    }
)


def _dt_to_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _dt_from_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item) for item in value)


@dataclass(slots=True)
class ConnectionState:
    active_profile_id: str = ""
    connected_at: datetime | None = None
    mode: str = "standby"
    tun_active: bool = False
    proxy_active: bool = False
    kill_switch_active: bool = False
    kill_switch_status: str = "inactive"
    kill_switch_method: str = ""
    kill_switch_consistent: bool = True
    runtime_mismatch_severity: str = ""
    runtime_artifacts: tuple[str, ...] = ()
    lan_gateway_active: bool = False
    lan_gateway_interface: str = ""
    lan_gateway_client_cidr: str = ""
    lan_gateway_dns_mode: str = ""
    lan_gateway_status: str = "disabled"
    status: str = "standby"
    last_failure_reason: str = ""
    last_failure_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.status not in ALLOWED_STATUSES:
            raise ValueError(f"invalid status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["connected_at"] = _dt_to_iso(self.connected_at)
        data["last_failure_at"] = _dt_to_iso(self.last_failure_at)
        data["runtime_artifacts"] = list(self.runtime_artifacts)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConnectionState":
        return cls(
            active_profile_id=str(data.get("active_profile_id", "")),
            connected_at=_dt_from_iso(data.get("connected_at")),
            mode=str(data.get("mode", "standby")),
            tun_active=bool(data.get("tun_active", False)),
            proxy_active=bool(data.get("proxy_active", False)),
            kill_switch_active=bool(data.get("kill_switch_active", False)),
            kill_switch_status=str(data.get("kill_switch_status", "inactive")),
            kill_switch_method=str(data.get("kill_switch_method", "")),
            kill_switch_consistent=bool(data.get("kill_switch_consistent", True)),
            runtime_mismatch_severity=str(data.get("runtime_mismatch_severity", "")),
            runtime_artifacts=_string_tuple(data.get("runtime_artifacts", ())),
            lan_gateway_active=bool(data.get("lan_gateway_active", False)),
            lan_gateway_interface=str(data.get("lan_gateway_interface", "")),
            lan_gateway_client_cidr=str(data.get("lan_gateway_client_cidr", "")),
            lan_gateway_dns_mode=str(data.get("lan_gateway_dns_mode", "")),
            lan_gateway_status=str(data.get("lan_gateway_status", "disabled")),
            status=str(data.get("status", "standby")),
            last_failure_reason=str(data.get("last_failure_reason", "")),
            last_failure_at=_dt_from_iso(data.get("last_failure_at")),
        )
