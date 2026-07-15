from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .models import DNSMode, DNSPolicy
from .state_manager import DNSStateSnapshot, LocalDNSEntryPoint


class KillSwitchState(Protocol):
    def is_active(self) -> bool:
        ...


class DNSHijackStateManager(Protocol):
    def apply_local_dns(
        self,
        entrypoint: LocalDNSEntryPoint,
        snapshot: DNSStateSnapshot | None = None,
    ) -> DNSStateSnapshot:
        ...

    def restore_state(self, snapshot: DNSStateSnapshot) -> None:
        ...


class DNSHijackError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DNSHijackApplyResult:
    applied: bool
    snapshot: DNSStateSnapshot | None = None
    reason: str | None = None


class DNSHijackController:
    def __init__(
        self,
        state_manager: DNSHijackStateManager,
        kill_switch: KillSwitchState | None = None,
        entrypoint: LocalDNSEntryPoint = LocalDNSEntryPoint(),
    ) -> None:
        self.state_manager = state_manager
        self.kill_switch = kill_switch
        self.entrypoint = entrypoint

    def apply(
        self,
        policy: DNSPolicy,
        snapshot: DNSStateSnapshot | None = None,
        systemd_link: str | None = None,
    ) -> DNSHijackApplyResult:
        if policy.mode == DNSMode.OFF:
            return DNSHijackApplyResult(applied=False, reason="dns policy is off")
        if not policy.tun_hijack:
            return DNSHijackApplyResult(applied=False, reason="tun hijack is disabled")

        entrypoint = LocalDNSEntryPoint(
            address=self.entrypoint.address,
            port=self.entrypoint.port,
            systemd_link=systemd_link or self.entrypoint.systemd_link,
        )
        try:
            saved = self.state_manager.apply_local_dns(entrypoint, snapshot=snapshot)
        except Exception as exc:
            if self._kill_switch_active():
                raise DNSHijackError(
                    f"dns hijack apply failed while kill switch is active; leaving traffic "
                    f"fail-closed: {exc}"
                ) from exc
            raise DNSHijackError(f"dns hijack apply failed: {exc}") from exc
        return DNSHijackApplyResult(applied=True, snapshot=saved)

    def restore(self, snapshot: DNSStateSnapshot | None) -> None:
        if snapshot is not None:
            self.state_manager.restore_state(snapshot)

    def _kill_switch_active(self) -> bool:
        if self.kill_switch is None:
            return False
        try:
            return self.kill_switch.is_active()
        except Exception:
            return False
