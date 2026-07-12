from __future__ import annotations

from abc import ABC, abstractmethod

from app_policy.models import AppPolicy
from dns.models import DNSPolicy
from models.connection_state import ConnectionState
from models.profile import Profile
from route_chains.runtime import ChainRuntimePlan


class BaseDriver(ABC):
    @abstractmethod
    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups=None,
        app_policy: AppPolicy | None = None,
        final_policy: str = "current_profile",
        rule_set_tags: dict[str, str] | None = None,
        rule_set_declarations: list[dict[str, str]] | None = None,
        chain_runtime_plans: dict[str, ChainRuntimePlan] | None = None,
        lan_proxy=None,
        lan_gateway=None,
        capture_modes: tuple[str, ...] | None = None,
    ) -> bool:
        """Connect the given profile.

        dns_policy, mode, groups, app_policy, final_policy, rule-set runtime
        data, LAN proxy/gateway runtime data, and capture_modes are only
        consumed by drivers that embed DNS/routing/listener behavior in
        their own runtime config (currently sing-box); other drivers accept
        and ignore them to keep a single BaseDriver contract.
        """

    @abstractmethod
    def disconnect(self) -> bool:
        """Disconnect the active profile."""

    @abstractmethod
    def health_check(self) -> str:
        """Return connection health as ok, degraded or down."""

    @abstractmethod
    def status(self) -> ConnectionState:
        """Return the current connection state."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return whether the driver dependencies are present."""


class ReentrantConnectGuard:
    """Opt-in mixin for drivers whose connect() spawns a process/interface
    into an instance field that a second connect() call would otherwise
    silently overwrite, orphaning whatever was there before (the process
    keeps running with no in-memory reference left to stop it).

    Not part of the BaseDriver ABC contract - several tests construct fake
    BaseDriver subclasses that don't own real OS resources, and forcing
    them to implement a reentrancy guard would be meaningless. Only the
    real drivers (SingBox/OpenVPN/OpenVPNCloak/AmneziaWG) mix this in.
    """

    def _has_existing_connection(self) -> bool:
        raise NotImplementedError

    def _ensure_disconnected_before_connect(self) -> None:
        if self._has_existing_connection():
            self.disconnect()
