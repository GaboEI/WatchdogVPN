from __future__ import annotations

from abc import ABC, abstractmethod

from app_policy.models import AppPolicy
from dns.models import DNSPolicy
from models.connection_state import ConnectionState
from models.profile import Profile
from route_chains.runtime import ChainRuntimePlan


DRIVER_POLICY_CAPABILITIES = frozenset({
    "dns",
    "routing",
    "app_policy",
    "chains",
    "lan_proxy",
    "lan_gateway",
    "capture",
})


class UnsupportedDriverPolicyError(RuntimeError):
    """Raised before runtime mutation when a driver cannot enforce policy."""

    def __init__(self, driver_name: str, unsupported_capabilities: frozenset[str]) -> None:
        self.driver_name = driver_name
        self.unsupported_capabilities = tuple(sorted(unsupported_capabilities))
        supported = ", ".join(self.unsupported_capabilities)
        super().__init__(
            f"driver {driver_name} cannot enforce requested WatchdogVPN policy: {supported}"
        )



class ManagementPathSafetyError(RuntimeError):
    """Raised before connection mutation when a live control path is unsafe."""


class BaseDriver(ABC):
    # Every driver must explicitly declare the WatchdogVPN policy it can
    # enforce at runtime. An empty set is deliberate fail-closed behavior.
    policy_capabilities: frozenset[str] = frozenset()

    def unsupported_policy_capabilities(
        self, requested_capabilities: frozenset[str]
    ) -> frozenset[str]:
        return requested_capabilities - self.policy_capabilities

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

        The shared parameters preserve one driver interface. Runtime policy
        preflight rejects a connection before this method is reached unless
        the selected driver declares every requested capability; drivers must
        therefore never silently ignore a requested WatchdogVPN policy.
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
