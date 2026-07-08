from __future__ import annotations

from abc import ABC, abstractmethod

from app_policy.models import AppPolicy
from dns.models import DNSPolicy
from models.connection_state import ConnectionState
from models.profile import Profile


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
        lan_proxy=None,
        lan_gateway=None,
    ) -> bool:
        """Connect the given profile.

        dns_policy, mode, groups, app_policy, final_policy, rule-set runtime
        data, and LAN proxy/gateway runtime data are only consumed by drivers that
        embed DNS/routing/listener behavior in their own runtime config
        (currently sing-box); other drivers accept and ignore them to keep a
        single BaseDriver contract.
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
