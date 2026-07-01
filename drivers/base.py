from __future__ import annotations

from abc import ABC, abstractmethod

from dns.models import DNSPolicy
from models.connection_state import ConnectionState
from models.profile import Profile


class BaseDriver(ABC):
    @abstractmethod
    def connect(self, profile: Profile, dns_policy: DNSPolicy | None = None) -> bool:
        """Connect the given profile.

        dns_policy is only consumed by drivers that embed DNS behavior in
        their own runtime config (currently sing-box); other drivers accept
        and ignore it to keep a single BaseDriver contract.
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

