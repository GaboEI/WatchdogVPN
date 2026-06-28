from __future__ import annotations

from abc import ABC, abstractmethod

from models.connection_state import ConnectionState
from models.profile import Profile


class BaseDriver(ABC):
    @abstractmethod
    def connect(self, profile: Profile) -> bool:
        """Connect the given profile."""

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

