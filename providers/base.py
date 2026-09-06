from __future__ import annotations

from abc import ABC, abstractmethod

from models.profile import Profile


class BaseProvider(ABC):
    @abstractmethod
    def load_profiles(self) -> list[Profile]:
        """Return the provider profiles currently known to the system."""

    @abstractmethod
    def update(self, provider_id: str | None = None) -> bool | int:
        """Refresh provider state from its source.

        Provider implementations may use an identifier and return a
        provider-specific result, such as a boolean or change count.
        """

    @abstractmethod
    def status(self) -> dict:
        """Return provider status metadata."""
