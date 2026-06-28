from __future__ import annotations

from abc import ABC, abstractmethod

from models.profile import Profile


class BaseProvider(ABC):
    @abstractmethod
    def load_profiles(self) -> list[Profile]:
        """Return the provider profiles currently known to the system."""

    @abstractmethod
    def update(self) -> bool:
        """Refresh provider state from its source."""

    @abstractmethod
    def status(self) -> dict:
        """Return provider status metadata."""

