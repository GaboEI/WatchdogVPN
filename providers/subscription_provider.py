from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urlparse

from config.profile_store import ProfileStore
from config.provider_store import ProviderLimitError, ProviderStore
from models.profile import Profile, ProfileSource
from models.provider import Provider
from parsers import ParseError, fetch_and_parse
from providers.base import BaseProvider

SubscriptionFetcher = Callable[[str], list[Profile]]


class ProviderNotFoundError(ValueError):
    pass


class SubscriptionProvider(BaseProvider):
    """Manage external subscription providers and their provider-owned nodes."""

    def __init__(
        self,
        provider_store: ProviderStore | None = None,
        profile_store: ProfileStore | None = None,
        fetcher: SubscriptionFetcher | None = None,
    ) -> None:
        self.provider_store = provider_store or ProviderStore()
        self.profile_store = profile_store or ProfileStore()
        self.fetcher = fetcher or fetch_and_parse

    def add(self, url: str, name: str) -> Provider:
        provider_id = self._unique_provider_id(self._provider_base_id(name, url))
        self._enforce_provider_limit(provider_id)

        profiles = self._fetch_profiles(url)
        provider = Provider(
            id=provider_id,
            name=name or provider_id,
            url=url,
            last_updated=datetime.now(timezone.utc),
            profiles=[],
            rotation_enabled=False,
        )
        normalized = self._normalize_profiles(provider, profiles)
        for profile in normalized:
            self.profile_store.add(profile)
        provider.profiles = [profile.id for profile in normalized]
        self.provider_store.add(provider)
        return provider

    def update(self, provider_id: str) -> int:
        provider = self.provider_store.get(provider_id)
        if provider is None:
            raise ProviderNotFoundError(f"provider not found: {provider_id}")

        fetched = self._fetch_profiles(provider.url)
        normalized = self._normalize_profiles(provider, fetched)
        existing = {
            profile.id: profile
            for profile in self.profile_store.list()
            if profile.provider_id == provider.id
        }
        incoming = {profile.id: profile for profile in normalized}

        changes = 0
        for profile_id in sorted(set(existing) - set(incoming)):
            self.profile_store.remove(profile_id)
            changes += 1

        for profile_id, profile in incoming.items():
            current = existing.get(profile_id)
            if current is None:
                self.profile_store.add(profile)
                changes += 1
                continue
            merged = self._merge_existing_state(current, profile)
            if self._profile_payload_changed(current, merged):
                self.profile_store.update(merged)
                changes += 1

        provider.last_updated = datetime.now(timezone.utc)
        provider.profiles = [profile.id for profile in normalized]
        self.provider_store.update(provider)
        return changes

    def update_all(self) -> dict[str, int | str]:
        results: dict[str, int | str] = {}
        for provider in self.provider_store.list():
            try:
                results[provider.id] = self.update(provider.id)
            except Exception as exc:
                results[provider.id] = f"error: {exc}"
        return results

    def remove(self, provider_id: str) -> None:
        for profile in self.profile_store.list():
            if profile.provider_id == provider_id:
                self.profile_store.remove(profile.id)
        self.provider_store.remove(provider_id)

    def load_profiles(self) -> list[Profile]:
        return [
            profile
            for profile in self.profile_store.list()
            if profile.source == ProfileSource.SUBSCRIPTION
        ]

    def status(self) -> dict:
        providers = self.provider_store.list()
        return {
            "provider": "subscription",
            "providers": len(providers),
            "profiles": len(self.load_profiles()),
        }

    def _fetch_profiles(self, url: str) -> list[Profile]:
        profiles = self.fetcher(url)
        if not profiles:
            raise ParseError("subscription contains no supported profiles")
        return profiles

    def _enforce_provider_limit(self, provider_id: str) -> None:
        existing_ids = {provider.id for provider in self.provider_store.list()}
        if provider_id not in existing_ids and len(existing_ids) >= 2:
            raise ProviderLimitError("maximum 2 external providers allowed")

    def _unique_provider_id(self, value: str) -> str:
        base = self._slug(value) or "provider"
        candidate = base
        suffix = 2
        existing_ids = {provider.id for provider in self.provider_store.list()}
        while candidate in existing_ids:
            candidate = f"{base}-{suffix}"
            suffix += 1
        return candidate

    def _provider_base_id(self, name: str, url: str) -> str:
        if name.strip():
            return name
        parsed = urlparse(url)
        if parsed.hostname:
            return parsed.hostname
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
        return f"provider-{digest}"

    def _normalize_profiles(self, provider: Provider, profiles: list[Profile]) -> list[Profile]:
        normalized: list[Profile] = []
        used_ids: set[str] = set()
        for index, profile in enumerate(profiles, start=1):
            base_node_id = self._slug(profile.id or profile.name) or f"node-{index}"
            node_id = self._unique_node_id(provider.id, base_node_id, used_ids)
            profile.id = node_id
            profile.source = ProfileSource.SUBSCRIPTION
            profile.provider_id = provider.id
            profile.in_rotation_pool = True
            normalized.append(profile)
        return normalized

    def _unique_node_id(self, provider_id: str, base_node_id: str, used_ids: set[str]) -> str:
        candidate = f"{provider_id}:{base_node_id}"
        suffix = 2
        while candidate in used_ids:
            candidate = f"{provider_id}:{base_node_id}-{suffix}"
            suffix += 1
        used_ids.add(candidate)
        return candidate

    def _merge_existing_state(self, current: Profile, incoming: Profile) -> Profile:
        incoming.created_at = current.created_at
        incoming.last_used = current.last_used
        incoming.last_health_check = current.last_health_check
        incoming.health_status = current.health_status
        incoming.enabled = current.enabled
        incoming.in_rotation_pool = current.in_rotation_pool
        return incoming

    def _profile_payload_changed(self, current: Profile, incoming: Profile) -> bool:
        return (
            current.name != incoming.name
            or current.protocol != incoming.protocol
            or current.config != incoming.config
            or current.source != incoming.source
            or current.provider_id != incoming.provider_id
            or current.enabled != incoming.enabled
            or current.in_rotation_pool != incoming.in_rotation_pool
            or current.health_status != incoming.health_status
        )

    def _slug(self, value: str) -> str:
        raw = (value or "").strip().lower()
        if not raw:
            return ""
        slug = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-._")
        if slug:
            return slug[:80]
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return f"provider-{digest}"
