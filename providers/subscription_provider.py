from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from config.profile_store import ProfileStore
from config.provider_store import DuplicateProviderError, ProviderLimitError, ProviderStore
from models.profile import Profile, ProfileSource, profile_fingerprint
from models.provider import Provider, normalized_provider_url
from parsers import ParseError, fetch_and_parse, fetch_subscription
from parsers.endpoint_policy import EndpointPolicyError, validate_profile_endpoint
from providers.base import BaseProvider

SubscriptionFetcher = Callable[[str], list[Profile]]
SubscriptionMetadataFetcher = Callable[[str], dict[str, Any]]


class ProviderNotFoundError(ValueError):
    pass


class SubscriptionProvider(BaseProvider):
    """Manage external subscription providers and their provider-owned nodes."""

    def __init__(
        self,
        provider_store: ProviderStore | None = None,
        profile_store: ProfileStore | None = None,
        fetcher: SubscriptionFetcher | None = None,
        metadata_fetcher: SubscriptionMetadataFetcher | None = None,
    ) -> None:
        self.provider_store = provider_store or ProviderStore()
        self.profile_store = profile_store or ProfileStore()
        # fetcher's Callable[[str], list[Profile]] contract is unchanged and
        # still injectable on its own (existing tests rely on this) - when a
        # caller overrides only `fetcher`, we honestly report no metadata
        # instead of fabricating traffic/expiry data from an unrelated
        # request, rather than silently making a second real HTTP call.
        self._fetcher_overridden = fetcher is not None
        self.fetcher = fetcher or fetch_and_parse
        self.metadata_fetcher = metadata_fetcher

    def _fetch(self, url: str) -> tuple[list[Profile], dict[str, Any]]:
        if not self._fetcher_overridden:
            result = fetch_subscription(url)
            if not result.profiles:
                raise ParseError("subscription contains no supported profiles")
            metadata = (
                self.metadata_fetcher(url) if self.metadata_fetcher is not None else result.metadata
            )
            return result.profiles, metadata
        profiles = self._fetch_profiles(url)
        metadata = self.metadata_fetcher(url) if self.metadata_fetcher is not None else {}
        return profiles, metadata

    def add(self, url: str, name: str) -> Provider:
        normalized_url = normalized_provider_url(url)
        duplicate = self._provider_with_url(normalized_url)
        if duplicate is not None:
            raise DuplicateProviderError(f"provider already exists: {duplicate.id}")

        provider_id = self._unique_provider_id(self._provider_base_id(name, normalized_url))
        self._enforce_provider_limit(provider_id)

        profiles, metadata = self._fetch(normalized_url)
        provider = Provider(
            id=provider_id,
            name=name or provider_id,
            url=normalized_url,
            last_updated=datetime.now(timezone.utc),
            profiles=[],
            rotation_enabled=False,
            metadata=metadata,
        )
        normalized = self._normalize_profiles(provider, profiles)
        for profile in normalized:
            self.profile_store.add(profile)
        provider.profiles = [profile.id for profile in normalized]
        self.provider_store.add(provider)
        return provider

    def _provider_with_url(self, url: str) -> Provider | None:
        normalized = normalized_provider_url(url)
        for provider in self.provider_store.list():
            if normalized_provider_url(provider.url) == normalized:
                return provider
        return None

    def update(self, provider_id: str) -> int:
        provider = self.provider_store.get(provider_id)
        if provider is None:
            raise ProviderNotFoundError(f"provider not found: {provider_id}")

        existing = {
            profile.id: profile
            for profile in self.profile_store.list()
            if profile.provider_id == provider.id
        }
        fetched, metadata = self._fetch(provider.url)
        normalized = self._normalize_profiles(
            provider,
            fetched,
            existing_profiles=list(existing.values()),
        )
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
        provider.metadata = metadata
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

    def _normalize_profiles(
        self,
        provider: Provider,
        profiles: list[Profile],
        *,
        existing_profiles: list[Profile] | None = None,
    ) -> list[Profile]:
        normalized: list[Profile] = []
        used_ids: set[str] = set()
        used_fingerprints: set[str] = set()
        existing_by_fingerprint = {
            profile_fingerprint(profile): profile.id
            for profile in existing_profiles or []
        }
        for index, profile in enumerate(profiles, start=1):
            try:
                validate_profile_endpoint(profile)
            except EndpointPolicyError as exc:
                raise ParseError(str(exc)) from exc
            fingerprint = profile_fingerprint(profile)
            if fingerprint in used_fingerprints:
                continue
            used_fingerprints.add(fingerprint)
            base_node_id = self._slug(profile.id or profile.name) or f"node-{index}"
            node_id = existing_by_fingerprint.get(fingerprint)
            if node_id is None:
                node_id = self._unique_node_id(provider.id, base_node_id, used_ids)
            else:
                used_ids.add(node_id)
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
