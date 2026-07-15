from __future__ import annotations

import hashlib
import re
from contextlib import ExitStack
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from config.profile_store import ProfileStore
from config.provider_store import DuplicateProviderError, ProviderLimitError, ProviderStore
from config.persistence import atomic_write_bytes, file_lock
from models.profile import Profile, ProfileSource, profile_fingerprint
from models.provider import Provider, normalized_provider_url
from parsers import ParseError, fetch_and_parse, fetch_subscription
from parsers.endpoint_policy import EndpointPolicyError, validate_profile_endpoint
from parsers.openvpn_safety import validate_openvpn_profile
from parsers.profile_schema import ProfileSemanticValidationError, validate_profile_semantics
from providers.base import BaseProvider

SubscriptionFetcher = Callable[[str], list[Profile]]
SubscriptionMetadataFetcher = Callable[[str], dict[str, Any]]


class ProviderNotFoundError(ValueError):
    pass


class ProviderProfileTransactionError(RuntimeError):
    """Raised only when a failed provider/profile commit cannot be rolled back."""


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
        profiles, metadata = self._fetch(normalized_url)

        def commit(current_providers: list[Provider], current_profiles: list[Profile]) -> tuple[
            list[Provider], list[Profile], Provider
        ]:
            duplicate = self._provider_with_url_from(current_providers, normalized_url)
            if duplicate is not None:
                raise DuplicateProviderError(f"provider already exists: {duplicate.id}")
            provider_id = self._unique_provider_id_from(
                current_providers, self._provider_base_id(name, normalized_url)
            )
            self._enforce_provider_limit_from(current_providers, provider_id)
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
            replacement_providers = [*current_providers, provider]
            replacement_profiles = [*current_profiles, *normalized]
            provider.profiles = self._owned_profile_ids_by_provider(
                replacement_providers, replacement_profiles
            )[provider.id]
            return replacement_providers, replacement_profiles, provider

        return self._commit_provider_profile_transaction(commit)

    def _provider_with_url(self, url: str) -> Provider | None:
        return self._provider_with_url_from(self.provider_store.list(), url)

    def _provider_with_url_from(self, providers: list[Provider], url: str) -> Provider | None:
        normalized = normalized_provider_url(url)
        for provider in providers:
            if normalized_provider_url(provider.url) == normalized:
                return provider
        return None

    def update(self, provider_id: str) -> int:
        provider = self.provider_store.get(provider_id)
        if provider is None:
            raise ProviderNotFoundError(f"provider not found: {provider_id}")
        fetched, metadata = self._fetch(provider.url)

        def commit(current_providers: list[Provider], current_profiles: list[Profile]) -> tuple[
            list[Provider], list[Profile], int
        ]:
            current_provider = next(
                (candidate for candidate in current_providers if candidate.id == provider_id), None
            )
            if current_provider is None:
                raise ProviderNotFoundError(f"provider not found: {provider_id}")
            existing = {
                profile.id: profile
                for profile in current_profiles
                if profile.provider_id == current_provider.id
            }
            normalized = self._normalize_profiles(
                current_provider,
                fetched,
                existing_profiles=list(existing.values()),
            )
            unowned_profiles = [
                current for current in current_profiles if current.provider_id != current_provider.id
            ]
            merged_owned_profiles: list[Profile] = []
            changes = 0
            for profile in normalized:
                current = existing.get(profile.id)
                if current is None:
                    merged_owned_profiles.append(profile)
                    changes += 1
                    continue
                merged = self._merge_existing_state(current, profile)
                if self._profile_payload_changed(current, merged):
                    changes += 1
                merged_owned_profiles.append(merged)
            changes += len(set(existing) - {profile.id for profile in normalized})

            replacement_profiles = [*unowned_profiles, *merged_owned_profiles]
            current_provider.last_updated = datetime.now(timezone.utc)
            # A refresh is an exact replacement of this provider's current
            # subscription payload. Derive its references from the same final
            # profile list that will be transactionally published.
            current_provider.profiles = self._owned_profile_ids_by_provider(
                current_providers, replacement_profiles
            )[current_provider.id]
            current_provider.metadata = metadata
            return current_providers, replacement_profiles, changes

        return self._commit_provider_profile_transaction(commit)

    def update_all(self) -> dict[str, int | str]:
        results: dict[str, int | str] = {}
        for provider in self.provider_store.list():
            try:
                results[provider.id] = self.update(provider.id)
            except Exception as exc:
                results[provider.id] = f"error: {exc}"
        return results

    def remove(self, provider_id: str) -> None:
        def commit(current_providers: list[Provider], current_profiles: list[Profile]) -> tuple[
            list[Provider], list[Profile], None
        ]:
            return (
                [provider for provider in current_providers if provider.id != provider_id],
                [profile for profile in current_profiles if profile.provider_id != provider_id],
                None,
            )

        self._commit_provider_profile_transaction(commit)

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
        self._enforce_provider_limit_from(self.provider_store.list(), provider_id)

    def _enforce_provider_limit_from(self, providers: list[Provider], provider_id: str) -> None:
        existing_ids = {provider.id for provider in providers}
        if provider_id not in existing_ids and len(existing_ids) >= 2:
            raise ProviderLimitError("maximum 2 external providers allowed")

    def _unique_provider_id(self, value: str) -> str:
        return self._unique_provider_id_from(self.provider_store.list(), value)

    def _unique_provider_id_from(self, providers: list[Provider], value: str) -> str:
        base = self._slug(value) or "provider"
        candidate = base
        suffix = 2
        existing_ids = {provider.id for provider in providers}
        while candidate in existing_ids:
            candidate = f"{base}-{suffix}"
            suffix += 1
        return candidate

    def _commit_provider_profile_transaction(
        self,
        transform: Callable[
            [list[Provider], list[Profile]], tuple[list[Provider], list[Profile], Any]
        ],
    ) -> Any:
        """Publish provider metadata and its owned profiles as one unit.

        The two JSON documents cannot be replaced by one filesystem operation,
        so both store locks stay held through validation, publication, and a
        byte-exact compensation rollback if either write fails. All ordinary
        readers use the same locks and therefore never observe the transient
        first write.
        """
        provider_path = self.provider_store.path
        profile_path = self.profile_store.path
        ordered_paths = sorted((provider_path, profile_path), key=lambda path: str(path.resolve()))
        with ExitStack() as stack:
            for path in ordered_paths:
                stack.enter_context(file_lock(path))
            providers = [Provider.from_dict(item) for item in self.provider_store._load_raw()]
            profiles = [Profile.from_dict(item) for item in self.profile_store._load_raw()]
            replacement_providers, replacement_profiles, result = transform(providers, profiles)
            self._validate_transaction_replacement(replacement_providers, replacement_profiles)
            provider_before = self._snapshot_bytes(provider_path)
            profile_before = self._snapshot_bytes(profile_path)
            try:
                self.provider_store._save_raw([provider.to_dict() for provider in replacement_providers])
                self.profile_store._save_raw([profile.to_dict() for profile in replacement_profiles])
            except Exception as exc:
                rollback_errors = self._restore_transaction_snapshots(
                    provider_path,
                    provider_before,
                    profile_path,
                    profile_before,
                )
                if rollback_errors:
                    detail = "; ".join(str(error) for error in rollback_errors)
                    raise ProviderProfileTransactionError(
                        f"provider/profile transaction failed and rollback was incomplete: {detail}"
                    ) from exc
                raise
            return result

    def _validate_transaction_replacement(
        self, providers: list[Provider], profiles: list[Profile]
    ) -> None:
        provider_ids = [provider.id for provider in providers]
        if len(provider_ids) != len(set(provider_ids)):
            raise ValueError("provider transaction contains duplicate provider identifiers")
        if len(providers) > 2:
            raise ProviderLimitError("maximum 2 external providers allowed")
        normalized_urls = [normalized_provider_url(provider.url) for provider in providers]
        if len(normalized_urls) != len(set(normalized_urls)):
            raise DuplicateProviderError("provider transaction contains duplicate subscription URLs")
        profile_ids = [profile.id for profile in profiles]
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("provider transaction contains duplicate profile identifiers")
        for profile in profiles:
            validate_openvpn_profile(profile)
        owned_profile_ids = self._owned_profile_ids_by_provider(providers, profiles)
        for provider in providers:
            if (
                len(provider.profiles) != len(set(provider.profiles))
                or set(provider.profiles) != set(owned_profile_ids[provider.id])
            ):
                raise ValueError("provider profile membership does not match owned profiles")

    def _owned_profile_ids_by_provider(
        self, providers: list[Provider], profiles: list[Profile]
    ) -> dict[str, list[str]]:
        """Derive provider ownership from the final profile replacement.

        provider_id is the persisted ownership edge. New subscription profiles
        always have source=subscription, but older installations can contain
        provider-owned profiles created before that source marker was enforced.
        Treating only the marker as ownership lets such a historical record
        block unrelated provider refreshes.
        """
        owned_profile_ids: dict[str, list[str]] = {provider.id: [] for provider in providers}
        for profile in profiles:
            if profile.source is ProfileSource.SUBSCRIPTION and not profile.provider_id:
                raise ValueError("subscription profile has no matching provider")
            if not profile.provider_id:
                continue
            if profile.provider_id not in owned_profile_ids:
                raise ValueError("profile has no matching provider")
            owned_profile_ids[profile.provider_id].append(profile.id)
        return owned_profile_ids

    def _snapshot_bytes(self, path: Path) -> bytes | None:
        return path.read_bytes() if path.exists() else None

    def _restore_transaction_snapshots(
        self,
        provider_path: Path,
        provider_before: bytes | None,
        profile_path: Path,
        profile_before: bytes | None,
    ) -> list[OSError]:
        errors: list[OSError] = []
        for path, snapshot in ((provider_path, provider_before), (profile_path, profile_before)):
            try:
                if snapshot is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write_bytes(path, snapshot)
            except OSError as exc:
                errors.append(exc)
        return errors

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
            try:
                validate_profile_semantics(profile)
            except ProfileSemanticValidationError as exc:
                raise ParseError(str(exc)) from exc
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
