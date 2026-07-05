from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from models.profile import Profile, ProfileSource


def _origin_enabled(profile: Profile, provider_store: ProviderStore) -> bool:
    if profile.source is ProfileSource.SUBSCRIPTION:
        provider = provider_store.get(profile.provider_id) if profile.provider_id else None
        return provider is not None and provider.rotation_enabled
    return True


def _recently_failed(profile: Profile, cooldown_seconds: float) -> bool:
    if profile.health_status != "down":
        return False
    last_check = profile.last_health_check
    if last_check is None:
        return False
    if last_check.tzinfo is None:
        last_check = last_check.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if last_check > now:
        return False
    elapsed = (now - last_check).total_seconds()
    return elapsed < cooldown_seconds


def filter_eligible_profiles(
    profiles: Iterable[Profile],
    provider_store: ProviderStore,
    config: dict[str, Any],
) -> list[Profile]:
    """Health/eligibility pass: origin-enabled, enabled, not recently failed.

    Takes any already-scoped iterable - it does not decide *which* profiles
    are in scope, only which of them are currently healthy candidates. This
    is the one reusable runtime layer node-group resolution (Phase 14) reuses
    instead of reimplementing eligibility checks: callers pick the scope
    (`in_rotation_pool` for the legacy pool, group membership for a
    NodeGroup), this function applies the same health filter to either.
    """
    cooldown_seconds = float(config.get("rotation", {}).get("health_status_cooldown_seconds", 0))
    eligible: list[Profile] = []
    for profile in profiles:
        if not _origin_enabled(profile, provider_store):
            continue
        if not profile.enabled:
            continue
        if _recently_failed(profile, cooldown_seconds):
            continue
        eligible.append(profile)
    return eligible


def build_pool(
    profile_store: ProfileStore,
    provider_store: ProviderStore,
    config: dict[str, Any],
) -> list[Profile]:
    candidates = [profile for profile in profile_store.list() if profile.in_rotation_pool]
    return filter_eligible_profiles(candidates, provider_store, config)
