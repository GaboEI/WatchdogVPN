from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

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


def build_pool(
    profile_store: ProfileStore,
    provider_store: ProviderStore,
    config: dict[str, Any],
) -> list[Profile]:
    cooldown_seconds = float(config.get("rotation", {}).get("health_status_cooldown_seconds", 0))
    pool: list[Profile] = []
    for profile in profile_store.list():
        if not _origin_enabled(profile, provider_store):
            continue
        if not profile.in_rotation_pool:
            continue
        if not profile.enabled:
            continue
        if _recently_failed(profile, cooldown_seconds):
            continue
        pool.append(profile)
    return pool
