from __future__ import annotations

from typing import Any

from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from models.profile import Profile, ResilienceCategory, profile_resilience_category
from node_groups.models import NodeGroup, NodeGroupResiliencePolicy
from rotation import pool_builder


def _resolve_membership(group: NodeGroup, profile_store: ProfileStore) -> list[Profile]:
    """Included profiles, minus excluded ones - exclusion always wins.

    A profile reachable only via member_provider_ids that is also listed in
    exclude_profile_ids is a legitimate "this provider except these nodes"
    pattern (NodeGroup.__post_init__ only rejects the direct
    member_profile_ids/exclude_profile_ids overlap, not this indirect one),
    resolved here by set difference.
    """
    profiles = profile_store.list()
    included_ids = set(group.member_profile_ids)
    included_ids |= {
        profile.id for profile in profiles if profile.provider_id in group.member_provider_ids
    }
    included_ids -= set(group.exclude_profile_ids)
    by_id = {profile.id: profile for profile in profiles}
    return [by_id[profile_id] for profile_id in included_ids if profile_id in by_id]


def resolve_candidates(
    group: NodeGroup,
    profile_store: ProfileStore,
    provider_store: ProviderStore,
    config: dict[str, Any],
) -> list[Profile]:
    """The eligible candidate set for this group, unranked.

    Reuses pool_builder.filter_eligible_profiles for the health pass
    (origin-enabled, enabled, not recently failed) - the same function
    build_pool uses for the legacy global pool. This function only decides
    *scope* (group membership), not health; it does not reimplement any
    eligibility check.

    resilience_policy effects, by design:
    - RESILIENT_ONLY hard-filters to ResilienceCategory.RESILIENT profiles.
      An empty result here means fail-closed: the caller must not fall back
      to a compatibility profile, same vocabulary as
      RotationEngine.pool_size_category() == "unavailable".
    - PREFERRED and COMPATIBILITY_ALLOWED do not filter anything here - the
      difference between them is ranking (Task 14.4's scoring), which this
      function does not do. Both return the same eligible set.
    """
    members = _resolve_membership(group, profile_store)
    eligible = pool_builder.filter_eligible_profiles(members, provider_store, config)
    if group.resilience_policy is NodeGroupResiliencePolicy.RESILIENT_ONLY:
        eligible = [
            profile
            for profile in eligible
            if profile_resilience_category(profile) is ResilienceCategory.RESILIENT
        ]
    return eligible
