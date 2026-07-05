from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider
from node_groups.models import NodeGroup, NodeGroupResiliencePolicy
from node_groups.resolver import resolve_candidates


class NodeGroupResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.profile_store = ProfileStore(Path(self.tmpdir.name) / "profiles.json")
        self.provider_store = ProviderStore(Path(self.tmpdir.name) / "providers.json")
        self.config = {"rotation": {"health_status_cooldown_seconds": 300}}

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _profile(self, profile_id: str, protocol: ProtocolType, **overrides) -> Profile:
        defaults = dict(
            id=profile_id,
            name=profile_id,
            protocol=protocol,
            config={},
            source=ProfileSource.MANUAL,
            in_rotation_pool=True,
            enabled=True,
        )
        defaults.update(overrides)
        return Profile(**defaults)

    def test_empty_group_resolves_to_no_candidates(self) -> None:
        group = NodeGroup(name="g")

        self.assertEqual(resolve_candidates(group, self.profile_store, self.provider_store, self.config), [])

    def test_in_rotation_pool_flag_does_not_affect_group_membership(self) -> None:
        profile = self._profile("p1", ProtocolType.VLESS, in_rotation_pool=False)
        self.profile_store.add(profile)
        group = NodeGroup(name="g", member_profile_ids=["p1"])

        candidates = resolve_candidates(group, self.profile_store, self.provider_store, self.config)

        self.assertEqual([p.id for p in candidates], ["p1"])

    def test_excludes_disabled_member(self) -> None:
        profile = self._profile("p1", ProtocolType.VLESS, enabled=False)
        self.profile_store.add(profile)
        group = NodeGroup(name="g", member_profile_ids=["p1"])

        self.assertEqual(resolve_candidates(group, self.profile_store, self.provider_store, self.config), [])

    def test_member_provider_ids_expands_to_its_profiles(self) -> None:
        self.provider_store.add(Provider(id="prov1", name="Prov", url="https://example.test", rotation_enabled=True))
        p1 = self._profile("p1", ProtocolType.TROJAN, source=ProfileSource.SUBSCRIPTION, provider_id="prov1")
        p2 = self._profile("p2", ProtocolType.TROJAN, source=ProfileSource.SUBSCRIPTION, provider_id="prov1")
        self.profile_store.add(p1)
        self.profile_store.add(p2)
        group = NodeGroup(name="g", member_provider_ids=["prov1"])

        candidates = resolve_candidates(group, self.profile_store, self.provider_store, self.config)

        self.assertEqual(sorted(p.id for p in candidates), ["p1", "p2"])

    def test_exclusion_wins_over_provider_expansion(self) -> None:
        self.provider_store.add(Provider(id="prov1", name="Prov", url="https://example.test", rotation_enabled=True))
        p1 = self._profile("p1", ProtocolType.TROJAN, source=ProfileSource.SUBSCRIPTION, provider_id="prov1")
        p2 = self._profile("p2", ProtocolType.TROJAN, source=ProfileSource.SUBSCRIPTION, provider_id="prov1")
        self.profile_store.add(p1)
        self.profile_store.add(p2)
        group = NodeGroup(name="g", member_provider_ids=["prov1"], exclude_profile_ids=["p2"])

        candidates = resolve_candidates(group, self.profile_store, self.provider_store, self.config)

        self.assertEqual([p.id for p in candidates], ["p1"])

    def test_subscription_member_excluded_when_provider_rotation_disabled(self) -> None:
        # The health pass still applies to group-scoped candidates, same as
        # the legacy pool - origin-enabled is not bypassed by membership.
        self.provider_store.add(Provider(id="prov1", name="Prov", url="https://example.test", rotation_enabled=False))
        p1 = self._profile("p1", ProtocolType.TROJAN, source=ProfileSource.SUBSCRIPTION, provider_id="prov1")
        self.profile_store.add(p1)
        group = NodeGroup(name="g", member_profile_ids=["p1"])

        self.assertEqual(resolve_candidates(group, self.profile_store, self.provider_store, self.config), [])

    def test_preferred_does_not_filter_compatibility_profiles(self) -> None:
        resilient = self._profile("r1", ProtocolType.VLESS)
        compatibility = self._profile("c1", ProtocolType.WIREGUARD)
        self.profile_store.add(resilient)
        self.profile_store.add(compatibility)
        group = NodeGroup(name="g", member_profile_ids=["r1", "c1"])  # PREFERRED default

        candidates = resolve_candidates(group, self.profile_store, self.provider_store, self.config)

        self.assertEqual(sorted(p.id for p in candidates), ["c1", "r1"])

    def test_compatibility_allowed_does_not_filter_either(self) -> None:
        resilient = self._profile("r1", ProtocolType.VLESS)
        compatibility = self._profile("c1", ProtocolType.WIREGUARD)
        self.profile_store.add(resilient)
        self.profile_store.add(compatibility)
        group = NodeGroup(
            name="g",
            member_profile_ids=["r1", "c1"],
            resilience_policy=NodeGroupResiliencePolicy.COMPATIBILITY_ALLOWED,
        )

        candidates = resolve_candidates(group, self.profile_store, self.provider_store, self.config)

        self.assertEqual(sorted(p.id for p in candidates), ["c1", "r1"])

    def test_preferred_and_compatibility_allowed_produce_identical_sets(self) -> None:
        # Pins the documented invariant: the difference between these two
        # policies is ranking (Task 14.4), not filtering - resolve_candidates
        # must not be able to tell them apart.
        resilient = self._profile("r1", ProtocolType.VLESS)
        compatibility = self._profile("c1", ProtocolType.WIREGUARD)
        self.profile_store.add(resilient)
        self.profile_store.add(compatibility)

        preferred_group = NodeGroup(
            name="g1", member_profile_ids=["r1", "c1"], resilience_policy=NodeGroupResiliencePolicy.PREFERRED
        )
        compat_allowed_group = NodeGroup(
            name="g2",
            member_profile_ids=["r1", "c1"],
            resilience_policy=NodeGroupResiliencePolicy.COMPATIBILITY_ALLOWED,
        )

        preferred = resolve_candidates(preferred_group, self.profile_store, self.provider_store, self.config)
        compat_allowed = resolve_candidates(
            compat_allowed_group, self.profile_store, self.provider_store, self.config
        )

        self.assertEqual({p.id for p in preferred}, {p.id for p in compat_allowed})

    def test_resilient_only_filters_out_compatibility_profiles(self) -> None:
        resilient = self._profile("r1", ProtocolType.VLESS)
        compatibility = self._profile("c1", ProtocolType.WIREGUARD)
        self.profile_store.add(resilient)
        self.profile_store.add(compatibility)
        group = NodeGroup(
            name="g",
            member_profile_ids=["r1", "c1"],
            resilience_policy=NodeGroupResiliencePolicy.RESILIENT_ONLY,
        )

        candidates = resolve_candidates(group, self.profile_store, self.provider_store, self.config)

        self.assertEqual([p.id for p in candidates], ["r1"])

    def test_resilient_only_fails_closed_when_no_resilient_candidate_is_healthy(self) -> None:
        # This is the safety-critical case: no silent degrade to
        # compatibility. Empty result = fail-closed, same vocabulary as
        # RotationEngine.pool_size_category() == "unavailable".
        compatibility = self._profile("c1", ProtocolType.WIREGUARD)
        unhealthy_resilient = self._profile("r1", ProtocolType.VLESS, enabled=False)
        self.profile_store.add(compatibility)
        self.profile_store.add(unhealthy_resilient)
        group = NodeGroup(
            name="g",
            member_profile_ids=["r1", "c1"],
            resilience_policy=NodeGroupResiliencePolicy.RESILIENT_ONLY,
        )

        candidates = resolve_candidates(group, self.profile_store, self.provider_store, self.config)

        self.assertEqual(candidates, [])


if __name__ == "__main__":
    unittest.main()
