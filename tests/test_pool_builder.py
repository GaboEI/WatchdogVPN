from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider
from rotation.pool_builder import build_pool, filter_eligible_profiles


class PoolBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.profile_store = ProfileStore(Path(self.tmpdir.name) / "profiles.json")
        self.provider_store = ProviderStore(Path(self.tmpdir.name) / "providers.json")
        self.config = {
            "rotation": {"health_status_cooldown_seconds": 300},
        }

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def _manual_profile(self, profile_id: str = "manual1", **overrides) -> Profile:
        defaults = dict(
            id=profile_id,
            name="Manual",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
            in_rotation_pool=True,
            enabled=True,
        )
        defaults.update(overrides)
        return Profile(**defaults)

    def test_empty_profile_store_returns_empty_pool(self) -> None:
        self.assertEqual(build_pool(self.profile_store, self.provider_store, self.config), [])

    def test_own_profile_included_when_opted_in_and_enabled(self) -> None:
        profile = self._manual_profile()
        self.profile_store.add(profile)

        pool = build_pool(self.profile_store, self.provider_store, self.config)

        self.assertEqual([p.id for p in pool], [profile.id])

    def test_own_profile_excluded_when_not_in_rotation_pool(self) -> None:
        profile = self._manual_profile(in_rotation_pool=False)
        self.profile_store.add(profile)

        pool = build_pool(self.profile_store, self.provider_store, self.config)

        self.assertEqual(pool, [])

    def test_own_profile_excluded_when_disabled(self) -> None:
        profile = self._manual_profile(enabled=False)
        self.profile_store.add(profile)

        pool = build_pool(self.profile_store, self.provider_store, self.config)

        self.assertEqual(pool, [])

    def test_subscription_node_excluded_when_provider_rotation_disabled(self) -> None:
        provider = Provider(id="prov1", name="Prov", url="https://example.test/sub", rotation_enabled=False)
        self.provider_store.add(provider)
        profile = self._manual_profile(
            source=ProfileSource.SUBSCRIPTION,
            provider_id=provider.id,
        )
        self.profile_store.add(profile)

        pool = build_pool(self.profile_store, self.provider_store, self.config)

        self.assertEqual(pool, [])

    def test_subscription_node_included_when_provider_rotation_enabled(self) -> None:
        provider = Provider(id="prov1", name="Prov", url="https://example.test/sub", rotation_enabled=True)
        self.provider_store.add(provider)
        profile = self._manual_profile(
            source=ProfileSource.SUBSCRIPTION,
            provider_id=provider.id,
        )
        self.profile_store.add(profile)

        pool = build_pool(self.profile_store, self.provider_store, self.config)

        self.assertEqual([p.id for p in pool], [profile.id])

    def test_subscription_node_excluded_when_provider_missing(self) -> None:
        profile = self._manual_profile(
            source=ProfileSource.SUBSCRIPTION,
            provider_id="missing-provider",
        )
        self.profile_store.add(profile)

        pool = build_pool(self.profile_store, self.provider_store, self.config)

        self.assertEqual(pool, [])

    def test_excludes_profile_that_failed_within_cooldown(self) -> None:
        profile = self._manual_profile(health_status="down")
        profile.last_health_check = datetime.now(timezone.utc) - timedelta(seconds=10)
        self.profile_store.add(profile)

        pool = build_pool(self.profile_store, self.provider_store, self.config)

        self.assertEqual(pool, [])

    def test_includes_profile_that_failed_outside_cooldown(self) -> None:
        profile = self._manual_profile(health_status="down")
        profile.last_health_check = datetime.now(timezone.utc) - timedelta(seconds=600)
        self.profile_store.add(profile)

        pool = build_pool(self.profile_store, self.provider_store, self.config)

        self.assertEqual([p.id for p in pool], [profile.id])

    def test_includes_down_profile_with_no_last_health_check(self) -> None:
        profile = self._manual_profile(health_status="down")
        self.profile_store.add(profile)

        pool = build_pool(self.profile_store, self.provider_store, self.config)

        self.assertEqual([p.id for p in pool], [profile.id])

    def test_includes_profile_with_future_last_health_check(self) -> None:
        profile = self._manual_profile(health_status="down")
        profile.last_health_check = datetime.now(timezone.utc) + timedelta(days=1)
        self.profile_store.add(profile)

        pool = build_pool(self.profile_store, self.provider_store, self.config)

        self.assertEqual([p.id for p in pool], [profile.id])

    def test_filter_eligible_profiles_ignores_in_rotation_pool_flag(self) -> None:
        # filter_eligible_profiles only applies the health/eligibility pass -
        # scope (which profiles to consider at all) is entirely the caller's
        # decision. A profile with in_rotation_pool=False must still pass
        # through here if the caller decided to scope it in (e.g. a
        # NodeGroup's own membership, unrelated to the legacy pool flag).
        profile = self._manual_profile(in_rotation_pool=False)

        eligible = filter_eligible_profiles([profile], self.provider_store, self.config)

        self.assertEqual([p.id for p in eligible], [profile.id])

    def test_filter_eligible_profiles_excludes_disabled_regardless_of_scope(self) -> None:
        profile = self._manual_profile(enabled=False)

        eligible = filter_eligible_profiles([profile], self.provider_store, self.config)

        self.assertEqual(eligible, [])

    def test_build_pool_delegates_to_filter_eligible_profiles(self) -> None:
        # Regression guard for the extraction itself: build_pool must not
        # grow a second, divergent implementation of the health filter.
        profile = self._manual_profile()
        self.profile_store.add(profile)

        via_build_pool = build_pool(self.profile_store, self.provider_store, self.config)
        via_filter = filter_eligible_profiles([profile], self.provider_store, self.config)

        self.assertEqual(via_build_pool, via_filter)


if __name__ == "__main__":
    unittest.main()
