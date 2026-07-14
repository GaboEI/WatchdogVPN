from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from config.profile_store import ProfileStore
from config.provider_store import DuplicateProviderError, ProviderLimitError, ProviderStore
from models.profile import Profile, ProfileSource, ProtocolType
from providers.subscription_provider import ProviderNotFoundError, SubscriptionProvider


def _profile(profile_id: str, name: str, host: str, protocol: ProtocolType = ProtocolType.VLESS) -> Profile:
    config = {"host": host, "port": 443}
    if protocol in {ProtocolType.VLESS, ProtocolType.VMESS}:
        config["uuid"] = "test-uuid"
    elif protocol in {ProtocolType.TROJAN, ProtocolType.HYSTERIA2}:
        config["password"] = "test-password"
    elif protocol is ProtocolType.TUIC:
        config.update({"uuid": "test-uuid", "password": "test-password"})
    elif protocol is ProtocolType.SHADOWSOCKS:
        config.update({"method": "chacha20-ietf-poly1305", "password": "test-password"})
    return Profile(
        id=profile_id,
        name=name,
        protocol=protocol,
        config=config,
        source=ProfileSource.MANUAL,
    )


class SubscriptionProviderTests(unittest.TestCase):
    def _provider(self, tmp: str, fetcher) -> SubscriptionProvider:
        return SubscriptionProvider(
            provider_store=ProviderStore(Path(tmp) / "providers.json"),
            profile_store=ProfileStore(Path(tmp) / "profiles.json"),
            fetcher=fetcher,
        )

    def test_add_fetches_profiles_and_stores_provider_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(
                tmp,
                lambda _url: [
                    _profile("fr-1", "France 1", "fr.example.com"),
                    _profile("de-1", "Germany 1", "de.example.com", ProtocolType.TROJAN),
                ],
            )

            stored_provider = provider.add("https://provider.example/sub", "Example Provider")

            profiles = ProfileStore(Path(tmp) / "profiles.json").list()
            self.assertEqual(stored_provider.id, "example-provider")
            self.assertEqual(stored_provider.profiles, ["example-provider:fr-1", "example-provider:de-1"])
            self.assertEqual([p.source for p in profiles], [ProfileSource.SUBSCRIPTION, ProfileSource.SUBSCRIPTION])
            self.assertEqual([p.provider_id for p in profiles], ["example-provider", "example-provider"])
            self.assertTrue(all(p.in_rotation_pool for p in profiles))

    def test_add_enforces_max_two_external_providers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, lambda _url: [_profile("node", "Node", "node.example.com")])
            provider.add("https://a.example/sub", "A")
            provider.add("https://b.example/sub", "B")

            with self.assertRaises(ProviderLimitError):
                provider.add("https://c.example/sub", "C")

    def test_add_rejects_duplicate_subscription_url_without_leaking_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, lambda _url: [_profile("node", "Node", "node.example.com")])
            provider.add(" https://provider.example/private-token ", "First")

            with self.assertRaises(DuplicateProviderError) as captured:
                provider.add("https://provider.example/private-token", "Second")

            self.assertEqual(str(captured.exception), "provider already exists: first")
            self.assertNotIn("private-token", str(captured.exception))

    def test_add_without_name_does_not_leak_subscription_token_to_provider_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, lambda _url: [_profile("node", "Node", "node.example.com")])

            stored_provider = provider.add("https://netz.tg/private-token-value", "")

            self.assertEqual(stored_provider.id, "netz.tg")
            self.assertNotIn("private-token-value", stored_provider.id)

    def test_update_adds_removes_and_updates_profiles(self) -> None:
        calls = {"count": 0}

        def fetcher(_url: str) -> list[Profile]:
            calls["count"] += 1
            if calls["count"] == 1:
                return [
                    _profile("fr-1", "France 1", "fr.example.com"),
                    _profile("de-1", "Germany 1", "de.example.com"),
                ]
            return [
                _profile("fr-1", "France Updated", "fr-new.example.com"),
                _profile("nl-1", "Netherlands 1", "nl.example.com"),
            ]

        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, fetcher)
            stored_provider = provider.add("https://provider.example/sub", "Example Provider")

            profile_store = ProfileStore(Path(tmp) / "profiles.json")
            existing = profile_store.get("example-provider:fr-1")
            self.assertIsNotNone(existing)
            assert existing is not None
            existing.enabled = False
            existing.in_rotation_pool = False
            existing.health_status = "ok"
            profile_store.update(existing)

            changes = provider.update(stored_provider.id)

            profiles = {profile.id: profile for profile in profile_store.list()}
            updated_provider = ProviderStore(Path(tmp) / "providers.json").get(stored_provider.id)
            self.assertEqual(changes, 3)
            self.assertEqual(set(profiles), {"example-provider:fr-1", "example-provider:nl-1"})
            self.assertEqual(profiles["example-provider:fr-1"].name, "France Updated")
            self.assertEqual(profiles["example-provider:fr-1"].config["host"], "fr-new.example.com")
            self.assertFalse(profiles["example-provider:fr-1"].enabled)
            self.assertFalse(profiles["example-provider:fr-1"].in_rotation_pool)
            self.assertEqual(profiles["example-provider:fr-1"].health_status, "ok")
            self.assertIsNotNone(updated_provider)
            assert updated_provider is not None
            self.assertEqual(updated_provider.profiles, ["example-provider:fr-1", "example-provider:nl-1"])

    def test_update_without_changes_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, lambda _url: [_profile("node", "Node", "node.example.com")])
            stored_provider = provider.add("https://provider.example/sub", "Provider")

            self.assertEqual(provider.update(stored_provider.id), 0)

    def test_update_matches_existing_nodes_by_fingerprint_not_new_id(self) -> None:
        calls = {"count": 0}

        def fetcher(_url: str) -> list[Profile]:
            calls["count"] += 1
            if calls["count"] == 1:
                return [_profile("old-node", "Old Name", "node.example.com")]
            return [_profile("new-node", "New Name", "node.example.com")]

        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, fetcher)
            stored_provider = provider.add("https://provider.example/sub", "Provider")

            changes = provider.update(stored_provider.id)

            profiles = ProfileStore(Path(tmp) / "profiles.json").list()
            updated_provider = ProviderStore(Path(tmp) / "providers.json").get(stored_provider.id)
            self.assertEqual(changes, 1)
            self.assertEqual([profile.id for profile in profiles], ["provider:old-node"])
            self.assertEqual(profiles[0].name, "New Name")
            self.assertIsNotNone(updated_provider)
            assert updated_provider is not None
            self.assertEqual(updated_provider.profiles, ["provider:old-node"])

    def test_add_skips_duplicate_nodes_in_same_provider_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(
                tmp,
                lambda _url: [
                    _profile("node-a", "Node A", "node.example.com"),
                    _profile("node-b", "Node B", "node.example.com"),
                ],
            )

            stored_provider = provider.add("https://provider.example/sub", "Provider")

            profiles = ProfileStore(Path(tmp) / "profiles.json").list()
            self.assertEqual(stored_provider.profiles, ["provider:node-a"])
            self.assertEqual([profile.id for profile in profiles], ["provider:node-a"])

    def test_update_missing_provider_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, lambda _url: [_profile("node", "Node", "node.example.com")])

            with self.assertRaises(ProviderNotFoundError):
                provider.update("missing")

    def test_update_all_reports_each_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, lambda _url: [_profile("node", "Node", "node.example.com")])
            first = provider.add("https://a.example/sub", "A")
            second = provider.add("https://b.example/sub", "B")

            result = provider.update_all()

            self.assertEqual(result, {first.id: 0, second.id: 0})

    def test_remove_deletes_provider_and_owned_profiles_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, lambda _url: [_profile("node", "Node", "node.example.com")])
            stored_provider = provider.add("https://provider.example/sub", "Provider")
            profile_store = ProfileStore(Path(tmp) / "profiles.json")
            manual = _profile("manual-1", "Manual", "manual.example.com")
            manual.source = ProfileSource.MANUAL
            profile_store.add(manual)

            provider.remove(stored_provider.id)

            self.assertIsNone(ProviderStore(Path(tmp) / "providers.json").get(stored_provider.id))
            self.assertEqual([profile.id for profile in profile_store.list()], ["manual-1"])

    def test_status_reports_provider_and_profile_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, lambda _url: [_profile("node", "Node", "node.example.com")])
            provider.add("https://provider.example/sub", "Provider")

            status = provider.status()

            self.assertEqual(status["provider"], "subscription")
            self.assertEqual(status["providers"], 1)
            self.assertEqual(status["profiles"], 1)

    def test_provider_metadata_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, lambda _url: [_profile("node", "Node", "node.example.com")])
            stored_provider = provider.add("https://provider.example/sub", "Provider")
            stored_provider.metadata = {
                "traffic_used": "51.6 GB",
                "traffic_limit": "1000.0 GB",
                "expires_at": "2026-09-17",
            }
            ProviderStore(Path(tmp) / "providers.json").update(stored_provider)

            restored = ProviderStore(Path(tmp) / "providers.json").get(stored_provider.id)

            self.assertIsNotNone(restored)
            assert restored is not None
            self.assertEqual(restored.metadata["traffic_used"], "51.6 GB")

    def test_add_with_only_profile_fetcher_injected_reports_no_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = self._provider(tmp, lambda _url: [_profile("node", "Node", "node.example.com")])

            stored_provider = provider.add("https://provider.example/sub", "Provider")

            self.assertEqual(stored_provider.metadata, {})

    def test_add_populates_metadata_from_injected_metadata_fetcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = SubscriptionProvider(
                provider_store=ProviderStore(Path(tmp) / "providers.json"),
                profile_store=ProfileStore(Path(tmp) / "profiles.json"),
                fetcher=lambda _url: [_profile("node", "Node", "node.example.com")],
                metadata_fetcher=lambda _url: {
                    "traffic_used": "12.0 GB",
                    "traffic_limit": "100.0 GB",
                    "expires_at": "2026-12-01",
                },
            )

            stored_provider = provider.add("https://provider.example/sub", "Provider")

            self.assertEqual(stored_provider.metadata["traffic_used"], "12.0 GB")
            self.assertEqual(stored_provider.metadata["expires_at"], "2026-12-01")

    def test_update_populates_metadata_from_injected_metadata_fetcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = SubscriptionProvider(
                provider_store=ProviderStore(Path(tmp) / "providers.json"),
                profile_store=ProfileStore(Path(tmp) / "profiles.json"),
                fetcher=lambda _url: [_profile("node", "Node", "node.example.com")],
                metadata_fetcher=lambda _url: {"traffic_used": "1.0 GB"},
            )
            stored_provider = provider.add("https://provider.example/sub", "Provider")
            self.assertEqual(stored_provider.metadata, {"traffic_used": "1.0 GB"})

            provider.metadata_fetcher = lambda _url: {"traffic_used": "2.0 GB"}
            provider.update(stored_provider.id)

            updated = ProviderStore(Path(tmp) / "providers.json").get(stored_provider.id)
            assert updated is not None
            self.assertEqual(updated.metadata, {"traffic_used": "2.0 GB"})

    def test_default_fetcher_uses_fetch_subscription_for_single_network_call(self) -> None:
        # Regression guard: the default (non-overridden) fetch path must go
        # through parsers.fetch_subscription exactly once per add()/update(),
        # not one call for profiles and a second for metadata headers.
        from unittest.mock import patch

        from parsers.subscription import SubscriptionFetchResult

        with tempfile.TemporaryDirectory() as tmp:
            provider = SubscriptionProvider(
                provider_store=ProviderStore(Path(tmp) / "providers.json"),
                profile_store=ProfileStore(Path(tmp) / "profiles.json"),
            )
            result = SubscriptionFetchResult(
                profiles=[_profile("node", "Node", "node.example.com")],
                metadata={"traffic_used": "5.0 GB"},
            )
            with patch(
                "providers.subscription_provider.fetch_subscription", return_value=result
            ) as fetch_mock:
                stored_provider = provider.add("https://provider.example/sub", "Provider")

            fetch_mock.assert_called_once_with("https://provider.example/sub")
            self.assertEqual(stored_provider.metadata, {"traffic_used": "5.0 GB"})


if __name__ == "__main__":
    unittest.main()
