from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from config.persistence import PersistentValidationError
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from dns.models import DNSChannel, DNSChannelName, DNSPolicy, Resolver
from models.profile import Profile, ProfileSource, ProtocolType
from node_groups.models import NodeGroup
from node_groups.store import NodeGroupStore
from route_chains.models import (
    ChainHop,
    RouteChain,
    RouteChainDocument,
    chain_target,
    redact_chain_document,
)
from route_chains.runtime import (
    ChainDNSPathStatus,
    ChainRuntimeResolver,
    ChainRuntimeStatus,
    chain_hop_outbound_tag,
)
from route_chains.store import RouteChainStore
from route_chains.validation import (
    validate_chain_action_reference,
    validate_chain_references,
    validate_chain_runtime_dependencies,
)


class RouteChainModelTests(unittest.TestCase):
    def test_default_document_is_disabled_and_empty(self) -> None:
        document = RouteChainDocument()

        self.assertEqual(
            document.to_dict(),
            {
                "schema_version": 1,
                "chains": [],
            },
        )

    def test_chain_round_trips_with_profile_and_group_hops(self) -> None:
        chain = RouteChain(
            id="work-safe",
            enabled=True,
            description="Local operator label",
            hops=[
                ChainHop(type="profile", target="profile-one"),
                ChainHop(
                    type="group",
                    target="resilient-exit",
                    selection_policy="group_policy",
                ),
            ],
            created_at="2026-07-09T00:00:00+00:00",
            updated_at="2026-07-09T00:00:00+00:00",
        )

        restored = RouteChain.from_dict(chain.to_dict())

        self.assertEqual(restored.to_dict(), chain.to_dict())
        self.assertEqual(restored.dns_strategy.value, "chain")
        self.assertEqual(restored.failure_policy.value, "fail_closed")
        self.assertEqual(restored.health_policy.value, "all_required")

    def test_rejects_invalid_document_shapes(self) -> None:
        invalid_documents = [
            {"schema_version": 2, "chains": []},
            {"schema_version": 1, "chains": "not-list"},
            {"schema_version": 1, "chains": [], "extra": True},
            {
                "schema_version": 1,
                "chains": [
                    {"id": "dup", "hops": [{"type": "profile", "target": "p1"}]},
                    {"id": "dup", "hops": [{"type": "profile", "target": "p2"}]},
                ],
            },
        ]

        for payload in invalid_documents:
            with self.subTest(payload=payload):
                with self.assertRaises(PersistentValidationError):
                    RouteChainDocument.from_dict(payload)

    def test_rejects_invalid_chain_shapes(self) -> None:
        invalid_chains = [
            {"id": "Bad Name", "hops": [{"type": "profile", "target": "p1"}]},
            {"id": "empty", "hops": []},
            {"id": "unknown", "hops": [{"type": "direct", "target": "direct"}]},
            {"id": "nested", "hops": [{"type": "chain", "target": "other"}]},
            {"id": "optional", "hops": [{"type": "profile", "target": "p1", "required": False}]},
            {"id": "bad-dns", "hops": [{"type": "profile", "target": "p1"}], "dns_strategy": "direct"},
            {
                "id": "bad-failure",
                "hops": [{"type": "profile", "target": "p1"}],
                "failure_policy": "fallback",
            },
            {
                "id": "bad-health",
                "hops": [{"type": "profile", "target": "p1"}],
                "health_policy": "any",
            },
            {
                "id": "profile-selection",
                "hops": [
                    {
                        "type": "profile",
                        "target": "p1",
                        "selection_policy": "group_policy",
                    }
                ],
            },
            {
                "id": "bad-group-selection",
                "hops": [
                    {
                        "type": "group",
                        "target": "g1",
                        "selection_policy": "manual",
                    }
                ],
            },
            {
                "id": "unknown-field",
                "hops": [{"type": "profile", "target": "p1", "private_key": "secret"}],
            },
        ]

        for payload in invalid_chains:
            with self.subTest(payload=payload):
                with self.assertRaises(PersistentValidationError):
                    RouteChain.from_dict(payload)

    def test_chain_action_parser_is_canonical_but_does_not_enable_route_actions(self) -> None:
        self.assertEqual(chain_target("chain:work-safe"), "work-safe")
        self.assertIsNone(chain_target("group:work-safe"))
        with self.assertRaises(PersistentValidationError):
            chain_target("chain:Bad Name")

    def test_redaction_preserves_status_without_hop_targets_or_description(self) -> None:
        document = RouteChainDocument(
            chains=[
                RouteChain(
                    id="work-safe",
                    enabled=True,
                    description="Do not export this local label",
                    hops=[
                        ChainHop(type="profile", target="profile-secret-id"),
                        ChainHop(type="group", target="private-group"),
                    ],
                )
            ]
        )

        redacted = redact_chain_document(document)
        text = str(redacted)

        self.assertEqual(redacted["chain_count"], 1)
        self.assertEqual(redacted["chains"][0]["hop_types"], ["profile", "group"])
        self.assertEqual(redacted["chains"][0]["description"], "<redacted>")
        self.assertNotIn("profile-secret-id", text)
        self.assertNotIn("private-group", text)
        self.assertNotIn("Do not export", text)

    def test_reference_validation_reports_missing_profile_and_group_targets(self) -> None:
        document = RouteChainDocument(
            chains=[
                RouteChain(
                    id="work-safe",
                    hops=[
                        ChainHop(type="profile", target="missing-profile"),
                        ChainHop(type="group", target="missing-group"),
                    ],
                )
            ]
        )

        findings = validate_chain_references(
            document,
            profile_ids=frozenset({"other-profile"}),
            group_names=frozenset({"other-group"}),
        )

        self.assertEqual([finding.code for finding in findings], ["missing_profile", "missing_group"])
        self.assertEqual(findings[0].hop_index, 1)
        self.assertEqual(findings[1].hop_index, 2)

    def test_chain_action_reference_reports_missing_or_disabled_chain(self) -> None:
        document = RouteChainDocument(
            chains=[
                RouteChain(
                    id="disabled",
                    enabled=False,
                    hops=[ChainHop(type="profile", target="profile-one")],
                )
            ]
        )

        missing = validate_chain_action_reference("chain:missing", document)
        disabled = validate_chain_action_reference("chain:disabled", document)

        self.assertIsNotNone(missing)
        self.assertIsNotNone(disabled)
        self.assertEqual(missing.code, "missing_chain")  # type: ignore[union-attr]
        self.assertEqual(disabled.code, "disabled_chain")  # type: ignore[union-attr]
        self.assertIsNone(validate_chain_action_reference("direct", document))

    def test_runtime_dependency_validation_reports_self_cycles(self) -> None:
        document = RouteChainDocument(
            chains=[
                RouteChain(
                    id="work-safe",
                    hops=[
                        ChainHop(type="profile", target="profile-one"),
                        ChainHop(type="group", target="primary"),
                    ],
                )
            ]
        )

        findings = validate_chain_runtime_dependencies(
            document,
            profile_route_actions={
                "profile-one": "chain:work-safe",
                "selected-profile": "chain:work-safe",
            },
            group_selected_profile_ids={"primary": "selected-profile"},
        )

        self.assertEqual(
            [finding.code for finding in findings],
            ["self_cycle_profile_route_action", "self_cycle_group_selected_profile"],
        )


class RouteChainStoreTests(unittest.TestCase):
    def test_store_round_trips_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "chains.json"
            store = RouteChainStore(path)
            document = RouteChainDocument(
                chains=[
                    RouteChain(
                        id="work-safe",
                        enabled=True,
                        hops=[ChainHop(type="profile", target="profile-one")],
                    )
                ]
            )

            store.save(document)

            self.assertEqual(store.load().to_dict(), document.to_dict())

    def test_store_defaults_to_empty_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RouteChainStore(Path(tmp) / "missing.json")

            self.assertEqual(store.load().to_dict(), RouteChainDocument().to_dict())

    def test_store_rejects_invalid_on_disk_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "chains.json"
            path.write_text('{"schema_version": 1, "chains": "bad"}\n', encoding="utf-8")

            with self.assertRaises(PersistentValidationError):
                RouteChainStore(path).load()

    def test_add_then_get(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RouteChainStore(Path(tmp) / "chains.json")
            chain = RouteChain(id="work-safe", hops=[ChainHop(type="profile", target="p1")])

            store.add(chain)

            self.assertEqual(store.get("work-safe").to_dict(), chain.to_dict())

    def test_add_is_upsert_by_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RouteChainStore(Path(tmp) / "chains.json")
            store.add(RouteChain(id="work-safe", hops=[ChainHop(type="profile", target="p1")]))
            store.add(
                RouteChain(
                    id="work-safe",
                    enabled=True,
                    hops=[ChainHop(type="profile", target="p2")],
                )
            )

            chains = store.list()
            self.assertEqual(len(chains), 1)
            self.assertTrue(chains[0].enabled)
            self.assertEqual(chains[0].hops[0].target, "p2")

    def test_get_missing_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RouteChainStore(Path(tmp) / "chains.json")

            self.assertIsNone(store.get("missing"))

    def test_remove_deletes_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RouteChainStore(Path(tmp) / "chains.json")
            store.add(RouteChain(id="work-safe", hops=[ChainHop(type="profile", target="p1")]))

            store.remove("work-safe")

            self.assertIsNone(store.get("work-safe"))

    def test_remove_missing_is_a_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RouteChainStore(Path(tmp) / "chains.json")

            store.remove("missing")  # must not raise

    def test_mutation_does_not_disturb_other_chains(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RouteChainStore(Path(tmp) / "chains.json")
            store.add(RouteChain(id="a", hops=[ChainHop(type="profile", target="p1")]))
            store.add(RouteChain(id="b", hops=[ChainHop(type="profile", target="p2")]))

            store.remove("a")

            self.assertIsNone(store.get("a"))
            self.assertIsNotNone(store.get("b"))


class ChainRuntimeResolverTests(unittest.TestCase):
    def test_resolves_valid_profile_hop_chain(self) -> None:
        with self._stores() as stores:
            stores["profiles"].add(_profile("profile-one"))
            stores["chains"].save(
                RouteChainDocument(
                    chains=[
                        RouteChain(
                            id="work-safe",
                            enabled=True,
                            hops=[ChainHop(type="profile", target="profile-one")],
                        )
                    ]
                )
            )

            plan = stores["resolver"].resolve_action(
                "chain:work-safe",
                dns_policy=_chain_dns_policy(),
                config={},
            )

            self.assertIsNotNone(plan)
            self.assertEqual(plan.status, ChainRuntimeStatus.RESOLVED)
            self.assertEqual(plan.route_outbound_tag, "watchdogvpn-chain-work-safe-hop-1")
            self.assertEqual(plan.hops[0].resolved_profile_id, "profile-one")

    def test_resolves_valid_group_hop_chain_deterministically(self) -> None:
        with self._stores() as stores:
            stores["profiles"].add(_profile("profile-b"))
            stores["profiles"].add(_profile("profile-a"))
            stores["groups"].add(
                NodeGroup(
                    name="primary",
                    member_profile_ids=["profile-b", "profile-a"],
                )
            )
            stores["chains"].save(
                RouteChainDocument(
                    chains=[
                        RouteChain(
                            id="work-safe",
                            enabled=True,
                            hops=[ChainHop(type="group", target="primary")],
                        )
                    ]
                )
            )

            plan = stores["resolver"].resolve_action(
                "chain:work-safe",
                dns_policy=_chain_dns_policy(),
                config={},
            )

            self.assertIsNotNone(plan)
            self.assertEqual(plan.status, ChainRuntimeStatus.RESOLVED)
            self.assertEqual(plan.hops[0].resolved_profile_id, "profile-a")

    def test_missing_chain_and_disabled_chain_fail_closed(self) -> None:
        with self._stores() as stores:
            stores["chains"].save(
                RouteChainDocument(
                    chains=[
                        RouteChain(
                            id="disabled",
                            enabled=False,
                            hops=[ChainHop(type="profile", target="profile-one")],
                        )
                    ]
                )
            )

            missing = stores["resolver"].resolve_action(
                "chain:missing",
                dns_policy=_chain_dns_policy(),
                config={},
            )
            disabled = stores["resolver"].resolve_action(
                "chain:disabled",
                dns_policy=_chain_dns_policy(),
                config={},
            )

            self.assertEqual(missing.status, ChainRuntimeStatus.BLOCKED)
            self.assertEqual(missing.failure_reason, "missing_chain")
            self.assertEqual(disabled.status, ChainRuntimeStatus.BLOCKED)
            self.assertEqual(disabled.failure_reason, "disabled_chain")

    def test_missing_profile_missing_group_and_empty_group_fail_closed(self) -> None:
        with self._stores() as stores:
            stores["groups"].add(NodeGroup(name="empty", member_profile_ids=[]))
            stores["chains"].save(
                RouteChainDocument(
                    chains=[
                        RouteChain(
                            id="missing-profile",
                            enabled=True,
                            hops=[ChainHop(type="profile", target="nope")],
                        ),
                        RouteChain(
                            id="missing-group",
                            enabled=True,
                            hops=[ChainHop(type="group", target="nope")],
                        ),
                        RouteChain(
                            id="empty-group",
                            enabled=True,
                            hops=[ChainHop(type="group", target="empty")],
                        ),
                    ]
                )
            )

            missing_profile = stores["resolver"].resolve_action(
                "chain:missing-profile",
                dns_policy=_chain_dns_policy(),
                config={},
            )
            missing_group = stores["resolver"].resolve_action(
                "chain:missing-group",
                dns_policy=_chain_dns_policy(),
                config={},
            )
            empty_group = stores["resolver"].resolve_action(
                "chain:empty-group",
                dns_policy=_chain_dns_policy(),
                config={},
            )

            self.assertEqual(missing_profile.failure_reason, "missing_profile")
            self.assertEqual(missing_group.failure_reason, "missing_group")
            self.assertEqual(empty_group.failure_reason, "empty_group_resolution")
            self.assertTrue(all(not plan.resolved for plan in (missing_profile, missing_group, empty_group)))

    def test_dns_path_unavailable_fails_closed_after_hops_resolve(self) -> None:
        with self._stores() as stores:
            stores["profiles"].add(_profile("profile-one"))
            stores["chains"].save(
                RouteChainDocument(
                    chains=[
                        RouteChain(
                            id="work-safe",
                            enabled=True,
                            hops=[ChainHop(type="profile", target="profile-one")],
                        )
                    ]
                )
            )

            plan = stores["resolver"].resolve_action(
                "chain:work-safe",
                dns_policy=DNSPolicy(),
                config={},
            )

            self.assertEqual(plan.status, ChainRuntimeStatus.BLOCKED)
            self.assertEqual(plan.dns_path_status, ChainDNSPathStatus.UNAVAILABLE)
            self.assertEqual(plan.failure_reason, "dns_path_unavailable")

    def test_outbound_tag_stability(self) -> None:
        self.assertEqual(chain_hop_outbound_tag("work-safe", 1), "watchdogvpn-chain-work-safe-hop-1")
        self.assertEqual(chain_hop_outbound_tag("work-safe", 2), "watchdogvpn-chain-work-safe-hop-2")

    def _stores(self):
        class StoreContext:
            def __enter__(self):
                self.tmpdir = tempfile.TemporaryDirectory()
                root = Path(self.tmpdir.name)
                profile_store = ProfileStore(root / "profiles.json")
                provider_store = ProviderStore(root / "providers.json")
                group_store = NodeGroupStore(root / "node_groups.json")
                chain_store = RouteChainStore(root / "chains.json")
                resolver = ChainRuntimeResolver(
                    chain_store=chain_store,
                    profile_store=profile_store,
                    node_group_store=group_store,
                    provider_store=provider_store,
                )
                return {
                    "profiles": profile_store,
                    "providers": provider_store,
                    "groups": group_store,
                    "chains": chain_store,
                    "resolver": resolver,
                }

            def __exit__(self, exc_type, exc, tb):
                self.tmpdir.cleanup()

        return StoreContext()


def _profile(profile_id: str) -> Profile:
    return Profile(
        id=profile_id,
        name=profile_id,
        protocol=ProtocolType.VLESS,
        config={"host": f"{profile_id}.example", "port": 443, "uuid": profile_id},
        source=ProfileSource.MANUAL,
    )


def _chain_dns_policy() -> DNSPolicy:
    return DNSPolicy(
        channels={
            DNSChannelName.PROXY: DNSChannel(
                name=DNSChannelName.PROXY,
                resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
            )
        }
    )


if __name__ == "__main__":
    unittest.main()
