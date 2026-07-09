from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from config.persistence import PersistentValidationError
from route_chains.models import (
    ChainHop,
    RouteChain,
    RouteChainDocument,
    chain_target,
    redact_chain_document,
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


if __name__ == "__main__":
    unittest.main()
