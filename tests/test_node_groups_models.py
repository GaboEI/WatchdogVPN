from __future__ import annotations

import unittest

from config.persistence import PersistentValidationError
from node_groups.models import (
    NodeGroup,
    NodeGroupResiliencePolicy,
    NodeGroupSelectionMode,
    group_target,
)


class GroupTargetParserTests(unittest.TestCase):
    """group_target() is the single canonical parser for the group:<name>
    syntax (Task 14.6) - rules/models.py and app_policy/models.py both
    import this instead of keeping their own regex."""

    def test_extracts_the_group_name(self) -> None:
        self.assertEqual(group_target("group:paris"), "paris")

    def test_strips_surrounding_whitespace(self) -> None:
        self.assertEqual(group_target("  group:paris  "), "paris")

    def test_non_group_actions_return_none(self) -> None:
        for action in ("direct", "current_profile", "auto_select", "block", "current"):
            with self.subTest(action=action):
                self.assertIsNone(group_target(action))

    def test_bare_group_prefix_with_no_name_returns_none(self) -> None:
        self.assertIsNone(group_target("group:"))

    def test_does_not_validate_the_extracted_name_as_a_slug(self) -> None:
        # Matches the historical rules/models.py behavior this replaces:
        # syntax extraction and "does this NodeGroup actually exist" are
        # different concerns - the latter is a runtime question
        # (core.watchdog.WatchdogRuntime._effective_node_group), not this
        # parser's job.
        self.assertEqual(group_target("group:Not A Valid Slug!"), "Not A Valid Slug!")


class NodeGroupDefaultsTests(unittest.TestCase):
    def test_defaults(self) -> None:
        group = NodeGroup(name="paris")

        self.assertTrue(group.enabled)
        self.assertEqual(group.member_profile_ids, [])
        self.assertEqual(group.member_provider_ids, [])
        self.assertEqual(group.exclude_profile_ids, [])
        self.assertEqual(group.resilience_policy, NodeGroupResiliencePolicy.PREFERRED)
        self.assertEqual(group.selection_mode, NodeGroupSelectionMode.AUTO)
        self.assertIsNone(group.manual_profile_id)

    def test_empty_group_is_valid(self) -> None:
        # The CLI flow is create-then-add-profile as separate steps
        # (Task 14.7): a freshly created group with no members must be a
        # valid, expected intermediate state, not rejected.
        NodeGroup(name="empty-group")

    def test_to_dict_from_dict_roundtrip(self) -> None:
        group = NodeGroup(
            name="paris",
            member_profile_ids=["p1", "p2"],
            member_provider_ids=["prov1"],
            exclude_profile_ids=["p3"],
            resilience_policy=NodeGroupResiliencePolicy.RESILIENT_ONLY,
        )

        restored = NodeGroup.from_dict(group.to_dict())

        self.assertEqual(restored, group)


class NodeGroupNameValidationTests(unittest.TestCase):
    def test_rejects_uppercase_name(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NodeGroup(name="Paris")

    def test_rejects_name_with_spaces(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NodeGroup(name="my group")

    def test_accepts_slug_with_dashes_and_underscores(self) -> None:
        group = NodeGroup(name="paris-eu_1")
        self.assertEqual(group.name, "paris-eu_1")

    def test_strips_whitespace(self) -> None:
        group = NodeGroup(name="  paris  ")
        self.assertEqual(group.name, "paris")


class NodeGroupSelectionValidationTests(unittest.TestCase):
    def test_manual_requires_profile_id(self) -> None:
        with self.assertRaises(PersistentValidationError) as ctx:
            NodeGroup(name="g", selection_mode=NodeGroupSelectionMode.MANUAL)
        self.assertIn("manual_profile_id", str(ctx.exception))
        self.assertIn("manual", str(ctx.exception))

    def test_manual_rejects_blank_profile_id(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NodeGroup(name="g", selection_mode=NodeGroupSelectionMode.MANUAL, manual_profile_id="   ")

    def test_auto_rejects_profile_id(self) -> None:
        with self.assertRaises(PersistentValidationError) as ctx:
            NodeGroup(name="g", selection_mode=NodeGroupSelectionMode.AUTO, manual_profile_id="p1")
        self.assertIn("manual_profile_id", str(ctx.exception))
        self.assertIn("auto", str(ctx.exception))

    def test_manual_with_profile_id_is_valid(self) -> None:
        group = NodeGroup(name="g", selection_mode=NodeGroupSelectionMode.MANUAL, manual_profile_id="p1")
        self.assertEqual(group.manual_profile_id, "p1")

    def test_manual_profile_id_is_stripped(self) -> None:
        group = NodeGroup(name="g", selection_mode=NodeGroupSelectionMode.MANUAL, manual_profile_id="  p1  ")
        self.assertEqual(group.manual_profile_id, "p1")


class NodeGroupMembershipValidationTests(unittest.TestCase):
    def test_rejects_direct_overlap_between_member_and_exclude(self) -> None:
        with self.assertRaises(PersistentValidationError) as ctx:
            NodeGroup(name="g", member_profile_ids=["p1"], exclude_profile_ids=["p1"])
        self.assertIn("p1", str(ctx.exception))

    def test_allows_provider_member_overlapping_excluded_profile(self) -> None:
        # Legitimate "this provider except these nodes" pattern - resolved
        # at runtime (node_groups.resolver), not rejected here.
        group = NodeGroup(name="g", member_provider_ids=["prov1"], exclude_profile_ids=["p1"])
        self.assertEqual(group.member_provider_ids, ["prov1"])
        self.assertEqual(group.exclude_profile_ids, ["p1"])

    def test_dedups_member_profile_ids(self) -> None:
        group = NodeGroup(name="g", member_profile_ids=["p1", "p1", "p2"])
        self.assertEqual(group.member_profile_ids, ["p1", "p2"])

    def test_dedups_exclude_profile_ids(self) -> None:
        group = NodeGroup(name="g", exclude_profile_ids=["p1", "p1"])
        self.assertEqual(group.exclude_profile_ids, ["p1"])

    def test_rejects_empty_string_member_id(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NodeGroup(name="g", member_profile_ids=[""])

    def test_rejects_non_list_member_field(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NodeGroup(name="g", member_profile_ids="p1")  # type: ignore[arg-type]


class NodeGroupFromDictTests(unittest.TestCase):
    def test_rejects_unknown_fields(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NodeGroup.from_dict({"name": "g", "bogus": 1})

    def test_rejects_non_mapping(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NodeGroup.from_dict([])  # type: ignore[arg-type]

    def test_rejects_invalid_resilience_policy(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NodeGroup.from_dict({"name": "g", "resilience_policy": "bogus"})

    def test_rejects_invalid_selection_mode(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NodeGroup.from_dict({"name": "g", "selection_mode": "bogus"})

    def test_first_failing_check_reports_its_own_field(self) -> None:
        # Both an invalid selection pairing AND a member/exclude overlap are
        # present - the error must name the check that actually fires
        # (selection pairing, validated first), not a generic message.
        with self.assertRaises(PersistentValidationError) as ctx:
            NodeGroup(
                name="g",
                selection_mode=NodeGroupSelectionMode.MANUAL,
                member_profile_ids=["p1"],
                exclude_profile_ids=["p1"],
            )
        self.assertIn("manual_profile_id", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
