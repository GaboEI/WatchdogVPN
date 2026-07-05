from __future__ import annotations

import unittest

from models.profile import Profile, ProfileSource, ProtocolType
from node_groups.models import NodeGroup, NodeGroupResiliencePolicy
from node_groups.scoring import NodeGroupSelectionResult, score_candidates, select_best


def _profile(profile_id: str, protocol: ProtocolType) -> Profile:
    return Profile(id=profile_id, name=profile_id, protocol=protocol, config={}, source=ProfileSource.MANUAL)


RESILIENT_A = _profile("r-a", ProtocolType.VLESS)
RESILIENT_B = _profile("r-b", ProtocolType.TROJAN)
COMPATIBILITY_A = _profile("c-a", ProtocolType.WIREGUARD)
COMPATIBILITY_B = _profile("c-b", ProtocolType.SHADOWSOCKS)


class ScoreCandidatesTests(unittest.TestCase):
    def test_never_queries_any_store_pure_function_of_its_arguments(self) -> None:
        # No ProfileStore/ProviderStore argument exists in the signature at
        # all - this is a structural guarantee, not just a runtime one.
        scores = score_candidates([RESILIENT_A], NodeGroupResiliencePolicy.PREFERRED)
        self.assertEqual(len(scores), 1)

    def test_empty_input_returns_empty_output(self) -> None:
        self.assertEqual(score_candidates([], NodeGroupResiliencePolicy.PREFERRED), [])

    def test_latency_and_health_are_always_none_not_zero(self) -> None:
        # AUD-P14-001: no runtime path produces this data today. None must
        # never be conflated with a real, measured 0.0.
        scores = score_candidates([RESILIENT_A], NodeGroupResiliencePolicy.PREFERRED)

        self.assertIsNone(scores[0].latency_score)
        self.assertIsNone(scores[0].health_score)

    def test_to_dict_renders_none_not_zero(self) -> None:
        scores = score_candidates([RESILIENT_A], NodeGroupResiliencePolicy.PREFERRED)

        data = scores[0].to_dict()
        self.assertIsNone(data["latency_score"])
        self.assertIsNone(data["health_score"])

    def test_preferred_scores_resilient_above_compatibility(self) -> None:
        scores = score_candidates(
            [RESILIENT_A, COMPATIBILITY_A], NodeGroupResiliencePolicy.PREFERRED
        )

        by_id = {s.profile_id: s for s in scores}
        self.assertGreater(by_id["r-a"].total, by_id["c-a"].total)

    def test_resilient_only_does_not_discriminate_among_resilient_candidates(self) -> None:
        # In practice resolve_candidates() would never hand this function a
        # compatibility profile under resilient_only - but this function
        # does not re-filter, so it is tested purely on resilient inputs.
        scores = score_candidates(
            [RESILIENT_A, RESILIENT_B], NodeGroupResiliencePolicy.RESILIENT_ONLY
        )

        self.assertEqual(scores[0].total, scores[1].total)
        self.assertEqual(scores[0].resilience_score, 0.0)

    def test_compatibility_allowed_does_not_discriminate_by_category(self) -> None:
        scores = score_candidates(
            [RESILIENT_A, COMPATIBILITY_A], NodeGroupResiliencePolicy.COMPATIBILITY_ALLOWED
        )

        by_id = {s.profile_id: s for s in scores}
        self.assertEqual(by_id["r-a"].total, by_id["c-a"].total)


class SelectBestTests(unittest.TestCase):
    def test_empty_candidates_is_unavailable(self) -> None:
        group = NodeGroup(name="g")

        profile, explanation = select_best(group, [])

        self.assertIsNone(profile)
        self.assertEqual(explanation.result, NodeGroupSelectionResult.UNAVAILABLE)
        self.assertIsNone(explanation.selected_profile_id)
        self.assertEqual(explanation.candidates, [])

    def test_single_candidate_is_selected_as_only_candidate(self) -> None:
        group = NodeGroup(name="g")

        profile, explanation = select_best(group, [COMPATIBILITY_A])

        self.assertEqual(profile, COMPATIBILITY_A)
        self.assertEqual(explanation.result, NodeGroupSelectionResult.SELECTED)
        self.assertEqual(explanation.decided_by, "only_candidate")

    def test_preferred_selects_the_resilient_candidate(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)

        profile, explanation = select_best(group, [COMPATIBILITY_A, RESILIENT_A])

        self.assertEqual(profile, RESILIENT_A)
        self.assertEqual(explanation.decided_by, "resilience_score")

    def test_tie_break_is_deterministic_regardless_of_input_order(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)

        first_order, _ = select_best(group, [RESILIENT_B, RESILIENT_A])
        second_order, _ = select_best(group, [RESILIENT_A, RESILIENT_B])

        self.assertEqual(first_order, RESILIENT_A)  # "r-a" < "r-b"
        self.assertEqual(second_order, RESILIENT_A)

    def test_tie_break_explanation_names_the_tie_break(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)

        _, explanation = select_best(group, [RESILIENT_B, RESILIENT_A])

        self.assertEqual(explanation.decided_by, "tie_break_by_id")

    def test_compatibility_allowed_ties_break_by_id_across_categories(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.COMPATIBILITY_ALLOWED)

        profile, explanation = select_best(group, [RESILIENT_A, COMPATIBILITY_A])

        self.assertEqual(profile, COMPATIBILITY_A)  # "c-a" < "r-a"
        self.assertEqual(explanation.decided_by, "tie_break_by_id")

    def test_resilient_only_ties_break_by_id_among_resilient_candidates(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.RESILIENT_ONLY)

        profile, explanation = select_best(group, [RESILIENT_B, RESILIENT_A])

        self.assertEqual(profile, RESILIENT_A)
        self.assertEqual(explanation.decided_by, "tie_break_by_id")

    def test_explanation_includes_every_candidate_considered_not_just_the_winner(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)

        _, explanation = select_best(group, [COMPATIBILITY_A, COMPATIBILITY_B, RESILIENT_A])

        self.assertEqual(
            {c.profile_id for c in explanation.candidates},
            {"c-a", "c-b", "r-a"},
        )

    def test_explanation_group_name_matches_the_group(self) -> None:
        group = NodeGroup(name="my-group")

        _, explanation = select_best(group, [COMPATIBILITY_A])

        self.assertEqual(explanation.group_name, "my-group")

    def test_explanation_to_dict_is_json_serializable_shape(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)

        _, explanation = select_best(group, [COMPATIBILITY_A, RESILIENT_A])
        data = explanation.to_dict()

        self.assertEqual(data["result"], "selected")
        self.assertEqual(data["selected_profile_id"], "r-a")
        self.assertEqual(len(data["candidates"]), 2)
        self.assertIsNone(data["candidates"][0]["latency_score"])

    def test_never_selects_a_profile_outside_the_candidate_list(self) -> None:
        # Two-stage architecture guard: select_best has no access to any
        # store, so it structurally cannot "rescue" a profile resolve_
        # candidates() did not already declare eligible.
        group = NodeGroup(name="g", member_profile_ids=["not-a-real-candidate"])

        profile, explanation = select_best(group, [COMPATIBILITY_A])

        self.assertEqual(profile, COMPATIBILITY_A)
        self.assertEqual(explanation.selected_profile_id, "c-a")


if __name__ == "__main__":
    unittest.main()
