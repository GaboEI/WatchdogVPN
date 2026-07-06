from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from models.profile import Profile, ProfileSource, ProtocolType
from node_groups.models import NodeGroup, NodeGroupResiliencePolicy
from node_groups.scoring import (
    NodeGroupSelectionResult,
    rank_candidates,
    score_candidates,
    select_best,
)


def _profile(profile_id: str, protocol: ProtocolType, **overrides) -> Profile:
    defaults = dict(id=profile_id, name=profile_id, protocol=protocol, config={}, source=ProfileSource.MANUAL)
    defaults.update(overrides)
    return Profile(**defaults)


RESILIENT_A = _profile("r-a", ProtocolType.VLESS)
RESILIENT_B = _profile("r-b", ProtocolType.TROJAN)
COMPATIBILITY_A = _profile("c-a", ProtocolType.WIREGUARD)
COMPATIBILITY_B = _profile("c-b", ProtocolType.SHADOWSOCKS)

# Most tests don't care about latency staleness - an empty config falls
# back to the default latency_max_stale_seconds (config/app_config.py).
EMPTY_CONFIG: dict = {}


def _with_fresh_latency(profile: Profile, latency_ms: float, seconds_ago: float = 0.0) -> Profile:
    return _profile(
        profile.id,
        profile.protocol,
        latency_ms=latency_ms,
        last_latency_check=datetime.now(timezone.utc) - timedelta(seconds=seconds_ago),
    )


class ScoreCandidatesTests(unittest.TestCase):
    def test_never_queries_any_store_pure_function_of_its_arguments(self) -> None:
        # No ProfileStore/ProviderStore argument exists in the signature at
        # all - this is a structural guarantee, not just a runtime one.
        scores = score_candidates([RESILIENT_A], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG)
        self.assertEqual(len(scores), 1)

    def test_empty_input_returns_empty_output(self) -> None:
        self.assertEqual(score_candidates([], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG), [])

    def test_health_score_is_always_none_not_zero(self) -> None:
        # AUD-P14-001: health_status is binary and already consumed at the
        # filtering stage - no graded quality signal exists yet. None must
        # never be conflated with a real, measured 0.0.
        scores = score_candidates([RESILIENT_A], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG)

        self.assertIsNone(scores[0].health_score)

    def test_latency_score_is_none_when_never_measured(self) -> None:
        scores = score_candidates([RESILIENT_A], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG)

        self.assertIsNone(scores[0].latency_score)

    def test_latency_score_is_real_when_fresh(self) -> None:
        profile = _with_fresh_latency(RESILIENT_A, latency_ms=123.4, seconds_ago=5)

        scores = score_candidates([profile], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG)

        self.assertEqual(scores[0].latency_score, 123.4)

    def test_latency_score_is_none_when_stale(self) -> None:
        profile = _with_fresh_latency(RESILIENT_A, latency_ms=123.4, seconds_ago=999999)
        config = {"rotation": {"latency_max_stale_seconds": 300}}

        scores = score_candidates([profile], NodeGroupResiliencePolicy.PREFERRED, config)

        self.assertIsNone(scores[0].latency_score)

    def test_latency_score_respects_the_configured_stale_threshold(self) -> None:
        profile = _with_fresh_latency(RESILIENT_A, latency_ms=123.4, seconds_ago=100)

        still_fresh = score_candidates(
            [profile], NodeGroupResiliencePolicy.PREFERRED, {"rotation": {"latency_max_stale_seconds": 300}}
        )
        already_stale = score_candidates(
            [profile], NodeGroupResiliencePolicy.PREFERRED, {"rotation": {"latency_max_stale_seconds": 50}}
        )

        self.assertEqual(still_fresh[0].latency_score, 123.4)
        self.assertIsNone(already_stale[0].latency_score)

    def test_latency_never_contributes_to_total(self) -> None:
        # The core guard against Hallazgo B: raw milliseconds must never be
        # summed into total, or a slow-but-measured node could outrank a
        # fast-but-unmeasured one purely by magnitude.
        measured = _with_fresh_latency(COMPATIBILITY_A, latency_ms=800.0, seconds_ago=1)
        unmeasured = RESILIENT_A  # resilience_score=1.0 under PREFERRED

        scores = score_candidates(
            [measured, unmeasured], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG
        )
        by_id = {s.profile_id: s for s in scores}

        self.assertEqual(by_id["c-a"].total, 0.0)  # compatibility, no resilience credit
        self.assertEqual(by_id["r-a"].total, 1.0)  # resilient, unaffected by the other's latency
        self.assertGreater(by_id["r-a"].total, by_id["c-a"].total)

    def test_to_dict_renders_none_not_zero(self) -> None:
        scores = score_candidates([RESILIENT_A], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG)

        data = scores[0].to_dict()
        self.assertIsNone(data["latency_score"])
        self.assertIsNone(data["health_score"])

    def test_preferred_scores_resilient_above_compatibility(self) -> None:
        scores = score_candidates(
            [RESILIENT_A, COMPATIBILITY_A], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG
        )

        by_id = {s.profile_id: s for s in scores}
        self.assertGreater(by_id["r-a"].total, by_id["c-a"].total)

    def test_resilient_only_does_not_discriminate_among_resilient_candidates(self) -> None:
        # In practice resolve_candidates() would never hand this function a
        # compatibility profile under resilient_only - but this function
        # does not re-filter, so it is tested purely on resilient inputs.
        scores = score_candidates(
            [RESILIENT_A, RESILIENT_B], NodeGroupResiliencePolicy.RESILIENT_ONLY, EMPTY_CONFIG
        )

        self.assertEqual(scores[0].total, scores[1].total)
        self.assertEqual(scores[0].resilience_score, 0.0)

    def test_compatibility_allowed_does_not_discriminate_by_category(self) -> None:
        scores = score_candidates(
            [RESILIENT_A, COMPATIBILITY_A], NodeGroupResiliencePolicy.COMPATIBILITY_ALLOWED, EMPTY_CONFIG
        )

        by_id = {s.profile_id: s for s in scores}
        self.assertEqual(by_id["r-a"].total, by_id["c-a"].total)


class RankCandidatesTests(unittest.TestCase):
    def test_fresh_lower_latency_breaks_a_total_tie(self) -> None:
        fast = _with_fresh_latency(RESILIENT_A, latency_ms=50.0, seconds_ago=1)
        slow = _with_fresh_latency(RESILIENT_B, latency_ms=500.0, seconds_ago=1)

        ranked = rank_candidates([slow, fast], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG)

        self.assertEqual([s.profile_id for s in ranked], ["r-a", "r-b"])

    def test_unmeasured_latency_sorts_last_among_ties(self) -> None:
        measured = _with_fresh_latency(RESILIENT_A, latency_ms=500.0, seconds_ago=1)
        unmeasured = RESILIENT_B

        ranked = rank_candidates([unmeasured, measured], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG)

        # A real (if slow) measurement outranks no data at all.
        self.assertEqual([s.profile_id for s in ranked], ["r-a", "r-b"])

    def test_total_still_wins_over_latency(self) -> None:
        # A fast compatibility node must not outrank a resilient node under
        # PREFERRED just because it has better latency - total decides
        # first, latency is only a tie-break within an equal total.
        fast_compat = _with_fresh_latency(COMPATIBILITY_A, latency_ms=10.0, seconds_ago=1)
        slow_resilient = _with_fresh_latency(RESILIENT_A, latency_ms=900.0, seconds_ago=1)

        ranked = rank_candidates(
            [fast_compat, slow_resilient], NodeGroupResiliencePolicy.PREFERRED, EMPTY_CONFIG
        )

        self.assertEqual(ranked[0].profile_id, "r-a")

    def test_stale_latency_does_not_win_a_tie(self) -> None:
        stale = _with_fresh_latency(RESILIENT_A, latency_ms=1.0, seconds_ago=999999)
        unmeasured = RESILIENT_B
        config = {"rotation": {"latency_max_stale_seconds": 300}}

        ranked = rank_candidates([stale, unmeasured], NodeGroupResiliencePolicy.PREFERRED, config)

        # Both effectively unmeasured now - falls through to the id tie-break.
        self.assertEqual([s.profile_id for s in ranked], ["r-a", "r-b"])
        self.assertIsNone(ranked[0].latency_score)


class SelectBestTests(unittest.TestCase):
    def test_empty_candidates_is_unavailable(self) -> None:
        group = NodeGroup(name="g")

        profile, explanation = select_best(group, [], EMPTY_CONFIG)

        self.assertIsNone(profile)
        self.assertEqual(explanation.result, NodeGroupSelectionResult.UNAVAILABLE)
        self.assertIsNone(explanation.selected_profile_id)
        self.assertEqual(explanation.candidates, [])

    def test_single_candidate_is_selected_as_only_candidate(self) -> None:
        group = NodeGroup(name="g")

        profile, explanation = select_best(group, [COMPATIBILITY_A], EMPTY_CONFIG)

        self.assertEqual(profile, COMPATIBILITY_A)
        self.assertEqual(explanation.result, NodeGroupSelectionResult.SELECTED)
        self.assertEqual(explanation.decided_by, "only_candidate")

    def test_preferred_selects_the_resilient_candidate(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)

        profile, explanation = select_best(group, [COMPATIBILITY_A, RESILIENT_A], EMPTY_CONFIG)

        self.assertEqual(profile, RESILIENT_A)
        self.assertEqual(explanation.decided_by, "resilience_score")

    def test_tie_break_is_deterministic_regardless_of_input_order(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)

        first_order, _ = select_best(group, [RESILIENT_B, RESILIENT_A], EMPTY_CONFIG)
        second_order, _ = select_best(group, [RESILIENT_A, RESILIENT_B], EMPTY_CONFIG)

        self.assertEqual(first_order, RESILIENT_A)  # "r-a" < "r-b"
        self.assertEqual(second_order, RESILIENT_A)

    def test_tie_break_explanation_names_the_tie_break(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)

        _, explanation = select_best(group, [RESILIENT_B, RESILIENT_A], EMPTY_CONFIG)

        self.assertEqual(explanation.decided_by, "tie_break_by_id")

    def test_latency_tie_break_is_named_when_it_decides(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)
        fast = _with_fresh_latency(RESILIENT_A, latency_ms=10.0, seconds_ago=1)
        slow = _with_fresh_latency(RESILIENT_B, latency_ms=999.0, seconds_ago=1)

        profile, explanation = select_best(group, [slow, fast], EMPTY_CONFIG)

        self.assertEqual(profile, fast)
        self.assertEqual(explanation.decided_by, "latency_tie_break")

    def test_compatibility_allowed_ties_break_by_id_across_categories(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.COMPATIBILITY_ALLOWED)

        profile, explanation = select_best(group, [RESILIENT_A, COMPATIBILITY_A], EMPTY_CONFIG)

        self.assertEqual(profile, COMPATIBILITY_A)  # "c-a" < "r-a"
        self.assertEqual(explanation.decided_by, "tie_break_by_id")

    def test_resilient_only_ties_break_by_id_among_resilient_candidates(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.RESILIENT_ONLY)

        profile, explanation = select_best(group, [RESILIENT_B, RESILIENT_A], EMPTY_CONFIG)

        self.assertEqual(profile, RESILIENT_A)
        self.assertEqual(explanation.decided_by, "tie_break_by_id")

    def test_explanation_includes_every_candidate_considered_not_just_the_winner(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)

        _, explanation = select_best(group, [COMPATIBILITY_A, COMPATIBILITY_B, RESILIENT_A], EMPTY_CONFIG)

        self.assertEqual(
            {c.profile_id for c in explanation.candidates},
            {"c-a", "c-b", "r-a"},
        )

    def test_explanation_group_name_matches_the_group(self) -> None:
        group = NodeGroup(name="my-group")

        _, explanation = select_best(group, [COMPATIBILITY_A], EMPTY_CONFIG)

        self.assertEqual(explanation.group_name, "my-group")

    def test_explanation_to_dict_is_json_serializable_shape(self) -> None:
        group = NodeGroup(name="g", resilience_policy=NodeGroupResiliencePolicy.PREFERRED)

        _, explanation = select_best(group, [COMPATIBILITY_A, RESILIENT_A], EMPTY_CONFIG)
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

        profile, explanation = select_best(group, [COMPATIBILITY_A], EMPTY_CONFIG)

        self.assertEqual(profile, COMPATIBILITY_A)
        self.assertEqual(explanation.selected_profile_id, "c-a")


if __name__ == "__main__":
    unittest.main()
