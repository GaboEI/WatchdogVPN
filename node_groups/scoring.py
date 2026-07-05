from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from models.profile import Profile, ResilienceCategory, profile_resilience_category
from node_groups.models import NodeGroup, NodeGroupResiliencePolicy


def _resilience_score(profile: Profile, policy: NodeGroupResiliencePolicy) -> float:
    """Only PREFERRED discriminates on resilience category.

    RESILIENT_ONLY already filtered node_groups.resolver's output to an
    all-resilient set (Task 14.3) - every candidate reaching this function
    is resilient, so this factor cannot discriminate further and
    contributes nothing. COMPATIBILITY_ALLOWED is a deliberate no-preference
    opt-out - it must not discriminate either. Only PREFERRED is the "soft
    priority" policy where resilient candidates should rank above
    compatibility ones.

    This never returns an "unknown" state: profile_resilience_category()
    is total over every ProtocolType (Task 14.3's completeness guarantee),
    so the category itself is always known - only whether it is WEIGHTED
    depends on policy.
    """
    if policy is not NodeGroupResiliencePolicy.PREFERRED:
        return 0.0
    return 1.0 if profile_resilience_category(profile) is ResilienceCategory.RESILIENT else 0.0


@dataclass(frozen=True, slots=True)
class CandidateScore:
    """Per-candidate ranking breakdown, in the spirit of Phase 13's
    RuleExplanation: never collapse "not measured" into "measured as zero".

    `latency_score` and `health_score` are `float | None`, not `float`,
    and are `None` for every candidate today - see AUD-P14-001 (Phase 14
    master plan notes): no runtime path measures fresh latency, and
    `Profile.health_status` is never written by a real health check, so
    there is no real recent-failure data to score. `None` means "not
    considered" (Phase 13's `unknown`/`runtime-required` posture); it must
    never be conflated with a real `0.0` (measured and scored the worst).
    Task 14.5 (health_status persistence) and a future latency-measurement
    task are what will eventually turn these into real numbers - this
    dataclass's shape does not need to change when that happens, only
    `score_candidates()`'s body.

    `total` treats a `None` factor as a neutral (zero) contribution for
    ranking purposes only; the `None` itself is preserved on the
    dataclass so `to_dict()` renders `null`, not `0`, keeping the
    distinction visible to any future explainer/CLI output.
    """

    profile_id: str
    resilience_score: float
    latency_score: float | None
    health_score: float | None
    total: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "resilience_score": self.resilience_score,
            "latency_score": self.latency_score,
            "health_score": self.health_score,
            "total": self.total,
        }


def score_candidates(
    candidates: list[Profile],
    resilience_policy: NodeGroupResiliencePolicy,
) -> list[CandidateScore]:
    """Rank the eligible set node_groups.resolver.resolve_candidates()
    already produced. This function never queries ProfileStore/
    ProviderStore and never re-applies eligibility logic - if a profile is
    not in `candidates`, it does not exist for scoring; it does not get a
    low score, it gets none at all. Two-stage architecture: stage 1
    (resolve_candidates) decides eligibility, this stage only orders what
    stage 1 already declared eligible.
    """
    scores = []
    for profile in candidates:
        resilience_score = _resilience_score(profile, resilience_policy)
        # AUD-P14-001: no runtime path produces fresh latency or a real
        # health_status today - both stay explicitly unmeasured (None),
        # never a placeholder 0.0, until Task 14.5 and a latency mechanism
        # exist to populate them for real.
        latency_score: float | None = None
        health_score: float | None = None
        total = resilience_score + (latency_score or 0.0) + (health_score or 0.0)
        scores.append(
            CandidateScore(
                profile_id=profile.id,
                resilience_score=resilience_score,
                latency_score=latency_score,
                health_score=health_score,
                total=total,
            )
        )
    return scores


class NodeGroupSelectionResult(str, Enum):
    SELECTED = "selected"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class NodeGroupSelectionExplanation:
    """Why a candidate was (or wasn't) selected - mirrors
    rules.explanation.RuleExplanation's discipline: record every candidate
    considered and the criterion that decided, not just the winner's name.
    """

    group_name: str
    result: NodeGroupSelectionResult
    selected_profile_id: str | None
    candidates: list[CandidateScore] = field(default_factory=list)
    decided_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_name": self.group_name,
            "result": self.result.value,
            "selected_profile_id": self.selected_profile_id,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "decided_by": self.decided_by,
        }


def select_best(
    group: NodeGroup,
    candidates: list[Profile],
) -> tuple[Profile | None, NodeGroupSelectionExplanation]:
    """Rank `candidates` (already-eligible output of resolve_candidates())
    and pick one, deterministically.

    Tie-break mirrors rules/rule_engine.py's existing (priority, name)
    sort convention: highest total first, then ascending profile id as the
    deterministic tie-break, so the same input always produces the same
    winner - reproducible, explainable selection, never
    order-of-iteration-dependent.

    Only called for selection_mode=AUTO; MANUAL is a hard pin resolved
    entirely outside this function (Task 14.3) and never reaches scoring.
    """
    scores = score_candidates(candidates, group.resilience_policy)
    if not scores:
        return None, NodeGroupSelectionExplanation(
            group_name=group.name,
            result=NodeGroupSelectionResult.UNAVAILABLE,
            selected_profile_id=None,
        )

    ranked = sorted(scores, key=lambda score: (-score.total, score.profile_id))
    winner = ranked[0]
    # Today only resilience_score is ever non-zero (see AUD-P14-001), so
    # this three-way call is accurate: no other candidate to compare
    # against, a real margin at the top, or a tie broken by id. Revisit
    # this attribution once a second factor is ever non-neutral - it will
    # need to name whichever factor actually produced the winning margin,
    # not assume it was resilience_score.
    if len(ranked) == 1:
        decided_by = "only_candidate"
    elif ranked[0].total == ranked[1].total:
        decided_by = "tie_break_by_id"
    else:
        decided_by = "resilience_score"

    by_id = {profile.id: profile for profile in candidates}
    explanation = NodeGroupSelectionExplanation(
        group_name=group.name,
        result=NodeGroupSelectionResult.SELECTED,
        selected_profile_id=winner.profile_id,
        candidates=ranked,
        decided_by=decided_by,
    )
    return by_id[winner.profile_id], explanation
