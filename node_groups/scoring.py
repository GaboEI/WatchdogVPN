from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
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


def _fresh_latency_ms(profile: Profile, config: dict[str, Any]) -> float | None:
    """The profile's measured latency, or None if never measured or stale.

    Task 14.7: latency is captured opportunistically by
    WatchdogRuntime._checked_and_recorded whenever a real deep health check
    already happens - it is not a separate background prober (the single-
    outbound driver constraint documented in Task 14.6 rules that out for
    candidates that are not the currently connected profile). A candidate
    that has never been the active connection, or was checked too long ago,
    correctly has no fresh latency data - this returns None rather than a
    stale number pretending to be current. Mirrors
    rotation.pool_builder._recently_failed's exact staleness-window
    structure (including the future-timestamp guard against clock skew).
    """
    if profile.latency_ms is None or profile.last_latency_check is None:
        return None
    max_stale_seconds = config.get("rotation", {}).get("latency_max_stale_seconds", 300)
    last_check = profile.last_latency_check
    if last_check.tzinfo is None:
        last_check = last_check.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if last_check > now:
        return None
    elapsed = (now - last_check).total_seconds()
    if elapsed >= max_stale_seconds:
        return None
    return profile.latency_ms


@dataclass(frozen=True, slots=True)
class CandidateScore:
    """Per-candidate ranking breakdown, in the spirit of Phase 13's
    RuleExplanation: never collapse "not measured" into "measured as zero".

    `latency_score` and `health_score` are `float | None`. `None` means
    "not considered" (Phase 13's `unknown`/`runtime-required` posture); it
    must never be conflated with a real `0.0` (measured and scored the
    worst). `health_score` stays `None` for every candidate today - Task
    14.5 only gives a binary health_status, already fully consumed at the
    filtering stage (Task 14.3's cooldown), not a graded quality signal
    `total` could use. `latency_score` (Task 14.7) is real, fresh-or-None
    milliscond data now, sourced from `Profile.latency_ms`/
    `last_latency_check`.

    **`latency_score` deliberately does NOT contribute to `total`.**
    Raw milliseconds and the 0.0/1.0 `resilience_score` are not on a
    comparable scale - summing them would let latency's sheer numeric
    magnitude (tens to hundreds) dominate or distort a ranking that should
    be decided by real, meaningful factors first. Instead, latency is a
    secondary, ranking tie-break: it only distinguishes between candidates
    that are already equal on `total`, and only ever loses to a real
    difference in `total`, never overrides one. See `select_best()`'s sort
    key.
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
    config: dict[str, Any],
) -> list[CandidateScore]:
    """Rank the eligible set node_groups.resolver.resolve_candidates()
    already produced. This function never queries ProfileStore/
    ProviderStore and never re-applies eligibility logic - if a profile is
    not in `candidates`, it does not exist for scoring; it does not get a
    low score, it gets none at all. Two-stage architecture: stage 1
    (resolve_candidates) decides eligibility, this stage only orders what
    stage 1 already declared eligible.

    `config` (Task 14.7) is only consulted for
    `rotation.latency_max_stale_seconds` - it is not a second source of
    eligibility rules, those stay entirely in the resolver.
    """
    scores = []
    for profile in candidates:
        resilience_score = _resilience_score(profile, resilience_policy)
        latency_score = _fresh_latency_ms(profile, config)
        # AUD-P14-001 / Task 14.5: health_status is binary and already
        # consumed at the filtering stage - no graded quality signal exists
        # yet for a ranking factor to use, so this stays explicitly
        # unmeasured (None), never a placeholder 0.0.
        health_score: float | None = None
        total = resilience_score + (health_score or 0.0)
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


def _latency_rank(score: CandidateScore) -> float:
    """Sorts fresh, lower latency first; unmeasured/stale candidates
    (`None`) sort last among ties - absence of data must never look better
    than a real, if mediocre, measurement."""
    return score.latency_score if score.latency_score is not None else float("inf")


def rank_candidates(
    candidates: list[Profile],
    resilience_policy: NodeGroupResiliencePolicy,
    config: dict[str, Any],
) -> list[CandidateScore]:
    """`score_candidates()`, sorted by `(-total, latency_rank, profile_id)`.

    The single ranking implementation `select_best()` and
    `WatchdogRuntime._group_scoped_pool()` both use - RotationEngine needs
    the *entire* ordered candidate list (to try the next-best if the
    winner's live connect/health-check fails), not just the top pick, so
    the sort itself lives here once rather than being duplicated at each
    call site.
    """
    scores = score_candidates(candidates, resilience_policy, config)
    return sorted(scores, key=lambda score: (-score.total, _latency_rank(score), score.profile_id))


def select_best(
    group: NodeGroup,
    candidates: list[Profile],
    config: dict[str, Any],
) -> tuple[Profile | None, NodeGroupSelectionExplanation]:
    """Rank `candidates` (already-eligible output of resolve_candidates())
    and pick one, deterministically.

    Sort key is `(-total, latency_rank, profile_id)`: `total` (the real
    factors) decides first; fresh latency only breaks ties within an
    already-equal `total`, never outweighs it (see CandidateScore's
    docstring for why latency is not summed into `total`); ascending
    `profile_id` is the final, always-available tie-break, mirroring
    rules/rule_engine.py's existing `(priority, name)` sort convention.
    Same input always produces the same winner - reproducible, explainable
    selection, never order-of-iteration-dependent.

    Only called for selection_mode=AUTO; MANUAL is a hard pin resolved
    entirely outside this function (Task 14.3) and never reaches scoring.
    """
    ranked = rank_candidates(candidates, group.resilience_policy, config)
    if not ranked:
        return None, NodeGroupSelectionExplanation(
            group_name=group.name,
            result=NodeGroupSelectionResult.UNAVAILABLE,
            selected_profile_id=None,
        )

    winner = ranked[0]
    # Today only resilience_score is ever non-zero in `total` (see
    # AUD-P14-001 / CandidateScore docstring), so this attribution is
    # accurate: no other candidate to compare against, a real margin in
    # `total`, a fresh-latency tie-break, or a final tie broken by id.
    # Revisit once health_score is ever non-neutral too - it will need to
    # name whichever factor actually produced the winning margin in
    # `total`, not assume it was resilience_score.
    if len(ranked) == 1:
        decided_by = "only_candidate"
    elif ranked[0].total != ranked[1].total:
        decided_by = "resilience_score"
    elif _latency_rank(ranked[0]) != _latency_rank(ranked[1]):
        decided_by = "latency_tie_break"
    else:
        decided_by = "tie_break_by_id"

    by_id = {profile.id: profile for profile in candidates}
    explanation = NodeGroupSelectionExplanation(
        group_name=group.name,
        result=NodeGroupSelectionResult.SELECTED,
        selected_profile_id=winner.profile_id,
        candidates=ranked,
        decided_by=decided_by,
    )
    return by_id[winner.profile_id], explanation
