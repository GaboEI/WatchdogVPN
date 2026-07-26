"""L1 unit tests for the pure compatibility support model (Phase 23.7.5.2).

Table-driven, deterministic, no network, no real clock, no root, no host state.
"""

from __future__ import annotations

import pathlib
import unittest
from datetime import datetime, timedelta

from compat import (
    CoreCapabilityStatus,
    DomainError,
    FreshnessState,
    HostReadiness,
    ProtocolReadiness,
    ProtocolRuntimeStatus,
    RollingFacts,
    StableReleaseFacts,
    SupportClassification,
    check_rolling_invariants,
    check_stable_invariants,
    classify_host_readiness,
    classify_protocol_readiness,
    classify_support,
    classify_support_rolling,
    classify_support_stable,
    evaluate_freshness,
    parse,
    to_value,
)

NOW = datetime(2026, 7, 26, 12, 0, 0)
EXPIRY = timedelta(days=30)


def stable(**overrides) -> StableReleaseFacts:
    """Build stable facts from a plausible in-contract base; override per case."""
    base = dict(
        has_adapter=True,
        meets_technical_floor=True,
        admitted=False,
        expressly_excluded=False,
        future_or_unevaluated=False,
        eol_or_withdrawn=False,
        vendor_maintained=True,
        ci_green=True,
        is_derivative_without_own_evidence=False,
        has_valid_field_certification=False,
    )
    base.update(overrides)
    return StableReleaseFacts(**base)


def rolling(**overrides) -> RollingFacts:
    base = dict(
        has_adapter=True,
        meets_technical_floor=True,
        expressly_excluded=False,
        eol_or_withdrawn=False,
        is_derivative_without_own_evidence=False,
        has_valid_field_certification=False,
        last_validated=None,
    )
    base.update(overrides)
    return RollingFacts(**base)


class StableClassificationTests(unittest.TestCase):
    def test_stable_precedence_table(self) -> None:
        cases = [
            # (label, facts, expected)
            ("no_adapter", stable(has_adapter=False), SupportClassification.UNSUPPORTED),
            ("below_floor", stable(meets_technical_floor=False), SupportClassification.UNSUPPORTED),
            ("eol", stable(eol_or_withdrawn=True), SupportClassification.UNSUPPORTED),
            ("excluded", stable(expressly_excluded=True), SupportClassification.UNSUPPORTED),
            ("certified", stable(admitted=True, has_valid_field_certification=True), SupportClassification.CERTIFIED),
            ("derivative_inferred", stable(is_derivative_without_own_evidence=True), SupportClassification.FAMILY_INFERRED),
            ("future", stable(future_or_unevaluated=True), SupportClassification.EXPERIMENTAL),
            ("supported", stable(admitted=True), SupportClassification.SUPPORTED),
            ("admitted_but_ci_red", stable(admitted=True, ci_green=False), SupportClassification.EXPERIMENTAL),
            ("admitted_but_unmaintained", stable(admitted=True, vendor_maintained=False), SupportClassification.EXPERIMENTAL),
            # disqualifier precedence over higher-evidence facts:
            ("eol_beats_admitted", stable(eol_or_withdrawn=True, admitted=False, vendor_maintained=True), SupportClassification.UNSUPPORTED),
            ("no_adapter_beats_derivative", stable(has_adapter=False, is_derivative_without_own_evidence=True), SupportClassification.UNSUPPORTED),
            # a derivative with its own field cert is certified, not merely inferred:
            ("certified_derivative", stable(admitted=True, has_valid_field_certification=True, is_derivative_without_own_evidence=False), SupportClassification.CERTIFIED),
        ]
        for label, facts, expected in cases:
            with self.subTest(label):
                result = classify_support_stable(facts)
                self.assertIs(result, expected)
                check_stable_invariants(facts, result)

    def test_all_five_states_reachable(self) -> None:
        produced = {
            classify_support_stable(stable(admitted=True, has_valid_field_certification=True)),
            classify_support_stable(stable(admitted=True)),
            classify_support_stable(stable(is_derivative_without_own_evidence=True)),
            classify_support_stable(stable(future_or_unevaluated=True)),
            classify_support_stable(stable(has_adapter=False)),
        }
        self.assertEqual(produced, set(SupportClassification))

    def test_local_probe_cannot_change_classification(self) -> None:
        # The support classifiers accept no host/probe input at all.
        import inspect

        stable_params = set(inspect.signature(classify_support_stable).parameters)
        self.assertEqual(stable_params, {"f"})
        rolling_params = set(inspect.signature(classify_support_rolling).parameters)
        self.assertEqual(rolling_params, {"f", "expiry", "now"})


class StableContradictionTests(unittest.TestCase):
    def test_impossible_stable_inputs_raise(self) -> None:
        cases = [
            stable(admitted=True, expressly_excluded=True),
            stable(admitted=True, future_or_unevaluated=True),
            stable(admitted=True, eol_or_withdrawn=True),
            stable(expressly_excluded=True, future_or_unevaluated=True),
            stable(future_or_unevaluated=True, eol_or_withdrawn=True),
            stable(has_valid_field_certification=True, has_adapter=False),
            stable(has_valid_field_certification=True, meets_technical_floor=False),
            stable(has_valid_field_certification=True, is_derivative_without_own_evidence=True),
        ]
        for facts in cases:
            with self.subTest(facts=facts):
                with self.assertRaises(DomainError):
                    classify_support_stable(facts)


class RollingClassificationTests(unittest.TestCase):
    def test_rolling_freshness_table(self) -> None:
        cases = [
            ("current", rolling(last_validated=NOW - timedelta(days=1)), SupportClassification.SUPPORTED),
            ("expired", rolling(last_validated=NOW - timedelta(days=60)), SupportClassification.EXPERIMENTAL),
            ("absent_evidence", rolling(last_validated=None), SupportClassification.EXPERIMENTAL),
            ("certified", rolling(last_validated=NOW - timedelta(days=1), has_valid_field_certification=True), SupportClassification.CERTIFIED),
            ("derivative_inferred", rolling(is_derivative_without_own_evidence=True), SupportClassification.FAMILY_INFERRED),
            ("excluded", rolling(expressly_excluded=True), SupportClassification.UNSUPPORTED),
            ("eol", rolling(eol_or_withdrawn=True), SupportClassification.UNSUPPORTED),
            ("no_adapter", rolling(has_adapter=False), SupportClassification.UNSUPPORTED),
            ("below_floor", rolling(meets_technical_floor=False), SupportClassification.UNSUPPORTED),
        ]
        for label, facts, expected in cases:
            with self.subTest(label):
                result = classify_support_rolling(facts, expiry=EXPIRY, now=NOW)
                self.assertIs(result, expected)
                freshness = evaluate_freshness(facts.last_validated, EXPIRY, NOW)
                check_rolling_invariants(facts, result, freshness=freshness)

    def test_local_capability_does_not_substitute_support_evidence(self) -> None:
        # No host-capability input exists on the rolling classifier: a "correct
        # local capability" cannot make expired evidence look supported.
        facts = rolling(last_validated=NOW - timedelta(days=90))
        self.assertIs(
            classify_support_rolling(facts, expiry=EXPIRY, now=NOW),
            SupportClassification.EXPERIMENTAL,
        )


class FreshnessTests(unittest.TestCase):
    def test_injected_clock_is_deterministic(self) -> None:
        lv = NOW - timedelta(days=20)
        self.assertIs(evaluate_freshness(lv, EXPIRY, NOW), FreshnessState.CURRENT)
        later = NOW + timedelta(days=20)  # same last_validated, clock moved forward
        self.assertIs(evaluate_freshness(lv, EXPIRY, later), FreshnessState.EXPIRED)

    def test_states(self) -> None:
        self.assertIs(evaluate_freshness(None, EXPIRY, NOW), FreshnessState.ABSENT)
        self.assertIs(evaluate_freshness(NOW - timedelta(days=29), EXPIRY, NOW), FreshnessState.CURRENT)
        self.assertIs(evaluate_freshness(NOW - timedelta(days=31), EXPIRY, NOW), FreshnessState.EXPIRED)

    def test_future_last_validated_is_domain_error(self) -> None:
        with self.assertRaises(DomainError):
            evaluate_freshness(NOW + timedelta(days=1), EXPIRY, NOW)

    def test_non_timedelta_expiry_is_domain_error(self) -> None:
        with self.assertRaises(DomainError):
            evaluate_freshness(NOW, 30, NOW)  # type: ignore[arg-type]


class HostReadinessTests(unittest.TestCase):
    def test_host_table(self) -> None:
        S = CoreCapabilityStatus
        cases = [
            ("all_present", [S.PRESENT, S.PRESENT], HostReadiness.READY),
            ("needs_prep", [S.PRESENT, S.PROVISIONABLE], HostReadiness.NEEDS_PREPARATION),
            ("prep_failed", [S.PRESENT, S.PREPARATION_FAILED], HostReadiness.PREPARATION_FAILED),
            ("incompatible", [S.PRESENT, S.IMPOSSIBLE], HostReadiness.INCOMPATIBLE),
            ("impossible_wins", [S.PROVISIONABLE, S.PREPARATION_FAILED, S.IMPOSSIBLE], HostReadiness.INCOMPATIBLE),
            ("prep_failed_beats_provisionable", [S.PROVISIONABLE, S.PREPARATION_FAILED], HostReadiness.PREPARATION_FAILED),
            ("empty_is_ready", [], HostReadiness.READY),
        ]
        for label, statuses, expected in cases:
            with self.subTest(label):
                self.assertIs(classify_host_readiness(statuses), expected)

    def test_exhausted_preparation_is_not_unsupported(self) -> None:
        # unsupported is not even a host state; an exhausted chain is preparation_failed.
        result = classify_host_readiness([CoreCapabilityStatus.PREPARATION_FAILED])
        self.assertIs(result, HostReadiness.PREPARATION_FAILED)
        self.assertNotIn("unsupported", [s.value for s in HostReadiness])


class ProtocolReadinessTests(unittest.TestCase):
    def test_protocol_table(self) -> None:
        R = ProtocolRuntimeStatus
        cases = [
            ("operable", [R.PRESENT], ProtocolReadiness.OPERABLE),
            ("operable_multi", [R.PRESENT, R.PRESENT], ProtocolReadiness.OPERABLE),
            ("provisionable", [R.PRESENT, R.PROVISIONABLE], ProtocolReadiness.PROVISIONABLE),
            ("absent", [R.PRESENT, R.ABSENT], ProtocolReadiness.ABSENT),
            ("unsupported_here", [R.IMPOSSIBLE], ProtocolReadiness.UNSUPPORTED_HERE),
            ("impossible_wins", [R.PROVISIONABLE, R.ABSENT, R.IMPOSSIBLE], ProtocolReadiness.UNSUPPORTED_HERE),
            ("absent_beats_provisionable", [R.PROVISIONABLE, R.ABSENT], ProtocolReadiness.ABSENT),
        ]
        for label, statuses, expected in cases:
            with self.subTest(label):
                self.assertIs(classify_protocol_readiness(statuses), expected)

    def test_empty_runtimes_is_domain_error(self) -> None:
        with self.assertRaises(DomainError):
            classify_protocol_readiness([])


class OrthogonalityTests(unittest.TestCase):
    def test_supported_ready_with_mixed_protocols_is_valid(self) -> None:
        # The mandatory example: a supported release, a ready host, one operable
        # protocol and one provisionable protocol coexist and are independent.
        support = classify_support(stable(admitted=True))
        host = classify_host_readiness([CoreCapabilityStatus.PRESENT, CoreCapabilityStatus.PRESENT])
        vless = classify_protocol_readiness([ProtocolRuntimeStatus.PRESENT])
        amneziawg = classify_protocol_readiness([ProtocolRuntimeStatus.PROVISIONABLE])
        self.assertIs(support, SupportClassification.SUPPORTED)
        self.assertIs(host, HostReadiness.READY)
        self.assertIs(vless, ProtocolReadiness.OPERABLE)
        self.assertIs(amneziawg, ProtocolReadiness.PROVISIONABLE)

    def test_absent_protocol_does_not_affect_host_or_other_protocols(self) -> None:
        host = classify_host_readiness([CoreCapabilityStatus.PRESENT])  # no protocol input
        other = classify_protocol_readiness([ProtocolRuntimeStatus.PRESENT])
        missing = classify_protocol_readiness([ProtocolRuntimeStatus.ABSENT])
        self.assertIs(host, HostReadiness.READY)
        self.assertIs(other, ProtocolReadiness.OPERABLE)
        self.assertIs(missing, ProtocolReadiness.ABSENT)


class InvariantTests(unittest.TestCase):
    def test_invariant_violations_raise(self) -> None:
        # 1: certified without evidence
        with self.assertRaises(DomainError):
            check_stable_invariants(stable(has_valid_field_certification=False), SupportClassification.CERTIFIED)
        # 2: stable supported without admitted
        with self.assertRaises(DomainError):
            check_stable_invariants(stable(admitted=False), SupportClassification.SUPPORTED)
        # 3: family_inferred with a valid certification
        with self.assertRaises(DomainError):
            check_stable_invariants(stable(has_valid_field_certification=True, admitted=True), SupportClassification.FAMILY_INFERRED)
        # 4: experimental representing an excluded release
        with self.assertRaises(DomainError):
            check_stable_invariants(stable(expressly_excluded=True), SupportClassification.EXPERIMENTAL)
        # rolling supported without current evidence
        with self.assertRaises(DomainError):
            check_rolling_invariants(rolling(), SupportClassification.SUPPORTED, freshness=FreshnessState.EXPIRED)

    def test_classifier_output_always_satisfies_invariants(self) -> None:
        for facts in (
            stable(admitted=True, has_valid_field_certification=True),
            stable(admitted=True),
            stable(is_derivative_without_own_evidence=True),
            stable(future_or_unevaluated=True),
            stable(has_adapter=False),
        ):
            result = classify_support_stable(facts)
            check_stable_invariants(facts, result)  # must not raise


class SerializationTests(unittest.TestCase):
    def test_frozen_public_strings(self) -> None:
        self.assertEqual(
            [s.value for s in SupportClassification],
            ["certified", "supported", "family_inferred", "experimental", "unsupported"],
        )
        self.assertEqual(
            [s.value for s in HostReadiness],
            ["ready", "needs_preparation", "preparation_failed", "incompatible"],
        )
        self.assertEqual(
            [s.value for s in ProtocolReadiness],
            ["operable", "provisionable", "absent", "unsupported_here"],
        )

    def test_round_trip(self) -> None:
        for enum_cls in (SupportClassification, HostReadiness, ProtocolReadiness, FreshnessState):
            for member in enum_cls:
                self.assertEqual(to_value(member), member.value)
                self.assertIs(parse(enum_cls, member.value), member)

    def test_unknown_value_and_bad_type_raise(self) -> None:
        with self.assertRaises(DomainError):
            parse(SupportClassification, "definitely_not_a_state")
        with self.assertRaises(DomainError):
            to_value("supported")  # a raw string is not a state


class NoHardcodedReleasesTests(unittest.TestCase):
    def test_model_source_has_no_real_distro_or_release(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[1]
        forbidden = [
            "ubuntu", "debian", "fedora", "arch", "cachyos", "mint", "kali",
            "rocky", "almalinux", "opensuse", "tumbleweed", "leap",
            "22.04", "24.04", "26.04", "noble", "focal", "jammy", "resolute",
        ]
        for name in ("support_model.py", "__init__.py"):
            text = (root / "compat" / name).read_text(encoding="utf-8").lower()
            for token in forbidden:
                self.assertNotIn(
                    token, text, f"{name} must not hardcode a real distro/release: {token}"
                )


if __name__ == "__main__":
    unittest.main()
