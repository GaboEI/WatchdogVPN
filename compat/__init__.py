"""WatchdogVPN compatibility domain (Phase 23.7.5).

This package holds the compatibility contract's pure domain model. The manifest,
detection, provisioning and their integrations are added by later frozen tasks.
"""

from __future__ import annotations

from compat.support_model import (
    CoreCapabilityStatus,
    DomainError,
    FreshnessState,
    HostReadiness,
    ProtocolReadiness,
    ProtocolRuntimeStatus,
    ReleaseModel,
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

__all__ = [
    "CoreCapabilityStatus",
    "DomainError",
    "FreshnessState",
    "HostReadiness",
    "ProtocolReadiness",
    "ProtocolRuntimeStatus",
    "ReleaseModel",
    "RollingFacts",
    "StableReleaseFacts",
    "SupportClassification",
    "check_rolling_invariants",
    "check_stable_invariants",
    "classify_host_readiness",
    "classify_protocol_readiness",
    "classify_support",
    "classify_support_rolling",
    "classify_support_stable",
    "evaluate_freshness",
    "parse",
    "to_value",
]
