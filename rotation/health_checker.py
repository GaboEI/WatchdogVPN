from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

from drivers.base import BaseDriver
from models.profile import Profile
from rotation.health_targets import (
    DEFAULT_HEALTH_TARGETS,
    DEFAULT_SUCCESS_QUORUM,
    HealthProbeResult,
    probe_targets,
)


LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 5.0

# Drivers whose ConnectionState.mode CAN mean "traffic exits through the
# local SOCKS proxy when proxy_active is also True. Every other driver/state
# is treated as a full system tunnel and verified directly.
PROXY_BASED_MODES = frozenset({"sing-box"})

# Health is selected-egress reachability through a policy-controlled target
# quorum. A public-IP reflector is deliberately not a health prerequisite.
VerifyFn = Callable[[bool], HealthProbeResult]


@dataclass(frozen=True, slots=True)
class HealthCheckResult:
    """Result of one deep, policy-controlled health check."""

    status: str
    latency_ms: float | None = None
    classification: str = "unknown"


def verify_health_targets(
    via_proxy: bool,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    targets: tuple[str, ...] = DEFAULT_HEALTH_TARGETS,
    success_quorum: int = DEFAULT_SUCCESS_QUORUM,
) -> HealthProbeResult:
    return probe_targets(
        via_proxy=via_proxy,
        targets=targets,
        timeout=timeout,
        success_quorum=success_quorum,
    )


def _check_full(
    profile: Profile,
    driver: BaseDriver,
    verify: VerifyFn,
) -> HealthCheckResult:
    driver_status = driver.health_check()
    if driver_status == "down":
        LOGGER.warning("health_check_down profile_id=%s reason=tunnel_failure", profile.id)
        return HealthCheckResult(status="down", classification="tunnel_failure")

    state = driver.status()
    if state.mode in PROXY_BASED_MODES and state.proxy_active:
        probe = verify(True)
    elif state.tun_active:
        probe = verify(False)
    else:
        LOGGER.warning("health_check_down profile_id=%s reason=no_active_route", profile.id)
        return HealthCheckResult(status="down", classification="no_active_route")

    if not probe.reachable:
        LOGGER.warning(
            "health_check_degraded profile_id=%s reason=%s successful_targets=%s required_targets=%s",
            profile.id,
            probe.classification,
            probe.success_count,
            probe.required_successes,
        )
        return HealthCheckResult(status="degraded", classification=probe.classification)

    if probe.latency_ms is not None:
        LOGGER.info("health_check_latency profile_id=%s latency_ms=%s", profile.id, probe.latency_ms)

    if driver_status == "degraded":
        LOGGER.info("health_check_degraded profile_id=%s reason=driver_reported_degraded", profile.id)
        return HealthCheckResult(
            status="degraded",
            latency_ms=probe.latency_ms,
            classification="driver_degraded",
        )

    LOGGER.info("health_check_ok profile_id=%s successful_targets=%s", profile.id, probe.success_count)
    return HealthCheckResult(
        status="ok",
        latency_ms=probe.latency_ms,
        classification=probe.classification,
    )


def check(profile: Profile, driver: BaseDriver, verify: VerifyFn = verify_health_targets) -> str:
    return _check_full(profile, driver, verify).status


def check_with_latency(
    profile: Profile,
    driver: BaseDriver,
    verify: VerifyFn = verify_health_targets,
) -> HealthCheckResult:
    return _check_full(profile, driver, verify)
