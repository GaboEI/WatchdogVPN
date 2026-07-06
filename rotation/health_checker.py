from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Callable

from drivers.base import BaseDriver
from models.profile import Profile


LOGGER = logging.getLogger(__name__)

EXTERNAL_CHECK_URL = "https://example.com"
PUBLIC_IP_URL = "https://api.ipify.org"
LOCAL_SOCKS_PROXY = "127.0.0.1:2080"
DEFAULT_TIMEOUT_SECONDS = 5.0

# Drivers whose ConnectionState.mode CAN mean "traffic exits through the
# local SOCKS proxy at LOCAL_SOCKS_PROXY" when proxy_active is also True.
# Every other driver/state is treated as a full system tunnel (TUN-based),
# verified directly instead.
#
# This can't be inferred from ConnectionState.proxy_active alone: that flag
# is not used consistently across drivers. SingBoxDriver sets it to mean
# "the local SOCKS proxy is up", but a TUN-based driver (OpenVPN,
# OpenVPN+Cloak, AmneziaWG) could in principle set it to mean something else
# entirely - routing those through the proxy-verification path would
# misreport a healthy connection as "degraded". Membership here is necessary
# but not sufficient: a driver in PROXY_BASED_MODES with proxy_active=False
# (e.g. a future sing-box TUN connection mode, Phase 11) still falls through
# to direct/TUN verification below instead of being reported as "down".
PROXY_BASED_MODES = frozenset({"sing-box"})

# (reachable, public_ip, latency_ms) - latency_ms is None whenever reachable
# is False (nothing meaningful was timed) or a verify implementation simply
# doesn't measure it (e.g. a test fake with only two elements would break
# unpacking deliberately, forcing every real verify implementation to report
# all three - no silent partial adoption).
VerifyFn = Callable[[bool], "tuple[bool, str | None, float | None]"]


@dataclass(frozen=True, slots=True)
class HealthCheckResult:
    """Everything a single deep health check produced. `check()` below
    exposes only `.status` (its long-established, unchanged contract -
    RotationEngine's HealthCheckFn stays `Callable[[Profile, BaseDriver],
    str]`, untouched by Task 14.7). `check_with_latency()` exposes the
    rest for callers that want it, without a second implementation of the
    check logic - both call the same internal `_check_full()`.
    """

    status: str
    latency_ms: float | None = None


def _curl(args: list[str], timeout: float) -> tuple[bool, str]:
    if not shutil.which("curl"):
        return False, ""
    result = subprocess.run(
        ["curl", "--silent", "--show-error", "--fail", "--max-time", str(int(timeout)), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0, (result.stdout or "").strip()


def reachable_and_public_ip(
    via_proxy: bool,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    test_url: str = EXTERNAL_CHECK_URL,
) -> tuple[bool, str | None, float | None]:
    """`test_url` is a parameter, not a second module constant, so Task
    14.7's configurable `rotation.test_url` and the hardcoded default are
    the same code path - every profile measured in a given daemon run uses
    whatever single value is configured, never a per-profile URL. That is
    what makes latency comparable across candidates: one shared reference
    point, by construction, not by an extra check.
    """
    proxy_args = ["--socks5-hostname", LOCAL_SOCKS_PROXY] if via_proxy else []
    started = time.perf_counter()
    reachable, _ = _curl([*proxy_args, test_url], timeout)
    latency_ms = round((time.perf_counter() - started) * 1000, 3) if reachable else None
    if not reachable:
        return False, None, None
    ip_ok, ip_value = _curl([*proxy_args, PUBLIC_IP_URL], timeout)
    return True, (ip_value if ip_ok and ip_value else None), latency_ms


def _check_full(
    profile: Profile,
    driver: BaseDriver,
    verify: VerifyFn,
) -> HealthCheckResult:
    driver_status = driver.health_check()
    if driver_status == "down":
        LOGGER.warning("health_check_down profile_id=%s reason=driver_reported_down", profile.id)
        return HealthCheckResult(status="down")

    state = driver.status()
    if state.mode in PROXY_BASED_MODES and state.proxy_active:
        reachable, public_ip, latency_ms = verify(True)
    elif state.tun_active:
        # Also covers a driver whose mode is in PROXY_BASED_MODES but is
        # currently running in TUN mode instead (proxy_active=False) - e.g.
        # a future sing-box TUN connection mode (Phase 11). Falling through
        # here instead of short-circuiting to "down" keeps this correct
        # once a driver can report either transport depending on config.
        reachable, public_ip, latency_ms = verify(False)
    else:
        LOGGER.warning("health_check_down profile_id=%s reason=no_active_route", profile.id)
        return HealthCheckResult(status="down")

    if not reachable:
        LOGGER.warning(
            "health_check_degraded profile_id=%s reason=external_endpoint_unreachable",
            profile.id,
        )
        return HealthCheckResult(status="degraded")

    if public_ip:
        LOGGER.info("health_check_public_ip profile_id=%s public_ip=%s", profile.id, public_ip)
    if latency_ms is not None:
        LOGGER.info("health_check_latency profile_id=%s latency_ms=%s", profile.id, latency_ms)

    if driver_status == "degraded":
        LOGGER.info("health_check_degraded profile_id=%s reason=driver_reported_degraded", profile.id)
        return HealthCheckResult(status="degraded", latency_ms=latency_ms)

    LOGGER.info("health_check_ok profile_id=%s", profile.id)
    return HealthCheckResult(status="ok", latency_ms=latency_ms)


def check(profile: Profile, driver: BaseDriver, verify: VerifyFn = reachable_and_public_ip) -> str:
    return _check_full(profile, driver, verify).status


def check_with_latency(
    profile: Profile, driver: BaseDriver, verify: VerifyFn = reachable_and_public_ip
) -> HealthCheckResult:
    return _check_full(profile, driver, verify)
