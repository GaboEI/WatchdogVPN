"""Policy-controlled multi-target egress health probes."""

from __future__ import annotations

import shutil
import statistics
import subprocess
import time
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit


DEFAULT_HEALTH_TARGETS = (
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.ietf.org/",
    "https://www.wikipedia.org/",
)
DEFAULT_SUCCESS_QUORUM = 2
MIN_HEALTH_TARGETS = 2
MAX_HEALTH_TARGETS = 8
LOCAL_SOCKS_PROXY = "127.0.0.1:2080"


@dataclass(frozen=True, slots=True)
class HealthTargetResult:
    target: str
    reachable: bool
    classification: str
    curl_exit_code: int | None
    latency_ms: float | None


@dataclass(frozen=True, slots=True)
class HealthProbeResult:
    targets: tuple[HealthTargetResult, ...]
    success_count: int
    required_successes: int
    classification: str
    latency_ms: float | None

    @property
    def reachable(self) -> bool:
        return self.success_count >= self.required_successes


def validate_targets(value: object, field_name: str = "rotation.health_targets") -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list of HTTPS URLs")
    if not MIN_HEALTH_TARGETS <= len(value) <= MAX_HEALTH_TARGETS:
        raise ValueError(
            f"{field_name} must contain between {MIN_HEALTH_TARGETS} and {MAX_HEALTH_TARGETS} targets"
        )

    targets: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} entries must be strings")
        target = item.strip()
        parsed = urlsplit(target)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError(
                f"{field_name} entries must be credential-free HTTPS URLs without fragments"
            )
        if target in targets:
            raise ValueError(f"{field_name} entries must be unique")
        targets.append(target)
    return tuple(targets)


def validate_success_quorum(
    value: object,
    targets: Iterable[str],
    field_name: str = "rotation.health_success_quorum",
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    target_count = len(tuple(targets))
    if value < 1 or value > target_count:
        raise ValueError(f"{field_name} must be between 1 and {target_count}")
    return value


def _target_failure_classification(exit_code: int) -> str:
    if exit_code in {5, 6}:
        # SOCKS hostname resolution occurs through the selected egress. A
        # resolution failure is evidence of DNS interference or outage, not
        # conclusive proof of poisoning.
        return "dns_interference_suspected"
    if exit_code == 22:
        return "third_party_service_failure"
    if exit_code in {7, 28, 35, 52, 55, 56, 92, 95, 97}:
        return "endpoint_censorship_or_network_interference_suspected"
    return "target_transport_failure"


def _overall_classification(results: tuple[HealthTargetResult, ...], required: int) -> str:
    successful = sum(item.reachable for item in results)
    if successful >= required:
        return "healthy"
    failures = {item.classification for item in results if not item.reachable}
    if successful:
        return "insufficient_target_quorum"
    if failures == {"dns_interference_suspected"}:
        return "dns_interference_suspected"
    if failures == {"third_party_service_failure"}:
        return "third_party_outage"
    if failures == {"endpoint_censorship_or_network_interference_suspected"}:
        return "endpoint_censorship_or_network_interference_suspected"
    if failures == {"probe_unavailable"}:
        return "probe_unavailable"
    return "all_targets_unreachable"


def probe_targets(
    *,
    via_proxy: bool,
    targets: Iterable[str] = DEFAULT_HEALTH_TARGETS,
    timeout: float,
    success_quorum: int = DEFAULT_SUCCESS_QUORUM,
) -> HealthProbeResult:
    checked_targets = tuple(targets)
    required = validate_success_quorum(success_quorum, checked_targets)
    if not shutil.which("curl"):
        results = tuple(
            HealthTargetResult(target, False, "probe_unavailable", None, None)
            for target in checked_targets
        )
        return HealthProbeResult(results, 0, required, "probe_unavailable", None)

    proxy_args = ["--socks5-hostname", LOCAL_SOCKS_PROXY] if via_proxy else []
    results: list[HealthTargetResult] = []
    for target in checked_targets:
        started = time.perf_counter()
        result = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                str(int(timeout)),
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                *proxy_args,
                target,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        latency_ms = round((time.perf_counter() - started) * 1000, 3)
        if result.returncode == 0:
            results.append(HealthTargetResult(target, True, "ok", 0, latency_ms))
        else:
            results.append(
                HealthTargetResult(
                    target,
                    False,
                    _target_failure_classification(result.returncode),
                    result.returncode,
                    None,
                )
            )

    frozen_results = tuple(results)
    successful_latencies = [item.latency_ms for item in frozen_results if item.latency_ms is not None]
    latency_ms = round(statistics.median(successful_latencies), 3) if successful_latencies else None
    return HealthProbeResult(
        targets=frozen_results,
        success_count=sum(item.reachable for item in frozen_results),
        required_successes=required,
        classification=_overall_classification(frozen_results, required),
        latency_ms=latency_ms,
    )
