from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from config.paths import resolve_config_dir
from config.persistence import atomic_write_bytes
from rules.models import RuleGroup
from rules.rule_parser import RuleParseError, parse_singbox_ruleset_json
from rules.ruleset_trust import (
    RuleSetFailureBehavior,
    RuleSetKind,
    RuleSetLoadState,
    RuleSetStatus,
    RuleSetTrustPolicy,
    RuleSetTrustRegistry,
)
from rules.ruleset_trust_store import RuleSetTrustStore


FetchRuleSet = Callable[[str, float], bytes]
NowFn = Callable[[], datetime]


class RuleSetLifecycleError(RuntimeError):
    pass


class RuleSetRuntimeError(RuleSetLifecycleError):
    pass


@dataclass(slots=True, frozen=True)
class RuleSetRefreshResult:
    id: str
    state: str
    refreshed: bool
    used_existing_cache: bool
    cache_path: str | None
    loaded_sha256: str | None
    error: str | None
    critical: bool
    failure_behavior: str

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "state": self.state,
            "refreshed": self.refreshed,
            "used_existing_cache": self.used_existing_cache,
            "cache_path": self.cache_path,
            "loaded_sha256": self.loaded_sha256,
            "error": self.error,
            "critical": self.critical,
            "failure_behavior": self.failure_behavior,
        }


@dataclass(slots=True, frozen=True)
class RuleSetRuntimePlan:
    tags: dict[str, str]
    declarations: list[dict[str, str]]
    results: list[RuleSetRefreshResult]

    def to_dict(self) -> dict[str, object]:
        return {
            "tags": dict(sorted(self.tags.items())),
            "declarations": list(self.declarations),
            "results": [result.to_dict() for result in self.results],
        }


def default_ruleset_cache_dir() -> Path:
    return resolve_config_dir() / "rulesets" / "cache"


def referenced_rule_set_ids(groups: list[RuleGroup]) -> set[str]:
    ids: set[str] = set()
    for group in groups:
        if not group.enabled:
            continue
        for rule in group.rules:
            if not rule.enabled:
                continue
            for key in ("ruleset_remote", "ruleset_builtin"):
                ids.update(rule.conditions.get(key, ()))
    return ids


def rule_set_tag(rule_set_id: str) -> str:
    digest = hashlib.sha256(rule_set_id.encode("utf-8")).hexdigest()[:16]
    return f"wd-rule-set-{digest}"


def default_fetch_rule_set(source: str, timeout: float) -> bytes:
    parsed = urlparse(source)
    if parsed.scheme != "https":
        raise RuleSetLifecycleError("remote rule-set downloads require https sources")
    request = urllib.request.Request(source, headers={"User-Agent": "WatchdogVPN"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.URLError as exc:
        raise RuleSetLifecycleError(f"download failed: {exc}") from exc


class RuleSetLifecycleManager:
    def __init__(
        self,
        store: RuleSetTrustStore | None = None,
        cache_dir: Path | None = None,
        fetch_rule_set: FetchRuleSet | None = None,
        now: NowFn | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.store = store or RuleSetTrustStore()
        self.cache_dir = cache_dir or default_ruleset_cache_dir()
        self.fetch_rule_set = fetch_rule_set or default_fetch_rule_set
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.timeout_seconds = timeout_seconds

    def status(self) -> RuleSetTrustRegistry:
        return self.store.load()

    def refresh(
        self,
        rule_set_ids: set[str] | None = None,
        *,
        force: bool = False,
        evict: bool = True,
    ) -> list[RuleSetRefreshResult]:
        registry = self.store.load()
        selected_ids = sorted(rule_set_ids if rule_set_ids is not None else registry.policies)
        missing = [rule_set_id for rule_set_id in selected_ids if rule_set_id not in registry.policies]
        if missing:
            raise RuleSetLifecycleError(
                "rule-set trust policy not found: " + ", ".join(missing)
            )

        statuses: list[RuleSetStatus] = []
        results: list[RuleSetRefreshResult] = []
        for rule_set_id in selected_ids:
            policy = registry.policies[rule_set_id]
            previous = registry.status_for(rule_set_id)
            status, result = self._refresh_one(policy, previous, force=force)
            statuses.append(status)
            results.append(result)
        if statuses:
            self.store.update_statuses(statuses)
        if evict:
            self.evict_unowned_cache_files(set(registry.policies))
        return results

    def runtime_plan(
        self,
        groups: list[RuleGroup],
        *,
        refresh_due: bool = True,
    ) -> RuleSetRuntimePlan:
        referenced = referenced_rule_set_ids(groups)
        if not referenced:
            return RuleSetRuntimePlan(tags={}, declarations=[], results=[])

        registry = self.store.load()
        missing = sorted(rule_set_id for rule_set_id in referenced if rule_set_id not in registry.policies)
        if missing:
            raise RuleSetRuntimeError(
                "referenced rule-set has no trust policy: " + ", ".join(missing)
            )

        results: list[RuleSetRefreshResult] = []
        if refresh_due:
            due = {
                rule_set_id
                for rule_set_id in referenced
                if self._refresh_due(registry.policies[rule_set_id], registry.status_for(rule_set_id))
            }
            if due:
                results = self.refresh(due, force=False)
                registry = self.store.load()

        tags: dict[str, str] = {}
        declarations: list[dict[str, str]] = []
        failures: list[str] = []
        for rule_set_id in sorted(referenced):
            policy = registry.policies[rule_set_id]
            status = registry.status_for(rule_set_id)
            if status.state in {RuleSetLoadState.LOADED, RuleSetLoadState.STALE} and status.cache_path:
                tag = rule_set_tag(rule_set_id)
                tags[rule_set_id] = tag
                declarations.append(
                    {
                        "type": "local",
                        "tag": tag,
                        "format": _source_format(policy.source),
                        "path": status.cache_path,
                    }
                )
                continue
            if policy.failure_behavior == RuleSetFailureBehavior.FAIL_CLOSED:
                failures.append(f"{rule_set_id}: {status.error or status.state.value}")
        if failures:
            raise RuleSetRuntimeError(
                "critical rule-set unavailable; refusing runtime start: " + "; ".join(failures)
            )
        return RuleSetRuntimePlan(tags=tags, declarations=declarations, results=results)

    def evict_unowned_cache_files(self, owned_rule_set_ids: set[str]) -> list[str]:
        if not self.cache_dir.exists():
            return []
        registry = self.store.load()
        owned_names = {
            self._cache_path_for(policy).name
            for policy in registry.policies.values()
            if policy.id in owned_rule_set_ids
        }
        owned_names.update(
            Path(status.cache_path).name
            for rule_set_id, status in registry.statuses.items()
            if rule_set_id in owned_rule_set_ids and status.cache_path
        )
        removed: list[str] = []
        for path in self.cache_dir.iterdir():
            if not path.is_file() or path.name in owned_names or path.name.endswith(".lock"):
                continue
            path.unlink()
            removed.append(str(path))
        return removed

    def _refresh_one(
        self,
        policy: RuleSetTrustPolicy,
        previous: RuleSetStatus,
        *,
        force: bool,
    ) -> tuple[RuleSetStatus, RuleSetRefreshResult]:
        existing_cache = self._existing_cache_path(policy, previous)
        if not force and not self._refresh_due(policy, previous) and existing_cache is not None:
            result = self._result(
                policy,
                previous,
                refreshed=False,
                used_existing_cache=True,
            )
            return previous, result

        checked_at = _timestamp(self.now())
        try:
            payload = self._load_payload(policy)
            actual_sha = hashlib.sha256(payload).hexdigest()
            if policy.expected_sha256 and actual_sha != policy.expected_sha256:
                raise RuleSetLifecycleError(
                    f"sha256 mismatch: expected {policy.expected_sha256}, got {actual_sha}"
                )
            _validate_payload(policy, payload)
            cache_path = self._cache_path_for(policy)
            atomic_write_bytes(cache_path, payload)
            status = RuleSetStatus(
                id=policy.id,
                state=RuleSetLoadState.LOADED,
                loaded_sha256=actual_sha,
                last_loaded_at=checked_at,
                last_checked_at=checked_at,
                cache_path=str(cache_path),
                error=None,
            )
            return status, self._result(policy, status, refreshed=True, used_existing_cache=False)
        except Exception as exc:
            error = str(exc)
            fallback = self._fallback_status(policy, previous, checked_at, error)
            return fallback, self._result(
                policy,
                fallback,
                refreshed=False,
                used_existing_cache=fallback.state == RuleSetLoadState.STALE,
            )

    def _fallback_status(
        self,
        policy: RuleSetTrustPolicy,
        previous: RuleSetStatus,
        checked_at: str,
        error: str,
    ) -> RuleSetStatus:
        existing_cache = self._existing_cache_path(policy, previous)
        if existing_cache is not None and self._cache_fresh(policy, previous):
            return RuleSetStatus(
                id=policy.id,
                state=RuleSetLoadState.STALE,
                loaded_sha256=previous.loaded_sha256,
                last_loaded_at=previous.last_loaded_at,
                last_checked_at=checked_at,
                cache_path=str(existing_cache),
                error=error,
            )
        return RuleSetStatus(
            id=policy.id,
            state=RuleSetLoadState.FAILED,
            loaded_sha256=previous.loaded_sha256,
            last_loaded_at=previous.last_loaded_at,
            last_checked_at=checked_at,
            cache_path=str(existing_cache) if existing_cache else previous.cache_path,
            error=error,
        )

    def _load_payload(self, policy: RuleSetTrustPolicy) -> bytes:
        if policy.kind == RuleSetKind.REMOTE:
            return self.fetch_rule_set(policy.source, self.timeout_seconds)
        path = Path(policy.source)
        if not path.exists():
            raise RuleSetLifecycleError(f"built-in rule-set source not found: {path}")
        return path.read_bytes()

    def _cache_path_for(self, policy: RuleSetTrustPolicy) -> Path:
        digest = hashlib.sha256(policy.id.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.{_cache_extension(policy.source)}"

    def _existing_cache_path(
        self,
        policy: RuleSetTrustPolicy,
        previous: RuleSetStatus,
    ) -> Path | None:
        candidates = []
        if previous.cache_path:
            candidates.append(Path(previous.cache_path))
        candidates.append(self._cache_path_for(policy))
        for path in candidates:
            if path.exists() and path.is_file():
                return path
        return None

    def _refresh_due(self, policy: RuleSetTrustPolicy, status: RuleSetStatus) -> bool:
        if status.state not in {RuleSetLoadState.LOADED, RuleSetLoadState.STALE}:
            return True
        if not status.cache_path or not Path(status.cache_path).exists():
            return True
        if not status.last_checked_at:
            return True
        checked = _parse_timestamp(status.last_checked_at)
        if checked is None:
            return True
        return (self.now() - checked).total_seconds() >= policy.update_interval_seconds

    def _cache_fresh(self, policy: RuleSetTrustPolicy, status: RuleSetStatus) -> bool:
        if not status.last_loaded_at:
            return False
        loaded = _parse_timestamp(status.last_loaded_at)
        if loaded is None:
            return False
        return (self.now() - loaded).total_seconds() <= policy.max_stale_seconds

    def _result(
        self,
        policy: RuleSetTrustPolicy,
        status: RuleSetStatus,
        *,
        refreshed: bool,
        used_existing_cache: bool,
    ) -> RuleSetRefreshResult:
        return RuleSetRefreshResult(
            id=policy.id,
            state=status.state.value,
            refreshed=refreshed,
            used_existing_cache=used_existing_cache,
            cache_path=status.cache_path,
            loaded_sha256=status.loaded_sha256,
            error=status.error,
            critical=policy.critical,
            failure_behavior=policy.failure_behavior.value,
        )


def _validate_payload(policy: RuleSetTrustPolicy, payload: bytes) -> None:
    if _source_format(policy.source) != "source":
        return
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuleSetLifecycleError("source rule-set must be valid UTF-8") from exc
    try:
        parse_singbox_ruleset_json(text)
    except RuleParseError as exc:
        raise RuleSetLifecycleError(f"malformed source rule-set: {exc}") from exc


def _source_format(source: str) -> str:
    return "binary" if _cache_extension(source) == "srs" else "source"


def _cache_extension(source: str) -> str:
    path = urlparse(source).path
    suffix = Path(path).suffix.lower()
    if suffix == ".srs":
        return "srs"
    return "json"


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
