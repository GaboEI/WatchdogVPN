from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from models.connection_state import ALLOWED_STATUSES

from config.persistence import (
    PersistentValidationError,
    reject_unknown_keys,
    strict_bool,
    strict_int,
)


METRICS_SCHEMA_VERSION = 1
DEFAULT_METRICS_RETENTION_DAYS = 7
MAX_METRICS_RETENTION_DAYS = 30
DEFAULT_METRICS_MAX_BYTES = 1024 * 1024
MAX_METRICS_MAX_BYTES = 10 * 1024 * 1024


class MetricsRedactionMode(str, Enum):
    OFF = "off"
    AGGREGATE = "aggregate"
    DETAILED = "detailed"


METRICS_BUCKET_FIELDS = frozenset(
    {
        "bucket_start",
        "bucket_end",
        "counters",
    }
)

AGGREGATE_COUNTER_KEYS = frozenset(
    {
        "command.connect.attempt",
        "command.connect.success",
        "command.connect.failure",
        "command.disconnect.attempt",
        "command.disconnect.success",
        "command.disconnect.failure",
        "rotation.manual.attempt",
        "rotation.scheduled.attempt",
        "node_group.auto_test.attempt",
        "node_group.auto_test.selected",
        "node_group.auto_test.unavailable",
        "node_group.auto_test.unknown",
        "error.runtime",
        "route_action.recorded",
        "rule_group.recorded",
        "profile.event",
    }
)
AGGREGATE_STATUS_COUNTER_PREFIXES = (
    "rotation.manual.status.",
    "rotation.scheduled.status.",
    "health_check.status.",
    "recovery.status.",
)


def is_aggregate_counter_key(key: str) -> bool:
    if key in AGGREGATE_COUNTER_KEYS:
        return True
    return any(
        key == f"{prefix}{status}"
        for prefix in AGGREGATE_STATUS_COUNTER_PREFIXES
        for status in ALLOWED_STATUSES
    )


def aggregate_counters(counters: Mapping[str, int]) -> dict[str, int]:
    """Return only the fixed, non-identifying aggregate counter dimensions."""
    return {
        key: value
        for key, value in counters.items()
        if isinstance(key, str) and is_aggregate_counter_key(key)
    }


METRICS_DOCUMENT_FIELDS = frozenset(
    {
        "schema_version",
        "enabled",
        "retention_days",
        "redaction_mode",
        "max_bytes",
        "buckets",
        "updated_at",
    }
)


@dataclass(frozen=True, slots=True)
class MetricsBucket:
    bucket_start: str
    bucket_end: str
    counters: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_iso_datetime(self.bucket_start, "metrics.bucket_start")
        _require_iso_datetime(self.bucket_end, "metrics.bucket_end")
        _validate_counter_mapping(self.counters, "metrics.bucket.counters")

    def to_dict(self) -> dict[str, object]:
        return {
            "bucket_start": self.bucket_start,
            "bucket_end": self.bucket_end,
            "counters": dict(sorted(self.counters.items())),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "MetricsBucket":
        reject_unknown_keys(data, METRICS_BUCKET_FIELDS, "metrics bucket")
        counters = data.get("counters", {})
        if not isinstance(counters, dict):
            raise PersistentValidationError("metrics.bucket.counters must be an object")
        return cls(
            bucket_start=_require_string(
                data.get("bucket_start"),
                "metrics.bucket_start",
            ),
            bucket_end=_require_string(data.get("bucket_end"), "metrics.bucket_end"),
            counters={
                str(key): strict_int(value, f"metrics counter {key}")
                for key, value in counters.items()
            },
        )


@dataclass(frozen=True, slots=True)
class MetricsDocument:
    schema_version: int = METRICS_SCHEMA_VERSION
    enabled: bool = False
    retention_days: int = DEFAULT_METRICS_RETENTION_DAYS
    redaction_mode: MetricsRedactionMode = MetricsRedactionMode.AGGREGATE
    max_bytes: int = DEFAULT_METRICS_MAX_BYTES
    buckets: tuple[MetricsBucket, ...] = ()
    updated_at: str | None = None

    def __post_init__(self) -> None:
        if (
            strict_int(self.schema_version, "metrics.schema_version")
            != METRICS_SCHEMA_VERSION
        ):
            raise PersistentValidationError(
                f"metrics.schema_version must be {METRICS_SCHEMA_VERSION}"
            )
        strict_bool(self.enabled, "metrics.enabled")
        retention_days = strict_int(self.retention_days, "metrics.retention_days")
        if retention_days < 1 or retention_days > MAX_METRICS_RETENTION_DAYS:
            raise PersistentValidationError(
                f"metrics.retention_days must be between 1 and {MAX_METRICS_RETENTION_DAYS}"
            )
        max_bytes = strict_int(self.max_bytes, "metrics.max_bytes")
        if max_bytes < 1024 or max_bytes > MAX_METRICS_MAX_BYTES:
            raise PersistentValidationError(
                f"metrics.max_bytes must be between 1024 and {MAX_METRICS_MAX_BYTES}"
            )
        if not isinstance(self.redaction_mode, MetricsRedactionMode):
            try:
                object.__setattr__(
                    self,
                    "redaction_mode",
                    MetricsRedactionMode(str(self.redaction_mode)),
                )
            except ValueError as exc:
                raise PersistentValidationError(
                    "metrics.redaction_mode must be one of: off, aggregate, detailed"
                ) from exc
        if self.updated_at is not None:
            _require_iso_datetime(self.updated_at, "metrics.updated_at")

    def with_updated_at_now(self) -> "MetricsDocument":
        return MetricsDocument(
            schema_version=self.schema_version,
            enabled=self.enabled,
            retention_days=self.retention_days,
            redaction_mode=self.redaction_mode,
            max_bytes=self.max_bytes,
            buckets=self.buckets,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "enabled": self.enabled,
            "retention_days": self.retention_days,
            "redaction_mode": self.redaction_mode.value,
            "max_bytes": self.max_bytes,
            "buckets": [bucket.to_dict() for bucket in self.buckets],
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "MetricsDocument":
        reject_unknown_keys(data, METRICS_DOCUMENT_FIELDS, "metrics document")
        raw_buckets = data.get("buckets", [])
        if not isinstance(raw_buckets, list):
            raise PersistentValidationError("metrics.buckets must be a list")
        try:
            redaction_mode = MetricsRedactionMode(
                _require_string(
                    data.get("redaction_mode", MetricsRedactionMode.AGGREGATE.value),
                    "metrics.redaction_mode",
                )
            )
        except ValueError as exc:
            raise PersistentValidationError(
                "metrics.redaction_mode must be one of: off, aggregate, detailed"
            ) from exc
        buckets: list[MetricsBucket] = []
        for item in raw_buckets:
            if not isinstance(item, dict):
                raise PersistentValidationError(
                    "metrics.buckets entries must be objects"
                )
            buckets.append(MetricsBucket.from_dict(item))
        return cls(
            schema_version=strict_int(
                data.get("schema_version", METRICS_SCHEMA_VERSION),
                "metrics.schema_version",
            ),
            enabled=strict_bool(data.get("enabled", False), "metrics.enabled"),
            retention_days=strict_int(
                data.get("retention_days", DEFAULT_METRICS_RETENTION_DAYS),
                "metrics.retention_days",
            ),
            redaction_mode=redaction_mode,
            max_bytes=strict_int(
                data.get("max_bytes", DEFAULT_METRICS_MAX_BYTES),
                "metrics.max_bytes",
            ),
            buckets=tuple(buckets),
            updated_at=(
                _require_string(data.get("updated_at"), "metrics.updated_at")
                if data.get("updated_at") is not None
                else None
            ),
        )


def _require_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PersistentValidationError(f"{field_name} must be a non-empty string")
    return value.strip()


def _require_iso_datetime(value: str, field_name: str) -> None:
    try:
        datetime.fromisoformat(value)
    except ValueError as exc:
        raise PersistentValidationError(f"{field_name} must be an ISO datetime") from exc


def _validate_counter_mapping(counters: dict[str, Any], field_name: str) -> None:
    for key, value in counters.items():
        if not isinstance(key, str) or not key.strip():
            raise PersistentValidationError(
                f"{field_name} keys must be non-empty strings"
            )
        number = strict_int(value, f"{field_name}.{key}")
        if number < 0:
            raise PersistentValidationError(f"{field_name}.{key} must not be negative")
