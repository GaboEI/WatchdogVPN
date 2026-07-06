from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

from config.paths import resolve_config_dir
from config.persistence import (
    PersistentValidationError,
    dump_json,
    file_lock,
    load_json,
    require_mapping,
)

from .models import MetricsBucket, MetricsDocument


def _metrics_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_METRICS_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / "metrics.json"


class MetricsStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _metrics_path()

    def load(self) -> MetricsDocument:
        if not self.path.exists():
            return MetricsDocument()
        with file_lock(self.path):
            data = require_mapping(load_json(self.path, {}), self.path)
            if not data:
                return MetricsDocument()
            return MetricsDocument.from_dict(data)

    def save(self, document: MetricsDocument) -> None:
        document = document.with_updated_at_now()
        self._validate_size(document)
        with file_lock(self.path):
            dump_json(self.path, document.to_dict())

    def increment(
        self,
        counters: Mapping[str, int],
        *,
        now: datetime | None = None,
    ) -> bool:
        if not counters:
            return False
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        now = now.astimezone(timezone.utc)
        document = self.load()
        if not document.enabled:
            return False
        bucket_start = now.replace(minute=0, second=0, microsecond=0)
        bucket_end = bucket_start + timedelta(hours=1)
        bucket_start_text = bucket_start.isoformat()
        bucket_end_text = bucket_end.isoformat()
        buckets: list[MetricsBucket] = []
        updated = False
        for bucket in document.buckets:
            if bucket.bucket_start == bucket_start_text:
                merged = dict(bucket.counters)
                for key, value in counters.items():
                    if value < 0:
                        raise PersistentValidationError(
                            f"metrics counter increment {key} must not be negative"
                        )
                    merged[key] = merged.get(key, 0) + value
                buckets.append(
                    MetricsBucket(
                        bucket_start=bucket.bucket_start,
                        bucket_end=bucket.bucket_end,
                        counters=merged,
                    )
                )
                updated = True
            else:
                buckets.append(bucket)
        if not updated:
            buckets.append(
                MetricsBucket(
                    bucket_start=bucket_start_text,
                    bucket_end=bucket_end_text,
                    counters=dict(counters),
                )
            )
        updated_document = MetricsDocument(
            schema_version=document.schema_version,
            enabled=document.enabled,
            retention_days=document.retention_days,
            redaction_mode=document.redaction_mode,
            max_bytes=document.max_bytes,
            buckets=tuple(buckets),
            updated_at=document.updated_at,
        )
        updated_document = self._pruned_document(updated_document, now=now)
        self.save(updated_document)
        return True

    def prune(self, now: datetime | None = None) -> MetricsDocument:
        now = now or datetime.now(timezone.utc)
        document = self.load()
        pruned = self._pruned_document(document, now=now)
        if len(pruned.buckets) != len(document.buckets):
            self.save(pruned)
        return pruned

    def _pruned_document(
        self,
        document: MetricsDocument,
        *,
        now: datetime,
    ) -> MetricsDocument:
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        now = now.astimezone(timezone.utc)
        cutoff = now - timedelta(days=document.retention_days)
        kept = tuple(
            bucket
            for bucket in document.buckets
            if datetime.fromisoformat(bucket.bucket_end) >= cutoff
        )
        pruned = MetricsDocument(
            schema_version=document.schema_version,
            enabled=document.enabled,
            retention_days=document.retention_days,
            redaction_mode=document.redaction_mode,
            max_bytes=document.max_bytes,
            buckets=kept,
            updated_at=document.updated_at,
        )
        return pruned

    def purge(self) -> bool:
        with file_lock(self.path):
            existed = self.path.exists()
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            return existed

    def _validate_size(self, document: MetricsDocument) -> None:
        encoded = json.dumps(document.to_dict(), indent=2, sort_keys=True).encode("utf-8")
        if len(encoded) > document.max_bytes:
            raise PersistentValidationError(
                f"metrics document exceeds max_bytes ({len(encoded)} > {document.max_bytes})"
            )


__all__ = ["MetricsStore"]
