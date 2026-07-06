from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config.paths import resolve_config_dir
from config.persistence import (
    PersistentValidationError,
    dump_json,
    file_lock,
    load_json,
    require_mapping,
)

from .models import MetricsDocument


def _metrics_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_METRICS_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / "metrics.json"


class MetricsStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _metrics_path()

    def load(self) -> MetricsDocument:
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

    def prune(self, now: datetime | None = None) -> MetricsDocument:
        now = now or datetime.now(timezone.utc)
        document = self.load()
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
        if len(kept) != len(document.buckets):
            self.save(pruned)
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
