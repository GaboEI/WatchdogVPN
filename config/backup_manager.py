from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

from app_policy.models import AppPolicy
from app_policy.store import AppPolicyStore
from config.app_config import AppConfig, _validate_config
from config.dns_policy_store import DNSPolicyStore
from config.paths import resolve_config_dir
from config.persistence import (
    PersistentStoreError,
    PersistentValidationError,
    atomic_write_text,
    dump_json,
)
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.state_manager import StateManager, _validate_state
from dns.models import DNSPolicy
from metrics.models import MetricsDocument, MetricsRedactionMode
from metrics.store import MetricsStore
from models.profile import Profile
from models.provider import Provider
from node_groups.models import NodeGroup
from node_groups.store import NodeGroupStore
from rules.models import RuleGroup, validate_group_name
from rules.rule_store import RuleStore


BACKUP_SCHEMA_VERSION = 1
BACKUP_SECTION_SCHEMA_VERSION = 1
BACKUP_PRODUCT = "WatchdogVPN"

BACKUP_ENTRIES = (
    "manifest.json",
    "settings.json",
    "profiles.json",
    "providers.json",
    "provider-state.json",
    "routing-rules.json",
    "app-policy.json",
    "node-groups.json",
    "selection-state.json",
    "dns-policy.json",
    "metrics-policy.json",
    "backup-policy.json",
    "metadata.json",
)

SECTION_ENTRIES = tuple(entry for entry in BACKUP_ENTRIES if entry != "manifest.json")
SECTION_NAMES = tuple(entry.removesuffix(".json") for entry in SECTION_ENTRIES)


class BackupError(PersistentStoreError):
    pass


class BackupValidationError(PersistentValidationError):
    pass


@dataclass(frozen=True, slots=True)
class BackupResult:
    path: Path
    manifest: dict[str, Any]


@dataclass(frozen=True, slots=True)
class RestoreResult:
    path: Path
    manifest: dict[str, Any]
    pre_restore_backup: Path


class BackupManager:
    def __init__(
        self,
        *,
        config_dir: Path | None = None,
        backup_dir: Path | None = None,
    ) -> None:
        self.config_dir = config_dir or resolve_config_dir()
        self.backup_dir = backup_dir or self.config_dir / "backups"

    def create_backup(
        self,
        output_path: Path | None = None,
        *,
        reason: str = "manual",
    ) -> BackupResult:
        created_at = _utc_now()
        output_path = output_path or self._default_backup_path(created_at, reason)
        sections = self._collect_sections()
        manifest = self._manifest(created_at, reason, sections)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(output_path, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", _json_text(manifest))
            for entry in SECTION_ENTRIES:
                archive.writestr(entry, _json_text(sections[entry]))
        return BackupResult(path=output_path, manifest=manifest)

    def restore_backup(self, backup_path: Path) -> RestoreResult:
        parsed = self.inspect_backup(backup_path)
        pre_restore = self.create_backup(reason="pre-restore")
        snapshot = self._snapshot_targets()
        try:
            self._apply_sections(parsed.sections)
        except Exception:
            self._restore_snapshot(snapshot)
            raise
        return RestoreResult(
            path=backup_path,
            manifest=parsed.manifest,
            pre_restore_backup=pre_restore.path,
        )

    def inspect_backup(self, backup_path: Path) -> "_ParsedBackup":
        try:
            with ZipFile(backup_path) as archive:
                names = [info.filename for info in archive.infolist()]
                self._validate_entry_names(names)
                raw_manifest = _load_archive_json(archive, "manifest.json")
                manifest = _require_object(raw_manifest, "manifest.json")
                self._validate_manifest(manifest, names)
                try:
                    sections = {
                        entry: self._validate_section(
                            entry,
                            _load_archive_json(archive, entry),
                        )
                        for entry in SECTION_ENTRIES
                        if entry in names
                    }
                except BackupValidationError:
                    raise
                except (KeyError, TypeError, ValueError, PersistentStoreError) as exc:
                    raise BackupValidationError(f"invalid backup section: {exc}") from exc
        except BadZipFile as exc:
            raise BackupValidationError(f"invalid backup zip: {backup_path}") from exc
        return _ParsedBackup(manifest=manifest, sections=sections)

    def _default_backup_path(self, created_at: str, reason: str) -> Path:
        stamp = created_at.replace("-", "").replace(":", "").split(".")[0]
        safe_reason = "".join(char if char.isalnum() or char in "-_" else "-" for char in reason)
        return self.backup_dir / f"watchdogvpn-{safe_reason}-{stamp}.zip"

    def _manifest(
        self,
        created_at: str,
        reason: str,
        sections: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "product": BACKUP_PRODUCT,
            "created_at": created_at,
            "reason": reason,
            "format": "watchdogvpn-backup-zip",
            "section_schema_version": BACKUP_SECTION_SCHEMA_VERSION,
            "sections": list(SECTION_NAMES),
            "section_files": {
                entry.removesuffix(".json"): entry for entry in SECTION_ENTRIES
            },
            "sensitive": True,
            "notes": [
                "backup may contain private keys, provider tokens and routing policy",
                "metrics-policy excludes metrics history and counters",
            ],
        }

    def _collect_sections(self) -> dict[str, dict[str, Any]]:
        app_config = AppConfig(self.config_dir / "config.toml").load()
        profiles = [
            profile.to_dict()
            for profile in ProfileStore(self.config_dir / "profiles.json").list()
        ]
        providers = [
            provider.to_dict()
            for provider in ProviderStore(self.config_dir / "providers.json").list()
        ]
        rule_groups = [
            group.to_dict()
            for group in RuleStore(self.config_dir / "rules").list_groups()
        ]
        app_policy = AppPolicyStore(self.config_dir / "app-policy.json").load()
        node_groups = [
            group.to_dict()
            for group in NodeGroupStore(self.config_dir / "node_groups.json").list()
        ]
        selection_state = StateManager(self.config_dir / "state.toml").load()
        dns_policy = DNSPolicyStore(self.config_dir / "dns-policy.json").load()
        metrics = MetricsStore(self.config_dir / "metrics.json").load()
        return {
            "settings.json": _section({"config": app_config}),
            "profiles.json": _section({"items": profiles}),
            "providers.json": _section({"items": providers}),
            "provider-state.json": _section(
                {
                    "items": [
                        {
                            "id": provider.get("id", ""),
                            "last_updated": provider.get("last_updated"),
                            "metadata": provider.get("metadata", {}),
                        }
                        for provider in providers
                    ]
                }
            ),
            "routing-rules.json": _section({"groups": rule_groups}),
            "app-policy.json": _section({"policy": app_policy.to_dict()}),
            "node-groups.json": _section({"items": node_groups}),
            "selection-state.json": _section({"state": selection_state}),
            "dns-policy.json": _section({"policy": dns_policy.to_dict()}),
            "metrics-policy.json": _section(
                {
                    "enabled": metrics.enabled,
                    "retention_days": metrics.retention_days,
                    "redaction_mode": metrics.redaction_mode.value,
                    "max_bytes": metrics.max_bytes,
                    "updated_at": metrics.updated_at,
                    "history_included": False,
                }
            ),
            "backup-policy.json": _section(
                {
                    "auto_backup": {
                        "before_restore": True,
                        "before_destructive_remove": True,
                        "before_replace_import": True,
                        "before_uninstall_delete": True,
                    },
                    "retention": {
                        "max_backups": 10,
                    },
                    "remote_upload": False,
                }
            ),
            "metadata.json": _section(
                {
                    "product": BACKUP_PRODUCT,
                    "hostname_included": False,
                    "platform": os.name,
                }
            ),
        }

    def _validate_entry_names(self, names: list[str]) -> None:
        if len(names) != len(set(names)):
            raise BackupValidationError("backup contains duplicate entries")
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
                raise BackupValidationError(f"backup contains unsafe path: {name}")
            if name not in BACKUP_ENTRIES:
                raise BackupValidationError(f"backup contains unsupported entry: {name}")
        if "manifest.json" not in names:
            raise BackupValidationError("backup missing manifest.json")

    def _validate_manifest(self, manifest: dict[str, Any], names: list[str]) -> None:
        if manifest.get("schema_version") != BACKUP_SCHEMA_VERSION:
            raise BackupValidationError("unsupported backup schema_version")
        if manifest.get("product") != BACKUP_PRODUCT:
            raise BackupValidationError("backup product is not WatchdogVPN")
        section_files = _require_object(manifest.get("section_files"), "manifest.section_files")
        sections = _require_list(manifest.get("sections"), "manifest.sections")
        expected_names = set(SECTION_NAMES)
        if set(sections) != expected_names:
            raise BackupValidationError("manifest sections do not match supported sections")
        expected_files = {section: f"{section}.json" for section in expected_names}
        if section_files != expected_files:
            raise BackupValidationError("manifest section_files do not match supported files")
        if set(names) != set(BACKUP_ENTRIES):
            raise BackupValidationError("backup entries do not match manifest contract")

    def _validate_section(self, entry: str, payload: object) -> dict[str, Any]:
        data = _require_object(payload, entry)
        if data.get("schema_version") != BACKUP_SECTION_SCHEMA_VERSION:
            raise BackupValidationError(f"{entry} has unsupported schema_version")
        if entry == "settings.json":
            _validate_config(
                _require_object(data.get("config"), "settings.config"),
                self.config_dir / "config.toml",
            )
            return data
        if entry == "profiles.json":
            for item in _require_list(data.get("items"), "profiles.items"):
                Profile.from_dict(_require_object(item, "profile"))
            return data
        if entry == "providers.json":
            for item in _require_list(data.get("items"), "providers.items"):
                Provider.from_dict(_require_object(item, "provider"))
            return data
        if entry == "routing-rules.json":
            for item in _require_list(data.get("groups"), "routing-rules.groups"):
                RuleGroup.from_dict(_require_object(item, "routing rule group"))
            return data
        if entry == "app-policy.json":
            AppPolicy.from_dict(_require_object(data.get("policy"), "app-policy.policy"))
            return data
        if entry == "node-groups.json":
            for item in _require_list(data.get("items"), "node-groups.items"):
                NodeGroup.from_dict(_require_object(item, "node group"))
            return data
        if entry == "selection-state.json":
            _validate_state(
                _require_object(data.get("state"), "selection-state.state"),
                self.config_dir / "state.toml",
            )
            return data
        if entry == "dns-policy.json":
            DNSPolicy.from_dict(_require_object(data.get("policy"), "dns-policy.policy"))
            return data
        if entry == "metrics-policy.json":
            _metrics_policy_document(data)
            return data
        if entry == "provider-state.json":
            for item in _require_list(data.get("items"), "provider-state.items"):
                provider_state = _require_object(item, "provider-state item")
                if not isinstance(provider_state.get("id"), str):
                    raise BackupValidationError("provider-state item id must be a string")
                _require_object(provider_state.get("metadata", {}), "provider-state metadata")
            return data
        if entry == "backup-policy.json":
            _require_object(data.get("auto_backup"), "backup-policy.auto_backup")
            _require_object(data.get("retention"), "backup-policy.retention")
            if not isinstance(data.get("remote_upload"), bool):
                raise BackupValidationError("backup-policy.remote_upload must be a boolean")
            return data
        if entry == "metadata.json":
            if data.get("product") != BACKUP_PRODUCT:
                raise BackupValidationError("metadata product is not WatchdogVPN")
            return data
        raise BackupValidationError(f"unsupported backup section: {entry}")

    def _snapshot_targets(self) -> dict[Path, bytes | None]:
        paths = [
            self.config_dir / "config.toml",
            self.config_dir / "profiles.json",
            self.config_dir / "providers.json",
            self.config_dir / "app-policy.json",
            self.config_dir / "node_groups.json",
            self.config_dir / "state.toml",
            self.config_dir / "dns-policy.json",
            self.config_dir / "metrics.json",
        ]
        rules_dir = self.config_dir / "rules"
        if rules_dir.exists():
            paths.extend(path for path in sorted(rules_dir.glob("*.json")))
        snapshot: dict[Path, bytes | None] = {}
        for path in paths:
            snapshot[path] = path.read_bytes() if path.exists() else None
        return snapshot

    def _restore_snapshot(self, snapshot: dict[Path, bytes | None]) -> None:
        for path, content in snapshot.items():
            if content is None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)

    def _apply_sections(self, sections: dict[str, dict[str, Any]]) -> None:
        for entry in SECTION_ENTRIES:
            data = sections[entry]
            if entry == "settings.json":
                AppConfig(self.config_dir / "config.toml").save(data["config"])
            elif entry == "profiles.json":
                self._write_json_file(self.config_dir / "profiles.json", data["items"])
            elif entry == "providers.json":
                self._write_json_file(self.config_dir / "providers.json", data["items"])
            elif entry == "routing-rules.json":
                self._write_rule_groups(data["groups"])
            elif entry == "app-policy.json":
                AppPolicyStore(self.config_dir / "app-policy.json").save(
                    AppPolicy.from_dict(data["policy"])
                )
            elif entry == "node-groups.json":
                self._write_json_file(self.config_dir / "node_groups.json", data["items"])
            elif entry == "selection-state.json":
                StateManager(self.config_dir / "state.toml").save(data["state"])
            elif entry == "dns-policy.json":
                DNSPolicyStore(self.config_dir / "dns-policy.json").save(
                    DNSPolicy.from_dict(data["policy"])
                )
            elif entry == "metrics-policy.json":
                MetricsStore(self.config_dir / "metrics.json").save(
                    _metrics_policy_document(data)
                )
            elif entry in {"provider-state.json", "backup-policy.json", "metadata.json"}:
                continue

    def _write_json_file(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        dump_json(path, value)

    def _write_rule_groups(self, groups: list[dict[str, Any]]) -> None:
        rules_dir = self.config_dir / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        for existing in rules_dir.glob("*.json"):
            existing.unlink()
        for item in groups:
            group = RuleGroup.from_dict(item)
            dump_json(rules_dir / f"{validate_group_name(group.name)}.json", group.to_dict())


@dataclass(frozen=True, slots=True)
class _ParsedBackup:
    manifest: dict[str, Any]
    sections: dict[str, dict[str, Any]]


def _section(payload: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": BACKUP_SECTION_SCHEMA_VERSION, **payload}


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _load_archive_json(archive: ZipFile, entry: str) -> object:
    try:
        return json.loads(archive.read(entry).decode("utf-8"))
    except KeyError as exc:
        raise BackupValidationError(f"backup missing {entry}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupValidationError(f"{entry} is not valid JSON") from exc


def _require_object(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BackupValidationError(f"{name} must be a JSON object")
    return value


def _require_list(value: object, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise BackupValidationError(f"{name} must be a JSON array")
    return value


def _metrics_policy_document(data: dict[str, Any]) -> MetricsDocument:
    return MetricsDocument.from_dict(
        {
            "schema_version": 1,
            "enabled": data.get("enabled", False),
            "retention_days": data.get("retention_days", 7),
            "redaction_mode": data.get("redaction_mode", MetricsRedactionMode.AGGREGATE.value),
            "max_bytes": data.get("max_bytes", 1024 * 1024),
            "buckets": [],
            "updated_at": data.get("updated_at"),
        }
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "BACKUP_SCHEMA_VERSION",
    "BACKUP_SECTION_SCHEMA_VERSION",
    "BackupError",
    "BackupManager",
    "BackupResult",
    "BackupValidationError",
    "RestoreResult",
]
