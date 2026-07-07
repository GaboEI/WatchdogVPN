from __future__ import annotations

import base64
import io
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
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

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ModuleNotFoundError:  # pragma: no cover - exercised on hosts without cryptography
    InvalidTag = None  # type: ignore[assignment]
    AESGCM = None  # type: ignore[assignment]
    Scrypt = None  # type: ignore[assignment]


BACKUP_SCHEMA_VERSION = 1
BACKUP_SECTION_SCHEMA_VERSION = 1
BACKUP_PRODUCT = "WatchdogVPN"
BACKUP_ENCRYPTION_SUPPORTED = AESGCM is not None and Scrypt is not None
BACKUP_ENCRYPTION_FORMAT = "watchdogvpn-backup-aesgcm-scrypt-v1"
BACKUP_ENCRYPTION_AAD = b"WatchdogVPN encrypted backup v1"
ENCRYPTED_PAYLOAD_ENTRY = "payload.bin"
ENCRYPTION_SALT_BYTES = 16
ENCRYPTION_NONCE_BYTES = 12
ENCRYPTION_KEY_BYTES = 32
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
BACKUP_SENSITIVE_WARNING = (
    "Backup may contain private keys, passwords, provider tokens, subscription "
    "URLs, routing policy, app policy and local selection state. Store and share "
    "it as sensitive data."
)

SECTION_FILE_BY_NAME = {
    "settings": "settings.json",
    "profiles": "profiles.json",
    "providers": "providers.json",
    "provider-state": "provider-state.json",
    "routing-rules": "routing-rules.json",
    "app-policy": "app-policy.json",
    "node-groups": "node-groups.json",
    "selection-state": "selection-state.json",
    "dns-policy": "dns-policy.json",
    "metrics-policy": "metrics-policy.json",
    "backup-policy": "backup-policy.json",
    "metadata": "metadata.json",
    "diagnostics": "diagnostics.json",
}
DEFAULT_SECTION_NAMES = tuple(
    section for section in SECTION_FILE_BY_NAME if section != "diagnostics"
)
SUPPORTED_SECTION_NAMES = tuple(SECTION_FILE_BY_NAME)
BACKUP_ENTRIES = ("manifest.json",) + tuple(
    SECTION_FILE_BY_NAME[section] for section in DEFAULT_SECTION_NAMES
)
SUPPORTED_BACKUP_ENTRIES = ("manifest.json",) + tuple(SECTION_FILE_BY_NAME.values())
MERGE_SECTION_NAMES = ("routing-rules", "app-policy", "node-groups")
RESTORE_REPLACE_CONFIRMATION = "RESTORE-WATCHDOGVPN-BACKUP"
AUTO_BACKUP_REASONS = (
    "pre-restore",
    "pre-replace-import",
    "pre-destructive-remove",
    "pre-uninstall-delete",
)
DEFAULT_AUTO_BACKUP_MAX_BACKUPS = 10


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


@dataclass(frozen=True, slots=True)
class _RestoreSnapshot:
    files: dict[Path, bytes | None]
    rule_files: set[Path]


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
        sections: Iterable[str] | None = None,
        diagnostics: dict[str, Any] | None = None,
        encrypt: bool = False,
        password: str | None = None,
    ) -> BackupResult:
        created_at = _utc_now()
        output_path = output_path or self._default_backup_path(created_at, reason)
        selected_sections = _normalize_sections(sections)
        section_payloads = self._collect_sections(
            selected_sections,
            diagnostics=diagnostics,
            created_at=created_at,
        )
        manifest = self._manifest(created_at, reason, section_payloads)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if encrypt:
            plaintext = _plaintext_archive_bytes(manifest, section_payloads, selected_sections)
            encrypted_payload, encryption_metadata = _encrypt_backup_payload(
                plaintext,
                password,
            )
            encrypted_manifest = self._encrypted_manifest(manifest, encryption_metadata)
            with ZipFile(output_path, "w", compression=ZIP_DEFLATED) as archive:
                archive.writestr("manifest.json", _json_text(encrypted_manifest))
                archive.writestr(ENCRYPTED_PAYLOAD_ENTRY, encrypted_payload)
            return BackupResult(path=output_path, manifest=encrypted_manifest)
        with ZipFile(output_path, "w", compression=ZIP_DEFLATED) as archive:
            _write_plaintext_archive(
                archive,
                manifest,
                section_payloads,
                selected_sections,
            )
        return BackupResult(path=output_path, manifest=manifest)

    def create_auto_backup(
        self,
        *,
        reason: str,
        max_backups: int = DEFAULT_AUTO_BACKUP_MAX_BACKUPS,
        encrypt: bool = False,
        password: str | None = None,
    ) -> BackupResult:
        reason = _normalize_auto_backup_reason(reason)
        max_backups = _validate_max_backups(max_backups)
        result = self.create_backup(reason=reason, encrypt=encrypt, password=password)
        self.prune_auto_backups(max_backups=max_backups)
        return result

    def list_auto_backups(self) -> list[Path]:
        return [
            path
            for path in self._list_backup_files()
            if _backup_reason_from_name(path) in AUTO_BACKUP_REASONS
        ]

    def prune_auto_backups(
        self,
        *,
        max_backups: int = DEFAULT_AUTO_BACKUP_MAX_BACKUPS,
    ) -> list[Path]:
        max_backups = _validate_max_backups(max_backups)
        backups = self.list_auto_backups()
        expired = backups[:-max_backups]
        removed: list[Path] = []
        for path in expired:
            try:
                path.unlink()
            except FileNotFoundError:
                continue
            removed.append(path)
        return removed

    def restore_backup(
        self,
        backup_path: Path,
        *,
        sections: Iterable[str] | None = None,
        mode: str = "replace",
        replace_confirmation: str | None = None,
        password: str | None = None,
    ) -> RestoreResult:
        parsed = self.inspect_backup(backup_path, password=password)
        selected_sections = _normalize_sections(
            sections,
            default=tuple(parsed.manifest["sections"]),
        )
        restore_mode = _normalize_restore_mode(mode)
        if restore_mode == "replace":
            _require_replace_confirmation(replace_confirmation)
        else:
            _validate_merge_sections(selected_sections)
        missing = set(selected_sections) - set(parsed.manifest["sections"])
        if missing:
            names = ", ".join(sorted(missing))
            raise BackupValidationError(f"backup does not contain requested sections: {names}")
        auto_reason = "pre-replace-import" if restore_mode == "replace" else "pre-restore"
        pre_restore = self.create_auto_backup(
            reason=auto_reason,
            encrypt=parsed.encrypted,
            password=password if parsed.encrypted else None,
        )
        snapshot = self._snapshot_targets()
        try:
            section_payloads = {
                SECTION_FILE_BY_NAME[section]: parsed.sections[
                    SECTION_FILE_BY_NAME[section]
                ]
                for section in selected_sections
            }
            if restore_mode == "replace":
                self._apply_sections(section_payloads)
            else:
                self._merge_sections(section_payloads)
        except Exception:
            self._restore_snapshot(snapshot)
            raise
        return RestoreResult(
            path=backup_path,
            manifest=parsed.manifest,
            pre_restore_backup=pre_restore.path,
        )

    def inspect_backup(
        self,
        backup_path: Path,
        *,
        password: str | None = None,
    ) -> "_ParsedBackup":
        try:
            with ZipFile(backup_path) as archive:
                names = [info.filename for info in archive.infolist()]
                if _looks_like_encrypted_backup(names):
                    return self._inspect_encrypted_backup(archive, names, password=password)
                self._validate_entry_names(names)
                raw_manifest = _load_archive_json(archive, "manifest.json")
                manifest = _require_object(raw_manifest, "manifest.json")
                self._validate_manifest(manifest, names)
                try:
                    section_payloads = {
                        entry: self._validate_section(
                            entry,
                            _load_archive_json(archive, entry),
                        )
                        for entry in names
                        if entry != "manifest.json"
                    }
                except BackupValidationError:
                    raise
                except (KeyError, TypeError, ValueError, PersistentStoreError) as exc:
                    raise BackupValidationError(f"invalid backup section: {exc}") from exc
        except BadZipFile as exc:
            raise BackupValidationError(f"invalid backup zip: {backup_path}") from exc
        return _ParsedBackup(manifest=manifest, sections=section_payloads)

    def _inspect_encrypted_backup(
        self,
        archive: ZipFile,
        names: list[str],
        *,
        password: str | None,
    ) -> "_ParsedBackup":
        self._validate_encrypted_entry_names(names)
        raw_manifest = _load_archive_json(archive, "manifest.json")
        manifest = _require_object(raw_manifest, "manifest.json")
        self._validate_encrypted_manifest(manifest)
        plaintext = _decrypt_backup_payload(
            archive.read(ENCRYPTED_PAYLOAD_ENTRY),
            _require_object(manifest["encryption"], "manifest.encryption"),
            password,
        )
        try:
            with ZipFile(io.BytesIO(plaintext)) as inner_archive:
                parsed = self._inspect_plaintext_archive(inner_archive)
                return _ParsedBackup(
                    manifest=parsed.manifest,
                    sections=parsed.sections,
                    encrypted=True,
                )
        except BadZipFile as exc:
            raise BackupValidationError("encrypted backup payload is not a valid zip") from exc

    def _inspect_plaintext_archive(self, archive: ZipFile) -> "_ParsedBackup":
        names = [info.filename for info in archive.infolist()]
        self._validate_entry_names(names)
        raw_manifest = _load_archive_json(archive, "manifest.json")
        manifest = _require_object(raw_manifest, "manifest.json")
        self._validate_manifest(manifest, names)
        try:
            section_payloads = {
                entry: self._validate_section(
                    entry,
                    _load_archive_json(archive, entry),
                )
                for entry in names
                if entry != "manifest.json"
            }
        except BackupValidationError:
            raise
        except (KeyError, TypeError, ValueError, PersistentStoreError) as exc:
            raise BackupValidationError(f"invalid backup section: {exc}") from exc
        return _ParsedBackup(manifest=manifest, sections=section_payloads)

    def _default_backup_path(self, created_at: str, reason: str) -> Path:
        stamp = created_at.replace("-", "").replace(":", "").split(".")[0]
        safe_reason = "".join(char if char.isalnum() or char in "-_" else "-" for char in reason)
        base = self.backup_dir / f"watchdogvpn-{safe_reason}-{stamp}.zip"
        if not base.exists():
            return base
        suffix = 2
        while True:
            candidate = self.backup_dir / f"watchdogvpn-{safe_reason}-{stamp}-{suffix}.zip"
            if not candidate.exists():
                return candidate
            suffix += 1

    def _list_backup_files(self) -> list[Path]:
        if not self.backup_dir.exists():
            return []
        return sorted(
            self.backup_dir.glob("watchdogvpn-*.zip"),
            key=lambda path: (path.stat().st_mtime_ns, path.name),
        )

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
            "sections": [
                section
                for section, entry in SECTION_FILE_BY_NAME.items()
                if entry in sections
            ],
            "section_files": {
                section: entry
                for section, entry in SECTION_FILE_BY_NAME.items()
                if entry in sections
            },
            "sensitive": True,
            "sensitive_warning": BACKUP_SENSITIVE_WARNING,
            "encryption": {
                "enabled": False,
                "supported": BACKUP_ENCRYPTION_SUPPORTED,
                "format": None,
            },
            "notes": [
                BACKUP_SENSITIVE_WARNING,
                "plaintext backup; use encrypt=True for encrypted backup archives",
                "metrics-policy excludes metrics history and counters",
            ],
        }

    def _encrypted_manifest(
        self,
        plaintext_manifest: dict[str, Any],
        encryption_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "product": BACKUP_PRODUCT,
            "created_at": plaintext_manifest["created_at"],
            "reason": plaintext_manifest["reason"],
            "format": "watchdogvpn-encrypted-backup-zip",
            "section_schema_version": BACKUP_SECTION_SCHEMA_VERSION,
            "sections": list(plaintext_manifest["sections"]),
            "section_files": dict(plaintext_manifest["section_files"]),
            "sensitive": True,
            "sensitive_warning": BACKUP_SENSITIVE_WARNING,
            "encryption": encryption_metadata,
            "notes": [
                BACKUP_SENSITIVE_WARNING,
                "payload.bin contains an encrypted full WatchdogVPN backup archive",
                "password recovery is not available if the passphrase is lost",
                "metrics-policy excludes metrics history and counters",
            ],
        }

    def _collect_sections(
        self,
        selected_sections: tuple[str, ...],
        *,
        diagnostics: dict[str, Any] | None,
        created_at: str,
    ) -> dict[str, dict[str, Any]]:
        requested = set(selected_sections)
        selected_payloads: dict[str, dict[str, Any]] = {}
        providers: list[dict[str, Any]] | None = None

        if "settings" in requested:
            app_config = AppConfig(self.config_dir / "config.toml").load()
            selected_payloads["settings.json"] = _section({"config": app_config})
        if "profiles" in requested:
            profiles = [
                profile.to_dict()
                for profile in ProfileStore(self.config_dir / "profiles.json").list()
            ]
            selected_payloads["profiles.json"] = _section({"items": profiles})
        if {"providers", "provider-state"} & requested:
            providers = [
                provider.to_dict()
                for provider in ProviderStore(self.config_dir / "providers.json").list()
            ]
        if "providers" in requested:
            selected_payloads["providers.json"] = _section({"items": providers or []})
        if "provider-state" in requested:
            selected_payloads["provider-state.json"] = _section(
                {
                    "items": [
                        {
                            "id": provider.get("id", ""),
                            "last_updated": provider.get("last_updated"),
                            "metadata": provider.get("metadata", {}),
                        }
                        for provider in providers or []
                    ]
                }
            )
        if "routing-rules" in requested:
            rule_groups = [
                group.to_dict()
                for group in RuleStore(self.config_dir / "rules").list_groups()
            ]
            selected_payloads["routing-rules.json"] = _section({"groups": rule_groups})
        if "app-policy" in requested:
            app_policy = AppPolicyStore(self.config_dir / "app-policy.json").load()
            selected_payloads["app-policy.json"] = _section({"policy": app_policy.to_dict()})
        if "node-groups" in requested:
            node_groups = [
                group.to_dict()
                for group in NodeGroupStore(self.config_dir / "node_groups.json").list()
            ]
            selected_payloads["node-groups.json"] = _section({"items": node_groups})
        if "selection-state" in requested:
            selection_state = StateManager(self.config_dir / "state.toml").load()
            selected_payloads["selection-state.json"] = _section({"state": selection_state})
        if "dns-policy" in requested:
            dns_policy = DNSPolicyStore(self.config_dir / "dns-policy.json").load()
            selected_payloads["dns-policy.json"] = _section({"policy": dns_policy.to_dict()})
        if "metrics-policy" in requested:
            metrics = MetricsStore(self.config_dir / "metrics.json").load()
            selected_payloads["metrics-policy.json"] = _section(
                {
                    "enabled": metrics.enabled,
                    "retention_days": metrics.retention_days,
                    "redaction_mode": metrics.redaction_mode.value,
                    "max_bytes": metrics.max_bytes,
                    "updated_at": metrics.updated_at,
                    "history_included": False,
                }
            )
        if "backup-policy" in requested:
            selected_payloads["backup-policy.json"] = _section(
                {
                    "auto_backup": {
                        "before_restore": True,
                        "before_destructive_remove": True,
                        "before_replace_import": True,
                        "before_uninstall_delete": True,
                    },
                    "retention": {
                        "max_backups": DEFAULT_AUTO_BACKUP_MAX_BACKUPS,
                    },
                    "remote_upload": False,
                }
            )
        if "metadata" in requested:
            selected_payloads["metadata.json"] = _section(
                {
                    "product": BACKUP_PRODUCT,
                    "hostname_included": False,
                    "platform": os.name,
                }
            )
        if "diagnostics" in requested:
            selected_payloads["diagnostics.json"] = _section(
                {
                    "generated_at": created_at,
                    "payload": diagnostics or {},
                    "included_by_explicit_request": True,
                }
            )
        return {
            SECTION_FILE_BY_NAME[section]: selected_payloads[SECTION_FILE_BY_NAME[section]]
            for section in selected_sections
        }

    def _validate_entry_names(self, names: list[str]) -> None:
        if len(names) != len(set(names)):
            raise BackupValidationError("backup contains duplicate entries")
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
                raise BackupValidationError(f"backup contains unsafe path: {name}")
            if name not in SUPPORTED_BACKUP_ENTRIES:
                raise BackupValidationError(f"backup contains unsupported entry: {name}")
        if "manifest.json" not in names:
            raise BackupValidationError("backup missing manifest.json")

    def _validate_manifest(self, manifest: dict[str, Any], names: list[str]) -> None:
        if manifest.get("schema_version") != BACKUP_SCHEMA_VERSION:
            raise BackupValidationError("unsupported backup schema_version")
        if manifest.get("product") != BACKUP_PRODUCT:
            raise BackupValidationError("backup product is not WatchdogVPN")
        encryption = manifest.get("encryption", {"enabled": False})
        encryption_data = _require_object(encryption, "manifest.encryption")
        if encryption_data.get("enabled") is not False:
            raise BackupValidationError("encrypted backups must use the encrypted container")
        section_files = _require_object(manifest.get("section_files"), "manifest.section_files")
        sections = _require_list(manifest.get("sections"), "manifest.sections")
        normalized_sections = _normalize_sections(sections, default=())
        if len(normalized_sections) != len(sections):
            raise BackupValidationError("manifest contains duplicate sections")
        expected_files = {
            section: SECTION_FILE_BY_NAME[section] for section in normalized_sections
        }
        if section_files != expected_files:
            raise BackupValidationError("manifest section_files do not match supported files")
        expected_entries = {"manifest.json", *expected_files.values()}
        if set(names) != expected_entries:
            raise BackupValidationError("backup entries do not match manifest contract")

    def _validate_encrypted_entry_names(self, names: list[str]) -> None:
        if len(names) != len(set(names)):
            raise BackupValidationError("encrypted backup contains duplicate entries")
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
                raise BackupValidationError(f"encrypted backup contains unsafe path: {name}")
        if set(names) != {"manifest.json", ENCRYPTED_PAYLOAD_ENTRY}:
            raise BackupValidationError("encrypted backup entries do not match manifest contract")

    def _validate_encrypted_manifest(self, manifest: dict[str, Any]) -> None:
        if manifest.get("schema_version") != BACKUP_SCHEMA_VERSION:
            raise BackupValidationError("unsupported encrypted backup schema_version")
        if manifest.get("product") != BACKUP_PRODUCT:
            raise BackupValidationError("encrypted backup product is not WatchdogVPN")
        if manifest.get("format") != "watchdogvpn-encrypted-backup-zip":
            raise BackupValidationError("unsupported encrypted backup format")
        encryption = _require_object(manifest.get("encryption"), "manifest.encryption")
        if encryption.get("enabled") is not True:
            raise BackupValidationError("encrypted backup manifest must enable encryption")
        _validate_encryption_metadata(encryption)
        section_files = _require_object(manifest.get("section_files"), "manifest.section_files")
        sections = _require_list(manifest.get("sections"), "manifest.sections")
        normalized_sections = _normalize_sections(sections, default=())
        if len(normalized_sections) != len(sections):
            raise BackupValidationError("manifest contains duplicate sections")
        expected_files = {
            section: SECTION_FILE_BY_NAME[section] for section in normalized_sections
        }
        if section_files != expected_files:
            raise BackupValidationError("manifest section_files do not match supported files")

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
                _parse_optional_datetime(provider_state.get("last_updated"))
                _require_object(provider_state.get("metadata", {}), "provider-state metadata")
            return data
        if entry == "backup-policy.json":
            _require_object(data.get("auto_backup"), "backup-policy.auto_backup")
            retention = _require_object(data.get("retention"), "backup-policy.retention")
            _validate_max_backups(retention.get("max_backups", DEFAULT_AUTO_BACKUP_MAX_BACKUPS))
            if not isinstance(data.get("remote_upload"), bool):
                raise BackupValidationError("backup-policy.remote_upload must be a boolean")
            return data
        if entry == "metadata.json":
            if data.get("product") != BACKUP_PRODUCT:
                raise BackupValidationError("metadata product is not WatchdogVPN")
            return data
        if entry == "diagnostics.json":
            _require_object(data.get("payload"), "diagnostics.payload")
            if data.get("included_by_explicit_request") is not True:
                raise BackupValidationError("diagnostics must be explicitly requested")
            return data
        raise BackupValidationError(f"unsupported backup section: {entry}")

    def _snapshot_targets(self) -> _RestoreSnapshot:
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
        return _RestoreSnapshot(
            files=snapshot,
            rule_files={
                path
                for path in paths
                if path.parent == rules_dir and path.suffix == ".json"
            },
        )

    def _restore_snapshot(self, snapshot: _RestoreSnapshot) -> None:
        rules_dir = self.config_dir / "rules"
        if rules_dir.exists():
            for path in sorted(rules_dir.glob("*.json")):
                if path not in snapshot.rule_files:
                    path.unlink()
        for path, content in snapshot.files.items():
            if content is None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)

    def _apply_sections(self, sections: dict[str, dict[str, Any]]) -> None:
        for entry in _entries_for_sections(DEFAULT_SECTION_NAMES):
            if entry not in sections:
                continue
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
                StateManager(self.config_dir / "state.toml").save(
                    self._selection_state_document(data["state"])
                )
            elif entry == "dns-policy.json":
                DNSPolicyStore(self.config_dir / "dns-policy.json").save(
                    DNSPolicy.from_dict(data["policy"])
                )
            elif entry == "metrics-policy.json":
                MetricsStore(self.config_dir / "metrics.json").save(
                    _metrics_policy_document(data)
                )
            elif entry == "provider-state.json":
                self._apply_provider_state(data["items"])
            elif entry in {"backup-policy.json", "metadata.json"}:
                continue
            elif entry == "diagnostics.json":
                continue

    def _merge_sections(self, sections: dict[str, dict[str, Any]]) -> None:
        timestamp = _timestamp_suffix()
        for entry in _entries_for_sections(MERGE_SECTION_NAMES):
            if entry not in sections:
                continue
            data = sections[entry]
            if entry == "routing-rules.json":
                self._merge_rule_groups(data["groups"], timestamp=timestamp)
            elif entry == "app-policy.json":
                self._merge_app_policy(data["policy"], timestamp=timestamp)
            elif entry == "node-groups.json":
                self._merge_node_groups(data["items"], timestamp=timestamp)

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

    def _selection_state_document(self, state: dict[str, Any]) -> dict[str, Any]:
        validated = _validate_state(state, self.config_dir / "state.toml")
        active_profile_id = validated.get("active_profile_id", "")
        if active_profile_id:
            profile_ids = {
                profile.id
                for profile in ProfileStore(self.config_dir / "profiles.json").list()
            }
            if active_profile_id not in profile_ids:
                raise BackupValidationError(
                    f"selection-state active_profile_id is not available: {active_profile_id}"
                )
        return validated

    def _apply_provider_state(self, items: list[dict[str, Any]]) -> None:
        store = ProviderStore(self.config_dir / "providers.json")
        providers_by_id = {provider.id: provider for provider in store.list()}
        for item in items:
            provider_id = str(item.get("id", "")).strip()
            provider = providers_by_id.get(provider_id)
            if provider is None:
                continue
            provider.last_updated = _parse_optional_datetime(item.get("last_updated"))
            provider.metadata = dict(_require_object(item.get("metadata", {}), "provider-state metadata"))
            store.update(provider)

    def _merge_rule_groups(self, groups: list[dict[str, Any]], *, timestamp: str) -> None:
        store = RuleStore(self.config_dir / "rules")
        existing_names = {group.name for group in store.list_groups()}
        for item in groups:
            imported = RuleGroup.from_dict(item)
            name = _unique_timestamped_name(imported.name, existing_names, timestamp=timestamp)
            existing_names.add(name)
            store.add_group(
                RuleGroup(
                    name=name,
                    enabled=imported.enabled,
                    rules=list(imported.rules),
                    priority=imported.priority,
                )
            )

    def _merge_app_policy(self, policy: dict[str, Any], *, timestamp: str) -> None:
        imported = AppPolicy.from_dict(policy)
        store = AppPolicyStore(self.config_dir / "app-policy.json")
        local = store.load()
        existing_ids = {rule.id for rule in local.rules}
        merged_rules = list(local.rules)
        for rule in imported.rules:
            rule_data = rule.to_dict()
            rule_data["id"] = _unique_imported_id(rule.id, existing_ids, timestamp=timestamp)
            existing_ids.add(rule_data["id"])
            merged_rules.append(rule_data)
        store.save(
            AppPolicy(
                schema_version=local.schema_version,
                enabled=local.enabled,
                mode=local.mode,
                default_action=local.default_action,
                rules=merged_rules,
            )
        )

    def _merge_node_groups(self, groups: list[dict[str, Any]], *, timestamp: str) -> None:
        store = NodeGroupStore(self.config_dir / "node_groups.json")
        existing_names = {group.name for group in store.list()}
        for item in groups:
            imported = NodeGroup.from_dict(item)
            group_data = imported.to_dict()
            group_data["name"] = _unique_timestamped_name(
                imported.name,
                existing_names,
                timestamp=timestamp,
            )
            existing_names.add(group_data["name"])
            store.add(NodeGroup.from_dict(group_data))


@dataclass(frozen=True, slots=True)
class _ParsedBackup:
    manifest: dict[str, Any]
    sections: dict[str, dict[str, Any]]
    encrypted: bool = False


def _section(payload: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": BACKUP_SECTION_SCHEMA_VERSION, **payload}


def _json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _write_plaintext_archive(
    archive: ZipFile,
    manifest: dict[str, Any],
    section_payloads: dict[str, dict[str, Any]],
    selected_sections: tuple[str, ...],
) -> None:
    archive.writestr("manifest.json", _json_text(manifest))
    for section in selected_sections:
        entry = SECTION_FILE_BY_NAME[section]
        archive.writestr(entry, _json_text(section_payloads[entry]))


def _plaintext_archive_bytes(
    manifest: dict[str, Any],
    section_payloads: dict[str, dict[str, Any]],
    selected_sections: tuple[str, ...],
) -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        _write_plaintext_archive(archive, manifest, section_payloads, selected_sections)
    return buffer.getvalue()


def _encrypt_backup_payload(
    plaintext: bytes,
    password: str | None,
) -> tuple[bytes, dict[str, Any]]:
    if not BACKUP_ENCRYPTION_SUPPORTED:
        raise BackupValidationError(
            "backup encryption requires the optional cryptography dependency"
        )
    password_bytes = _password_bytes(password)
    salt = os.urandom(ENCRYPTION_SALT_BYTES)
    nonce = os.urandom(ENCRYPTION_NONCE_BYTES)
    key = _derive_encryption_key(password_bytes, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, BACKUP_ENCRYPTION_AAD)  # type: ignore[operator]
    return ciphertext, _encryption_metadata(salt=salt, nonce=nonce)


def _decrypt_backup_payload(
    ciphertext: bytes,
    encryption: dict[str, Any],
    password: str | None,
) -> bytes:
    if not BACKUP_ENCRYPTION_SUPPORTED:
        raise BackupValidationError(
            "backup encryption requires the optional cryptography dependency"
        )
    _validate_encryption_metadata(encryption)
    password_bytes = _password_bytes(password)
    salt = _b64_decode(str(encryption["salt"]), "manifest.encryption.salt")
    nonce = _b64_decode(str(encryption["nonce"]), "manifest.encryption.nonce")
    key = _derive_encryption_key(password_bytes, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, BACKUP_ENCRYPTION_AAD)  # type: ignore[operator]
    except InvalidTag as exc:  # type: ignore[misc]
        raise BackupValidationError(
            "encrypted backup password is incorrect or payload authentication failed"
        ) from exc


def _encryption_metadata(*, salt: bytes, nonce: bytes) -> dict[str, Any]:
    return {
        "enabled": True,
        "supported": BACKUP_ENCRYPTION_SUPPORTED,
        "format": BACKUP_ENCRYPTION_FORMAT,
        "algorithm": "AES-256-GCM",
        "kdf": "scrypt",
        "kdf_params": {
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "length": ENCRYPTION_KEY_BYTES,
        },
        "salt": _b64_encode(salt),
        "nonce": _b64_encode(nonce),
        "aad": BACKUP_ENCRYPTION_AAD.decode("utf-8"),
    }


def _validate_encryption_metadata(encryption: dict[str, Any]) -> None:
    if encryption.get("enabled") is not True:
        raise BackupValidationError("encrypted backup manifest must enable encryption")
    if encryption.get("format") != BACKUP_ENCRYPTION_FORMAT:
        raise BackupValidationError("unsupported encrypted backup format")
    if encryption.get("algorithm") != "AES-256-GCM":
        raise BackupValidationError("unsupported encrypted backup algorithm")
    if encryption.get("kdf") != "scrypt":
        raise BackupValidationError("unsupported encrypted backup KDF")
    params = _require_object(encryption.get("kdf_params"), "manifest.encryption.kdf_params")
    expected_params = {
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "length": ENCRYPTION_KEY_BYTES,
    }
    if params != expected_params:
        raise BackupValidationError("unsupported encrypted backup KDF parameters")
    if encryption.get("aad") != BACKUP_ENCRYPTION_AAD.decode("utf-8"):
        raise BackupValidationError("unsupported encrypted backup AAD")
    salt = _b64_decode(str(encryption.get("salt", "")), "manifest.encryption.salt")
    nonce = _b64_decode(str(encryption.get("nonce", "")), "manifest.encryption.nonce")
    if len(salt) != ENCRYPTION_SALT_BYTES:
        raise BackupValidationError("encrypted backup salt has invalid length")
    if len(nonce) != ENCRYPTION_NONCE_BYTES:
        raise BackupValidationError("encrypted backup nonce has invalid length")


def _password_bytes(password: str | None) -> bytes:
    if password is None or password == "":
        raise BackupValidationError("encrypted backup password is required")
    if not isinstance(password, str):
        raise BackupValidationError("encrypted backup password must be a string")
    return password.encode("utf-8")


def _derive_encryption_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(  # type: ignore[operator]
        salt=salt,
        length=ENCRYPTION_KEY_BYTES,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password)


def _b64_encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64_decode(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise BackupValidationError(f"{name} is not valid base64") from exc


def _looks_like_encrypted_backup(names: list[str]) -> bool:
    return ENCRYPTED_PAYLOAD_ENTRY in names


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


def _parse_optional_datetime(value: object) -> datetime | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise BackupValidationError("provider-state last_updated must be a string or null")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise BackupValidationError("provider-state last_updated must be ISO-8601") from exc


def _normalize_auto_backup_reason(reason: str) -> str:
    normalized = str(reason).strip()
    if normalized not in AUTO_BACKUP_REASONS:
        names = ", ".join(AUTO_BACKUP_REASONS)
        raise BackupValidationError(f"auto-backup reason must be one of: {names}")
    return normalized


def _validate_max_backups(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BackupValidationError("backup-policy retention.max_backups must be an integer")
    if value < 1:
        raise BackupValidationError("backup-policy retention.max_backups must be at least 1")
    if value > 100:
        raise BackupValidationError("backup-policy retention.max_backups must be at most 100")
    return value


def _backup_reason_from_name(path: Path) -> str | None:
    prefix = "watchdogvpn-"
    suffix = ".zip"
    name = path.name
    if not name.startswith(prefix) or not name.endswith(suffix):
        return None
    stem = name[len(prefix) : -len(suffix)]
    for reason in AUTO_BACKUP_REASONS:
        if stem.startswith(f"{reason}-"):
            return reason
    return None


def _normalize_sections(
    sections: Iterable[str] | None,
    *,
    default: tuple[str, ...] = DEFAULT_SECTION_NAMES,
) -> tuple[str, ...]:
    raw_sections = default if sections is None else tuple(sections)
    normalized: list[str] = []
    for section in raw_sections:
        name = str(section).strip()
        if name not in SUPPORTED_SECTION_NAMES:
            raise BackupValidationError(f"unsupported backup section: {name}")
        if name in normalized:
            raise BackupValidationError(f"duplicate backup section: {name}")
        normalized.append(name)
    if not normalized:
        raise BackupValidationError("at least one backup section is required")
    return tuple(normalized)


def _entries_for_sections(sections: Iterable[str]) -> tuple[str, ...]:
    return tuple(SECTION_FILE_BY_NAME[section] for section in sections)


def _normalize_restore_mode(mode: str) -> str:
    normalized = str(mode).strip()
    if normalized not in {"replace", "merge"}:
        raise BackupValidationError("restore mode must be one of: replace, merge")
    return normalized


def _require_replace_confirmation(replace_confirmation: str | None) -> None:
    if replace_confirmation != RESTORE_REPLACE_CONFIRMATION:
        raise BackupValidationError(
            "replace restore requires RESTORE-WATCHDOGVPN-BACKUP confirmation"
        )


def _validate_merge_sections(sections: tuple[str, ...]) -> None:
    unsupported = set(sections) - set(MERGE_SECTION_NAMES)
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise BackupValidationError(f"merge restore does not support sections: {names}")


def _timestamp_suffix() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def _unique_timestamped_name(
    source_name: str,
    existing_names: set[str],
    *,
    timestamp: str,
) -> str:
    base = _slug_prefix(f"imported-{source_name}", max_prefix_length=48)
    candidate = validate_group_name(f"{base}-{timestamp}")
    suffix = 2
    while candidate in existing_names:
        suffix_text = f"-{suffix}"
        prefix = _slug_prefix(
            f"imported-{source_name}",
            max_prefix_length=64 - len(timestamp) - len(suffix_text) - 1,
        )
        candidate = validate_group_name(f"{prefix}-{timestamp}{suffix_text}")
        suffix += 1
    return candidate


def _unique_imported_id(
    source_id: str,
    existing_ids: set[str],
    *,
    timestamp: str,
) -> str:
    base = str(source_id).strip() or "rule"
    candidate = f"imported-{base}-{timestamp}"
    suffix = 2
    while candidate in existing_ids:
        candidate = f"imported-{base}-{timestamp}-{suffix}"
        suffix += 1
    return candidate


def _slug_prefix(value: str, *, max_prefix_length: int) -> str:
    normalized = "".join(
        char if char.isalnum() or char in "-_" else "-"
        for char in value.lower().strip()
    )
    normalized = normalized.strip("-_") or "imported"
    return normalized[:max_prefix_length].rstrip("-_") or "imported"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "BACKUP_SCHEMA_VERSION",
    "BACKUP_SECTION_SCHEMA_VERSION",
    "BACKUP_ENCRYPTION_FORMAT",
    "BACKUP_ENCRYPTION_SUPPORTED",
    "AUTO_BACKUP_REASONS",
    "BACKUP_SENSITIVE_WARNING",
    "BackupError",
    "BackupManager",
    "BackupResult",
    "BackupValidationError",
    "DEFAULT_AUTO_BACKUP_MAX_BACKUPS",
    "RESTORE_REPLACE_CONFIRMATION",
    "RestoreResult",
]
