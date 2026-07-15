from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
import warnings
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

from app_policy.models import AppPolicy, AppPolicyRule
from app_policy.store import AppPolicyStore
from config.app_config import AppConfig
from config.backup_manager import (
    BACKUP_ENTRIES,
    BACKUP_ENCRYPTION_FORMAT,
    BACKUP_ENCRYPTION_SUPPORTED,
    BACKUP_SCHEMA_VERSION,
    BACKUP_SECTION_SCHEMA_VERSION,
    BACKUP_SENSITIVE_WARNING,
    AUTO_BACKUP_REASONS,
    BackupManager,
    BackupValidationError,
    RESTORE_REPLACE_CONFIRMATION,
)
from config.dns_policy_store import DNSPolicyStore
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.persistence import atomic_write_bytes, restore_transaction_journal_path, write_restore_transaction_journal
from config.state_manager import StateManager
from dns.models import DNSPolicy
from metrics.models import MetricsBucket, MetricsDocument
from metrics.store import MetricsStore
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider
from node_groups.models import NodeGroup
from node_groups.store import NodeGroupStore
from route_chains.models import ChainHop, RouteChain, RouteChainDocument
from route_chains.store import RouteChainStore
from rules.models import Rule, RuleGroup
from rules.rule_store import RuleStore


class BackupManagerTests(unittest.TestCase):
    def test_create_backup_writes_versioned_zip_with_manifest_and_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            backup_path = root / "backup.zip"

            result = BackupManager(config_dir=root, backup_dir=root / "backups").create_backup(
                backup_path,
                reason="test",
            )

            self.assertEqual(result.path, backup_path)
            with ZipFile(backup_path) as archive:
                self.assertEqual(set(archive.namelist()), set(BACKUP_ENTRIES))
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(manifest["schema_version"], BACKUP_SCHEMA_VERSION)
                self.assertTrue(manifest["sensitive"])
                self.assertEqual(manifest["sensitive_warning"], BACKUP_SENSITIVE_WARNING)
                self.assertEqual(
                    manifest["encryption"],
                    {
                        "enabled": False,
                        "supported": BACKUP_ENCRYPTION_SUPPORTED,
                        "format": None,
                    },
                )
                metrics_policy = json.loads(archive.read("metrics-policy.json"))
                self.assertFalse(metrics_policy["history_included"])
                self.assertNotIn("buckets", metrics_policy)
                profiles = json.loads(archive.read("profiles.json"))
                self.assertEqual(profiles["items"][0]["id"], "profile-one")
                selection = json.loads(archive.read("selection-state.json"))
                self.assertEqual(selection["state"]["active_profile_id"], "profile-one")
                route_chains = json.loads(archive.read("route-chains.json"))
                self.assertEqual(
                    route_chains["document"]["chains"][0]["id"],
                    "work-safe",
                )

    def test_create_backup_is_private_regardless_of_umask(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            backup_path = root / "backup.zip"
            old_umask = os.umask(0o022)
            try:
                BackupManager(config_dir=root, backup_dir=root / "backups").create_backup(
                    backup_path,
                    reason="test",
                )
            finally:
                os.umask(old_umask)

            mode = stat.S_IMODE(backup_path.stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_create_backup_does_not_follow_symlinked_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            sentinel = root / "sentinel"
            sentinel.write_bytes(b"do not overwrite")
            output_path = root / "output.zip"
            output_path.symlink_to(sentinel)

            BackupManager(config_dir=root, backup_dir=root / "backups").create_backup(
                output_path,
                reason="test",
            )

            self.assertEqual(sentinel.read_bytes(), b"do not overwrite")
            self.assertFalse(output_path.is_symlink())
            with ZipFile(output_path) as archive:
                self.assertIn("manifest.json", archive.namelist())

    def test_inspect_backup_rejects_path_traversal_duplicate_and_schema_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root, backup_dir=root / "backups")
            clean = manager.create_backup(root / "clean.zip").path

            traversal = root / "traversal.zip"
            with ZipFile(clean) as source, ZipFile(traversal, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    target.writestr(item.filename, source.read(item.filename))
                target.writestr("../evil.json", "{}")
            with self.assertRaisesRegex(BackupValidationError, "unsafe path"):
                manager.inspect_backup(traversal)

            duplicate = root / "duplicate.zip"
            with ZipFile(clean) as source, ZipFile(duplicate, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    target.writestr(item.filename, source.read(item.filename))
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    target.writestr("settings.json", "{}")
            with self.assertRaisesRegex(BackupValidationError, "duplicate"):
                manager.inspect_backup(duplicate)

            unsupported = root / "unsupported.zip"
            with ZipFile(clean) as source, ZipFile(unsupported, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename == "manifest.json":
                        manifest = json.loads(data)
                        manifest["schema_version"] = 999
                        data = json.dumps(manifest).encode()
                    target.writestr(item.filename, data)
            with self.assertRaisesRegex(BackupValidationError, "schema_version"):
                manager.inspect_backup(unsupported)

            encrypted = root / "encrypted.zip"
            with ZipFile(clean) as source, ZipFile(encrypted, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename == "manifest.json":
                        manifest = json.loads(data)
                        manifest["encryption"]["enabled"] = True
                        manifest["encryption"]["format"] = "example"
                        data = json.dumps(manifest).encode()
                    target.writestr(item.filename, data)
            with self.assertRaisesRegex(BackupValidationError, "encrypted"):
                manager.inspect_backup(encrypted)

    def test_restore_validates_before_mutation_and_creates_pre_restore_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root, backup_dir=root / "backups")
            backup = manager.create_backup(root / "source.zip").path
            ProfileStore(root / "profiles.json").add(
                Profile(
                    id="changed",
                    name="changed",
                    protocol=ProtocolType.TROJAN,
                    config={"host": "changed.example", "port": 443},
                    source=ProfileSource.MANUAL,
                )
            )

            result = manager.restore_backup(
                backup,
                replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
            )

            profiles = ProfileStore(root / "profiles.json").list()
            self.assertEqual([profile.id for profile in profiles], ["profile-one"])
            self.assertTrue(result.pre_restore_backup.exists())
            with ZipFile(result.pre_restore_backup) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(manifest["reason"], "pre-replace-import")
                previous = json.loads(archive.read("profiles.json"))
            self.assertEqual(
                sorted(item["id"] for item in previous["items"]),
                ["changed", "profile-one"],
            )

    def test_restore_rolls_back_keyboard_interrupt_and_clears_journal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root, backup_dir=root / "backups")
            backup = manager.create_backup(root / "source.zip").path
            original_profiles = (root / "profiles.json").read_bytes()

            with patch.object(BackupManager, "_write_json_file", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    manager.restore_backup(
                        backup,
                        replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
                    )

            self.assertEqual((root / "profiles.json").read_bytes(), original_profiles)
            self.assertFalse(restore_transaction_journal_path(root).exists())

    def test_pending_restore_journal_recovers_before_profile_store_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root, backup_dir=root / "backups")
            unmanaged = root / "procattr-test.json"
            unmanaged.write_bytes(b"unmanaged\n")
            snapshot = manager._snapshot_targets()
            original_profiles = (root / "profiles.json").read_bytes()
            original_providers = (root / "providers.json").read_bytes()
            write_restore_transaction_journal(
                root,
                snapshot.files,
                prune_unlisted_rule_files=True,
            )
            atomic_write_bytes(root / "profiles.json", b"[]\n")
            atomic_write_bytes(root / "providers.json", b"[]\n")
            atomic_write_bytes(root / "rules" / "interrupted.json", b"{}\n")

            profiles = ProfileStore(root / "profiles.json").list()

            self.assertEqual([profile.id for profile in profiles], ["profile-one"])
            self.assertEqual((root / "profiles.json").read_bytes(), original_profiles)
            self.assertEqual((root / "providers.json").read_bytes(), original_providers)
            self.assertEqual(unmanaged.read_bytes(), b"unmanaged\n")
            self.assertFalse((root / "rules" / "interrupted.json").exists())
            self.assertFalse(restore_transaction_journal_path(root).exists())

    def test_restore_rolls_back_when_apply_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root, backup_dir=root / "backups")
            backup = manager.create_backup(root / "source.zip").path
            original_profiles = (root / "profiles.json").read_text(encoding="utf-8")

            with patch.object(
                BackupManager,
                "_write_json_file",
                side_effect=RuntimeError("disk full"),
            ):
                with self.assertRaisesRegex(RuntimeError, "disk full"):
                    manager.restore_backup(
                        backup,
                        replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
                    )

            self.assertEqual(
                (root / "profiles.json").read_text(encoding="utf-8"),
                original_profiles,
            )

    def test_restore_rolls_back_new_rule_files_when_later_apply_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = Path(tmp) / "target"
            source.mkdir()
            target.mkdir()
            self.seed_config(source)
            self.seed_config(target)
            RuleStore(source / "rules").add_group(
                RuleGroup(
                    name="source-only",
                    rules=[
                        Rule(
                            id="source-only-rule",
                            action="block",
                            conditions={"domain_suffix": ["source-only.example"]},
                        )
                    ],
                )
            )
            manager = BackupManager(config_dir=target, backup_dir=target / "backups")
            backup = BackupManager(config_dir=source).create_backup(Path(tmp) / "source.zip").path
            original_rule_files = sorted(path.name for path in (target / "rules").glob("*.json"))

            with patch.object(AppPolicyStore, "save", side_effect=RuntimeError("policy write failed")):
                with self.assertRaisesRegex(RuntimeError, "policy write failed"):
                    manager.restore_backup(
                        backup,
                        replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
                    )

            self.assertEqual(
                sorted(path.name for path in (target / "rules").glob("*.json")),
                original_rule_files,
            )
            self.assertIsNone(RuleStore(target / "rules").get_group("source-only"))

    def test_restore_rollback_writes_group_writable_shared_state(self) -> None:
        # Regression coverage for the Phase 18 Task 18.4 shared-state audit:
        # _restore_snapshot() used to write the rolled-back files with
        # path.write_bytes() directly, bypassing config.persistence's shared
        # permission normalization. Under the daemon's real UMask=0077, a raw
        # write lands as 0600 (unreadable/unwritable by the watchdogvpn
        # group) - the same bug class as the historical Phase 2.6 incident.
        # This locks in the fix: files restored by a rollback must still end
        # up 0660/2770 even under a restrictive umask.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root, backup_dir=root / "backups")
            backup = manager.create_backup(root / "source.zip").path

            old_umask = os.umask(0o077)
            try:
                with patch("config.paths.SYSTEM_CONFIG_DIR", root):
                    with patch.object(
                        BackupManager,
                        "_write_json_file",
                        side_effect=RuntimeError("disk full"),
                    ):
                        with self.assertRaisesRegex(RuntimeError, "disk full"):
                            manager.restore_backup(
                                backup,
                                replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
                            )
            finally:
                os.umask(old_umask)

            restored = root / "profiles.json"
            self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o660)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o2770)

    def test_create_partial_backup_contains_only_requested_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            backup = BackupManager(config_dir=root).create_backup(
                root / "partial.zip",
                sections=["profiles", "selection-state"],
            )

            with ZipFile(backup.path) as archive:
                self.assertEqual(
                    set(archive.namelist()),
                    {"manifest.json", "profiles.json", "selection-state.json"},
                )
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(manifest["sections"], ["profiles", "selection-state"])

    def test_restore_partial_backup_applies_only_requested_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root, backup_dir=root / "backups")
            backup = manager.create_backup(
                root / "partial.zip",
                sections=["profiles", "selection-state"],
            ).path
            ProfileStore(root / "profiles.json").remove("profile-one")
            StateManager(root / "state.toml").save({"active_profile_id": ""})
            ProviderStore(root / "providers.json").remove("provider-one")

            manager.restore_backup(
                backup,
                sections=["profiles"],
                replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
            )

            self.assertEqual(
                [profile.id for profile in ProfileStore(root / "profiles.json").list()],
                ["profile-one"],
            )
            self.assertEqual(StateManager(root / "state.toml").load()["active_profile_id"], "")
            self.assertEqual(ProviderStore(root / "providers.json").list(), [])

    def test_diagnostics_section_is_explicit_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root)

            default_backup = manager.create_backup(root / "default.zip").path
            with ZipFile(default_backup) as archive:
                self.assertNotIn("diagnostics.json", archive.namelist())

            diagnostics_backup = manager.create_backup(
                root / "diagnostics.zip",
                sections=["diagnostics"],
                diagnostics={"report": "redacted"},
            ).path
            with ZipFile(diagnostics_backup) as archive:
                payload = json.loads(archive.read("diagnostics.json"))
            self.assertTrue(payload["included_by_explicit_request"])
            self.assertEqual(payload["payload"], {"report": "redacted"})

    def test_diagnostics_only_export_does_not_touch_unrequested_stores(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = BackupManager(config_dir=root)

            manager.create_backup(
                root / "diagnostics.zip",
                sections=["diagnostics"],
                diagnostics={"report": "redacted"},
            )

            self.assertEqual(
                sorted(path.name for path in root.glob("*.lock")),
                [],
            )
            self.assertFalse((root / "config.toml").exists())
            self.assertFalse((root / "profiles.json").exists())
            self.assertFalse((root / "providers.json").exists())
            self.assertFalse((root / "metrics.json").exists())

    def test_partial_restore_rejects_missing_requested_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            backup = BackupManager(config_dir=root).create_backup(
                root / "partial.zip",
                sections=["profiles"],
            ).path

            with self.assertRaisesRegex(BackupValidationError, "does not contain"):
                BackupManager(config_dir=root).restore_backup(
                    backup,
                    sections=["providers"],
                    replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
                )

    def test_create_backup_rejects_unknown_or_duplicate_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root)

            with self.assertRaisesRegex(BackupValidationError, "unsupported"):
                manager.create_backup(root / "bad.zip", sections=["secrets"])
            with self.assertRaisesRegex(BackupValidationError, "duplicate"):
                manager.create_backup(root / "bad.zip", sections=["profiles", "profiles"])

    def test_create_backup_rejects_encryption_without_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)

            with self.assertRaisesRegex(BackupValidationError, "password"):
                BackupManager(config_dir=root).create_backup(root / "encrypted.zip", encrypt=True)

    @unittest.skipUnless(BACKUP_ENCRYPTION_SUPPORTED, "cryptography dependency unavailable")
    def test_create_encrypted_backup_writes_outer_manifest_and_hides_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root)
            backup = manager.create_backup(
                root / "encrypted.zip",
                encrypt=True,
                password="correct horse battery staple",
            )

            with ZipFile(backup.path) as archive:
                self.assertEqual(set(archive.namelist()), {"manifest.json", "payload.bin"})
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(manifest["format"], "watchdogvpn-encrypted-backup-zip")
                self.assertEqual(manifest["encryption"]["format"], BACKUP_ENCRYPTION_FORMAT)
                self.assertEqual(manifest["encryption"]["algorithm"], "AES-256-GCM")
                self.assertEqual(manifest["encryption"]["kdf"], "scrypt")
                self.assertTrue(manifest["encryption"]["enabled"])
                self.assertNotIn("profiles.json", archive.namelist())

            parsed = manager.inspect_backup(
                backup.path,
                password="correct horse battery staple",
            )
            self.assertIn("profiles", parsed.manifest["sections"])
            self.assertIn("profiles.json", parsed.sections)

    @unittest.skipUnless(BACKUP_ENCRYPTION_SUPPORTED, "cryptography dependency unavailable")
    def test_restore_encrypted_backup_with_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root, backup_dir=root / "backups")
            backup = manager.create_backup(
                root / "encrypted.zip",
                encrypt=True,
                password="secret",
            ).path
            ProfileStore(root / "profiles.json").remove("profile-one")

            result = manager.restore_backup(
                backup,
                password="secret",
                replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
            )

            self.assertEqual(
                [profile.id for profile in ProfileStore(root / "profiles.json").list()],
                ["profile-one"],
            )
            self.assertTrue(result.pre_restore_backup.exists())
            with self.assertRaisesRegex(BackupValidationError, "password"):
                manager.inspect_backup(result.pre_restore_backup)
            parsed_pre_restore = manager.inspect_backup(
                result.pre_restore_backup,
                password="secret",
            )
            self.assertIn("profiles.json", parsed_pre_restore.sections)

    @unittest.skipUnless(BACKUP_ENCRYPTION_SUPPORTED, "cryptography dependency unavailable")
    def test_encrypted_backup_rejects_missing_or_wrong_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root)
            backup = manager.create_backup(
                root / "encrypted.zip",
                encrypt=True,
                password="secret",
            ).path

            with self.assertRaisesRegex(BackupValidationError, "password"):
                manager.inspect_backup(backup)
            with self.assertRaisesRegex(BackupValidationError, "password|authentication"):
                manager.inspect_backup(backup, password="wrong")

    @unittest.skipUnless(BACKUP_ENCRYPTION_SUPPORTED, "cryptography dependency unavailable")
    def test_encrypted_backup_rejects_corrupt_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root)
            backup = manager.create_backup(
                root / "encrypted.zip",
                encrypt=True,
                password="secret",
            ).path
            corrupt = root / "corrupt.zip"

            with ZipFile(backup) as source, ZipFile(corrupt, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename == "payload.bin":
                        data = bytes([data[0] ^ 1]) + data[1:]
                    target.writestr(item.filename, data)

            with self.assertRaisesRegex(BackupValidationError, "authentication"):
                manager.inspect_backup(corrupt, password="secret")

    @unittest.skipUnless(BACKUP_ENCRYPTION_SUPPORTED, "cryptography dependency unavailable")
    def test_encrypted_backup_rejects_unsupported_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root)
            backup = manager.create_backup(
                root / "encrypted.zip",
                encrypt=True,
                password="secret",
            ).path
            future = root / "future.zip"

            with ZipFile(backup) as source, ZipFile(future, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename == "manifest.json":
                        manifest = json.loads(data)
                        manifest["encryption"]["format"] = "watchdogvpn-backup-future-v99"
                        data = json.dumps(manifest).encode()
                    target.writestr(item.filename, data)

            with self.assertRaisesRegex(BackupValidationError, "unsupported encrypted backup format"):
                manager.inspect_backup(future, password="secret")

    def test_replace_restore_requires_strong_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root)
            backup = manager.create_backup(root / "source.zip").path

            with self.assertRaisesRegex(BackupValidationError, "requires"):
                manager.restore_backup(backup)

    def test_merge_restore_preserves_local_policy_and_imports_timestamped_groups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = Path(tmp) / "target"
            source.mkdir()
            target.mkdir()
            self.seed_config(source)
            self.seed_config(target)
            AppPolicyStore(source / "app-policy.json").save(
                AppPolicy(
                    enabled=True,
                    mode="whitelist",
                    default_action="block",
                    rules=[
                        AppPolicyRule(
                            id="source-rule",
                            action="direct",
                            match={"process_name": ["curl"]},
                        )
                    ],
                )
            )
            AppPolicyStore(target / "app-policy.json").save(
                AppPolicy(
                    enabled=False,
                    mode="blacklist",
                    default_action="current",
                    rules=[
                        AppPolicyRule(
                            id="local-rule",
                            action="block",
                            match={"process_name": ["browser"]},
                        )
                    ],
                )
            )
            backup = BackupManager(config_dir=source).create_backup(
                Path(tmp) / "merge.zip",
                sections=["routing-rules", "app-policy", "node-groups", "route-chains"],
            ).path

            with patch(
                "config.backup_manager._timestamp_suffix",
                return_value="20260707120000",
            ):
                BackupManager(config_dir=target).restore_backup(
                    backup,
                    sections=["routing-rules", "app-policy", "node-groups", "route-chains"],
                    mode="merge",
                )

            rule_names = sorted(group.name for group in RuleStore(target / "rules").list_groups())
            self.assertIn("custom", rule_names)
            self.assertIn("imported-custom-20260707120000", rule_names)
            node_group_names = sorted(
                group.name for group in NodeGroupStore(target / "node_groups.json").list()
            )
            self.assertIn("primary", node_group_names)
            self.assertIn("imported-primary-20260707120000", node_group_names)
            chain_names = sorted(
                chain.id for chain in RouteChainStore(target / "chains.json").list()
            )
            self.assertIn("work-safe", chain_names)
            self.assertIn("imported-work-safe-20260707120000", chain_names)
            policy = AppPolicyStore(target / "app-policy.json").load()
            self.assertFalse(policy.enabled)
            self.assertEqual(policy.mode.value, "blacklist")
            self.assertEqual(policy.default_action.value, "current")
            self.assertEqual(
                [rule.id for rule in policy.rules],
                ["local-rule", "imported-source-rule-20260707120000"],
            )

    def test_merge_restore_rejects_sections_without_merge_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            backup = BackupManager(config_dir=root).create_backup(
                root / "settings.zip",
                sections=["settings"],
            ).path

            with self.assertRaisesRegex(BackupValidationError, "does not support"):
                BackupManager(config_dir=root).restore_backup(
                    backup,
                    sections=["settings"],
                    mode="merge",
                )

    def test_route_chains_restore_rejects_invalid_document_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            clean = BackupManager(config_dir=root).create_backup(
                root / "route-chains.zip",
                sections=["route-chains"],
            ).path
            broken = root / "broken-route-chains.zip"
            original = (root / "chains.json").read_text(encoding="utf-8")

            with ZipFile(clean) as source, ZipFile(broken, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename == "route-chains.json":
                        payload = json.loads(data)
                        payload["document"]["chains"][0]["hops"][0]["type"] = "chain"
                        data = json.dumps(payload).encode()
                    target.writestr(item.filename, data)

            with self.assertRaisesRegex(BackupValidationError, "route_chain.hop.type"):
                BackupManager(config_dir=root).restore_backup(
                    broken,
                    sections=["route-chains"],
                    replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
                )

            self.assertEqual((root / "chains.json").read_text(encoding="utf-8"), original)

    def test_selection_state_restore_rejects_missing_active_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            backup = BackupManager(config_dir=root).create_backup(
                root / "selection.zip",
                sections=["selection-state"],
            ).path
            ProfileStore(root / "profiles.json").remove("profile-one")
            StateManager(root / "state.toml").save({"active_profile_id": ""})

            with self.assertRaisesRegex(BackupValidationError, "active_profile_id"):
                BackupManager(config_dir=root).restore_backup(
                    backup,
                    sections=["selection-state"],
                    replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
                )

            self.assertEqual(StateManager(root / "state.toml").load()["active_profile_id"], "")

    def test_selection_state_restore_accepts_legacy_active_mode_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            clean = BackupManager(config_dir=root).create_backup(
                root / "selection.zip",
                sections=["selection-state"],
            ).path
            legacy = root / "legacy-selection.zip"
            with ZipFile(clean) as source, ZipFile(legacy, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename == "selection-state.json":
                        payload = json.loads(data)
                        payload["state"] = {
                            "active_profile_id": "profile-one",
                            "active_mode": "direct",
                        }
                        data = json.dumps(payload).encode()
                    target.writestr(item.filename, data)
            StateManager(root / "state.toml").save({"active_profile_id": ""})

            BackupManager(config_dir=root).restore_backup(
                legacy,
                sections=["selection-state"],
                replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
            )

            state = StateManager(root / "state.toml").load()
            self.assertEqual(state["active_profile_id"], "profile-one")
            self.assertEqual(state["active_mode"], "direct")
            self.assertEqual(state["routing_policy"], "global")
            self.assertEqual(state["capture_modes"], "local_proxy")
            self.assertEqual(state["default_route_action"], "direct")

    def test_selection_state_restore_rejects_invalid_routing_shape_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            clean = BackupManager(config_dir=root).create_backup(
                root / "selection.zip",
                sections=["selection-state"],
            ).path
            broken = root / "broken-selection.zip"
            with ZipFile(clean) as source, ZipFile(broken, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename == "selection-state.json":
                        payload = json.loads(data)
                        payload["state"]["default_route_action"] = "group:alpha"
                        data = json.dumps(payload).encode()
                    target.writestr(item.filename, data)
            StateManager(root / "state.toml").save({"active_profile_id": ""})

            with self.assertRaisesRegex(BackupValidationError, "default_route_action"):
                BackupManager(config_dir=root).restore_backup(
                    broken,
                    sections=["selection-state"],
                    replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
                )

            self.assertEqual(StateManager(root / "state.toml").load()["active_profile_id"], "")

    def test_provider_state_restore_updates_existing_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            target = Path(tmp) / "target"
            source.mkdir()
            target.mkdir()
            self.seed_config(source)
            self.seed_config(target)
            ProviderStore(source / "providers.json").add(
                Provider(
                    id="provider-two",
                    name="Provider Two",
                    url="https://provider-two.example/sub",
                    last_updated=datetime(2026, 7, 7, 13, 0, tzinfo=timezone.utc),
                    profiles=[],
                    metadata={"traffic_used": "2 GB"},
                )
            )
            ProviderStore(target / "providers.json").add(
                Provider(
                    id="provider-one",
                    name="Local Provider Name",
                    url="https://local-provider.example/sub",
                    last_updated=None,
                    profiles=["local-profile"],
                    rotation_enabled=False,
                    metadata={"traffic_used": "old"},
                )
            )
            backup = BackupManager(config_dir=source).create_backup(
                Path(tmp) / "provider-state.zip",
                sections=["provider-state"],
            ).path

            BackupManager(config_dir=target).restore_backup(
                backup,
                sections=["provider-state"],
                replace_confirmation=RESTORE_REPLACE_CONFIRMATION,
            )

            providers = ProviderStore(target / "providers.json").list()
            self.assertEqual([provider.id for provider in providers], ["provider-one"])
            provider = providers[0]
            self.assertEqual(provider.name, "Local Provider Name")
            self.assertEqual(provider.url, "https://local-provider.example/sub")
            self.assertEqual(provider.profiles, ["local-profile"])
            self.assertFalse(provider.rotation_enabled)
            self.assertEqual(provider.last_updated, datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc))
            self.assertEqual(provider.metadata, {"traffic_used": "1 GB"})

    def test_provider_state_rejects_invalid_last_updated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            clean = BackupManager(config_dir=root).create_backup(
                root / "provider-state.zip",
                sections=["provider-state"],
            ).path
            broken = root / "broken-provider-state.zip"

            with ZipFile(clean) as source, ZipFile(broken, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename == "provider-state.json":
                        payload = json.loads(data)
                        payload["items"][0]["last_updated"] = "not-a-date"
                        data = json.dumps(payload).encode()
                    target.writestr(item.filename, data)

            with self.assertRaisesRegex(BackupValidationError, "last_updated"):
                BackupManager(config_dir=root).inspect_backup(broken)

    def test_default_backup_path_is_unique_with_same_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root, backup_dir=root / "backups")

            with patch("config.backup_manager._utc_now", return_value="2026-07-07T12:00:00+00:00"):
                first = manager.create_backup(reason="manual").path
                second = manager.create_backup(reason="manual").path

            self.assertNotEqual(first, second)
            self.assertTrue(first.exists())
            self.assertTrue(second.exists())
            self.assertTrue(second.name.endswith("-2.zip"))

    def test_auto_backup_prunes_old_entries_and_keeps_manual_backups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root, backup_dir=root / "backups")

            with patch("config.backup_manager._utc_now", return_value="2026-07-07T12:00:00+00:00"):
                manual = manager.create_backup(reason="manual").path
                first = manager.create_auto_backup(reason="pre-restore", max_backups=2).path
                second = manager.create_auto_backup(reason="pre-restore", max_backups=2).path
                third = manager.create_auto_backup(reason="pre-restore", max_backups=2).path

            self.assertTrue(manual.exists())
            self.assertFalse(first.exists())
            self.assertTrue(second.exists())
            self.assertTrue(third.exists())
            self.assertEqual(manager.list_auto_backups(), [second, third])

    def test_auto_backup_rejects_unknown_reason_or_invalid_retention(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            manager = BackupManager(config_dir=root)

            with self.assertRaisesRegex(BackupValidationError, "reason"):
                manager.create_auto_backup(reason="manual")
            with self.assertRaisesRegex(BackupValidationError, "max_backups"):
                manager.create_auto_backup(reason=AUTO_BACKUP_REASONS[0], max_backups=0)

    def test_backup_policy_rejects_invalid_retention(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed_config(root)
            clean = BackupManager(config_dir=root).create_backup(
                root / "backup-policy.zip",
                sections=["backup-policy"],
            ).path
            broken = root / "broken-backup-policy.zip"

            with ZipFile(clean) as source, ZipFile(broken, "w", compression=ZIP_DEFLATED) as target:
                for item in source.infolist():
                    data = source.read(item.filename)
                    if item.filename == "backup-policy.json":
                        payload = json.loads(data)
                        payload["retention"]["max_backups"] = 0
                        data = json.dumps(payload).encode()
                    target.writestr(item.filename, data)

            with self.assertRaisesRegex(BackupValidationError, "max_backups"):
                BackupManager(config_dir=root).inspect_backup(broken)

    def test_profiles_section_rejects_unsafe_openvpn_before_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = Profile(
                id="unsafe-openvpn",
                name="unsafe-openvpn",
                protocol=ProtocolType.OPENVPN,
                config={
                    "raw_config": "client\nremote vpn.example.com 1194\nplugin /tmp/evil.so\n",
                },
                source=ProfileSource.MANUAL,
            )
            payload = {
                "schema_version": BACKUP_SECTION_SCHEMA_VERSION,
                "items": [profile.to_dict()],
            }
            with self.assertRaisesRegex(BackupValidationError, "unsafe OpenVPN"):
                BackupManager(config_dir=root)._validate_section("profiles.json", payload)

    def seed_config(self, root: Path) -> None:
        AppConfig(root / "config.toml").save(AppConfig(root / "config.toml").load())
        ProfileStore(root / "profiles.json").add(
            Profile(
                id="profile-one",
                name="Profile One",
                protocol=ProtocolType.TROJAN,
                config={"host": "example.com", "port": 443},
                source=ProfileSource.MANUAL,
                in_rotation_pool=True,
            )
        )
        ProviderStore(root / "providers.json").add(
            Provider(
                id="provider-one",
                name="Provider One",
                url="https://provider.example/sub",
                last_updated=datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc),
                profiles=["profile-one"],
                rotation_enabled=True,
                metadata={"traffic_used": "1 GB"},
            )
        )
        RuleStore(root / "rules").add_group(
            RuleGroup(
                name="custom",
                rules=[
                    Rule(
                        id="rule-one",
                        action="direct",
                        conditions={"domain_suffix": ["example.com"]},
                    )
                ],
            )
        )
        AppPolicyStore(root / "app-policy.json").save(AppPolicy())
        NodeGroupStore(root / "node_groups.json").add(
            NodeGroup(name="primary", member_profile_ids=["profile-one"])
        )
        RouteChainStore(root / "chains.json").save(
            RouteChainDocument(
                chains=[
                    RouteChain(
                        id="work-safe",
                        enabled=False,
                        description="Local chain label",
                        hops=[
                            ChainHop(type="profile", target="profile-one"),
                            ChainHop(
                                type="group",
                                target="primary",
                                selection_policy="group_policy",
                            ),
                        ],
                    )
                ]
            )
        )
        StateManager(root / "state.toml").save(
            {
                "active_profile_id": "profile-one",
                "active_mode": "rules",
            }
        )
        DNSPolicyStore(root / "dns-policy.json").save(DNSPolicy())
        MetricsStore(root / "metrics.json").save(
            MetricsDocument(
                enabled=True,
                buckets=(
                    MetricsBucket(
                        bucket_start="2026-07-07T12:00:00+00:00",
                        bucket_end="2026-07-07T13:00:00+00:00",
                        counters={"command.connect.success": 1},
                    ),
                ),
            )
        )


if __name__ == "__main__":
    unittest.main()
