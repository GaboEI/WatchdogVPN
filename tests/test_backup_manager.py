from __future__ import annotations

import json
import tempfile
import unittest
import warnings
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

from app_policy.models import AppPolicy
from app_policy.store import AppPolicyStore
from config.app_config import AppConfig
from config.backup_manager import (
    BACKUP_ENTRIES,
    BACKUP_SCHEMA_VERSION,
    BackupManager,
    BackupValidationError,
)
from config.dns_policy_store import DNSPolicyStore
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from config.state_manager import StateManager
from dns.models import DNSPolicy
from metrics.models import MetricsBucket, MetricsDocument
from metrics.store import MetricsStore
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider
from node_groups.models import NodeGroup
from node_groups.store import NodeGroupStore
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
                metrics_policy = json.loads(archive.read("metrics-policy.json"))
                self.assertFalse(metrics_policy["history_included"])
                self.assertNotIn("buckets", metrics_policy)
                profiles = json.loads(archive.read("profiles.json"))
                self.assertEqual(profiles["items"][0]["id"], "profile-one")
                selection = json.loads(archive.read("selection-state.json"))
                self.assertEqual(selection["state"]["active_profile_id"], "profile-one")

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

            result = manager.restore_backup(backup)

            profiles = ProfileStore(root / "profiles.json").list()
            self.assertEqual([profile.id for profile in profiles], ["profile-one"])
            self.assertTrue(result.pre_restore_backup.exists())
            with ZipFile(result.pre_restore_backup) as archive:
                previous = json.loads(archive.read("profiles.json"))
            self.assertEqual(
                sorted(item["id"] for item in previous["items"]),
                ["changed", "profile-one"],
            )

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
                    manager.restore_backup(backup)

            self.assertEqual(
                (root / "profiles.json").read_text(encoding="utf-8"),
                original_profiles,
            )

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
