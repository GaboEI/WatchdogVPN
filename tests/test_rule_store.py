from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from config.persistence import (
    PersistentStoreError,
    PersistentValidationError,
    load_json,
    require_mapping,
)
from rules.models import DEFAULT_RULE_GROUPS, Rule, RuleGroup
from rules.rule_store import RuleStore, RuleStoreError


class RuleModelTests(unittest.TestCase):
    def test_rule_round_trip(self) -> None:
        rule = Rule(
            id="block-ads",
            action="block",
            conditions={"domain_suffix": ["ads.example.com"], "port": ["443"]},
        )
        restored = Rule.from_dict(rule.to_dict())
        self.assertEqual(restored, rule)

    def test_rule_accepts_group_action(self) -> None:
        rule = Rule(id="r1", action="group:custom", conditions={"domain": ["example.com"]})
        self.assertEqual(rule.action, "group:custom")

    def test_rule_rejects_unknown_action(self) -> None:
        with self.assertRaises(ValueError):
            Rule(id="r1", action="teleport", conditions={"domain": ["example.com"]})

    def test_rule_accepts_chain_action_syntax(self) -> None:
        rule = Rule(id="r1", action="chain:primary", conditions={"domain": ["example.com"]})
        self.assertEqual(rule.action, "chain:primary")

    def test_rule_rejects_group_action_without_id(self) -> None:
        with self.assertRaises(ValueError):
            Rule(id="r1", action="group:", conditions={"domain": ["example.com"]})

    def test_rule_rejects_unknown_condition_type(self) -> None:
        with self.assertRaises(ValueError):
            Rule(id="r1", action="direct", conditions={"wifi_ssid": ["home"]})

    def test_rule_rejects_empty_conditions(self) -> None:
        with self.assertRaises(ValueError):
            Rule(id="r1", action="direct", conditions={})

    def test_rule_rejects_empty_condition_values(self) -> None:
        with self.assertRaises(ValueError):
            Rule(id="r1", action="direct", conditions={"domain": []})

    def test_rule_group_round_trip(self) -> None:
        group = RuleGroup(
            name="custom",
            priority=5,
            rules=[Rule(id="r1", action="direct", conditions={"domain": ["example.com"]})],
        )
        restored = RuleGroup.from_dict(group.to_dict())
        self.assertEqual(restored, group)

    def test_rule_group_rejects_invalid_name(self) -> None:
        with self.assertRaises(ValueError):
            RuleGroup(name="../../etc/passwd")

    def test_rule_group_rejects_uppercase_name(self) -> None:
        with self.assertRaises(ValueError):
            RuleGroup(name="Custom")

    def test_rule_group_rejects_duplicate_rule_ids(self) -> None:
        with self.assertRaises(ValueError):
            RuleGroup(
                name="custom",
                rules=[
                    Rule(id="same", action="direct", conditions={"domain": ["a.com"]}),
                    Rule(id="same", action="block", conditions={"domain": ["b.com"]}),
                ],
            )


class RuleStoreTests(unittest.TestCase):
    def test_add_get_list_remove_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            group = RuleGroup(
                name="custom",
                rules=[Rule(id="r1", action="direct", conditions={"domain": ["example.com"]})],
            )
            store.add_group(group)

            self.assertEqual(store.get_group("custom"), group)
            self.assertEqual(store.list_groups(), [group])

            store.remove_group("custom")
            self.assertIsNone(store.get_group("custom"))
            self.assertEqual(store.list_groups(), [])

    def test_enable_disable_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            store.add_group(RuleGroup(name="custom", enabled=False))

            store.enable_group("custom")
            self.assertTrue(store.get_group("custom").enabled)

            store.disable_group("custom")
            self.assertFalse(store.get_group("custom").enabled)

    def test_enable_group_missing_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            with self.assertRaises(RuleStoreError):
                store.enable_group("does-not-exist")

    def test_add_rule_validates_and_persists_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            store.add_group(RuleGroup(name="custom"))

            updated = store.add_rule(
                "custom",
                Rule(id="r1", action="direct", conditions={"domain": ["example.com"]}),
            )

            self.assertEqual(updated.rules[0].id, "r1")
            self.assertEqual(store.get_group("custom").rules[0].action, "direct")

    def test_add_rule_rejects_duplicate_rule_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            store.add_group(
                RuleGroup(
                    name="custom",
                    rules=[Rule(id="r1", action="direct", conditions={"domain": ["a.com"]})],
                )
            )

            with self.assertRaises(RuleStoreError):
                store.add_rule(
                    "custom",
                    Rule(id="r1", action="block", conditions={"domain": ["b.com"]}),
                )

            self.assertEqual(store.get_group("custom").rules[0].conditions["domain"], ["a.com"])

    def test_set_priority_persists_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            store.add_group(RuleGroup(name="custom", priority=100))

            updated = store.set_priority("custom", 25)

            self.assertEqual(updated.priority, 25)
            self.assertEqual(store.get_group("custom").priority, 25)

    def test_set_priority_missing_group_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            with self.assertRaises(RuleStoreError):
                store.set_priority("does-not-exist", 25)

    def test_set_rule_enabled_toggles_single_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            store.add_group(
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(id="r1", action="direct", conditions={"domain": ["a.com"]}),
                        Rule(id="r2", action="block", conditions={"domain": ["b.com"]}),
                    ],
                )
            )

            updated = store.set_rule_enabled("custom", "r1", False)

            rules_by_id = {rule.id: rule for rule in updated.rules}
            self.assertFalse(rules_by_id["r1"].enabled)
            self.assertTrue(rules_by_id["r2"].enabled)
            self.assertFalse(store.get_group("custom").rules[0].enabled)

    def test_set_rule_enabled_missing_rule_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            store.add_group(RuleGroup(name="custom"))

            with self.assertRaises(RuleStoreError):
                store.set_rule_enabled("custom", "missing", False)

    def test_remove_rule_rejects_missing_rule_without_clobbering_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            group = RuleGroup(
                name="custom",
                rules=[Rule(id="r1", action="direct", conditions={"domain": ["a.com"]})],
            )
            store.add_group(group)

            with self.assertRaises(RuleStoreError):
                store.remove_rule("custom", "missing")

            self.assertEqual(store.get_group("custom"), group)

    def test_replace_group_can_backup_existing_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            original = RuleGroup(
                name="custom",
                rules=[Rule(id="old", action="direct", conditions={"domain": ["a.com"]})],
            )
            replacement = RuleGroup(
                name="custom",
                rules=[Rule(id="new", action="block", conditions={"domain": ["b.com"]})],
            )
            store.add_group(original)

            backup_path = store.replace_group(replacement, backup_existing=True)

            self.assertIsNotNone(backup_path)
            self.assertTrue(backup_path.exists())
            self.assertEqual(RuleGroup.from_dict(require_mapping(load_json(backup_path, {}), backup_path)), original)
            self.assertEqual(store.get_group("custom"), replacement)

    def test_ensure_default_groups_creates_all_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            custom = RuleGroup(
                name="custom",
                rules=[Rule(id="r1", action="block", conditions={"domain": ["ads.example.com"]})],
            )
            store.add_group(custom)

            store.ensure_default_groups()

            names = {group.name for group in store.list_groups()}
            self.assertEqual(names, set(DEFAULT_RULE_GROUPS))
            # existing group content must not be clobbered by ensure_default_groups
            self.assertEqual(store.get_group("custom"), custom)

    def test_import_group_uses_timestamped_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            rules = [Rule(id="r1", action="block", conditions={"domain": ["ads.example.com"]})]

            group = store.import_group(rules)

            self.assertTrue(group.name.startswith("imported-"))
            self.assertEqual(store.get_group(group.name).rules, rules)

    def test_import_group_disambiguates_same_second_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            rules = [Rule(id="r1", action="block", conditions={"domain": ["ads.example.com"]})]
            fixed_now = datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc)

            class _FixedDateTime(datetime):
                @classmethod
                def now(cls, tz=None):
                    return fixed_now

            with patch("rules.rule_store.datetime", _FixedDateTime):
                first = store.import_group(rules)
                second = store.import_group(rules)

            self.assertNotEqual(first.name, second.name)
            self.assertEqual(second.name, f"{first.name}-2")
            self.assertEqual(len(store.list_groups()), 2)

    def test_path_follows_environment_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp) / "custom-rules"
            with patch.dict("os.environ", {"WATCHDOGVPN_RULES_DIR": str(rules_dir)}, clear=False):
                store = RuleStore()
            self.assertEqual(store.path, rules_dir)

    def test_reports_corrupt_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp) / "rules"
            rules_dir.mkdir()
            (rules_dir / "custom.json").write_text("{", encoding="utf-8")

            store = RuleStore(rules_dir)
            with self.assertRaises(PersistentStoreError):
                store.get_group("custom")

    def test_reports_invalid_group_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp) / "rules"
            rules_dir.mkdir()
            (rules_dir / "custom.json").write_text('{"name": "custom", "enabled": "false"}', encoding="utf-8")

            store = RuleStore(rules_dir)
            with self.assertRaises(PersistentValidationError):
                store.get_group("custom")

    def test_rejects_path_traversal_group_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = RuleStore(Path(tmp) / "rules")
            with self.assertRaises(ValueError):
                store.get_group("../../etc/passwd")

    def test_atomic_save_does_not_leave_temp_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = Path(tmp) / "rules"
            store = RuleStore(rules_dir)

            store.add_group(RuleGroup(name="custom"))

            self.assertTrue((rules_dir / "custom.json").exists())
            self.assertEqual(list(rules_dir.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
