from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app_policy.models import (
    AppPolicy,
    AppPolicyAction,
    AppPolicyMode,
    AppPolicyRule,
    MatchConfidence,
)
from app_policy.store import AppPolicyStore
from config.persistence import PersistentStoreError, PersistentValidationError


class AppPolicyRuleModelTests(unittest.TestCase):
    def test_rule_round_trip_with_all_supported_matchers(self) -> None:
        rule = AppPolicyRule(
            id="browser",
            action="current",
            match={
                "process_name": ["firefox"],
                "process_path": ["/usr/lib/firefox/firefox"],
                "process_path_regex": ["^/usr/lib/firefox/.+"],
                "user": ["gabodev"],
                "user_id": [1000],
            },
        )

        restored = AppPolicyRule.from_dict(rule.to_dict())

        self.assertEqual(restored, rule)
        self.assertEqual(restored.action, AppPolicyAction.CURRENT)
        self.assertEqual(restored.match_confidence, MatchConfidence.HIGH)

    def test_process_name_only_is_low_confidence(self) -> None:
        rule = AppPolicyRule(
            id="curl",
            action="direct",
            match={"process_name": ["curl"]},
        )

        self.assertEqual(rule.match_confidence, MatchConfidence.LOW)

    def test_user_or_path_regex_is_medium_confidence(self) -> None:
        regex_rule = AppPolicyRule(
            id="appimage",
            action="block",
            match={"process_path_regex": ["^/tmp/.+AppImage$"]},
        )
        user_rule = AppPolicyRule(
            id="sandbox-user",
            action="block",
            match={"user": ["wdvpn-app"]},
        )

        self.assertEqual(regex_rule.match_confidence, MatchConfidence.MEDIUM)
        self.assertEqual(user_rule.match_confidence, MatchConfidence.MEDIUM)

    def test_rejects_bare_auto_action(self) -> None:
        # "auto" (bare, no group) still has no backing mechanism - unlike
        # group:<name>, which Task 14.6 now backs with a real NodeGroup
        # selector. If a bare auto-select-from-default-pool action is ever
        # built, it should be spelled "auto_select" (matching
        # rules.models.SIMPLE_RULE_ACTIONS), not "auto" - a second name for
        # the same concept, not reintroducing this literal.
        with self.assertRaises(PersistentValidationError):
            AppPolicyRule(
                id="future",
                action="auto",
                match={"process_path": ["/usr/bin/curl"]},
            )

    def test_accepts_group_action_backed_by_task_14_6(self) -> None:
        rule = AppPolicyRule(
            id="secure",
            action="group:secure",
            match={"process_path": ["/usr/bin/curl"]},
        )

        self.assertEqual(rule.action, "group:secure")
        self.assertEqual(rule.to_dict()["action"], "group:secure")

    def test_group_action_round_trips_through_from_dict(self) -> None:
        rule = AppPolicyRule(
            id="secure",
            action="group:secure",
            match={"process_path": ["/usr/bin/curl"]},
        )

        restored = AppPolicyRule.from_dict(rule.to_dict())

        self.assertEqual(restored, rule)

    def test_rejects_unknown_action(self) -> None:
        with self.assertRaises(PersistentValidationError):
            AppPolicyRule(
                id="bad",
                action="proxy",
                match={"process_path": ["/usr/bin/curl"]},
            )

    def test_accepts_chain_action_syntax(self) -> None:
        rule = AppPolicyRule(
            id="chain",
            action="chain:primary",
            match={"process_path": ["/usr/bin/curl"]},
        )
        self.assertEqual(rule.action, "chain:primary")

    def test_accepts_chain_default_action_syntax(self) -> None:
        policy = AppPolicy(default_action="chain:primary")
        self.assertEqual(policy.default_action, "chain:primary")

    def test_rejects_unknown_matcher(self) -> None:
        with self.assertRaises(PersistentValidationError):
            AppPolicyRule(
                id="bad",
                action="block",
                match={"package_name": ["org.example.App"]},
            )

    def test_rejects_empty_matchers_and_values(self) -> None:
        with self.assertRaises(PersistentValidationError):
            AppPolicyRule(id="empty", action="block", match={})
        with self.assertRaises(PersistentValidationError):
            AppPolicyRule(id="empty-value", action="block", match={"process_name": [""]})

    def test_rejects_non_integer_user_id(self) -> None:
        with self.assertRaises(PersistentValidationError):
            AppPolicyRule(id="uid", action="block", match={"user_id": ["1000"]})

    def test_rejects_negative_user_id(self) -> None:
        with self.assertRaises(PersistentValidationError):
            AppPolicyRule(id="uid", action="block", match={"user_id": [-1]})

    def test_rejects_missing_required_rule_fields_as_validation_error(self) -> None:
        with self.assertRaises(PersistentValidationError):
            AppPolicyRule.from_dict({"id": "missing-action", "match": {"user_id": [1000]}})


class AppPolicyModelTests(unittest.TestCase):
    def test_policy_round_trip(self) -> None:
        policy = AppPolicy(
            enabled=True,
            mode="whitelist",
            default_action="block",
            rules=[
                AppPolicyRule(
                    id="curl",
                    action="direct",
                    match={"process_path": ["/usr/bin/curl"]},
                )
            ],
        )

        restored = AppPolicy.from_dict(policy.to_dict())

        self.assertEqual(restored, policy)
        self.assertEqual(restored.mode, AppPolicyMode.WHITELIST)
        self.assertEqual(restored.default_action, AppPolicyAction.BLOCK)

    def test_default_policy_is_disabled_blacklist_current(self) -> None:
        policy = AppPolicy()

        self.assertFalse(policy.enabled)
        self.assertEqual(policy.mode, AppPolicyMode.BLACKLIST)
        self.assertEqual(policy.default_action, AppPolicyAction.CURRENT)
        self.assertEqual(policy.rules, [])

    def test_disabled_due_to_error_is_fail_closed(self) -> None:
        policy = AppPolicy.disabled_due_to_error("bad file")

        self.assertFalse(policy.enabled)
        self.assertEqual(policy.mode, AppPolicyMode.BLACKLIST)
        self.assertEqual(policy.default_action, AppPolicyAction.BLOCK)
        self.assertEqual(policy.rules, [])

    def test_rejects_string_boolean(self) -> None:
        with self.assertRaises(PersistentValidationError):
            AppPolicy.from_dict({"enabled": "false"})

    def test_rejects_unknown_policy_field(self) -> None:
        with self.assertRaises(PersistentValidationError):
            AppPolicy.from_dict({"future": True})

    def test_rejects_unknown_schema_version(self) -> None:
        with self.assertRaises(PersistentValidationError):
            AppPolicy.from_dict({"schema_version": 2})

    def test_rejects_auto_default_action(self) -> None:
        with self.assertRaises(PersistentValidationError):
            AppPolicy.from_dict({"default_action": "auto"})

    def test_group_default_action_round_trips(self) -> None:
        policy = AppPolicy(
            enabled=True,
            mode="whitelist",
            default_action="group:secure",
            rules=[],
        )

        restored = AppPolicy.from_dict(policy.to_dict())

        self.assertEqual(restored, policy)
        self.assertEqual(restored.default_action, "group:secure")
        self.assertEqual(restored.to_dict()["default_action"], "group:secure")


class AppPolicyStoreTests(unittest.TestCase):
    def test_load_missing_file_returns_disabled_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = AppPolicyStore(Path(tmp) / "app-policy.json").load()

        self.assertFalse(policy.enabled)
        self.assertEqual(policy.default_action, AppPolicyAction.CURRENT)

    def test_save_load_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app-policy.json"
            store = AppPolicyStore(path)
            policy = AppPolicy(
                enabled=True,
                mode="blacklist",
                default_action="current",
                rules=[
                    AppPolicyRule(
                        id="blocked-helper",
                        action="block",
                        match={"process_path": ["/usr/bin/helper"]},
                    )
                ],
            )

            store.save(policy)

            self.assertEqual(store.load(), policy)

    def test_load_or_disabled_fails_closed_on_corrupt_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app-policy.json"
            path.write_text("{", encoding="utf-8")

            result = AppPolicyStore(path).load_or_disabled()

        self.assertFalse(result.valid)
        self.assertIsNotNone(result.error)
        self.assertFalse(result.policy.enabled)
        self.assertEqual(result.policy.default_action, AppPolicyAction.BLOCK)

    def test_load_raises_on_corrupt_json_for_strict_callers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app-policy.json"
            path.write_text("{", encoding="utf-8")

            with self.assertRaises(PersistentStoreError):
                AppPolicyStore(path).load()

    def test_load_or_disabled_fails_closed_on_invalid_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app-policy.json"
            path.write_text('{"enabled": "false"}', encoding="utf-8")

            result = AppPolicyStore(path).load_or_disabled()

        self.assertFalse(result.valid)
        self.assertFalse(result.policy.enabled)
        self.assertEqual(result.policy.default_action, AppPolicyAction.BLOCK)

    def test_path_follows_environment_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "custom-policy.json"
            with patch.dict(
                "os.environ",
                {"WATCHDOGVPN_APP_POLICY_FILE": str(policy_path)},
                clear=False,
            ):
                store = AppPolicyStore()

        self.assertEqual(store.path, policy_path)

    def test_atomic_save_does_not_leave_temp_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app-policy.json"

            AppPolicyStore(path).save(AppPolicy())

            self.assertTrue(path.exists())
            self.assertEqual(list(Path(tmp).glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
