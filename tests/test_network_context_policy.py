from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from config.persistence import PersistentStoreError, PersistentValidationError
from network_context.models import (
    ActionIntent,
    NetworkContextPolicy,
    NetworkContextTrigger,
    NetworkMatch,
    NetworkMatchKind,
    NetworkPolicyAction,
    NetworkProfile,
    NetworkTrust,
)
from network_context.store import NetworkContextPolicyStore


HASHED_VALUE = "a" * 64


class NetworkContextActionIntentTests(unittest.TestCase):
    def test_default_intent_is_manual_disabled_explainable_and_reversible(self) -> None:
        intent = ActionIntent()

        self.assertFalse(intent.enabled)
        self.assertEqual(intent.action, NetworkPolicyAction.MANUAL)
        self.assertTrue(intent.explanation)
        self.assertTrue(intent.disable_hint)
        self.assertTrue(intent.reversible)
        self.assertTrue(intent.reversal)

    def test_enabled_action_cannot_be_manual(self) -> None:
        with self.assertRaises(PersistentValidationError):
            ActionIntent(enabled=True, action="manual")

    def test_automatic_actions_must_be_reversible(self) -> None:
        with self.assertRaises(PersistentValidationError):
            ActionIntent(
                enabled=True,
                action="connect",
                explanation="Connect only after explicit policy consent.",
                disable_hint="Disable this intent in network context policy.",
                reversible=False,
                reversal="Disconnect manually.",
            )

    def test_enabled_disconnect_intent_round_trips_with_semantics(self) -> None:
        intent = ActionIntent(
            enabled=True,
            action="disconnect",
            explanation="Disconnect when an explicitly untrusted profile matches.",
            disable_hint="Disable the untrusted network trigger.",
            reversible=True,
            reversal="Reconnect manually or by another explicit policy.",
        )

        restored = ActionIntent.from_dict(intent.to_dict())

        self.assertEqual(restored, intent)


class NetworkContextProfileTests(unittest.TestCase):
    def test_profile_round_trip_with_hashed_match(self) -> None:
        profile = NetworkProfile(
            id="home-safe",
            label="Home",
            trust="trusted",
            matches=[NetworkMatch(kind="ssid_sha256", value=HASHED_VALUE)],
        )

        restored = NetworkProfile.from_dict(profile.to_dict())

        self.assertEqual(restored, profile)
        self.assertEqual(restored.trust, NetworkTrust.TRUSTED)
        self.assertEqual(restored.matches[0].kind, NetworkMatchKind.SSID_SHA256)

    def test_rejects_invalid_profile_shape(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NetworkProfile.from_dict(
                {
                    "id": "../bad",
                    "label": "Bad",
                    "matches": [{"kind": "profile_tag", "value": "bad"}],
                }
            )
        with self.assertRaises(PersistentValidationError):
            NetworkProfile.from_dict({"id": "missing", "label": "Missing"})
        with self.assertRaises(PersistentValidationError):
            NetworkProfile(
                id="empty",
                label="Empty",
                trust="unknown",
                matches=[],
            )

    def test_rejects_invalid_hash_match(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NetworkMatch(kind="ssid_sha256", value="not-a-sha256")

    def test_raw_sensitive_match_requires_explicit_consent(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NetworkMatch(kind="raw_ssid", value="Home Wi-Fi")
        with self.assertRaises(PersistentValidationError):
            NetworkMatch(
                kind="raw_interface_name",
                value="wlp3s0",
                explicit_consent=True,
            )

    def test_raw_sensitive_match_is_allowed_with_explicit_consent_note(self) -> None:
        match = NetworkMatch(
            kind="raw_bssid",
            value="aa:bb:cc:dd:ee:ff",
            explicit_consent=True,
            consent_note="User chose to persist this local identifier.",
        )

        restored = NetworkMatch.from_dict(match.to_dict())

        self.assertEqual(restored, match)


class NetworkContextPolicyTests(unittest.TestCase):
    def test_default_policy_is_disabled_manual_and_redacted(self) -> None:
        policy = NetworkContextPolicy()

        self.assertFalse(policy.enabled)
        self.assertEqual(policy.profiles, [])
        self.assertTrue(policy.redaction["support_export"])
        self.assertFalse(policy.redaction["include_profile_labels"])
        self.assertFalse(policy.redaction["include_match_values"])
        self.assertEqual(set(policy.triggers), set(NetworkContextTrigger))
        for intent in policy.triggers.values():
            self.assertFalse(intent.enabled)
            self.assertEqual(intent.action, NetworkPolicyAction.MANUAL)

    def test_policy_round_trip_with_trusted_untrusted_and_state_triggers(self) -> None:
        policy = NetworkContextPolicy(
            enabled=True,
            profiles=[
                NetworkProfile(
                    id="trusted-home",
                    label="Home",
                    trust="trusted",
                    matches=[NetworkMatch(kind="ssid_sha256", value=HASHED_VALUE)],
                ),
                NetworkProfile(
                    id="public",
                    label="Public",
                    trust="untrusted",
                    matches=[NetworkMatch(kind="interface_type", value="wifi")],
                ),
            ],
            triggers={
                NetworkContextTrigger.TRUSTED_NETWORK: ActionIntent(
                    enabled=False,
                    action="keep_current",
                    explanation="Keep the current connection on trusted networks.",
                    disable_hint="Set this trigger to manual.",
                    reversible=True,
                    reversal="No runtime state is changed.",
                ),
                NetworkContextTrigger.UNTRUSTED_NETWORK: ActionIntent(
                    enabled=True,
                    action="connect",
                    explanation="Connect only when the user enabled this policy.",
                    disable_hint="Disable the untrusted network trigger.",
                    reversible=True,
                    reversal="Disconnect or return to manual mode.",
                ),
                NetworkContextTrigger.CAPTIVE_PORTAL: ActionIntent(
                    enabled=False,
                    action="warn_only",
                    explanation="Warn only; captive portal is advisory.",
                    disable_hint="Set this trigger to manual.",
                    reversible=True,
                    reversal="Dismiss the warning.",
                ),
                NetworkContextTrigger.OFFLINE: ActionIntent(
                    enabled=False,
                    action="warn_only",
                    explanation="Warn only; offline state is advisory.",
                    disable_hint="Set this trigger to manual.",
                    reversible=True,
                    reversal="Dismiss the warning.",
                ),
                NetworkContextTrigger.INTERFACE_CHANGED: ActionIntent(
                    enabled=False,
                    action="keep_current",
                    explanation="Keep current state after interface changes by default.",
                    disable_hint="Set this trigger to manual.",
                    reversible=True,
                    reversal="No runtime state is changed.",
                ),
            },
        )

        restored = NetworkContextPolicy.from_dict(policy.to_dict())

        self.assertEqual(restored, policy)

    def test_rejects_unknown_schema_version_and_duplicate_profile_ids(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NetworkContextPolicy.from_dict({"schema_version": 2})
        with self.assertRaises(PersistentValidationError):
            NetworkContextPolicy(
                profiles=[
                    NetworkProfile(
                        id="same",
                        label="One",
                        matches=[NetworkMatch(kind="profile_tag", value="one")],
                    ),
                    NetworkProfile(
                        id="same",
                        label="Two",
                        matches=[NetworkMatch(kind="profile_tag", value="two")],
                    ),
                ]
            )

    def test_rejects_history_and_raw_sensitive_policy_fields(self) -> None:
        forbidden_fields = (
            "raw_ssid",
            "raw_bssid",
            "raw_interface_name",
            "gateway_identifier",
            "public_exit_ip_history",
            "captive_portal_history",
            "per_network_automation_history",
        )
        for field_name in forbidden_fields:
            with self.subTest(field_name=field_name):
                with self.assertRaises(PersistentValidationError):
                    NetworkContextPolicy.from_dict({field_name: []})

    def test_rejects_unknown_redaction_or_trigger_shapes(self) -> None:
        with self.assertRaises(PersistentValidationError):
            NetworkContextPolicy.from_dict({"redaction": {"include_raw_values": True}})
        with self.assertRaises(PersistentValidationError):
            NetworkContextPolicy.from_dict({"triggers": {"roaming": {}}})
        with self.assertRaises(PersistentValidationError):
            NetworkContextPolicy.from_dict({"enabled": "false"})

    def test_redacted_export_hides_labels_hashes_and_raw_values(self) -> None:
        policy = NetworkContextPolicy(
            enabled=True,
            profiles=[
                NetworkProfile(
                    id="raw-consented",
                    label="Office Wi-Fi",
                    trust="trusted",
                    matches=[
                        NetworkMatch(
                            kind="raw_ssid",
                            value="Office Secret SSID",
                            explicit_consent=True,
                            consent_note="User explicitly chose raw SSID matching.",
                        ),
                        NetworkMatch(kind="gateway_identifier_sha256", value=HASHED_VALUE),
                    ],
                )
            ],
        )

        redacted = policy.to_redacted_dict()
        rendered = repr(redacted)

        self.assertIn("<redacted-profile-label>", rendered)
        self.assertIn("<redacted-sensitive-value>", rendered)
        self.assertIn("<redacted-match-value>", rendered)
        self.assertNotIn("Office Wi-Fi", rendered)
        self.assertNotIn("Office Secret SSID", rendered)
        self.assertNotIn(HASHED_VALUE, rendered)


class NetworkContextPolicyStoreTests(unittest.TestCase):
    def test_load_missing_file_returns_disabled_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = NetworkContextPolicyStore(
                Path(tmp) / "network-context-policy.json"
            ).load()

        self.assertFalse(policy.enabled)
        for intent in policy.triggers.values():
            self.assertEqual(intent.action, NetworkPolicyAction.MANUAL)

    def test_save_load_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "network-context-policy.json"
            store = NetworkContextPolicyStore(path)
            policy = NetworkContextPolicy(
                enabled=True,
                profiles=[
                    NetworkProfile(
                        id="trusted",
                        label="Trusted",
                        trust="trusted",
                        matches=[NetworkMatch(kind="profile_tag", value="lab")],
                    )
                ],
                triggers={
                    NetworkContextTrigger.INTERFACE_CHANGED: ActionIntent(
                        enabled=False,
                        action="warn_only",
                        explanation="Warn only on interface changes.",
                        disable_hint="Set this trigger to manual.",
                        reversible=True,
                        reversal="Dismiss the warning.",
                    )
                },
            )

            store.save(policy)

            self.assertEqual(store.load(), policy)

    def test_load_or_disabled_fails_closed_on_corrupt_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "network-context-policy.json"
            path.write_text("{", encoding="utf-8")

            result = NetworkContextPolicyStore(path).load_or_disabled()

        self.assertFalse(result.valid)
        self.assertIsNotNone(result.error)
        self.assertFalse(result.policy.enabled)
        for intent in result.policy.triggers.values():
            self.assertEqual(intent.action, NetworkPolicyAction.MANUAL)

    def test_load_raises_on_corrupt_json_for_strict_callers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "network-context-policy.json"
            path.write_text("{", encoding="utf-8")

            with self.assertRaises(PersistentStoreError):
                NetworkContextPolicyStore(path).load()
