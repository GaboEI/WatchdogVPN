from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from app_policy.models import AppPolicy, AppPolicyRule
from app_policy.store import AppPolicyStore
from config.dns_policy_store import DNSPolicyStore
from config.profile_store import ProfileStore
from config.state_manager import StateManager
from dns.models import DNSChannel, DNSChannelName, DNSPolicy, Resolver
from models.profile import Profile, ProfileSource, ProtocolType
from route_chains.models import ChainHop, RouteChain, RouteChainDocument
from route_chains.store import RouteChainStore
from rules.models import Rule, RuleGroup
from rules.rule_store import RuleStore
from rules.ruleset_trust import RuleSetTrustPolicy, RuleSetTrustRegistry


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


class CliRulesCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_RULES_DIR": str(Path(tmp) / "rules"),
            "PYTHONPATH": str(ROOT_DIR),
        }
        result = subprocess.run(
            [str(WATCHDOG), *args],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        if check and result.returncode != 0:
            self.fail(f"command failed: {result.stderr}\nstdout={result.stdout}")
        return result

    def add_group(self, tmp: str, group: RuleGroup) -> None:
        RuleStore(Path(tmp) / "rules").add_group(group)

    def test_list_groups_json_and_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="example-direct",
                            action="direct",
                            conditions={"domain": ["example.com"]},
                        )
                    ],
                ),
            )

            json_result = self.run_watchdog(["rules", "list", "--json"], tmp)
            text_result = self.run_watchdog(["rules", "list"], tmp)

        data = json.loads(json_result.stdout)
        self.assertEqual(data[0]["name"], "custom")
        self.assertEqual(data[0]["rule_count"], 1)
        self.assertIn("Name\tEnabled\tPriority\tRules", text_result.stdout)
        self.assertIn("custom", text_result.stdout)

    def test_enable_disable_group_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(tmp, RuleGroup(name="custom", enabled=False))

            enabled = self.run_watchdog(["rules", "enable", "custom", "--json"], tmp)
            disabled = self.run_watchdog(["rules", "disable", "custom", "--json"], tmp)

        self.assertTrue(json.loads(enabled.stdout)["group"]["enabled"])
        self.assertFalse(json.loads(disabled.stdout)["group"]["enabled"])

    def test_add_and_remove_rule_persist_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(tmp, RuleGroup(name="custom"))

            added = self.run_watchdog(
                [
                    "rules",
                    "add-rule",
                    "custom",
                    "example-direct",
                    "--action",
                    "direct",
                    "--condition",
                    "domain=example.com",
                    "--condition",
                    "port=443",
                    "--json",
                ],
                tmp,
            )
            removed = self.run_watchdog(
                ["rules", "remove-rule", "custom", "example-direct", "--json"],
                tmp,
            )

        added_data = json.loads(added.stdout)
        self.assertEqual(added_data["added"]["conditions"]["domain"], ["example.com"])
        self.assertEqual(added_data["added"]["conditions"]["port"], ["443"])
        self.assertEqual(json.loads(removed.stdout)["group"]["rules"], [])

    def test_add_rule_rejects_invalid_condition_without_mutating_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(tmp, RuleGroup(name="custom"))

            result = self.run_watchdog(
                [
                    "rules",
                    "add-rule",
                    "custom",
                    "bad",
                    "--action",
                    "direct",
                    "--condition",
                    "wifi_ssid=home",
                ],
                tmp,
                check=False,
            )
            status = self.run_watchdog(["rules", "list", "--json"], tmp)

        self.assertEqual(result.returncode, 65)
        self.assertIn("unsupported rule condition", result.stderr)
        self.assertEqual(json.loads(status.stdout)[0]["rules"], [])

    def test_export_group_json_and_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[Rule(id="r1", action="block", conditions={"domain": ["a.com"]})],
                ),
            )
            output = Path(tmp) / "custom-export.json"

            json_result = self.run_watchdog(["rules", "export", "custom", "--json"], tmp)
            file_result = self.run_watchdog(
                ["rules", "export", "custom", "--output", str(output), "--json"],
                tmp,
            )
            exported_file = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(json.loads(json_result.stdout)["name"], "custom")
        self.assertEqual(exported_file["name"], "custom")
        self.assertEqual(json.loads(file_result.stdout)["output"], str(output))

    def test_import_group_rejects_duplicate_without_replace_or_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[Rule(id="old", action="direct", conditions={"domain": ["old.com"]})],
                ),
            )
            import_file = Path(tmp) / "incoming.json"
            import_file.write_text(
                json.dumps(
                    RuleGroup(
                        name="custom",
                        rules=[
                            Rule(
                                id="new",
                                action="block",
                                conditions={"domain": ["new.com"]},
                            )
                        ],
                    ).to_dict()
                ),
                encoding="utf-8",
            )

            result = self.run_watchdog(
                ["rules", "import", str(import_file)],
                tmp,
                check=False,
            )
            status = self.run_watchdog(["rules", "export", "custom", "--json"], tmp)

        self.assertEqual(result.returncode, 65)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(json.loads(status.stdout)["rules"][0]["id"], "old")

    def test_import_group_replace_writes_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[Rule(id="old", action="direct", conditions={"domain": ["old.com"]})],
                ),
            )
            import_file = Path(tmp) / "incoming.json"
            import_file.write_text(
                json.dumps(
                    RuleGroup(
                        name="custom",
                        rules=[
                            Rule(
                                id="new",
                                action="block",
                                conditions={"domain": ["new.com"]},
                            )
                        ],
                    ).to_dict()
                ),
                encoding="utf-8",
            )

            result = self.run_watchdog(
                ["rules", "import", str(import_file), "--replace", "--json"],
                tmp,
            )
            data = json.loads(result.stdout)
            backup_exists = Path(data["backup_path"]).exists()
            status = self.run_watchdog(["rules", "export", "custom", "--json"], tmp)

        self.assertTrue(data["replaced"])
        self.assertTrue(backup_exists)
        self.assertEqual(json.loads(status.stdout)["rules"][0]["id"], "new")

    def test_import_group_rejects_invalid_schema_without_mutating_existing_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[Rule(id="old", action="direct", conditions={"domain": ["old.com"]})],
                ),
            )
            import_file = Path(tmp) / "invalid.json"
            import_file.write_text(
                json.dumps({"name": "custom", "rules": [{"id": "bad", "action": "teleport"}]}),
                encoding="utf-8",
            )

            result = self.run_watchdog(
                ["rules", "import", str(import_file), "--replace"],
                tmp,
                check=False,
            )
            status = self.run_watchdog(["rules", "export", "custom", "--json"], tmp)

        self.assertEqual(result.returncode, 65)
        self.assertIn("invalid rule group schema", result.stderr)
        self.assertEqual(json.loads(status.stdout)["rules"][0]["id"], "old")

    def test_import_group_rejects_unknown_fields_as_input_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import_file = Path(tmp) / "invalid.json"
            import_file.write_text(
                json.dumps({"name": "custom", "enabled": True, "rules": [], "future": True}),
                encoding="utf-8",
            )

            result = self.run_watchdog(
                ["rules", "import", str(import_file)],
                tmp,
                check=False,
            )

        self.assertEqual(result.returncode, 65)
        self.assertIn("invalid rule group schema", result.stderr)

    def test_import_group_rejects_duplicate_rule_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import_file = Path(tmp) / "duplicate-rules.json"
            import_file.write_text(
                json.dumps(
                    {
                        "name": "custom",
                        "enabled": True,
                        "priority": 100,
                        "rules": [
                            {
                                "id": "same",
                                "action": "direct",
                                "conditions": {"domain": ["a.com"]},
                            },
                            {
                                "id": "same",
                                "action": "block",
                                "conditions": {"domain": ["b.com"]},
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = self.run_watchdog(
                ["rules", "import", str(import_file)],
                tmp,
                check=False,
            )

        self.assertEqual(result.returncode, 65)
        self.assertIn("duplicate rule ids", result.stderr)

    def test_import_simple_domain_ip_list_with_preview_and_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import_file = Path(tmp) / "blocklist.txt"
            import_file.write_text(
                "\n".join(["# comment", "example.com", ".ads.example", "10.0.0.0/24"]),
                encoding="utf-8",
            )

            preview = self.run_watchdog(
                [
                    "rules",
                    "import",
                    str(import_file),
                    "--name",
                    "simple-list",
                    "--dry-run",
                    "--json",
                ],
                tmp,
            )
            self.assertEqual(RuleStore(Path(tmp) / "rules").get_group("simple-list"), None)

            written = self.run_watchdog(
                ["rules", "import", str(import_file), "--name", "simple-list", "--json"],
                tmp,
            )

        preview_data = json.loads(preview.stdout)
        written_data = json.loads(written.stdout)
        self.assertTrue(preview_data["dry_run"])
        self.assertEqual(preview_data["rollback_point"], {"kind": "preview-only"})
        self.assertEqual(preview_data["source_format"], "simple-domain-ip-list")
        self.assertEqual(preview_data["accepted_rule_count"], 3)
        self.assertEqual(written_data["accepted_rule_count"], 3)
        self.assertEqual(written_data["rollback_point"], {"kind": "new-group-delete", "group": "simple-list"})
        self.assertEqual(written_data["imported"]["rules"][0]["conditions"], {"domain": ["example.com"]})
        self.assertEqual(
            written_data["imported"]["rules"][1]["conditions"],
            {"domain_suffix": [".ads.example"]},
        )
        self.assertEqual(written_data["imported"]["rules"][2]["conditions"], {"ip_cidr": ["10.0.0.0/24"]})

    def test_import_simple_list_rejects_partial_by_default_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import_file = Path(tmp) / "mixed.txt"
            import_file.write_text("example.com\nnot a domain\n", encoding="utf-8")

            result = self.run_watchdog(
                ["rules", "import", str(import_file), "--name", "mixed"],
                tmp,
                check=False,
            )

        self.assertEqual(result.returncode, 65)
        self.assertIn("unsupported entries", result.stderr)
        self.assertEqual(RuleStore(Path(tmp) / "rules").get_group("mixed"), None)

    def test_import_simple_list_allows_explicit_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import_file = Path(tmp) / "mixed.txt"
            import_file.write_text("example.com\nnot a domain\n", encoding="utf-8")

            result = self.run_watchdog(
                [
                    "rules",
                    "import",
                    str(import_file),
                    "--name",
                    "mixed",
                    "--allow-partial",
                    "--json",
                ],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["accepted_rule_count"], 1)
        self.assertEqual(data["rejected"][0]["reason"], "not a supported domain or IP CIDR")

    def test_import_clash_subset_maps_supported_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import_file = Path(tmp) / "clash.json"
            import_file.write_text(
                json.dumps(
                    [
                        "DOMAIN,example.com,DIRECT",
                        "DOMAIN-SUFFIX,ads.example,REJECT",
                        "IP-CIDR,192.0.2.0/24,PROXY",
                    ]
                ),
                encoding="utf-8",
            )

            result = self.run_watchdog(
                ["rules", "import", str(import_file), "--name", "clash-safe", "--json"],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["source_format"], "clash-rule-list")
        self.assertEqual(data["accepted_rule_count"], 3)
        self.assertEqual([rule["action"] for rule in data["imported"]["rules"]], ["direct", "block", "current_profile"])

    def test_import_singbox_subset_rejects_unsupported_constructs_without_partial_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import_file = Path(tmp) / "singbox.json"
            import_file.write_text(
                json.dumps(
                    {
                        "route": {
                            "rules": [
                                {"domain": ["example.com"], "outbound": "direct"},
                                {"type": "logical", "mode": "or", "rules": []},
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )

            result = self.run_watchdog(
                ["rules", "import", str(import_file), "--name", "singbox-safe"],
                tmp,
                check=False,
            )

        self.assertEqual(result.returncode, 65)
        self.assertIn("unsupported entries", result.stderr)
        self.assertEqual(RuleStore(Path(tmp) / "rules").get_group("singbox-safe"), None)

    def test_import_singbox_subset_allows_explicit_partial_and_reports_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import_file = Path(tmp) / "singbox.json"
            import_file.write_text(
                json.dumps(
                    {
                        "route": {
                            "rules": [
                                {"domain": ["example.com"], "outbound": "direct"},
                                {"type": "logical", "mode": "or", "rules": []},
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )

            result = self.run_watchdog(
                [
                    "rules",
                    "import",
                    str(import_file),
                    "--name",
                    "singbox-safe",
                    "--allow-partial",
                    "--json",
                ],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["source_format"], "sing-box-route-rules")
        self.assertEqual(data["accepted_rule_count"], 1)
        self.assertIn("unsupported structural fields", data["rejected"][0]["reason"])

    def test_explain_json_returns_raw_model_dict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="block",
                    rules=[
                        Rule(
                            id="ads",
                            action="block",
                            conditions={"domain_suffix": [".ads.example"]},
                        )
                    ],
                ),
            )

            result = self.run_watchdog(
                ["rules", "explain", "--domain", "cdn.ads.example", "--json"],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["confidence"], "definitive")
        self.assertEqual(data["input_traffic"]["domain"], "cdn.ads.example")
        self.assertEqual(data["matched"]["action"], "block")
        self.assertEqual(data["matched"]["group_name"], "block")
        self.assertEqual(data["matched"]["rule_id"], "ads")
        self.assertEqual(data["priority_path"][0]["result"], "matched")
        self.assertEqual(data["diagnostic_scope"], "configured-policy-only")
        self.assertFalse(data["runtime_observation"])
        self.assertEqual(data["routing"]["routing_policy"], "rule")
        self.assertEqual(data["routing"]["active_mode_role"], "compatibility-display-only")
        self.assertEqual(data["route_action"], "block")

    def test_explain_json_uses_default_route_action_not_active_mode_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            StateManager(Path(tmp) / "state.toml").save(
                {
                    "routing_policy": "rule",
                    "capture_modes": "local_proxy",
                    "default_route_action": "block",
                    "active_mode": "global",
                }
            )

            result = self.run_watchdog(
                ["rules", "explain", "--domain", "unmatched.example", "--json"],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["routing"]["routing_policy"], "rule")
        self.assertEqual(data["routing"]["default_route_action"], "block")
        self.assertEqual(data["routing"]["active_mode"], "global")
        self.assertEqual(data["route_action"], "block")
        self.assertEqual(data["route_source"]["source"], "final")
        self.assertTrue(data["no_rule_match"])

    def test_explain_json_global_policy_ignores_matching_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            StateManager(Path(tmp) / "state.toml").save(
                {
                    "routing_policy": "global",
                    "capture_modes": "local_proxy",
                    "default_route_action": "direct",
                    "active_mode": "global",
                }
            )
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="would-block-under-rule-policy",
                            action="block",
                            conditions={"domain": ["example.com"]},
                        )
                    ],
                ),
            )

            result = self.run_watchdog(
                ["rules", "explain", "--domain", "example.com", "--json"],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["routing"]["routing_policy"], "global")
        self.assertEqual(data["route_action"], "direct")
        self.assertEqual(data["route_source"]["source"], "routing-policy")
        self.assertEqual(data["rule_evaluation"], "ignored-by-global-policy")
        self.assertIsNone(data["rule_explanation"])

    def test_explain_json_process_app_policy_reports_policy_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            AppPolicyStore(Path(tmp) / "app-policy.json").save(
                AppPolicy(
                    enabled=True,
                    rules=[
                        AppPolicyRule(
                            id="curl-block",
                            action="block",
                            match={"process_name": ["curl"]},
                        )
                    ],
                )
            )

            result = self.run_watchdog(
                [
                    "rules",
                    "explain",
                    "--domain",
                    "example.com",
                    "--process-name",
                    "curl",
                    "--json",
                ],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["route_action"], "block")
        self.assertEqual(data["route_source"]["source"], "app-policy")

    def test_explain_json_includes_redacted_chain_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ProfileStore(Path(tmp) / "profiles.json").add(
                Profile(
                    id="secret-profile-token-1234567890abcdef",
                    name="secret-profile-token-1234567890abcdef",
                    protocol=ProtocolType.VLESS,
                    config={
                        "host": "secret-profile-token-1234567890abcdef.example",
                        "port": 443,
                        "uuid": "secret-profile-token-1234567890abcdef",
                    },
                    source=ProfileSource.MANUAL,
                )
            )
            RouteChainStore(Path(tmp) / "chains.json").save(
                RouteChainDocument(
                    chains=[
                        RouteChain(
                            id="work-safe",
                            enabled=True,
                            hops=[
                                ChainHop(
                                    type="profile",
                                    target="secret-profile-token-1234567890abcdef",
                                )
                            ],
                        )
                    ]
                )
            )
            DNSPolicyStore(Path(tmp) / "dns-policy.json").save(
                DNSPolicy(
                    channels={
                        DNSChannelName.PROXY: DNSChannel(
                            name=DNSChannelName.PROXY,
                            resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                        )
                    }
                )
            )
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="chain",
                            action="chain:work-safe",
                            conditions={"domain": ["example.com"]},
                        )
                    ],
                ),
            )

            result = self.run_watchdog(
                ["rules", "explain", "--domain", "example.com", "--json"],
                tmp,
            )

        data = json.loads(result.stdout)
        rendered = json.dumps(data)
        self.assertEqual(data["chain"]["chain_id"], "work-safe")
        self.assertEqual(data["chain"]["status"], "resolved")
        self.assertEqual(data["chain"]["confidence"], "predicted")
        self.assertEqual(data["chain"]["hop_order"][0]["target"], "<redacted-profile-target>")
        self.assertNotIn("secret-profile-token", rendered)

    def test_definitive_text_can_state_configured_policy_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="example-direct",
                            action="direct",
                            conditions={"domain": ["example.com"]},
                        )
                    ],
                ),
            )

            result = self.run_watchdog(
                ["rules", "explain", "--domain", "example.com"],
                tmp,
            )

        self.assertIn("configured policy only, not live traffic observation", result.stdout)
        self.assertIn("Confidence: definitive", result.stdout)
        self.assertIn("would use action 'direct'", result.stdout)
        self.assertIn("Matched rule: custom/example-direct", result.stdout)

    def test_partial_text_does_not_overstate_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="https-example",
                            action="direct",
                            conditions={"domain": ["example.com"], "port": ["443"]},
                        )
                    ],
                ),
            )

            result = self.run_watchdog(
                ["rules", "explain", "--domain", "example.com"],
                tmp,
            )

        self.assertIn("Confidence: partial", result.stdout)
        self.assertIn("Decision: incomplete", result.stdout)
        self.assertIn("Candidate local action:", result.stdout)
        self.assertNotIn("would use action", result.stdout)

    def test_runtime_required_text_does_not_overstate_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="remote",
                            action="block",
                            conditions={"ruleset_remote": ["https://rules.example/set.srs"]},
                        ),
                        Rule(
                            id="local",
                            action="direct",
                            conditions={"domain": ["example.com"]},
                        ),
                    ],
                ),
            )

            result = self.run_watchdog(
                ["rules", "explain", "--domain", "example.com"],
                tmp,
            )

        self.assertIn("Confidence: runtime-required", result.stdout)
        self.assertIn("cannot be determined statically", result.stdout)
        self.assertIn("runtime-evaluated rule sets may change the result", result.stdout)
        self.assertIn("Unevaluated rule sets:", result.stdout)
        self.assertIn("state=not-evaluated", result.stdout)
        self.assertNotIn("would use action", result.stdout)

    def test_explain_reports_failed_critical_ruleset_from_trust_registry(self) -> None:
        rule_set_id = "https://rules.example/sensitive.srs"
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="sensitive",
                            action="current_profile",
                            conditions={"ruleset_remote": [rule_set_id]},
                        )
                    ],
                ),
            )
            trust_file = Path(tmp) / "ruleset-trust.json"
            trust_file.write_text(
                json.dumps(
                    {
                        "policies": {
                            rule_set_id: {
                                "id": rule_set_id,
                                "kind": "remote",
                                "source": rule_set_id,
                                "critical": True,
                                "expected_sha256": "a" * 64,
                            }
                        },
                        "statuses": {
                            rule_set_id: {
                                "id": rule_set_id,
                                "state": "failed",
                                "error": "sha256 mismatch",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = self.run_watchdog(
                [
                    "rules",
                    "explain",
                    "--domain",
                    "example.com",
                    "--ruleset-trust-file",
                    str(trust_file),
                ],
                tmp,
            )

        self.assertIn("Confidence: runtime-required", result.stdout)
        self.assertIn("state=failed", result.stdout)
        self.assertIn("behavior=fail-closed", result.stdout)
        self.assertIn("error=sha256 mismatch", result.stdout)
        self.assertNotIn("would use action", result.stdout)

    def test_ruleset_status_json_reports_trust_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {"version": 1, "rules": [{"domain": ["example.com"]}]}
            source = Path(tmp) / "builtin.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            policy = RuleSetTrustPolicy(
                id="builtin-example",
                kind="built-in",
                source=str(source),
                critical=False,
            )
            trust_file = Path(tmp) / "ruleset-trust.json"
            trust_file.write_text(
                json.dumps(RuleSetTrustRegistry(policies={policy.id: policy}).to_dict()),
                encoding="utf-8",
            )

            result = self.run_watchdog(["ruleset", "status", "--json"], tmp)

        data = json.loads(result.stdout)
        self.assertEqual(data["policies"]["builtin-example"]["kind"], "built-in")
        self.assertEqual(data["policies"]["builtin-example"]["failure_behavior"], "warn-and-skip")

    def test_ruleset_refresh_referenced_only_caches_builtin_ruleset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "builtin.json"
            source.write_text(
                json.dumps({"version": 1, "rules": [{"domain": ["example.com"]}]}),
                encoding="utf-8",
            )
            policy = RuleSetTrustPolicy(
                id="builtin-example",
                kind="built-in",
                source=str(source),
                critical=True,
            )
            trust_file = Path(tmp) / "ruleset-trust.json"
            trust_file.write_text(
                json.dumps(RuleSetTrustRegistry(policies={policy.id: policy}).to_dict()),
                encoding="utf-8",
            )
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="rs",
                            action="block",
                            conditions={"ruleset_builtin": [policy.id]},
                        )
                    ],
                ),
            )

            result = self.run_watchdog(
                ["ruleset", "refresh", "--referenced-only", "--force", "--json"],
                tmp,
            )
            data = json.loads(result.stdout)
            self.assertEqual(data["refreshed_count"], 1)
            item = data["results"][0]
            self.assertEqual(item["id"], "builtin-example")
            self.assertEqual(item["state"], "loaded")
            self.assertTrue(Path(item["cache_path"]).exists())

    def test_unknown_text_asks_for_input_without_overstating_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.add_group(
                tmp,
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="needs-domain",
                            action="block",
                            conditions={"domain": ["example.com"]},
                        )
                    ],
                ),
            )

            result = self.run_watchdog(["rules", "explain"], tmp)

        self.assertIn("Confidence: unknown", result.stdout)
        self.assertIn("provide a domain, IP, port, protocol, network, or process", result.stdout)
        self.assertNotIn("would use action", result.stdout)

    def test_explain_reads_rules_without_mutating_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            group = RuleGroup(
                name="custom",
                rules=[
                    Rule(
                        id="example-direct",
                        action="direct",
                        conditions={"domain": ["example.com"]},
                    )
                ],
            )
            self.add_group(tmp, group)
            before = (Path(tmp) / "rules" / "custom.json").read_text(encoding="utf-8")

            self.run_watchdog(["rules", "explain", "--domain", "example.com"], tmp)

            after = (Path(tmp) / "rules" / "custom.json").read_text(encoding="utf-8")

        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
