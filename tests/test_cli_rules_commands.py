from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from rules.models import Rule, RuleGroup
from rules.rule_store import RuleStore


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
