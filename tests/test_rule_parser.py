from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rules.models import Rule
from rules.rule_parser import (
    RuleParseError,
    export_watchdogvpn_json,
    parse_clash_yaml_rules,
    parse_singbox_ruleset_json,
    parse_singbox_ruleset_srs,
    parse_watchdogvpn_json,
)


class WatchdogVpnJsonParserTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        rules = [
            Rule(id="r1", action="block", conditions={"domain_suffix": ["ads.example.com"]}),
            Rule(id="r2", action="group:custom", conditions={"ip_cidr": ["10.0.0.0/8"]}),
        ]
        exported = export_watchdogvpn_json(rules)
        restored = parse_watchdogvpn_json(exported)
        self.assertEqual(restored, rules)

    def test_rejects_non_array_top_level(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_watchdogvpn_json('{"id": "r1"}')

    def test_rejects_invalid_json(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_watchdogvpn_json("{not json")

    def test_rejects_unknown_field_in_entry(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_watchdogvpn_json(
                '[{"id": "r1", "action": "block", "conditions": {"domain": ["a.com"]}, "future": true}]'
            )

    def test_rejects_invalid_action_in_entry(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_watchdogvpn_json(
                '[{"id": "r1", "action": "teleport", "conditions": {"domain": ["a.com"]}}]'
            )

    def test_rejects_entry_missing_required_key(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_watchdogvpn_json('[{"action": "block", "conditions": {"domain": ["a.com"]}}]')

    def test_rejects_non_object_entry(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_watchdogvpn_json('["not-an-object"]')
        with self.assertRaises(RuleParseError):
            parse_watchdogvpn_json("[42]")
        with self.assertRaises(RuleParseError):
            parse_watchdogvpn_json("[null]")


class SingboxRuleSetJsonParserTests(unittest.TestCase):
    def test_parses_supported_fields(self) -> None:
        data = {
            "version": 1,
            "rules": [
                {
                    "domain_suffix": [".ads.example.com"],
                    "ip_cidr": ["10.0.0.0/8"],
                    "port": [443],
                }
            ],
        }
        rules = parse_singbox_ruleset_json(data, action="block")
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].action, "block")
        self.assertEqual(rules[0].conditions["domain_suffix"], [".ads.example.com"])
        self.assertEqual(rules[0].conditions["port"], ["443"])

    def test_accepts_scalar_values_not_only_lists(self) -> None:
        data = {"version": 1, "rules": [{"domain": "example.com"}]}
        rules = parse_singbox_ruleset_json(data)
        self.assertEqual(rules[0].conditions["domain"], ["example.com"])

    def test_rejects_unsupported_field(self) -> None:
        data = {"version": 1, "rules": [{"protocol": ["tls"]}]}
        with self.assertRaises(RuleParseError):
            parse_singbox_ruleset_json(data)

    def test_rejects_logical_entries(self) -> None:
        data = {"version": 1, "rules": [{"type": "logical", "mode": "and", "rules": []}]}
        with self.assertRaises(RuleParseError):
            parse_singbox_ruleset_json(data)

    def test_rejects_missing_rules_key(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_singbox_ruleset_json({"version": 1})

    def test_rejects_empty_rules(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_singbox_ruleset_json({"version": 1, "rules": []})

    def test_rejects_invalid_json_text(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_singbox_ruleset_json("{not json")


class SingboxRuleSetSrsParserTests(unittest.TestCase):
    def test_rejects_missing_file(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_singbox_ruleset_srs("/nonexistent/path.srs")

    @patch("rules.rule_parser.subprocess.run")
    def test_decompiles_and_parses(self, run_mock) -> None:
        def _fake_run(cmd, check, capture_output, text):
            out_path = cmd[cmd.index("-o") + 1]
            with open(out_path, "w", encoding="utf-8") as handle:
                handle.write('{"version": 1, "rules": [{"domain_suffix": [".example.com"]}]}')
            return subprocess.CompletedProcess(cmd, 0, "", "")

        run_mock.side_effect = _fake_run

        with tempfile.TemporaryDirectory() as tmp:
            srs_path = Path(tmp) / "geosite-example.srs"
            srs_path.write_bytes(b"\x00")
            rules = parse_singbox_ruleset_srs(srs_path, action="block")

        self.assertEqual(rules[0].conditions["domain_suffix"], [".example.com"])
        self.assertEqual(rules[0].action, "block")

    @patch("rules.rule_parser.subprocess.run", side_effect=FileNotFoundError())
    def test_raises_when_singbox_binary_missing(self, run_mock) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            srs_path = Path(tmp) / "geosite-example.srs"
            srs_path.write_bytes(b"\x00")
            with self.assertRaises(RuleParseError):
                parse_singbox_ruleset_srs(srs_path)

    @patch("rules.rule_parser.subprocess.run")
    def test_raises_when_decompile_fails(self, run_mock) -> None:
        run_mock.side_effect = subprocess.CalledProcessError(1, ["sing-box"], stderr="bad file")
        with tempfile.TemporaryDirectory() as tmp:
            srs_path = Path(tmp) / "geosite-example.srs"
            srs_path.write_bytes(b"\x00")
            with self.assertRaises(RuleParseError):
                parse_singbox_ruleset_srs(srs_path)


class ClashYamlRuleParserTests(unittest.TestCase):
    def test_parses_supported_rule_types(self) -> None:
        text = """payload:
  - 'DOMAIN,example.com'
  - 'DOMAIN-SUFFIX,ads.example.com'
  - 'DOMAIN-KEYWORD,adserver'
  - 'IP-CIDR,10.0.0.0/8,no-resolve'
  - 'GEOIP,CN'
  - 'GEOSITE,netflix'
  - 'PROCESS-NAME,curl'
  - MATCH
"""
        rules = parse_clash_yaml_rules(text, action="direct")
        self.assertEqual(len(rules), 7)
        self.assertEqual(rules[0].conditions["domain"], ["example.com"])
        self.assertEqual(rules[3].conditions["ip_cidr"], ["10.0.0.0/8"])
        self.assertEqual(rules[4].conditions["ruleset_builtin"], ["geoip:cn"])
        self.assertEqual(rules[5].conditions["ruleset_builtin"], ["geosite:netflix"])
        self.assertTrue(all(rule.action == "direct" for rule in rules))

    def test_rejects_unsupported_rule_type(self) -> None:
        text = "payload:\n  - 'SRC-IP-CIDR,192.168.1.0/24'\n"
        with self.assertRaises(RuleParseError):
            parse_clash_yaml_rules(text)

    def test_rejects_missing_payload_section(self) -> None:
        with self.assertRaises(RuleParseError):
            parse_clash_yaml_rules("proxies:\n  - name: x\n")

    def test_rejects_entry_missing_value(self) -> None:
        text = "payload:\n  - 'DOMAIN'\n"
        with self.assertRaises(RuleParseError):
            parse_clash_yaml_rules(text)


if __name__ == "__main__":
    unittest.main()
