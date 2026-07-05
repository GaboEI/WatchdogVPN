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
