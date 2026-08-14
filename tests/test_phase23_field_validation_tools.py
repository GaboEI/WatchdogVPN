from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


VM_TOOLS_DIR = Path(__file__).resolve().parent / "vm"
sys.path.insert(0, str(VM_TOOLS_DIR))

from phase23_cli_field_validation_runner import (  # noqa: E402
    HTTP_EGRESS_URL,
    NORMAL_EGRESS_URL,
    SOCKS_EGRESS_URL,
    Runner,
)
from phase23_cli_field_validation_plan import _egress_probe_commands  # noqa: E402


class Phase23FieldValidationToolsTests(unittest.TestCase):
    def make_runner(self, evidence_dir: str) -> Runner:
        return Runner(
            {"evidence_dir": evidence_dir, "probe_domain": "ignored.example", "profiles": []},
            section="protocols",
            external_vpn_state="absent",
            dry_run=False,
            selected_protocols=None,
        )

    def test_egress_modes_use_three_required_public_destinations(self) -> None:
        commands = _egress_probe_commands("ignored.example")
        self.assertEqual(commands[0][-1], NORMAL_EGRESS_URL)
        self.assertEqual(commands[1][-1], SOCKS_EGRESS_URL)
        self.assertEqual(commands[2][-1], HTTP_EGRESS_URL)

        with tempfile.TemporaryDirectory() as tmp:
            runner = Runner(
                {"evidence_dir": tmp, "probe_domain": "ignored.example", "profiles": []},
                section="protocols",
                external_vpn_state="absent",
                dry_run=True,
                selected_protocols=None,
            )
            runner.egress_probes("protocols-required-targets")
            records = [
                json.loads(record.read_text(encoding="utf-8"))
                for record in sorted((Path(tmp) / "protocols-required-targets").glob("*.json"))
            ]
            self.assertEqual([record["command"][-1] for record in records], [
                NORMAL_EGRESS_URL,
                SOCKS_EGRESS_URL,
                HTTP_EGRESS_URL,
            ])

    def test_evidence_tree_is_private_with_permissive_umask(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence"
            runner = Runner(
                {"evidence_dir": str(evidence), "probe_domain": "ignored.example", "profiles": []},
                section="protocols",
                external_vpn_state="absent",
                dry_run=True,
                selected_protocols=None,
            )
            previous_umask = os.umask(0o022)
            try:
                runner.dispatch()
                runner.egress_probes("private-section")
            finally:
                os.umask(previous_umask)

            record = next((evidence / "private-section").glob("*.json"))
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(record.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)

    def test_preflight_git_check_does_not_require_local_main_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.make_runner(tmp)

            with patch.object(runner, "run", return_value=0) as mocked_run, patch.object(
                runner, "snapshot"
            ):
                runner.preflight()

            git_rev_parse = [
                call.args[2]
                for call in mocked_run.call_args_list
                if call.args[0] == "preflight" and call.args[1] == "git-rev-parse"
            ]
            self.assertEqual(len(git_rev_parse), 1)
            self.assertEqual(git_rev_parse[0][:3], ["git", "rev-parse", "HEAD"])
            self.assertNotIn("main", git_rev_parse[0])
            self.assertNotIn("origin/main", git_rev_parse[0])

    def test_mutation_polls_authoritative_outcome_until_success(self) -> None:
        command_id = "123e4567-e89b-12d3-a456-426614174000"
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.make_runner(tmp)
            outputs = [
                (70, {"ok": False, "payload": {"error_kind": "command_in_progress", "command_id": command_id}}),
                (70, {"ok": False, "payload": {"error_kind": "command_in_progress", "command_id": command_id}}),
                (0, {"ok": True, "payload": {"outcome": "completed", "command_id": command_id}}),
            ]

            def fake_run(*_args: object, **_kwargs: object) -> int:
                returncode, payload = outputs.pop(0)
                runner.last_stdout = json.dumps(payload)
                return returncode

            with patch.object(runner, "run", side_effect=fake_run) as mocked_run, patch(
                "phase23_cli_field_validation_runner.time.sleep"
            ):
                result = runner.run_mutation(
                    "protocols-absent-amneziawg",
                    "connect",
                    ["watchdog", "connect", "profile-id", "--json"],
                )

            self.assertEqual(result, 0)
            self.assertEqual(runner.failures, [])
            self.assertEqual(mocked_run.call_count, 3)
            self.assertEqual(
                mocked_run.call_args_list[-1].args[2],
                ["watchdog", "command", "outcome", command_id, "--json"],
            )

    def test_mutation_records_one_authoritative_final_failure(self) -> None:
        command_id = "123e4567-e89b-12d3-a456-426614174000"
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.make_runner(tmp)
            outputs = [
                (70, {"ok": False, "payload": {"error_kind": "command_in_progress", "command_id": command_id}}),
                (70, {"ok": False, "payload": {"error_kind": "connect_failed", "command_id": command_id}}),
            ]

            def fake_run(*_args: object, **_kwargs: object) -> int:
                returncode, payload = outputs.pop(0)
                runner.last_stdout = json.dumps(payload)
                return returncode

            with patch.object(runner, "run", side_effect=fake_run):
                result = runner.run_mutation(
                    "protocols-absent-amneziawg",
                    "connect",
                    ["watchdog", "connect", "profile-id", "--json"],
                )

            self.assertEqual(result, 70)
            self.assertEqual(
                runner.failures,
                ["protocols-absent-amneziawg:connect: final rc=70"],
            )

    def test_mutation_can_defer_candidate_failure_to_bounded_search(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.make_runner(tmp)
            with patch.object(runner, "run", return_value=70):
                result = runner.run_mutation(
                    "provider",
                    "connect-provider-node-1",
                    ["watchdog", "connect", "provider-node-id", "--json"],
                    record_failure=False,
                )

            self.assertEqual(result, 70)
            self.assertEqual(runner.failures, [])

    def test_rotation_resolves_dynamic_provider_and_node_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = Runner(
                {
                    "evidence_dir": tmp,
                    "probe_domain": "ignored.example",
                    "profiles": [],
                    "provider": {
                        "expected_provider_id": "provider-placeholder",
                        "expected_node_id": "node-placeholder",
                    },
                },
                section="rotation",
                external_vpn_state="absent",
                dry_run=False,
                selected_protocols=None,
            )
            (Path(tmp) / "phase23-provider-id-map.json").write_text(
                json.dumps({"provider_id": "provider-real", "node_id": "node-real"}),
                encoding="utf-8",
            )

            self.assertEqual(
                runner.resolved_provider_ids(),
                ("provider-real", "node-real"),
            )

    def test_app_policy_block_probe_cannot_pass_or_fail_on_dns_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = {
                "direct_probe_path": str(root / "direct-curl"),
                "vpn_probe_path": str(root / "vpn-curl"),
                "block_probe_path": str(root / "block-curl"),
            }
            runner = Runner(
                {
                    "evidence_dir": tmp,
                    "probe_domain": "example.com",
                    "profiles": [],
                    "app_policy": policy,
                    "rotation": {"primary_profile_id": "phase23-vless"},
                },
                section="app-policy",
                external_vpn_state="absent",
                dry_run=False,
                selected_protocols=None,
            )

            events: list[str] = []

            def fake_run(_section: str, label: str, _command: list[str], **_kwargs: object) -> int:
                events.append(label)
                if label == "resolve-block-target":
                    runner.last_stdout = "203.0.113.10 STREAM example.com\n"
                return 0

            def fake_mutation(_section: str, label: str, _command: list[str], **_kwargs: object) -> int:
                events.append(label)
                return 0

            with patch.object(runner, "run_mutation", side_effect=fake_mutation), patch.object(
                runner, "run", side_effect=fake_run
            ) as mocked_run:
                runner.app_policy()

            block_call = next(call for call in mocked_run.call_args_list if call.args[1] == "block-probe")
            self.assertIn("--resolve", block_call.args[2])
            self.assertNotIn(0, block_call.kwargs["ok_codes"])
            self.assertNotIn(6, block_call.kwargs["ok_codes"])
            self.assertLess(events.index("add-block"), events.index("connect-for-policy"))
            self.assertLess(events.index("disconnect-after-policy"), events.index("remove-block"))
            for path in policy.values():
                self.assertFalse(Path(path).exists())


if __name__ == "__main__":
    unittest.main()
