from __future__ import annotations

import json
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


if __name__ == "__main__":
    unittest.main()
