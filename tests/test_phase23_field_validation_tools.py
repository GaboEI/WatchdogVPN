from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
