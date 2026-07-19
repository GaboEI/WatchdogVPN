from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

VM_TESTS = Path(__file__).resolve().parent / "vm"
sys.path.insert(0, str(VM_TESTS))

from phase23_kill_switch_controlled_failure import (  # noqa: E402
    ControlledFailureError,
    _iptables_drop_packet_count,
    _firewall_snapshot,
    _nft_drop_packet_count,
    _owned_sing_box_child,
    _select_target_ip,
    _status_fields,
    _validated_probe_domain,
)


class ControlledFailureHelperTests(unittest.TestCase):
    def test_select_target_requires_global_ipv4_not_present_in_firewall_snapshot(self) -> None:
        payload = {
            "Answer": [
                {"data": "127.0.0.1"},
                {"data": "203.0.113.10"},
                {"data": "1.1.1.1"},
                {"data": "8.8.8.8"},
            ]
        }

        self.assertEqual(
            _select_target_ip(payload, "allowed endpoint 1.1.1.1 accept"),
            "8.8.8.8",
        )

    def test_select_target_rejects_missing_distinct_global_address(self) -> None:
        with self.assertRaisesRegex(ControlledFailureError, "distinct"):
            _select_target_ip({"Answer": [{"data": "127.0.0.1"}]}, "")

    def test_nft_drop_packet_count_sums_every_terminal_drop_rule(self) -> None:
        snapshot = """
            meta l4proto tcp counter packets 2 bytes 120 drop
            meta l4proto icmp counter packets 3 bytes 252 drop
            oifname \"lo\" counter packets 90 bytes 9000 accept
            counter packets 5 bytes 300 drop
        """

        self.assertEqual(_nft_drop_packet_count(snapshot), 10)

    def test_nft_snapshot_includes_output_and_postrouting_guard_chains(self) -> None:
        snapshot = """
            chain output { counter packets 2 bytes 120 drop }
            chain capture_postrouting { counter packets 3 bytes 252 drop }
        """
        with patch(
            "phase23_kill_switch_controlled_failure._require_ok",
            return_value=snapshot,
        ) as run:
            captured, drops = _firewall_snapshot("nftables")

        self.assertEqual(captured, snapshot)
        self.assertEqual(drops, 5)
        run.assert_called_once_with(
            ["sudo", "-n", "nft", "list", "table", "inet", "watchdogvpn"]
        )

    def test_iptables_drop_packet_count_sums_drop_and_reject_only(self) -> None:
        snapshot = """
        pkts bytes target prot opt in out source destination
        2 120 REJECT tcp -- * * 0.0.0.0/0 0.0.0.0/0
        3 252 DROP icmp -- * * 0.0.0.0/0 0.0.0.0/0
        9 900 ACCEPT all -- * lo 0.0.0.0/0 0.0.0.0/0
        """

        self.assertEqual(_iptables_drop_packet_count(snapshot), 5)

    def test_status_fields_and_probe_domain_validation(self) -> None:
        self.assertEqual(
            _status_fields("Status: connected\nKill switch state: applied\n"),
            {"status": "connected", "kill switch state": "applied"},
        )
        self.assertEqual(_validated_probe_domain("WWW.Example.COM."), "www.example.com")
        with self.assertRaisesRegex(ControlledFailureError, "hostname"):
            _validated_probe_domain("not_a_domain")

    def test_owned_child_is_discovered_from_worker_thread_children(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            proc_root = Path(temp_dir)
            daemon_pid = 120
            child_pid = 456
            main_task = proc_root / str(daemon_pid) / "task" / str(daemon_pid)
            worker_task = proc_root / str(daemon_pid) / "task" / "121"
            main_task.mkdir(parents=True)
            worker_task.mkdir(parents=True)
            (main_task / "children").write_text("", encoding="utf-8")
            (worker_task / "children").write_text(f"{child_pid}\n", encoding="utf-8")
            child_root = proc_root / str(child_pid)
            child_root.mkdir()
            (child_root / "comm").write_text("sing-box\n", encoding="utf-8")
            (child_root / "status").write_text(
                f"Name:\tsing-box\nPPid:\t{daemon_pid}\n", encoding="utf-8"
            )
            (child_root / "cgroup").write_text(
                "0::/system.slice/watchdogvpn.service\n", encoding="utf-8"
            )

            self.assertEqual(
                _owned_sing_box_child(daemon_pid, proc_root=proc_root), child_pid
            )


if __name__ == "__main__":
    unittest.main()
