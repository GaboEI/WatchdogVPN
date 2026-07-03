from __future__ import annotations

import unittest

from core.kill_switch import KillSwitch, WATCHDOGVPN_COMMENT, WATCHDOGVPN_IPTABLES_CHAIN
from core.kill_switch import WATCHDOGVPN_NFT_COMMENT
from core.kill_switch import WATCHDOGVPN_TABLE, CommandResult


class CommandRecorder:
    def __init__(self, failures: dict[tuple[str, ...], CommandResult] | None = None) -> None:
        self.commands: list[list[str]] = []
        self.failures = failures or {}

    def __call__(self, command: list[str]) -> CommandResult:
        self.commands.append(command)
        return self.failures.get(tuple(command), CommandResult(returncode=0))


def fake_which(*available: str):
    def _which(binary: str) -> str | None:
        if binary in available:
            return f"/usr/sbin/{binary}"
        return None

    return _which


class KillSwitchDetectionTests(unittest.TestCase):
    def test_detects_nftables_before_iptables(self) -> None:
        kill_switch = KillSwitch(which=fake_which("nft", "iptables"))

        self.assertEqual(kill_switch.detect_method(), "nftables")

    def test_falls_back_to_iptables(self) -> None:
        kill_switch = KillSwitch(which=fake_which("iptables"))

        self.assertEqual(kill_switch.detect_method(), "iptables")

    def test_returns_none_when_no_backend_exists(self) -> None:
        kill_switch = KillSwitch(which=fake_which())

        self.assertIsNone(kill_switch.detect_method())


class NftablesKillSwitchTests(unittest.TestCase):
    def test_enable_creates_nftables_table_chain_and_rules(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(
            tunnel_interface="wg0",
            runner=recorder,
            which=fake_which("nft", "iptables"),
        )

        self.assertTrue(kill_switch.enable())

        self.assertIn(["nft", "delete", "table", "inet", WATCHDOGVPN_TABLE], recorder.commands)
        self.assertIn(["nft", "add", "table", "inet", WATCHDOGVPN_TABLE], recorder.commands)
        self.assertIn(
            [
                "nft",
                "add",
                "chain",
                "inet",
                WATCHDOGVPN_TABLE,
                "output",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "0;",
                "policy",
                "drop;",
                "}",
            ],
            recorder.commands,
        )
        self.assertIn(
            [
                "nft",
                "add",
                "rule",
                "inet",
                WATCHDOGVPN_TABLE,
                "output",
                "oifname",
                "wg0",
                "accept",
                "comment",
                WATCHDOGVPN_NFT_COMMENT,
            ],
            recorder.commands,
        )

    def test_nftables_comment_is_quoted_for_real_nft_syntax(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        kill_switch.enable()

        rule_commands = [command for command in recorder.commands if command[:3] == ["nft", "add", "rule"]]
        self.assertTrue(rule_commands)
        for command in rule_commands:
            comment_index = command.index("comment")
            self.assertEqual(command[comment_index + 1], WATCHDOGVPN_NFT_COMMENT)

    def test_nftables_blocks_ipv6_by_default(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        kill_switch.enable()

        self.assertNotIn(
            [
                "nft",
                "add",
                "rule",
                "inet",
                WATCHDOGVPN_TABLE,
                "output",
                "ip6",
                "daddr",
                "::/0",
                "accept",
                "comment",
                WATCHDOGVPN_NFT_COMMENT,
            ],
            recorder.commands,
        )

    def test_nftables_can_allow_ipv6_when_configured(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(block_ipv6=False, runner=recorder, which=fake_which("nft"))

        kill_switch.enable()

        self.assertIn(
            [
                "nft",
                "add",
                "rule",
                "inet",
                WATCHDOGVPN_TABLE,
                "output",
                "ip6",
                "daddr",
                "::/0",
                "accept",
                "comment",
                WATCHDOGVPN_NFT_COMMENT,
            ],
            recorder.commands,
        )

    def test_nftables_blocks_dns_before_lan_allow_rules(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        kill_switch.enable()

        dns_rule = [
            "nft",
            "add",
            "rule",
            "inet",
            WATCHDOGVPN_TABLE,
            "output",
            "udp",
            "dport",
            "53",
            "reject",
            "comment",
            WATCHDOGVPN_NFT_COMMENT,
        ]
        lan_rule = [
            "nft",
            "add",
            "rule",
            "inet",
            WATCHDOGVPN_TABLE,
            "output",
            "ip",
            "daddr",
            "192.168.0.0/16",
            "accept",
            "comment",
            WATCHDOGVPN_NFT_COMMENT,
        ]
        self.assertLess(recorder.commands.index(dns_rule), recorder.commands.index(lan_rule))

    def test_nftables_blocks_dns_before_established_connections(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        kill_switch.enable()

        tunnel_rule = [
            "nft",
            "add",
            "rule",
            "inet",
            WATCHDOGVPN_TABLE,
            "output",
            "oifname",
            "wdvpn-tun0",
            "accept",
            "comment",
            WATCHDOGVPN_NFT_COMMENT,
        ]
        dns_rule = [
            "nft",
            "add",
            "rule",
            "inet",
            WATCHDOGVPN_TABLE,
            "output",
            "udp",
            "dport",
            "53",
            "reject",
            "comment",
            WATCHDOGVPN_NFT_COMMENT,
        ]
        established_rule = [
            "nft",
            "add",
            "rule",
            "inet",
            WATCHDOGVPN_TABLE,
            "output",
            "ct",
            "state",
            "established,related",
            "accept",
            "comment",
            WATCHDOGVPN_NFT_COMMENT,
        ]
        self.assertLess(recorder.commands.index(tunnel_rule), recorder.commands.index(dns_rule))
        self.assertLess(recorder.commands.index(dns_rule), recorder.commands.index(established_rule))

    def test_disable_deletes_nftables_table(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        self.assertTrue(kill_switch.disable())

        self.assertEqual(recorder.commands, [["nft", "delete", "table", "inet", WATCHDOGVPN_TABLE]])

    def test_enable_rolls_back_when_nftables_command_fails(self) -> None:
        failing_command = ("nft", "add", "table", "inet", WATCHDOGVPN_TABLE)
        recorder = CommandRecorder({failing_command: CommandResult(returncode=1, stderr="denied")})
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        self.assertFalse(kill_switch.enable())

        self.assertEqual(recorder.commands.count(["nft", "delete", "table", "inet", WATCHDOGVPN_TABLE]), 2)


class IptablesKillSwitchTests(unittest.TestCase):
    def test_enable_creates_iptables_chain_and_jump(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(
            tunnel_interface="tun9",
            runner=recorder,
            which=fake_which("iptables", "ip6tables"),
        )

        self.assertTrue(kill_switch.enable())

        self.assertIn(["iptables", "-N", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)
        self.assertIn(["iptables", "-I", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)
        self.assertIn(
            [
                "iptables",
                "-A",
                WATCHDOGVPN_IPTABLES_CHAIN,
                "-o",
                "tun9",
                "-m",
                "comment",
                "--comment",
                WATCHDOGVPN_COMMENT,
                "-j",
                "ACCEPT",
            ],
            recorder.commands,
        )

    def test_iptables_blocks_ipv6_when_ip6tables_is_available(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("iptables", "ip6tables"))

        kill_switch.enable()

        self.assertIn(["ip6tables", "-N", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)
        self.assertIn(["ip6tables", "-I", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)

    def test_iptables_blocks_dns_before_lan_allow_rules(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("iptables"))

        kill_switch.enable()

        dns_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "REJECT",
        ]
        lan_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-d",
            "192.168.0.0/16",
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        self.assertLess(recorder.commands.index(dns_rule), recorder.commands.index(lan_rule))

    def test_iptables_blocks_dns_before_established_connections(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("iptables"))

        kill_switch.enable()

        tunnel_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-o",
            "wdvpn-tun0",
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        dns_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "REJECT",
        ]
        established_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        self.assertLess(recorder.commands.index(tunnel_rule), recorder.commands.index(dns_rule))
        self.assertLess(recorder.commands.index(dns_rule), recorder.commands.index(established_rule))

    def test_iptables_skips_ip6tables_when_ipv6_blocking_disabled(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(
            block_ipv6=False,
            runner=recorder,
            which=fake_which("iptables", "ip6tables"),
        )

        kill_switch.enable()

        self.assertNotIn(["ip6tables", "-N", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)
        self.assertNotIn(["ip6tables", "-I", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)

    def test_disable_removes_iptables_and_ip6tables_rules(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("iptables", "ip6tables"))

        self.assertTrue(kill_switch.disable())

        self.assertIn(["iptables", "-D", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)
        self.assertIn(["iptables", "-F", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)
        self.assertIn(["iptables", "-X", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)
        self.assertIn(["ip6tables", "-D", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)
        self.assertIn(["ip6tables", "-F", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)
        self.assertIn(["ip6tables", "-X", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)


class KillSwitchStatusTests(unittest.TestCase):
    def test_is_active_uses_nftables_table_lookup(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        self.assertTrue(kill_switch.is_active())

        self.assertEqual(recorder.commands, [["nft", "list", "table", "inet", WATCHDOGVPN_TABLE]])

    def test_is_active_uses_iptables_chain_lookup(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("iptables"))

        self.assertTrue(kill_switch.is_active())

        self.assertEqual(recorder.commands, [["iptables", "-S", WATCHDOGVPN_IPTABLES_CHAIN]])

    def test_status_reports_configuration_and_activity(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(
            tunnel_interface="awg0",
            block_ipv6=False,
            allow_lan=False,
            runner=recorder,
            which=fake_which("nft"),
        )

        status = kill_switch.status()

        self.assertEqual(
            status,
            {
                "available": True,
                "active": True,
                "method": "nftables",
                "rules_applied": True,
                "tunnel_interface": "awg0",
                "block_ipv6": False,
                "allow_lan": False,
            },
        )


if __name__ == "__main__":
    unittest.main()
