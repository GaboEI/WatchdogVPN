from __future__ import annotations

import shlex
import unittest

from core.kill_switch import (
    KillSwitch,
    LOOPBACK_CIDRS,
    SING_BOX_AUTO_REDIRECT_MARKS,
    SING_BOX_TUN_DNS_ENDPOINTS,
    WATCHDOGVPN_COMMENT,
    WATCHDOGVPN_IPTABLES_CHAIN,
)
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


def nft_rule(*tokens: str) -> list[str]:
    return [
        "nft",
        "add",
        "rule",
        "inet",
        WATCHDOGVPN_TABLE,
        "output",
        *tokens[:-1],
        "counter",
        tokens[-1],
        "comment",
        WATCHDOGVPN_NFT_COMMENT,
    ]


def complete_nft_ruleset(kill_switch: KillSwitch) -> str:
    recorder = CommandRecorder()
    generator = KillSwitch(
        tunnel_interface=kill_switch.tunnel_interface,
        block_ipv6=kill_switch.block_ipv6,
        allow_lan=kill_switch.allow_lan,
        allowed_endpoints=kill_switch.allowed_endpoints,
        lan_cidrs=kill_switch.lan_cidrs,
        runner=recorder,
        which=fake_which("nft"),
    )
    if not generator.enable():
        raise AssertionError("fixture generation failed")
    rules: list[str] = []
    for command in recorder.commands:
        if command[:3] != ["nft", "add", "rule"]:
            continue
        body = command[6:]
        counter_index = body.index("counter")
        match = " ".join(body[:counter_index])
        verdict = body[counter_index + 1]
        prefix = f"{match} " if match else ""
        rules.append(
            f'        {prefix}counter packets 0 bytes 0 {verdict} comment "{WATCHDOGVPN_COMMENT}"'
        )
    return "\n".join(
        (
            f"table inet {WATCHDOGVPN_TABLE} {{",
            "    chain output {",
            "        type filter hook output priority filter; policy drop;",
            *rules,
            "    }",
            "}",
        )
    )


def complete_iptables_ruleset(kill_switch: KillSwitch, binary: str = "iptables") -> str:
    recorder = CommandRecorder()
    available = ("iptables", "ip6tables") if kill_switch.block_ipv6 else ("iptables",)
    generator = KillSwitch(
        tunnel_interface=kill_switch.tunnel_interface,
        block_ipv6=kill_switch.block_ipv6,
        allow_lan=kill_switch.allow_lan,
        allowed_endpoints=kill_switch.allowed_endpoints,
        lan_cidrs=kill_switch.lan_cidrs,
        runner=recorder,
        which=fake_which(*available),
    )
    if not generator.enable():
        raise AssertionError("fixture generation failed")
    return "\n".join(
        shlex.join(command[1:])
        for command in recorder.commands
        if command[:3] == [binary, "-A", WATCHDOGVPN_IPTABLES_CHAIN]
    )


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
            nft_rule("oifname", "wg0", "accept"),
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
            nft_rule("ip6", "daddr", "::/0", "accept"),
            recorder.commands,
        )

    def test_nftables_adds_counted_terminal_drop_rules(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        kill_switch.enable()

        self.assertEqual(
            recorder.commands[-5:],
            [
                nft_rule("meta", "l4proto", "tcp", "drop"),
                nft_rule("meta", "l4proto", "udp", "drop"),
                nft_rule("meta", "l4proto", "icmp", "drop"),
                nft_rule("meta", "l4proto", "ipv6-icmp", "drop"),
                nft_rule("drop"),
            ],
        )

    def test_nftables_allows_loopback_destination_before_dns_and_terminal_drop(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        kill_switch.enable()

        loopback_rule = nft_rule("ip", "daddr", LOOPBACK_CIDRS[0], "accept")
        ipv6_loopback_rule = nft_rule("ip6", "daddr", LOOPBACK_CIDRS[1], "accept")
        dns_block_rule = nft_rule("udp", "dport", "53", "reject")
        terminal_drop_rule = nft_rule("meta", "l4proto", "tcp", "drop")
        self.assertIn(loopback_rule, recorder.commands)
        self.assertIn(ipv6_loopback_rule, recorder.commands)
        self.assertLess(recorder.commands.index(loopback_rule), recorder.commands.index(dns_block_rule))
        self.assertLess(recorder.commands.index(loopback_rule), recorder.commands.index(terminal_drop_rule))

    def test_nftables_blocks_dns_before_lan_allow_rules(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        kill_switch.enable()

        dns_rule = nft_rule("udp", "dport", "53", "reject")
        lan_rule = nft_rule("ip", "daddr", "192.168.0.0/16", "accept")
        self.assertLess(recorder.commands.index(dns_rule), recorder.commands.index(lan_rule))

    def test_nftables_blocks_dns_before_established_connections(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        kill_switch.enable()

        tunnel_rule = nft_rule("oifname", "wdvpn-tun0", "accept")
        dns_rule = nft_rule("udp", "dport", "53", "reject")
        established_rule = nft_rule("ct", "state", "established,related", "accept")
        self.assertLess(recorder.commands.index(tunnel_rule), recorder.commands.index(dns_rule))
        self.assertLess(recorder.commands.index(dns_rule), recorder.commands.index(established_rule))

    def test_nftables_allows_vpn_endpoint_and_singbox_marks_before_dns_and_established_rules(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(
            allowed_endpoints=("203.0.113.10", "not-a-literal"),
            runner=recorder,
            which=fake_which("nft"),
        )

        kill_switch.enable()

        endpoint_rule = nft_rule("ip", "daddr", "203.0.113.10", "accept")
        dns_rule = nft_rule("udp", "dport", "53", "reject")
        established_rule = nft_rule("ct", "state", "established,related", "accept")
        mark_rule = nft_rule("meta", "mark", SING_BOX_AUTO_REDIRECT_MARKS[0], "accept")
        ct_mark_rule = nft_rule("ct", "mark", SING_BOX_AUTO_REDIRECT_MARKS[0], "accept")
        self.assertIn(endpoint_rule, recorder.commands)
        self.assertIn(mark_rule, recorder.commands)
        self.assertIn(ct_mark_rule, recorder.commands)
        self.assertLess(recorder.commands.index(endpoint_rule), recorder.commands.index(dns_rule))
        self.assertLess(recorder.commands.index(endpoint_rule), recorder.commands.index(established_rule))
        self.assertLess(recorder.commands.index(mark_rule), recorder.commands.index(dns_rule))
        self.assertLess(recorder.commands.index(ct_mark_rule), recorder.commands.index(dns_rule))

    def test_nftables_allows_internal_tun_dns_before_dns_leak_blocks(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        kill_switch.enable()

        internal_udp_rule = nft_rule(
            "ip",
            "daddr",
            SING_BOX_TUN_DNS_ENDPOINTS[0],
            "udp",
            "dport",
            "53",
            "accept",
        )
        internal_tcp_rule = nft_rule(
            "ip",
            "daddr",
            SING_BOX_TUN_DNS_ENDPOINTS[0],
            "tcp",
            "dport",
            "53",
            "accept",
        )
        dns_block_rule = nft_rule("udp", "dport", "53", "reject")
        self.assertIn(internal_udp_rule, recorder.commands)
        self.assertIn(internal_tcp_rule, recorder.commands)
        self.assertLess(recorder.commands.index(internal_udp_rule), recorder.commands.index(dns_block_rule))
        self.assertLess(recorder.commands.index(internal_tcp_rule), recorder.commands.index(dns_block_rule))

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


class AtomicNftablesKillSwitchTests(unittest.TestCase):
    def test_apply_atomic_replaces_the_table_in_one_nft_batch(self) -> None:
        recorder = CommandRecorder()
        batches: list[str] = []

        def run_batch(script: str) -> CommandResult:
            batches.append(script)
            return CommandResult(returncode=0)

        kill_switch = KillSwitch(
            tunnel_interface="wg0",
            allowed_endpoints=("203.0.113.10",),
            runner=recorder,
            nft_batch_runner=run_batch,
            which=fake_which("nft"),
        )
        kill_switch.status = lambda: {"active": True, "consistent": True}  # type: ignore[method-assign]

        self.assertTrue(kill_switch.apply_atomic())

        self.assertEqual(recorder.commands, [["nft", "list", "table", "inet", WATCHDOGVPN_TABLE]])
        self.assertEqual(len(batches), 1)
        script = batches[0]
        self.assertIn("add table inet watchdogvpn", script)
        self.assertIn("oifname wg0 counter accept", script)
        self.assertIn("ip daddr 203.0.113.10 counter accept", script)
        self.assertIn('comment "WatchdogVPN kill switch"', script)

    def test_apply_atomic_deletes_an_existing_policy_inside_the_same_batch(self) -> None:
        fixture = KillSwitch(tunnel_interface="wg0", which=fake_which("nft"))
        existing_rules = complete_nft_ruleset(fixture)
        list_table = ("nft", "list", "table", "inet", WATCHDOGVPN_TABLE)
        recorder = CommandRecorder({list_table: CommandResult(returncode=0, stdout=existing_rules)})
        batches: list[str] = []

        def run_batch(script: str) -> CommandResult:
            batches.append(script)
            return CommandResult(returncode=0)

        kill_switch = KillSwitch(
            tunnel_interface="wg0",
            runner=recorder,
            nft_batch_runner=run_batch,
            which=fake_which("nft"),
        )
        kill_switch.status = lambda: {"active": True, "consistent": True}  # type: ignore[method-assign]

        self.assertTrue(kill_switch.apply_atomic())

        self.assertEqual(len(batches), 1)
        self.assertTrue(batches[0].startswith("delete table inet watchdogvpn\n"))
        self.assertEqual(recorder.commands, [["nft", "list", "table", "inet", WATCHDOGVPN_TABLE]])
    def test_apply_atomic_refuses_connection_policy_when_the_batch_fails(self) -> None:
        recorder = CommandRecorder()
        batches: list[str] = []

        def run_batch(script: str) -> CommandResult:
            batches.append(script)
            return CommandResult(returncode=1, stderr="nft rejected transaction")

        kill_switch = KillSwitch(
            runner=recorder,
            nft_batch_runner=run_batch,
            which=fake_which("nft"),
        )

        self.assertFalse(kill_switch.apply_atomic())
        self.assertEqual(len(batches), 1)
        self.assertEqual(recorder.commands, [["nft", "list", "table", "inet", WATCHDOGVPN_TABLE]])

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

    def test_iptables_refuses_to_enable_when_ipv6_cannot_be_blocked(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("iptables"))

        self.assertFalse(kill_switch.enable())

        self.assertNotIn(["iptables", "-N", WATCHDOGVPN_IPTABLES_CHAIN], recorder.commands)

    def test_iptables_blocks_dns_before_lan_allow_rules(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(
            block_ipv6=False, runner=recorder, which=fake_which("iptables")
        )

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
        kill_switch = KillSwitch(
            block_ipv6=False, runner=recorder, which=fake_which("iptables")
        )

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

    def test_iptables_allows_vpn_endpoint_and_singbox_marks_before_dns_and_established_rules(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(
            allowed_endpoints=("203.0.113.10", "2001:db8::10", "not-a-literal"),
            runner=recorder,
            which=fake_which("iptables", "ip6tables"),
        )

        kill_switch.enable()

        endpoint_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-d",
            "203.0.113.10",
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        ipv6_endpoint_rule = [
            "ip6tables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-d",
            "2001:db8::10",
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
        mark_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-m",
            "mark",
            "--mark",
            SING_BOX_AUTO_REDIRECT_MARKS[0],
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        connmark_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-m",
            "connmark",
            "--mark",
            SING_BOX_AUTO_REDIRECT_MARKS[0],
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        self.assertIn(endpoint_rule, recorder.commands)
        self.assertIn(ipv6_endpoint_rule, recorder.commands)
        self.assertIn(mark_rule, recorder.commands)
        self.assertIn(connmark_rule, recorder.commands)
        self.assertLess(recorder.commands.index(endpoint_rule), recorder.commands.index(dns_rule))
        self.assertLess(recorder.commands.index(endpoint_rule), recorder.commands.index(established_rule))
        self.assertLess(recorder.commands.index(mark_rule), recorder.commands.index(dns_rule))
        self.assertLess(recorder.commands.index(connmark_rule), recorder.commands.index(dns_rule))

    def test_iptables_allows_internal_tun_dns_before_dns_leak_blocks(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("iptables", "ip6tables"))

        kill_switch.enable()

        internal_udp_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-d",
            SING_BOX_TUN_DNS_ENDPOINTS[0],
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        internal_tcp_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-d",
            SING_BOX_TUN_DNS_ENDPOINTS[0],
            "-p",
            "tcp",
            "--dport",
            "53",
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        dns_block_rule = [
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
        invalid_ip6_rule = [
            "ip6tables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-d",
            SING_BOX_TUN_DNS_ENDPOINTS[0],
            "-p",
            "udp",
            "--dport",
            "53",
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        self.assertIn(internal_udp_rule, recorder.commands)
        self.assertIn(internal_tcp_rule, recorder.commands)
        self.assertNotIn(invalid_ip6_rule, recorder.commands)
        self.assertLess(recorder.commands.index(internal_udp_rule), recorder.commands.index(dns_block_rule))
        self.assertLess(recorder.commands.index(internal_tcp_rule), recorder.commands.index(dns_block_rule))

    def test_iptables_allows_loopback_destination_before_dns_and_terminal_reject(self) -> None:
        recorder = CommandRecorder()
        kill_switch = KillSwitch(runner=recorder, which=fake_which("iptables", "ip6tables"))

        kill_switch.enable()

        loopback_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-d",
            LOOPBACK_CIDRS[0],
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        ipv6_loopback_rule = [
            "ip6tables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-d",
            LOOPBACK_CIDRS[1],
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "ACCEPT",
        ]
        dns_block_rule = [
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
        terminal_reject_rule = [
            "iptables",
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "REJECT",
        ]
        self.assertIn(loopback_rule, recorder.commands)
        self.assertIn(ipv6_loopback_rule, recorder.commands)
        self.assertLess(recorder.commands.index(loopback_rule), recorder.commands.index(dns_block_rule))
        self.assertLess(recorder.commands.index(loopback_rule), recorder.commands.index(terminal_reject_rule))

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
    def test_is_active_requires_complete_nftables_ruleset(self) -> None:
        kill_switch = KillSwitch(which=fake_which("nft"))
        output = complete_nft_ruleset(kill_switch)
        recorder = CommandRecorder(
            {
                ("nft", "list", "table", "inet", WATCHDOGVPN_TABLE): CommandResult(
                    returncode=0, stdout=output
                )
            }
        )
        kill_switch.runner = recorder

        self.assertTrue(kill_switch.is_active())

        self.assertEqual(recorder.commands, [["nft", "list", "table", "inet", WATCHDOGVPN_TABLE]])

    def test_nftables_inspection_accepts_kernel_zero_padded_marks(self) -> None:
        kill_switch = KillSwitch(which=fake_which("nft"))
        output = complete_nft_ruleset(kill_switch)
        output = output.replace("0x2023", "0x00002023").replace("0x2024", "0x00002024")
        recorder = CommandRecorder(
            {
                ("nft", "list", "table", "inet", WATCHDOGVPN_TABLE): CommandResult(
                    returncode=0, stdout=output
                )
            }
        )
        kill_switch.runner = recorder

        status = kill_switch.status()

        self.assertTrue(status["active"])
    def test_empty_nftables_table_is_partial_not_active(self) -> None:
        recorder = CommandRecorder(
            {
                ("nft", "list", "table", "inet", WATCHDOGVPN_TABLE): CommandResult(
                    returncode=0, stdout=f"table inet {WATCHDOGVPN_TABLE} {{}}"
                )
            }
        )
        kill_switch = KillSwitch(runner=recorder, which=fake_which("nft"))

        status = kill_switch.status()

        self.assertFalse(status["active"])
        self.assertTrue(status["artifacts_present"])
        self.assertFalse(status["consistent"])
        self.assertIn("missing_output_hook", status["mismatch_reasons"])

    def test_is_active_requires_complete_iptables_ruleset(self) -> None:
        kill_switch = KillSwitch(block_ipv6=False, which=fake_which("iptables"))
        output = complete_iptables_ruleset(kill_switch)
        recorder = CommandRecorder(
            {
                ("iptables", "-S", WATCHDOGVPN_IPTABLES_CHAIN): CommandResult(
                    returncode=0, stdout=output
                )
            }
        )
        kill_switch.runner = recorder

        self.assertTrue(kill_switch.is_active())

        self.assertEqual(
            recorder.commands,
            [
                ["iptables", "-S", WATCHDOGVPN_IPTABLES_CHAIN],
                ["iptables", "-C", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN],
            ],
        )

    def test_partial_iptables_chain_reports_missing_rules(self) -> None:
        output = shlex.join(
            [
                "-A",
                WATCHDOGVPN_IPTABLES_CHAIN,
                "-m",
                "comment",
                "--comment",
                WATCHDOGVPN_COMMENT,
                "-j",
                "REJECT",
            ]
        )
        recorder = CommandRecorder(
            {
                ("iptables", "-S", WATCHDOGVPN_IPTABLES_CHAIN): CommandResult(
                    returncode=0, stdout=output
                )
            }
        )
        kill_switch = KillSwitch(
            block_ipv6=False, runner=recorder, which=fake_which("iptables")
        )

        status = kill_switch.status()

        self.assertTrue(status["active"])
        self.assertFalse(status["consistent"])
        self.assertTrue(
            any(
                str(reason).startswith("missing_managed_rule:iptables/")
                for reason in status["mismatch_reasons"]
            )
        )

    def test_status_reports_configuration_and_activity(self) -> None:
        kill_switch = KillSwitch(
            tunnel_interface="awg0",
            block_ipv6=False,
            allow_lan=False,
            which=fake_which("nft"),
        )
        output = complete_nft_ruleset(kill_switch)
        kill_switch.runner = CommandRecorder(
            {
                ("nft", "list", "table", "inet", WATCHDOGVPN_TABLE): CommandResult(
                    returncode=0, stdout=output
                )
            }
        )

        status = kill_switch.status()

        self.assertEqual(
            status,
            {
                "available": True,
                "artifacts_present": True,
                "active": True,
                "method": "nftables",
                "rules_applied": True,
                "consistent": True,
                "mismatch_reasons": [],
                "tunnel_interface": "awg0",
                "block_ipv6": False,
                "allow_lan": False,
                "allowed_endpoints": [],
            },
        )

    def test_multiple_backends_are_reported_as_inconsistent(self) -> None:
        kill_switch = KillSwitch(block_ipv6=False, which=fake_which("nft", "iptables"))
        nft_output = complete_nft_ruleset(kill_switch)
        iptables_output = complete_iptables_ruleset(kill_switch)
        kill_switch.runner = CommandRecorder(
            {
                ("nft", "list", "table", "inet", WATCHDOGVPN_TABLE): CommandResult(
                    returncode=0, stdout=nft_output
                ),
                ("iptables", "-S", WATCHDOGVPN_IPTABLES_CHAIN): CommandResult(
                    returncode=0, stdout=iptables_output
                ),
            }
        )

        status = kill_switch.status()

        self.assertTrue(status["active"])
        self.assertFalse(status["consistent"])
        self.assertEqual(status["method"], "nftables+iptables")
        self.assertIn("multiple_firewall_backends_present", status["mismatch_reasons"])


if __name__ == "__main__":
    unittest.main()
