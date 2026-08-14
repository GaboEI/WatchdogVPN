from __future__ import annotations

import logging
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Callable


LOGGER = logging.getLogger(__name__)

WATCHDOGVPN_TABLE = "watchdogvpn"
WATCHDOGVPN_CHAIN = "output"
WATCHDOGVPN_CAPTURE_GUARD_CHAIN = "capture_postrouting"
WATCHDOGVPN_IPTABLES_CHAIN = "WATCHDOGVPN-OUTPUT"
WATCHDOGVPN_COMMENT = "WatchdogVPN kill switch"
WATCHDOGVPN_NFT_COMMENT = f'"{WATCHDOGVPN_COMMENT}"'
# Reserved sing-box routing marks remain useful for bounded residue discovery
# and collision avoidance in other drivers. A mark alone is intentionally not
# a firewall trust signal: auto_redirect can apply it while the packet's stale
# output route still names a physical interface. The output chain accepts the
# capture mark only together with a second postrouting guard that rejects it
# unless the final output interface is the managed TUN. The physical outbound
# mark used by the selected VPN transport and explicit direct routes may be
# authorized only when it is conjoined with the exact unprivileged daemon UID
# that owns the managed sing-box process.
SING_BOX_AUTO_REDIRECT_MARKS = ("0x2023", "0x2024")
SING_BOX_CAPTURE_MARK = SING_BOX_AUTO_REDIRECT_MARKS[0]
SING_BOX_OUTBOUND_MARK = SING_BOX_AUTO_REDIRECT_MARKS[1]
SING_BOX_TUN_DNS_ENDPOINTS = ("172.19.0.2",)

DEFAULT_LAN_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
)
LOOPBACK_CIDRS = ("127.0.0.0/8", "::1/128")


@dataclass(slots=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(slots=True)
class KillSwitchStatus:
    available: bool
    artifacts_present: bool
    active: bool
    method: str | None
    rules_applied: bool
    consistent: bool
    mismatch_reasons: tuple[str, ...]
    tunnel_interface: str
    block_ipv6: bool
    allow_lan: bool
    allowed_endpoints: tuple[str, ...]
    direct_egress_uid: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "artifacts_present": self.artifacts_present,
            "active": self.active,
            "method": self.method,
            "rules_applied": self.rules_applied,
            "consistent": self.consistent,
            "mismatch_reasons": list(self.mismatch_reasons),
            "tunnel_interface": self.tunnel_interface,
            "block_ipv6": self.block_ipv6,
            "allow_lan": self.allow_lan,
            "allowed_endpoints": list(self.allowed_endpoints),
            "direct_egress_uid": self.direct_egress_uid,
        }


RunCommand = Callable[[list[str]], CommandResult]
RunNftBatch = Callable[[str], CommandResult]


@dataclass(frozen=True, slots=True)
class _FirewallState:
    method: str
    artifacts_present: bool = False
    active: bool = False
    consistent: bool = True
    mismatch_reasons: tuple[str, ...] = ()


def _default_run(command: list[str]) -> CommandResult:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    return CommandResult(
        returncode=result.returncode,
        stdout=result.stdout or "",
        stderr=result.stderr or "",
    )


def _default_run_nft_batch(script: str) -> CommandResult:
    result = subprocess.run(
        ["nft", "-f", "-"],
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )
    return CommandResult(
        returncode=result.returncode,
        stdout=result.stdout or "",
        stderr=result.stderr or "",
    )


@dataclass
class KillSwitch:
    """Firewall kill switch with nftables preferred and iptables fallback."""

    tunnel_interface: str = "wdvpn-tun0"
    block_ipv6: bool = True
    allow_lan: bool = True
    allowed_endpoints: tuple[str, ...] = ()
    direct_egress_uid: int | None = None
    lan_cidrs: tuple[str, ...] = DEFAULT_LAN_CIDRS
    runner: RunCommand = _default_run
    nft_batch_runner: RunNftBatch = _default_run_nft_batch
    which: Callable[[str], str | None] = shutil.which
    method: str | None = field(default=None)

    def detect_method(self) -> str | None:
        if self.which("nft"):
            return "nftables"
        if self.which("iptables"):
            return "iptables"
        return None

    def enable(self) -> bool:
        method = self.method or self.detect_method()
        if method is None:
            LOGGER.error("kill_switch_enable_failed reason=no_firewall_backend")
            return False
        self.method = method
        if method == "nftables":
            if self.which("iptables"):
                self._disable_iptables()
            return self._enable_nftables()
        if self.which("nft"):
            self._disable_nftables()
        if self.block_ipv6 and not self.which("ip6tables"):
            LOGGER.error("kill_switch_enable_failed reason=ip6tables_unavailable")
            self._disable_iptables()
            return False
        return self._enable_iptables()

    def apply_atomic(self) -> bool:
        """Replace the nftables policy without a transient permit window.

        The imperative iptables fallback remains available for legacy manual
        use, but it is not an acceptable connection-security boundary because
        it cannot replace an active policy atomically.
        """

        method = self.method or self.detect_method()
        if method != "nftables":
            LOGGER.error("kill_switch_atomic_apply_failed reason=nftables_required")
            return False
        self.method = method
        existing = self._inspect_nftables().artifacts_present
        commands: list[list[str]] = []
        if existing:
            commands.append(["nft", "delete", "table", "inet", WATCHDOGVPN_TABLE])
        commands.extend(self._nft_enable_commands())
        result = self.nft_batch_runner(self._nft_batch_script(commands))
        if result.returncode != 0:
            LOGGER.error("kill_switch_atomic_apply_failed stderr=%s", result.stderr.strip())
            return False
        status = self.status()
        if bool(status.get("active")) and bool(status.get("consistent", True)):
            LOGGER.warning("kill_switch_atomic_apply_succeeded")
            return True
        LOGGER.error("kill_switch_atomic_apply_failed reason=post_apply_verification")
        return False

    def disable(self) -> bool:
        command_success = True
        if self.which("nft"):
            command_success = self._disable_nftables() and command_success
        if self.which("iptables"):
            command_success = self._disable_iptables() and command_success
        status = self.status()
        if not bool(status["active"]) and not bool(status["artifacts_present"]):
            self.method = None
            return True
        LOGGER.error(
            "kill_switch_disable_failed command_success=%s active=%s artifacts_present=%s method=%s reasons=%s",
            command_success,
            status["active"],
            status["artifacts_present"],
            status["method"],
            status["mismatch_reasons"],
        )
        return False

    def is_active(self) -> bool:
        return bool(self.status()["active"])

    def status(self) -> dict[str, object]:
        states: list[_FirewallState] = []
        if self.which("nft"):
            states.append(self._inspect_nftables())
        if self.which("iptables"):
            states.append(self._inspect_iptables())
        artifacts = [state for state in states if state.artifacts_present]
        reasons = [reason for state in artifacts for reason in state.mismatch_reasons]
        if len(artifacts) > 1:
            reasons.append("multiple_firewall_backends_present")
        active = any(state.active for state in artifacts)
        consistent = len(artifacts) <= 1 and all(state.consistent for state in artifacts)
        rules_applied = bool(artifacts) and active and consistent
        method = (
            artifacts[0].method
            if len(artifacts) == 1
            else "+".join(state.method for state in artifacts)
            if artifacts
            else self.method or self.detect_method()
        )
        return KillSwitchStatus(
            available=bool(states),
            artifacts_present=bool(artifacts),
            active=active,
            method=method,
            rules_applied=rules_applied,
            consistent=consistent,
            mismatch_reasons=tuple(sorted(set(reasons))),
            tunnel_interface=self.tunnel_interface,
            block_ipv6=self.block_ipv6,
            allow_lan=self.allow_lan,
            allowed_endpoints=tuple(self.allowed_endpoints),
            direct_egress_uid=self.direct_egress_uid,
        ).to_dict()

    def _inspect_nftables(self) -> "_FirewallState":
        result = self.runner(["nft", "list", "table", "inet", WATCHDOGVPN_TABLE])
        if result.returncode != 0:
            return _FirewallState(method="nftables")
        output = result.stdout
        chain_match = re.search(
            rf"\bchain\s+{re.escape(WATCHDOGVPN_CHAIN)}\s*\{{(?P<body>.*?)^\s*\}}",
            output,
            flags=re.MULTILINE | re.DOTALL,
        )
        guard_match = re.search(
            rf"\bchain\s+{re.escape(WATCHDOGVPN_CAPTURE_GUARD_CHAIN)}\s*\{{(?P<body>.*?)^\s*\}}",
            output,
            flags=re.MULTILINE | re.DOTALL,
        )
        chain = chain_match.group("body") if chain_match else ""
        guard_chain = guard_match.group("body") if guard_match else ""
        has_output_hook = bool(re.search(r"\bhook\s+output\b", chain))
        has_drop_policy = bool(re.search(r"\bpolicy\s+drop\b", chain))
        has_capture_guard_hook = bool(re.search(r"\bhook\s+postrouting\b", guard_chain))
        has_capture_guard_accept_policy = bool(
            re.search(r"\bpolicy\s+accept\b", guard_chain)
        )
        active = has_output_hook and has_drop_policy
        managed_lines = self._managed_nft_rule_lines(chain)
        guard_lines = self._managed_nft_rule_lines(guard_chain)
        managed_rule_count = len(managed_lines) + len(guard_lines)
        expected_rule_count = self._expected_nft_rule_count()
        checks = {
            "missing_output_hook": has_output_hook,
            "missing_drop_policy": has_drop_policy,
            "missing_loopback_allow": self._nft_rule_present(
                managed_lines, ("oifname", "lo"), "accept"
            ),
            "missing_loopback_ipv4_allow": self._nft_rule_present(
                managed_lines, ("ip", "daddr", "127.0.0.0/8"), "accept"
            ),
            "missing_loopback_ipv6_allow": self._nft_rule_present(
                managed_lines, ("ip6", "daddr", "::1"), "accept"
            ),
            "missing_tunnel_allow": self._nft_rule_present(
                managed_lines, ("oifname", self.tunnel_interface), "accept"
            ),
            "missing_capture_output_allow": self._nft_rule_present(
                managed_lines, ("meta", "mark", SING_BOX_CAPTURE_MARK), "accept"
            ),
            "missing_capture_guard_hook": has_capture_guard_hook,
            "missing_capture_guard_accept_policy": has_capture_guard_accept_policy,
            "missing_capture_guard_tunnel_allow": self._nft_rule_present(
                guard_lines,
                ("meta", "mark", SING_BOX_CAPTURE_MARK, "oifname", self.tunnel_interface),
                "accept",
            ),
            "missing_capture_guard_drop": self._nft_rule_present(
                guard_lines, ("meta", "mark", SING_BOX_CAPTURE_MARK), "drop"
            ),
            "missing_established_allow": self._nft_rule_present(
                managed_lines, ("ct", "state", "established,related"), "accept"
            ),
            "missing_terminal_drop": any(
                line.startswith("counter ") and " drop comment " in f" {line} "
                for line in managed_lines
            ),
        }
        if self.direct_egress_uid is not None:
            checks[f"missing_direct_egress_allow:{self.direct_egress_uid}"] = (
                self._nft_rule_present(
                    managed_lines,
                    (
                        "meta",
                        "skuid",
                        str(self.direct_egress_uid),
                        "meta",
                        "mark",
                        SING_BOX_OUTBOUND_MARK,
                    ),
                    "accept",
                )
            )
        for endpoint in self.allowed_endpoints:
            try:
                parsed = ip_address(endpoint)
            except ValueError:
                continue
            family = "ip6" if parsed.version == 6 else "ip"
            checks[f"missing_endpoint_allow:{parsed}"] = self._nft_rule_present(
                managed_lines, (family, "daddr", str(parsed)), "accept"
            )
        for endpoint in SING_BOX_TUN_DNS_ENDPOINTS:
            for protocol in ("udp", "tcp"):
                checks[f"missing_internal_dns_allow:{endpoint}/{protocol}"] = (
                    self._nft_rule_present(
                        managed_lines,
                        ("ip", "daddr", endpoint, protocol, "dport", "53"),
                        "accept",
                    )
                )
        for protocol in ("udp", "tcp"):
            for port in ("53", "853"):
                checks[f"missing_dns_reject:{protocol}/{port}"] = self._nft_rule_present(
                    managed_lines, (protocol, "dport", port), "reject"
                )
        if self.allow_lan:
            for cidr in self.lan_cidrs:
                checks[f"missing_lan_allow:{cidr}"] = self._nft_rule_present(
                    managed_lines, ("ip", "daddr", cidr), "accept"
                )
        if not self.block_ipv6:
            checks["missing_ipv6_allow"] = self._nft_rule_present(
                managed_lines, ("ip6", "daddr", "::/0"), "accept"
            )
        for protocol in ("tcp", "udp", "icmp", "ipv6-icmp"):
            checks[f"missing_terminal_drop:{protocol}"] = self._nft_rule_present(
                managed_lines, ("meta", "l4proto", protocol), "drop"
            )
        reasons = [reason for reason, passed in checks.items() if not passed]
        if managed_rule_count != expected_rule_count:
            reasons.append(
                f"managed_rule_count:{managed_rule_count}/{expected_rule_count}"
            )
        return _FirewallState(
            method="nftables",
            artifacts_present=True,
            active=active,
            consistent=active and not reasons,
            mismatch_reasons=tuple(reasons),
        )

    def _inspect_iptables(self) -> "_FirewallState":
        ipv4 = self._inspect_iptables_family("iptables")
        ipv6 = (
            self._inspect_iptables_family("ip6tables")
            if self.block_ipv6 and self.which("ip6tables")
            else _FirewallState(method="ip6tables")
        )
        artifacts_present = ipv4.artifacts_present or ipv6.artifacts_present
        reasons = list(ipv4.mismatch_reasons)
        if self.block_ipv6 and self.which("ip6tables"):
            reasons.extend(f"ipv6:{reason}" for reason in ipv6.mismatch_reasons)
        if self.block_ipv6 and not self.which("ip6tables"):
            reasons.append("ipv6_backend_unavailable")
        active = ipv4.active and (
            not self.block_ipv6 or not self.which("ip6tables") or ipv6.active
        )
        consistent = artifacts_present and active and not reasons
        return _FirewallState(
            method="iptables",
            artifacts_present=artifacts_present,
            active=active,
            consistent=consistent,
            mismatch_reasons=tuple(reasons),
        )

    def _inspect_iptables_family(self, binary: str) -> "_FirewallState":
        chain_result = self.runner([binary, "-S", WATCHDOGVPN_IPTABLES_CHAIN])
        jump_result = self.runner(
            [binary, "-C", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN]
        )
        artifacts_present = chain_result.returncode == 0 or jump_result.returncode == 0
        if not artifacts_present:
            return _FirewallState(method=binary)
        output = chain_result.stdout if chain_result.returncode == 0 else ""
        has_chain = chain_result.returncode == 0
        has_jump = jump_result.returncode == 0
        actual_rules = self._iptables_chain_rules(output)
        expected_rules = self._expected_iptables_rules(binary)
        missing_rules = [
            label
            for label, expected in expected_rules
            if not any(self._iptables_rule_matches_expected(rule, expected) for rule in actual_rules)
        ]
        terminal_rule = (
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            "-j",
            "REJECT",
        )
        has_terminal_reject = any(
            rule[: len(terminal_rule)] == terminal_rule
            for rule in actual_rules
        )
        active = has_chain and has_jump and has_terminal_reject
        checks = {
            "missing_managed_chain": has_chain,
            "missing_output_jump": has_jump,
            "missing_terminal_reject": has_terminal_reject,
        }
        reasons = [reason for reason, passed in checks.items() if not passed]
        reasons.extend(missing_rules)
        if len(actual_rules) != len(expected_rules):
            reasons.append(f"managed_rule_count:{len(actual_rules)}/{len(expected_rules)}")
        return _FirewallState(
            method=binary,
            artifacts_present=artifacts_present,
            active=active,
            consistent=active and not reasons,
            mismatch_reasons=tuple(reasons),
        )

    def _expected_nft_rule_count(self) -> int:
        endpoint_count = 0
        for endpoint in self.allowed_endpoints:
            try:
                ip_address(endpoint)
            except ValueError:
                continue
            endpoint_count += 1
        return (
            19
            + endpoint_count
            + (1 if self.direct_egress_uid is not None else 0)
            + (len(self.lan_cidrs) if self.allow_lan else 0)
            + (1 if not self.block_ipv6 else 0)
        )

    @staticmethod
    def _managed_nft_rule_lines(chain: str) -> tuple[str, ...]:
        values: list[str] = []
        for line in chain.splitlines():
            normalized = " ".join(line.replace('"', "").split())
            normalized = re.sub(
                r"\b0x0*([0-9a-fA-F]+)\b",
                lambda match: f"0x{int(match.group(1), 16):x}",
                normalized,
            )
            if f"comment {WATCHDOGVPN_COMMENT}" in normalized:
                values.append(normalized)
        return tuple(values)

    @staticmethod
    def _nft_rule_present(
        lines: tuple[str, ...],
        match_tokens: tuple[str, ...],
        verdict: str,
    ) -> bool:
        match = " ".join(match_tokens)
        return any(match in line and f" {verdict} comment " in f" {line} " for line in lines)

    def _expected_iptables_rules(
        self,
        binary: str,
    ) -> tuple[tuple[str, tuple[str, ...]], ...]:
        loopback = "::1/128" if binary == "ip6tables" else "127.0.0.0/8"
        commands = [
            self._iptables_rule_command(binary, "-o", "lo", "-j", "ACCEPT"),
            self._iptables_rule_command(binary, "-d", loopback, "-j", "ACCEPT"),
            self._iptables_rule_command(
                binary, "-o", self.tunnel_interface, "-j", "ACCEPT"
            ),
        ]
        commands.extend(self._iptables_direct_egress_rules(binary))
        commands.extend(
            self._ip6tables_endpoint_rules()
            if binary == "ip6tables"
            else self._iptables_endpoint_rules()
        )
        commands.extend(self._iptables_internal_dns_rules(binary))
        commands.extend(self._iptables_dns_leak_block_rules(binary))
        commands.append(
            self._iptables_rule_command(
                binary,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            )
        )
        if binary == "iptables" and self.allow_lan:
            commands.extend(self._iptables_lan_rules(binary))
        commands.append(self._iptables_rule_command(binary, "-j", "REJECT"))
        expected: list[tuple[str, tuple[str, ...]]] = []
        for index, command in enumerate(commands):
            rule = tuple(command[3:])
            expected.append((f"missing_managed_rule:{binary}/{index}", rule))
        return tuple(expected)

    def _iptables_direct_egress_rules(self, binary: str) -> list[list[str]]:
        if self.direct_egress_uid is None:
            return []
        return [
            self._iptables_rule_command(
                binary,
                "-m",
                "owner",
                "--uid-owner",
                str(self.direct_egress_uid),
                "-m",
                "mark",
                "--mark",
                SING_BOX_OUTBOUND_MARK,
                "-j",
                "ACCEPT",
            )
        ]

    @staticmethod
    def _iptables_rule_command(binary: str, *tokens: str) -> list[str]:
        verdict_index = tokens.index("-j")
        return [
            binary,
            "-A",
            WATCHDOGVPN_IPTABLES_CHAIN,
            *tokens[:verdict_index],
            "-m",
            "comment",
            "--comment",
            WATCHDOGVPN_COMMENT,
            *tokens[verdict_index:],
        ]

    @classmethod
    def _iptables_chain_rules(cls, output: str) -> tuple[tuple[str, ...], ...]:
        rules: list[tuple[str, ...]] = []
        for line in output.splitlines():
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            if tokens[:2] != ["-A", WATCHDOGVPN_IPTABLES_CHAIN]:
                continue
            rules.append(tuple(cls._canonicalize_iptables_tokens(tokens[2:])))
        return tuple(rules)

    @classmethod
    def _iptables_rule_contains(
        cls,
        actual: tuple[str, ...],
        expected: tuple[str, ...],
    ) -> bool:
        canonical_expected = tuple(cls._canonicalize_iptables_tokens(list(expected)))
        iterator = iter(actual)
        return all(any(token == candidate for candidate in iterator) for token in canonical_expected)

    @classmethod
    def _iptables_rule_matches_expected(
        cls,
        actual: tuple[str, ...],
        expected: tuple[str, ...],
    ) -> bool:
        canonical_expected = tuple(cls._canonicalize_iptables_tokens(list(expected)))
        if canonical_expected[:2] == ("-m", "comment"):
            return actual[: len(canonical_expected)] == canonical_expected
        return cls._iptables_rule_contains(actual, canonical_expected)

    @staticmethod
    def _canonicalize_iptables_tokens(tokens: list[str]) -> list[str]:
        values = list(tokens)
        for index, token in enumerate(values[:-1]):
            if token != "-d":
                continue
            try:
                parsed = ip_address(values[index + 1])
            except ValueError:
                continue
            suffix = 32 if parsed.version == 4 else 128
            values[index + 1] = f"{parsed}/{suffix}"
        for index, token in enumerate(values[:-1]):
            if token != "--mark":
                continue
            raw_mark = values[index + 1].split("/", 1)[0]
            try:
                values[index + 1] = f"0x{int(raw_mark, 0):x}"
            except ValueError:
                continue
        return values

    def _run_required(self, command: list[str]) -> bool:
        result = self.runner(command)
        if result.returncode == 0:
            return True
        LOGGER.error(
            "kill_switch_command_failed command=%s stderr=%s",
            " ".join(command),
            result.stderr.strip(),
        )
        return False

    def _run_optional(self, command: list[str]) -> bool:
        result = self.runner(command)
        return result.returncode == 0

    def _enable_nftables(self) -> bool:
        self._disable_nftables()
        commands = self._nft_enable_commands()
        for command in commands:
            if not self._run_required(command):
                self._disable_nftables()
                return False
        LOGGER.warning(
            "kill_switch_enabled method=nftables tunnel_interface=%s block_ipv6=%s allow_lan=%s",
            self.tunnel_interface,
            self.block_ipv6,
            self.allow_lan,
        )
        return True

    def _nft_enable_commands(self) -> list[list[str]]:
        commands = [
            ["nft", "add", "table", "inet", WATCHDOGVPN_TABLE],
            [
                "nft",
                "add",
                "chain",
                "inet",
                WATCHDOGVPN_TABLE,
                WATCHDOGVPN_CHAIN,
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
            [
                "nft",
                "add",
                "chain",
                "inet",
                WATCHDOGVPN_TABLE,
                WATCHDOGVPN_CAPTURE_GUARD_CHAIN,
                "{",
                "type",
                "filter",
                "hook",
                "postrouting",
                "priority",
                "0;",
                "policy",
                "accept;",
                "}",
            ],
            *self._nft_capture_guard_rules(),
            self._nft_rule("oifname", "lo", "accept"),
            *self._nft_loopback_destination_rules(),
            self._nft_rule("oifname", self.tunnel_interface, "accept"),
            *self._nft_direct_egress_rules(),
            *self._nft_endpoint_rules(),
            *self._nft_internal_dns_rules(),
            *self._nft_dns_leak_block_rules(),
            *self._nft_capture_egress_rules(),
            self._nft_rule("ct", "state", "established,related", "accept"),
        ]
        if self.allow_lan:
            commands.extend(self._nft_lan_rules())
        if not self.block_ipv6:
            commands.append(self._nft_rule("ip6", "daddr", "::/0", "accept"))
        commands.extend(self._nft_terminal_drop_rules())
        return commands

    @staticmethod
    def _nft_batch_script(commands: list[list[str]]) -> str:
        return "\n".join(KillSwitch._nft_batch_line(command) for command in commands) + "\n"

    @staticmethod
    def _nft_batch_line(command: list[str]) -> str:
        rendered: list[str] = []
        for token in command[1:]:
            if token in {"{", "}"} or token.endswith(";") or token == WATCHDOGVPN_NFT_COMMENT:
                rendered.append(token)
            elif re.fullmatch(r"[A-Za-z0-9_./:@,+-]+", token):
                rendered.append(token)
            else:
                rendered.append('"' + token.replace("\\", "\\\\").replace('"', '\\"') + '"')
        return " ".join(rendered)

    def _disable_nftables(self) -> bool:
        return self._run_optional(["nft", "delete", "table", "inet", WATCHDOGVPN_TABLE])

    def _nft_rule(self, *tokens: str) -> list[str]:
        return self._nft_rule_in_chain(WATCHDOGVPN_CHAIN, *tokens)

    def _nft_rule_in_chain(self, chain: str, *tokens: str) -> list[str]:
        match_tokens = list(tokens[:-1])
        verdict = tokens[-1]
        return [
            "nft",
            "add",
            "rule",
            "inet",
            WATCHDOGVPN_TABLE,
            chain,
            *match_tokens,
            "counter",
            verdict,
            "comment",
            WATCHDOGVPN_NFT_COMMENT,
        ]

    def _nft_lan_rules(self) -> list[list[str]]:
        return [self._nft_rule("ip", "daddr", cidr, "accept") for cidr in self.lan_cidrs]

    def _nft_loopback_destination_rules(self) -> list[list[str]]:
        rules: list[list[str]] = []
        for cidr in LOOPBACK_CIDRS:
            family = "ip6" if ":" in cidr else "ip"
            rules.append(self._nft_rule(family, "daddr", cidr, "accept"))
        return rules

    def _nft_endpoint_rules(self) -> list[list[str]]:
        rules: list[list[str]] = []
        for endpoint in self.allowed_endpoints:
            try:
                parsed = ip_address(endpoint)
            except ValueError:
                continue
            family = "ip6" if parsed.version == 6 else "ip"
            rules.append(self._nft_rule(family, "daddr", str(parsed), "accept"))
        return rules

    def _nft_direct_egress_rules(self) -> list[list[str]]:
        if self.direct_egress_uid is None:
            return []
        return [
            self._nft_rule(
                "meta",
                "skuid",
                str(self.direct_egress_uid),
                "meta",
                "mark",
                SING_BOX_OUTBOUND_MARK,
                "accept",
            )
        ]

    def _nft_internal_dns_rules(self) -> list[list[str]]:
        rules: list[list[str]] = []
        for endpoint in SING_BOX_TUN_DNS_ENDPOINTS:
            for protocol in ("udp", "tcp"):
                rules.append(self._nft_rule("ip", "daddr", endpoint, protocol, "dport", "53", "accept"))
        return rules

    def _nft_dns_leak_block_rules(self) -> list[list[str]]:
        return [
            self._nft_rule("udp", "dport", str(port), "reject")
            for port in (53, 853)
        ] + [
            self._nft_rule("tcp", "dport", str(port), "reject")
            for port in (53, 853)
        ]

    def _nft_capture_egress_rules(self) -> list[list[str]]:
        # sing-box's route/output hook marks captured UDP and ICMP before this
        # filter chain runs, but nftables may still expose the packet's stale
        # physical oifname here. Matching only oifname therefore drops healthy
        # capture traffic. The mark allow is safe only because the independent
        # postrouting guard below observes the final route and drops the same
        # mark unless it is actually leaving through the managed TUN.
        return [
            self._nft_rule("meta", "mark", SING_BOX_CAPTURE_MARK, "accept")
        ]

    def _nft_capture_guard_rules(self) -> list[list[str]]:
        return [
            self._nft_rule_in_chain(
                WATCHDOGVPN_CAPTURE_GUARD_CHAIN,
                "meta",
                "mark",
                SING_BOX_CAPTURE_MARK,
                "oifname",
                self.tunnel_interface,
                "accept",
            ),
            self._nft_rule_in_chain(
                WATCHDOGVPN_CAPTURE_GUARD_CHAIN,
                "meta",
                "mark",
                SING_BOX_CAPTURE_MARK,
                "drop",
            ),
        ]

    def _nft_terminal_drop_rules(self) -> list[list[str]]:
        return [
            self._nft_rule("meta", "l4proto", protocol, "drop")
            for protocol in ("tcp", "udp", "icmp", "ipv6-icmp")
        ] + [self._nft_rule("drop")]

    def _enable_iptables(self) -> bool:
        self._disable_iptables()
        commands = [
            ["iptables", "-N", WATCHDOGVPN_IPTABLES_CHAIN],
            [
                "iptables",
                "-A",
                WATCHDOGVPN_IPTABLES_CHAIN,
                "-o",
                "lo",
                "-m",
                "comment",
                "--comment",
                WATCHDOGVPN_COMMENT,
                "-j",
                "ACCEPT",
            ],
            [
                "iptables",
                "-A",
                WATCHDOGVPN_IPTABLES_CHAIN,
                "-d",
                "127.0.0.0/8",
                "-m",
                "comment",
                "--comment",
                WATCHDOGVPN_COMMENT,
                "-j",
                "ACCEPT",
            ],
            [
                "iptables",
                "-A",
                WATCHDOGVPN_IPTABLES_CHAIN,
                "-o",
                self.tunnel_interface,
                "-m",
                "comment",
                "--comment",
                WATCHDOGVPN_COMMENT,
                "-j",
                "ACCEPT",
            ],
        ]
        commands.extend(self._iptables_direct_egress_rules("iptables"))
        commands.extend(self._iptables_endpoint_rules())
        commands.extend(self._iptables_internal_dns_rules("iptables"))
        commands.extend(self._iptables_dns_leak_block_rules("iptables"))
        commands.append(
            [
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
        )
        if self.allow_lan:
            commands.extend(self._iptables_lan_rules("iptables"))
        commands.extend(
            [
                [
                    "iptables",
                    "-A",
                    WATCHDOGVPN_IPTABLES_CHAIN,
                    "-m",
                    "comment",
                    "--comment",
                    WATCHDOGVPN_COMMENT,
                    "-j",
                    "REJECT",
                ],
                ["iptables", "-I", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN],
            ]
        )
        if self.block_ipv6 and self.which("ip6tables"):
            commands.extend(self._ip6tables_enable_commands())

        for command in commands:
            if not self._run_required(command):
                self._disable_iptables()
                return False
        LOGGER.warning(
            "kill_switch_enabled method=iptables tunnel_interface=%s block_ipv6=%s allow_lan=%s",
            self.tunnel_interface,
            self.block_ipv6,
            self.allow_lan,
        )
        return True

    def _disable_iptables(self) -> bool:
        results = [
            self._run_optional(["iptables", "-D", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN]),
            self._run_optional(["iptables", "-F", WATCHDOGVPN_IPTABLES_CHAIN]),
            self._run_optional(["iptables", "-X", WATCHDOGVPN_IPTABLES_CHAIN]),
        ]
        if self.which("ip6tables"):
            results.extend(
                [
                    self._run_optional(["ip6tables", "-D", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN]),
                    self._run_optional(["ip6tables", "-F", WATCHDOGVPN_IPTABLES_CHAIN]),
                    self._run_optional(["ip6tables", "-X", WATCHDOGVPN_IPTABLES_CHAIN]),
                ]
            )
        return all(results)

    def _iptables_lan_rules(self, binary: str) -> list[list[str]]:
        return [
            [
                binary,
                "-A",
                WATCHDOGVPN_IPTABLES_CHAIN,
                "-d",
                cidr,
                "-m",
                "comment",
                "--comment",
                WATCHDOGVPN_COMMENT,
                "-j",
                "ACCEPT",
            ]
            for cidr in self.lan_cidrs
        ]

    def _iptables_endpoint_rules(self) -> list[list[str]]:
        commands: list[list[str]] = []
        for endpoint in self.allowed_endpoints:
            try:
                parsed = ip_address(endpoint)
            except ValueError:
                continue
            if parsed.version != 4:
                continue
            commands.append(
                [
                    "iptables",
                    "-A",
                    WATCHDOGVPN_IPTABLES_CHAIN,
                    "-d",
                    str(parsed),
                    "-m",
                    "comment",
                    "--comment",
                    WATCHDOGVPN_COMMENT,
                    "-j",
                    "ACCEPT",
                ]
            )
        return commands

    def _iptables_internal_dns_rules(self, binary: str) -> list[list[str]]:
        commands: list[list[str]] = []
        for endpoint in SING_BOX_TUN_DNS_ENDPOINTS:
            try:
                parsed = ip_address(endpoint)
            except ValueError:
                continue
            if binary == "iptables" and parsed.version != 4:
                continue
            if binary == "ip6tables" and parsed.version != 6:
                continue
            for protocol in ("udp", "tcp"):
                commands.append(
                    [
                        binary,
                        "-A",
                        WATCHDOGVPN_IPTABLES_CHAIN,
                        "-d",
                        str(parsed),
                        "-p",
                        protocol,
                        "--dport",
                        "53",
                        "-m",
                        "comment",
                        "--comment",
                        WATCHDOGVPN_COMMENT,
                        "-j",
                        "ACCEPT",
                    ]
                )
        return commands

    def _iptables_dns_leak_block_rules(self, binary: str) -> list[list[str]]:
        commands: list[list[str]] = []
        for protocol in ("udp", "tcp"):
            for port in ("53", "853"):
                commands.append(
                    [
                        binary,
                        "-A",
                        WATCHDOGVPN_IPTABLES_CHAIN,
                        "-p",
                        protocol,
                        "--dport",
                        port,
                        "-m",
                        "comment",
                        "--comment",
                        WATCHDOGVPN_COMMENT,
                        "-j",
                        "REJECT",
                    ]
                )
        return commands

    def _ip6tables_enable_commands(self) -> list[list[str]]:
        commands = [
            ["ip6tables", "-N", WATCHDOGVPN_IPTABLES_CHAIN],
            [
                "ip6tables",
                "-A",
                WATCHDOGVPN_IPTABLES_CHAIN,
                "-o",
                "lo",
                "-m",
                "comment",
                "--comment",
                WATCHDOGVPN_COMMENT,
                "-j",
                "ACCEPT",
            ],
            [
                "ip6tables",
                "-A",
                WATCHDOGVPN_IPTABLES_CHAIN,
                "-d",
                "::1/128",
                "-m",
                "comment",
                "--comment",
                WATCHDOGVPN_COMMENT,
                "-j",
                "ACCEPT",
            ],
            [
                "ip6tables",
                "-A",
                WATCHDOGVPN_IPTABLES_CHAIN,
                "-o",
                self.tunnel_interface,
                "-m",
                "comment",
                "--comment",
                WATCHDOGVPN_COMMENT,
                "-j",
                "ACCEPT",
            ],
        ]
        commands.extend(self._iptables_direct_egress_rules("ip6tables"))
        commands.extend(self._ip6tables_endpoint_rules())
        commands.extend(self._iptables_internal_dns_rules("ip6tables"))
        commands.extend(self._iptables_dns_leak_block_rules("ip6tables"))
        commands.append(
            [
                "ip6tables",
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
        )
        commands.extend(
            [
                [
                    "ip6tables",
                    "-A",
                    WATCHDOGVPN_IPTABLES_CHAIN,
                    "-m",
                    "comment",
                    "--comment",
                    WATCHDOGVPN_COMMENT,
                    "-j",
                    "REJECT",
                ],
                ["ip6tables", "-I", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN],
            ]
        )
        return commands

    def _ip6tables_endpoint_rules(self) -> list[list[str]]:
        commands: list[list[str]] = []
        for endpoint in self.allowed_endpoints:
            try:
                parsed = ip_address(endpoint)
            except ValueError:
                continue
            if parsed.version != 6:
                continue
            commands.append(
                [
                    "ip6tables",
                    "-A",
                    WATCHDOGVPN_IPTABLES_CHAIN,
                    "-d",
                    str(parsed),
                    "-m",
                    "comment",
                    "--comment",
                    WATCHDOGVPN_COMMENT,
                    "-j",
                    "ACCEPT",
                ]
            )
        return commands


_DEFAULT_KILL_SWITCH = KillSwitch()


def enable() -> bool:
    return _DEFAULT_KILL_SWITCH.enable()


def disable() -> bool:
    return _DEFAULT_KILL_SWITCH.disable()


def is_active() -> bool:
    return _DEFAULT_KILL_SWITCH.is_active()


def status() -> dict[str, object]:
    return _DEFAULT_KILL_SWITCH.status()
