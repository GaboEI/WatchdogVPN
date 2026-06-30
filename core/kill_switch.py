from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable


LOGGER = logging.getLogger(__name__)

WATCHDOGVPN_TABLE = "watchdogvpn"
WATCHDOGVPN_CHAIN = "output"
WATCHDOGVPN_IPTABLES_CHAIN = "WATCHDOGVPN-OUTPUT"
WATCHDOGVPN_COMMENT = "WatchdogVPN kill switch"

DEFAULT_LAN_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
)


@dataclass(slots=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(slots=True)
class KillSwitchStatus:
    available: bool
    active: bool
    method: str | None
    rules_applied: bool
    tunnel_interface: str
    block_ipv6: bool
    allow_lan: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "active": self.active,
            "method": self.method,
            "rules_applied": self.rules_applied,
            "tunnel_interface": self.tunnel_interface,
            "block_ipv6": self.block_ipv6,
            "allow_lan": self.allow_lan,
        }


RunCommand = Callable[[list[str]], CommandResult]


def _default_run(command: list[str]) -> CommandResult:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    return CommandResult(
        returncode=result.returncode,
        stdout=result.stdout or "",
        stderr=result.stderr or "",
    )


@dataclass
class KillSwitch:
    """Firewall kill switch with nftables preferred and iptables fallback."""

    tunnel_interface: str = "tun0"
    block_ipv6: bool = True
    allow_lan: bool = True
    lan_cidrs: tuple[str, ...] = DEFAULT_LAN_CIDRS
    runner: RunCommand = _default_run
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
            return self._enable_nftables()
        return self._enable_iptables()

    def disable(self) -> bool:
        method = self.method or self.detect_method()
        if method is None:
            return True
        self.method = method
        if method == "nftables":
            return self._disable_nftables()
        return self._disable_iptables()

    def is_active(self) -> bool:
        method = self.method or self.detect_method()
        if method is None:
            return False
        if method == "nftables":
            return self.runner(["nft", "list", "table", "inet", WATCHDOGVPN_TABLE]).returncode == 0
        return self.runner(["iptables", "-S", WATCHDOGVPN_IPTABLES_CHAIN]).returncode == 0

    def status(self) -> dict[str, object]:
        method = self.method or self.detect_method()
        active = self.is_active() if method is not None else False
        return KillSwitchStatus(
            available=method is not None,
            active=active,
            method=method,
            rules_applied=active,
            tunnel_interface=self.tunnel_interface,
            block_ipv6=self.block_ipv6,
            allow_lan=self.allow_lan,
        ).to_dict()

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
            self._nft_rule("ct", "state", "established,related", "accept"),
            self._nft_rule("oifname", "lo", "accept"),
            self._nft_rule("oifname", self.tunnel_interface, "accept"),
        ]
        if self.allow_lan:
            commands.extend(self._nft_lan_rules())
        if not self.block_ipv6:
            commands.append(self._nft_rule("ip6", "daddr", "::/0", "accept"))

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

    def _disable_nftables(self) -> bool:
        self._run_optional(["nft", "delete", "table", "inet", WATCHDOGVPN_TABLE])
        return True

    def _nft_rule(self, *tokens: str) -> list[str]:
        return [
            "nft",
            "add",
            "rule",
            "inet",
            WATCHDOGVPN_TABLE,
            WATCHDOGVPN_CHAIN,
            *tokens,
            "comment",
            WATCHDOGVPN_COMMENT,
        ]

    def _nft_lan_rules(self) -> list[list[str]]:
        return [self._nft_rule("ip", "daddr", cidr, "accept") for cidr in self.lan_cidrs]

    def _enable_iptables(self) -> bool:
        self._disable_iptables()
        commands = [
            ["iptables", "-N", WATCHDOGVPN_IPTABLES_CHAIN],
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
            ],
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
        self._run_optional(["iptables", "-D", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN])
        self._run_optional(["iptables", "-F", WATCHDOGVPN_IPTABLES_CHAIN])
        self._run_optional(["iptables", "-X", WATCHDOGVPN_IPTABLES_CHAIN])
        if self.which("ip6tables"):
            self._run_optional(["ip6tables", "-D", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN])
            self._run_optional(["ip6tables", "-F", WATCHDOGVPN_IPTABLES_CHAIN])
            self._run_optional(["ip6tables", "-X", WATCHDOGVPN_IPTABLES_CHAIN])
        return True

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

    def _ip6tables_enable_commands(self) -> list[list[str]]:
        return [
            ["ip6tables", "-N", WATCHDOGVPN_IPTABLES_CHAIN],
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
            ],
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
                "-o",
                self.tunnel_interface,
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
                "-m",
                "comment",
                "--comment",
                WATCHDOGVPN_COMMENT,
                "-j",
                "REJECT",
            ],
            ["ip6tables", "-I", "OUTPUT", "-j", WATCHDOGVPN_IPTABLES_CHAIN],
        ]


_DEFAULT_KILL_SWITCH = KillSwitch()


def enable() -> bool:
    return _DEFAULT_KILL_SWITCH.enable()


def disable() -> bool:
    return _DEFAULT_KILL_SWITCH.disable()


def is_active() -> bool:
    return _DEFAULT_KILL_SWITCH.is_active()


def status() -> dict[str, object]:
    return _DEFAULT_KILL_SWITCH.status()
