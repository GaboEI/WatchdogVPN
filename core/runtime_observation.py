from __future__ import annotations

import socket
import subprocess
from dataclasses import dataclass
from typing import Callable

from drivers.runtime_paths import observe_tcp_listener_ports, owned_processes


WATCHDOG_RUNTIME_EXECUTABLES = (
    "sing-box",
    "openvpn",
    "ck-client",
    "amneziawg-go",
)
WATCHDOG_INTERFACES = ("wdvpn-tun0", "watchdogvpn_awg")
SING_BOX_MARKS = ("0x2023", "0x2024")


@dataclass(frozen=True, slots=True)
class ObservationCommandResult:
    returncode: int
    stdout: str = ""


RunObservationCommand = Callable[[list[str]], ObservationCommandResult]


@dataclass(frozen=True, slots=True)
class EffectiveRuntimeObservation:
    """Read-only OS evidence attributable to WatchdogVPN."""

    processes: tuple[str, ...] = ()
    interfaces: tuple[str, ...] = ()
    listener_ports: tuple[int, ...] = ()
    routing_artifacts: tuple[str, ...] = ()
    listener_observable: bool = True

    @property
    def artifacts(self) -> tuple[str, ...]:
        values = [f"owned_process:{name}" for name in self.processes]
        values.extend(f"interface:{name}" for name in self.interfaces)
        values.extend(f"owned_listener:tcp/{port}" for port in self.listener_ports)
        values.extend(self.routing_artifacts)
        return tuple(sorted(set(values)))


def observe_effective_runtime(
    *,
    runner: RunObservationCommand | None = None,
) -> EffectiveRuntimeObservation:
    """Observe owned processes, sockets, interfaces and routing state."""

    command_runner = runner or _run
    processes = owned_processes(
        "watchdogvpn-",
        executable_names=WATCHDOG_RUNTIME_EXECUTABLES,
    )
    listeners = observe_tcp_listener_ports(processes)
    process_names = tuple(sorted({process.executable for process in processes}))
    interfaces = tuple(
        interface for interface in WATCHDOG_INTERFACES if _interface_exists(interface)
    )

    routing_artifacts: list[str] = []
    if _command_succeeds(
        command_runner,
        ["nft", "list", "table", "inet", "sing-box"],
    ):
        routing_artifacts.append("routing:nft/sing-box")
    if _command_succeeds(
        command_runner,
        ["nft", "list", "table", "inet", "watchdogvpn_lan_gateway"],
    ):
        routing_artifacts.append("routing:nft/watchdogvpn_lan_gateway")

    rule_result = command_runner(["ip", "rule", "show"])
    if rule_result.returncode == 0 and any(
        f"fwmark {mark}" in rule_result.stdout for mark in SING_BOX_MARKS
    ):
        routing_artifacts.append("routing:ip-rule/sing-box-mark")

    for family, command in (
        ("ipv4", ["ip", "route", "show", "table", "all"]),
        ("ipv6", ["ip", "-6", "route", "show", "table", "all"]),
    ):
        result = command_runner(command)
        if result.returncode == 0 and any(
            interface in result.stdout for interface in WATCHDOG_INTERFACES
        ):
            routing_artifacts.append(f"routing:{family}/watchdog-interface")

    return EffectiveRuntimeObservation(
        processes=process_names,
        interfaces=interfaces,
        listener_ports=listeners.ports,
        routing_artifacts=tuple(sorted(set(routing_artifacts))),
        listener_observable=listeners.observable,
    )


def _run(command: list[str]) -> ObservationCommandResult:
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return ObservationCommandResult(returncode=127)
    return ObservationCommandResult(
        returncode=result.returncode,
        stdout=result.stdout or "",
    )


def _command_succeeds(
    runner: RunObservationCommand,
    command: list[str],
) -> bool:
    return runner(command).returncode == 0


def _interface_exists(interface: str) -> bool:
    try:
        socket.if_nametoindex(interface)
    except OSError:
        return False
    return True
