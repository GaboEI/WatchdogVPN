from __future__ import annotations

import tempfile
import unittest
from subprocess import CompletedProcess
from pathlib import Path
from unittest.mock import patch

from dns.resolver_inventory import ResolverManager
from dns.state_manager import (
    DNSStateError,
    LocalDNSEntryPoint,
    SystemDNSStateManager,
    _run_command,
)


class FakeRunner:
    def __init__(
        self,
        active_services: set[str] | None = None,
        active_connections: tuple[str, ...] = (),
        connection_values: dict[str, tuple[str, str, str, str, str, str]] | None = None,
        fail_on: tuple[str, ...] = (),
    ) -> None:
        self.active_services = active_services or set()
        self.active_connections = active_connections
        self.connection_values = connection_values or {}
        self.fail_on = fail_on
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> str:
        self.commands.append(command)
        joined = " ".join(command)
        if any(token in joined for token in self.fail_on):
            raise DNSStateError(f"forced failure: {joined}")
        if command[:2] == ["systemctl", "is-active"] and len(command) == 3:
            return "active" if command[2] in self.active_services else "inactive"
        if command == ["nmcli", "-t", "-f", "NAME", "con", "show", "--active"]:
            return "\n".join(self.active_connections)
        if command[:2] == ["nmcli", "-g"] and command[-2:] != ["show", "--active"]:
            name = command[-1]
            return "\n".join(self.connection_values.get(name, ("", "no", "", "", "no", "")))
        return ""


class DNSStateManagerTests(unittest.TestCase):
    def test_save_state_detects_systemd_resolved_and_apply_restore_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
            runner = FakeRunner(active_services={"systemd-resolved.service"})
            manager = SystemDNSStateManager(resolv_conf_path=resolv_conf, runner=runner)

            snapshot = manager.apply_local_dns(
                LocalDNSEntryPoint(address="127.0.0.1", systemd_link="tun0")
            )
            manager.restore_state(snapshot)

            self.assertEqual(snapshot.inventory.manager, ResolverManager.SYSTEMD_RESOLVED)
            self.assertIn(["resolvectl", "dns", "tun0", "127.0.0.1"], runner.commands)
            self.assertIn(["resolvectl", "domain", "tun0", "~."], runner.commands)
            self.assertIn(["resolvectl", "revert", "tun0"], runner.commands)
            self.assertEqual(resolv_conf.read_text(encoding="utf-8"), "nameserver 127.0.0.53\n")

    def test_network_manager_apply_and_restore_connection_dns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 192.0.2.1\n", encoding="utf-8")
            runner = FakeRunner(
                active_services={"NetworkManager.service"},
                active_connections=("Home WiFi",),
                connection_values={
                    "Home WiFi": (
                        "192.0.2.1",
                        "no",
                        "lan",
                        "2001:db8::53",
                        "no",
                        "lan6",
                    )
                },
            )
            manager = SystemDNSStateManager(resolv_conf_path=resolv_conf, runner=runner)

            snapshot = manager.apply_local_dns(LocalDNSEntryPoint(address="127.0.0.1"))
            manager.restore_state(snapshot)

            self.assertEqual(snapshot.inventory.manager, ResolverManager.NETWORK_MANAGER)
            self.assertIn(
                [
                    "nmcli",
                    "con",
                    "mod",
                    "Home WiFi",
                    "ipv4.ignore-auto-dns",
                    "yes",
                    "ipv4.dns",
                    "127.0.0.1",
                    "ipv6.ignore-auto-dns",
                    "yes",
                    "ipv6.dns",
                    "",
                ],
                runner.commands,
            )
            self.assertIn(
                [
                    "nmcli",
                    "con",
                    "mod",
                    "Home WiFi",
                    "ipv4.ignore-auto-dns",
                    "no",
                    "ipv4.dns",
                    "192.0.2.1",
                    "ipv4.dns-search",
                    "lan",
                    "ipv6.ignore-auto-dns",
                    "no",
                    "ipv6.dns",
                    "2001:db8::53",
                    "ipv6.dns-search",
                    "lan6",
                ],
                runner.commands,
            )

    def test_classic_resolv_conf_apply_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resolv_conf = Path(tmp) / "resolv.conf"
            original = "search lan\nnameserver 203.0.113.53\n"
            resolv_conf.write_text(original, encoding="utf-8")
            manager = SystemDNSStateManager(
                resolv_conf_path=resolv_conf,
                runner=FakeRunner(),
            )

            snapshot = manager.apply_local_dns(LocalDNSEntryPoint(address="127.0.0.1"))

            self.assertEqual(snapshot.inventory.manager, ResolverManager.RESOLV_CONF)
            self.assertEqual(resolv_conf.read_text(encoding="utf-8"), "nameserver 127.0.0.1\n")
            manager.restore_state(snapshot)
            self.assertEqual(resolv_conf.read_text(encoding="utf-8"), original)

    def test_unknown_manager_uses_dns_rescue_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner()
            manager = SystemDNSStateManager(
                resolv_conf_path=Path(tmp) / "missing.conf",
                runner=runner,
                rescue_command=Path("/usr/local/bin/vpn_dns_rescue"),
            )
            snapshot = manager.save_state()

            manager.restore_state(snapshot)

            self.assertEqual(snapshot.inventory.manager, ResolverManager.UNKNOWN)
            self.assertIn(
                ["/usr/local/bin/vpn_dns_rescue", "auto", "--no-reconnect"],
                runner.commands,
            )

    def test_failed_network_manager_apply_restores_saved_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 192.0.2.1\n", encoding="utf-8")
            runner = FakeRunner(
                active_services={"NetworkManager.service"},
                active_connections=("Home WiFi",),
                connection_values={
                    "Home WiFi": ("192.0.2.1", "no", "", "", "no", "")
                },
                fail_on=("127.0.0.1",),
            )
            manager = SystemDNSStateManager(resolv_conf_path=resolv_conf, runner=runner)

            with self.assertRaises(DNSStateError):
                manager.apply_local_dns(LocalDNSEntryPoint(address="127.0.0.1"))

            restore_command = [
                "nmcli",
                "con",
                "mod",
                "Home WiFi",
                "ipv4.ignore-auto-dns",
                "no",
                "ipv4.dns",
                "192.0.2.1",
                "ipv4.dns-search",
                "",
                "ipv6.ignore-auto-dns",
                "no",
                "ipv6.dns",
                "",
                "ipv6.dns-search",
                "",
            ]
            self.assertIn(restore_command, runner.commands)

    def test_default_runner_does_not_raise_for_inactive_systemd_service(self) -> None:
        with patch("subprocess.run") as run:
            run.return_value = CompletedProcess(
                args=["systemctl", "is-active", "NetworkManager.service"],
                returncode=3,
                stdout="inactive\n",
                stderr="",
            )

            result = _run_command(["systemctl", "is-active", "NetworkManager.service"])

            self.assertEqual(result, "inactive")


if __name__ == "__main__":
    unittest.main()
