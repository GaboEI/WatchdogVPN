from __future__ import annotations

import json
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
    default_snapshot_path,
    load_snapshot,
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

    def test_systemd_resolved_restore_does_not_touch_resolv_conf_symlink(self) -> None:
        # apply_local_dns for systemd-resolved only ever calls resolvectl -
        # it never touches /etc/resolv.conf. Real /etc/resolv.conf is a
        # symlink to systemd-resolved's own stub file
        # (/run/systemd/resolve/stub-resolv.conf), owned by root; a real
        # field run showed restore attempting to replace that symlink
        # anyway, failing with "Permission denied" for a normal caller even
        # though the actual resolvectl revert had already succeeded.
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "stub-resolv.conf"
            stub.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.symlink_to(stub)
            runner = FakeRunner(active_services={"systemd-resolved.service"})
            manager = SystemDNSStateManager(resolv_conf_path=resolv_conf, runner=runner)

            snapshot = manager.apply_local_dns(
                LocalDNSEntryPoint(address="127.0.0.1", systemd_link="tun0")
            )
            with patch("dns.state_manager._replace_symlink") as replace_symlink:
                manager.restore_state(snapshot)
            replace_symlink.assert_not_called()
            self.assertIn(["resolvectl", "revert", "tun0"], runner.commands)
            self.assertEqual(resolv_conf.resolve(), stub.resolve())

    def test_systemd_resolved_restore_skips_revert_when_link_is_gone(self) -> None:
        # Field bug: a profile can connect in proxy-only capture mode (no
        # TUN device), so "dns apply --systemd-link wdvpn-tun0" saves a
        # snapshot naming a link that was never actually brought up. If
        # restore always calls "resolvectl revert <link>" unconditionally,
        # it fails with "No such device" forever afterward - every later
        # "dns reset" against that same stale snapshot keeps failing the
        # same way, since the link never comes back on its own. Restoring
        # against a link that is gone should be a clean no-op instead: the
        # systemd-resolved config that link would have carried is already
        # gone with the interface itself.
        with tempfile.TemporaryDirectory() as tmp:
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
            runner = FakeRunner(
                active_services={"systemd-resolved.service"},
                fail_on=("ip -o link show tun0",),
            )
            manager = SystemDNSStateManager(resolv_conf_path=resolv_conf, runner=runner)
            snapshot = manager.save_state(systemd_link="tun0")

            manager.restore_state(snapshot)

            self.assertIn(["ip", "-o", "link", "show", "tun0"], runner.commands)
            self.assertNotIn(["resolvectl", "revert", "tun0"], runner.commands)

    def test_apply_local_dns_failure_rolls_back_cleanly_when_link_is_gone(self) -> None:
        # Companion bug: when the apply itself fails because the named link
        # doesn't exist, apply_local_dns's own rollback (restore_state) used
        # to attempt the identical "resolvectl revert <link>" call, which
        # failed the same way and masked the original, more useful error
        # ("failed to apply local DNS entry point: ...") with a bare,
        # unwrapped "No such device" from the rollback attempt instead.
        with tempfile.TemporaryDirectory() as tmp:
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
            runner = FakeRunner(
                active_services={"systemd-resolved.service"},
                fail_on=("resolvectl dns", "ip -o link show tun0"),
            )
            manager = SystemDNSStateManager(resolv_conf_path=resolv_conf, runner=runner)

            with self.assertRaises(DNSStateError) as ctx:
                manager.apply_local_dns(
                    LocalDNSEntryPoint(address="127.0.0.1", systemd_link="tun0")
                )

            message = str(ctx.exception)
            self.assertIn("failed to apply local DNS entry point", message)
            self.assertNotIn(["resolvectl", "revert", "tun0"], runner.commands)

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


class DNSSnapshotHelperTests(unittest.TestCase):
    def test_default_snapshot_path_respects_env_override(self) -> None:
        with patch.dict(
            "os.environ",
            {"WATCHDOGVPN_DNS_SNAPSHOT_FILE": "/tmp/custom-dns-state.json"},
        ):
            self.assertEqual(default_snapshot_path(), Path("/tmp/custom-dns-state.json"))

    def test_load_snapshot_returns_none_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            self.assertIsNone(load_snapshot(missing))

    def test_load_snapshot_round_trips_a_saved_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
            runner = FakeRunner(active_services={"systemd-resolved.service"})
            manager = SystemDNSStateManager(resolv_conf_path=resolv_conf, runner=runner)
            snapshot = manager.save_state(systemd_link="tun0")
            snapshot_path = Path(tmp) / "dns-state.json"
            snapshot_path.write_text(
                json.dumps(snapshot.to_dict()),
                encoding="utf-8",
            )

            loaded = load_snapshot(snapshot_path)

            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.inventory.manager, ResolverManager.SYSTEMD_RESOLVED)
            self.assertEqual(loaded.systemd_link, "tun0")

    def test_load_snapshot_raises_on_invalid_json_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "dns-state.json"
            snapshot_path.write_text("[]", encoding="utf-8")

            with self.assertRaises(DNSStateError):
                load_snapshot(snapshot_path)


if __name__ == "__main__":
    unittest.main()
