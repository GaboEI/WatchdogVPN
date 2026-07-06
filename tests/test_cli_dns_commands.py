from __future__ import annotations

import json
import os
import subprocess
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import cli.main
from dns.models import DNSChannel, DNSChannelName, DNSPolicy, Resolver
from dns.resolver_inventory import ResolverInventory, ResolverManager
from dns.state_manager import DNSStateSnapshot


ROOT_DIR = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT_DIR / "bin" / "watchdog"


def _inventory(path: Path) -> ResolverInventory:
    return ResolverInventory(
        manager=ResolverManager.RESOLV_CONF,
        resolv_conf_path=path,
        nameservers=["203.0.113.53"],
    )


def _snapshot(path: Path) -> DNSStateSnapshot:
    return DNSStateSnapshot(
        inventory=_inventory(path),
        resolv_conf_content="nameserver 203.0.113.53\n",
    )


class FakeApplyResult:
    def __init__(self, snapshot: DNSStateSnapshot) -> None:
        self.applied = True
        self.snapshot = snapshot
        self.reason = None


class CliDNSCommandTests(unittest.TestCase):
    def run_watchdog(
        self,
        args: list[str],
        tmp: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "WATCHDOGVPN_CONFIG_DIR": tmp,
            "WATCHDOGVPN_DNS_POLICY_FILE": str(Path(tmp) / "dns-policy.json"),
            "WATCHDOGVPN_DNS_SNAPSHOT_FILE": str(Path(tmp) / "dns-state.json"),
            "PYTHONPATH": str(ROOT_DIR),
        }
        result = subprocess.run(
            [str(WATCHDOG), *args],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        if check and result.returncode != 0:
            self.fail(f"command failed: {result.stderr}\nstdout={result.stdout}")
        return result

    def test_dns_status_json_uses_default_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")

            result = self.run_watchdog(
                ["dns", "status", "--json", "--resolv-conf-path", str(resolv_conf)],
                tmp,
            )

            data = json.loads(result.stdout)
            self.assertEqual(data["policy"]["mode"], "auto")
            self.assertTrue(data["policy"]["tun_hijack"])
            self.assertEqual(data["snapshot"]["status"], "missing")

    def test_dns_status_json_reads_policy_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = DNSPolicy(
                channels={
                    DNSChannelName.DIRECT: DNSChannel(
                        name=DNSChannelName.DIRECT,
                        resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                    )
                },
                rules_enabled=True,
            )
            policy_path = Path(tmp) / "dns-policy.json"
            policy_path.write_text(json.dumps(policy.to_dict()), encoding="utf-8")
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")

            result = self.run_watchdog(
                ["dns", "status", "--json", "--resolv-conf-path", str(resolv_conf)],
                tmp,
            )

            data = json.loads(result.stdout)
            self.assertEqual(data["channels"]["configured"], 1)
            self.assertTrue(data["features"]["rules_enabled"])

    def test_dns_apply_requires_confirmation_or_dry_run(self) -> None:
        with redirect_stderr(StringIO()):
            result = cli.main.main(["dns", "apply"])

        self.assertEqual(result, 65)

    def test_dns_apply_rejects_non_standard_entrypoint_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "dns-state.json"
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")

            with redirect_stderr(StringIO()) as stderr:
                result = cli.main.main(
                    [
                        "dns",
                        "apply",
                        "--yes",
                        "--entrypoint-port",
                        "1053",
                        "--snapshot-file",
                        str(snapshot_path),
                        "--resolv-conf-path",
                        str(resolv_conf),
                    ]
                )

            self.assertEqual(result, 65)
            self.assertIn("dns apply requires --entrypoint-port 53", stderr.getvalue())
            self.assertFalse(snapshot_path.exists())

    def test_dns_apply_dry_run_does_not_create_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "dns-state.json"
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")

            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(
                    [
                        "dns",
                        "apply",
                        "--dry-run",
                        "--json",
                        "--snapshot-file",
                        str(snapshot_path),
                        "--resolv-conf-path",
                        str(resolv_conf),
                    ]
                )

            self.assertEqual(result, 0)
            data = json.loads(stdout.getvalue())
            self.assertEqual(data["status"], "dry-run")
            self.assertFalse(snapshot_path.exists())

    def test_dns_apply_dry_run_allows_non_standard_entrypoint_port_for_planning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "dns-state.json"
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")

            with redirect_stdout(StringIO()) as stdout:
                result = cli.main.main(
                    [
                        "dns",
                        "apply",
                        "--dry-run",
                        "--json",
                        "--entrypoint-port",
                        "1053",
                        "--snapshot-file",
                        str(snapshot_path),
                        "--resolv-conf-path",
                        str(resolv_conf),
                    ]
                )

            self.assertEqual(result, 0)
            data = json.loads(stdout.getvalue())
            self.assertEqual(data["status"], "dry-run")
            self.assertEqual(data["entrypoint"]["port"], 1053)
            self.assertFalse(snapshot_path.exists())

    def test_dns_apply_saves_snapshot_after_confirmed_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "dns-state.json"
            resolv_conf = Path(tmp) / "resolv.conf"
            snapshot = _snapshot(resolv_conf)

            with patch("cli.main.detect_resolver_manager", return_value=_inventory(resolv_conf)):
                with patch("cli.main.DNSHijackController") as controller_cls:
                    controller_cls.return_value.apply.return_value = FakeApplyResult(snapshot)
                    with redirect_stdout(StringIO()):
                        result = cli.main.main(
                            [
                                "dns",
                                "apply",
                                "--yes",
                                "--skip-entrypoint-check",
                                "--snapshot-file",
                                str(snapshot_path),
                                "--resolv-conf-path",
                                str(resolv_conf),
                            ]
                        )

            self.assertEqual(result, 0)
            saved = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["inventory"]["manager"], "resolv_conf")
            controller_cls.return_value.apply.assert_called_once()

    def test_dns_snapshot_save_uses_shared_state_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared_dir = Path(tmp) / "watchdogvpn"
            snapshot_path = shared_dir / "dns-state.json"
            resolv_conf = Path(tmp) / "resolv.conf"
            snapshot = _snapshot(resolv_conf)
            old_umask = os.umask(0o077)
            try:
                with patch("config.paths.SYSTEM_CONFIG_DIR", shared_dir):
                    cli.main._save_dns_snapshot(snapshot_path, snapshot)
            finally:
                os.umask(old_umask)

            self.assertEqual(stat.S_IMODE(shared_dir.stat().st_mode), 0o2770)
            self.assertEqual(stat.S_IMODE(snapshot_path.stat().st_mode), 0o660)
            self.assertEqual(stat.S_IMODE(snapshot_path.with_name("dns-state.json.lock").stat().st_mode), 0o660)
            saved = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["inventory"]["manager"], "resolv_conf")

    def test_dns_reset_restores_snapshot_and_removes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "dns-state.json"
            resolv_conf = Path(tmp) / "resolv.conf"
            snapshot_path.write_text(
                json.dumps(_snapshot(resolv_conf).to_dict()),
                encoding="utf-8",
            )

            with patch("cli.main.SystemDNSStateManager") as manager_cls:
                with redirect_stdout(StringIO()):
                    result = cli.main.main(
                        [
                            "dns",
                            "reset",
                            "--yes",
                            "--snapshot-file",
                            str(snapshot_path),
                            "--resolv-conf-path",
                            str(resolv_conf),
                        ]
                    )

            self.assertEqual(result, 0)
            self.assertFalse(snapshot_path.exists())
            manager_cls.return_value.restore_state.assert_called_once()

    def test_dns_test_uses_configured_channels(self) -> None:
        policy = DNSPolicy(
            channels={
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                )
            }
        )

        with patch("cli.main.DNSPolicyStore") as store_cls:
            store_cls.return_value.load.return_value = policy
            with patch("cli.main.DNSTester") as tester_cls:
                tester_cls.return_value.test_channel.return_value.to_dict.return_value = {
                    "channel": "proxy",
                    "results": [],
                    "selected": [],
                }
                with redirect_stdout(StringIO()) as stdout:
                    result = cli.main.main(["dns", "test", "--json"])

        self.assertEqual(result, 0)
        data = json.loads(stdout.getvalue())
        self.assertIn("proxy", data["channel_results"])
        tester_cls.return_value.test_channel.assert_called_once()


if __name__ == "__main__":
    unittest.main()
