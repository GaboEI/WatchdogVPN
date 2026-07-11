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
from app_policy.models import AppPolicy, AppPolicyRule
from app_policy.store import AppPolicyStore
from config.dns_policy_store import DNSPolicyStore
from config.state_manager import StateManager
from dns.models import DNSChannel, DNSChannelName, DNSPolicy, Resolver
from dns.resolver_inventory import ResolverInventory, ResolverManager
from dns.state_manager import DNSStateError, DNSStateSnapshot
from rules.models import Rule, RuleGroup
from rules.rule_store import RuleStore


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

    def test_dns_status_reports_fakeip_inactive_without_proxy_channel(self) -> None:
        # proxy_resolution_channel="fakeip" alone does not activate fakeip:
        # dns/singbox.py's build_singbox_dns_config only wires it in when a
        # "proxy" channel is also configured. A direct-only policy with the
        # setting still set to "fakeip" must not claim it is active.
        with tempfile.TemporaryDirectory() as tmp:
            policy = DNSPolicy(
                channels={
                    DNSChannelName.DIRECT: DNSChannel(
                        name=DNSChannelName.DIRECT,
                        resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                    )
                },
                proxy_resolution_channel="fakeip",
            )
            policy_path = Path(tmp) / "dns-policy.json"
            policy_path.write_text(json.dumps(policy.to_dict()), encoding="utf-8")
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")

            json_result = self.run_watchdog(
                ["dns", "status", "--json", "--resolv-conf-path", str(resolv_conf)],
                tmp,
            )
            data = json.loads(json_result.stdout)
            self.assertEqual(data["features"]["proxy_resolution_channel"], "fakeip")
            self.assertFalse(data["features"]["proxy_resolution_channel_active"])

            human_result = self.run_watchdog(
                ["dns", "status", "--resolv-conf-path", str(resolv_conf)],
                tmp,
            )
            self.assertIn("FakeIP: off", human_result.stdout)
            self.assertIn("requires a configured proxy DNS channel", human_result.stdout)

    def test_dns_status_reports_fakeip_active_with_proxy_channel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = DNSPolicy(
                channels={
                    DNSChannelName.DIRECT: DNSChannel(
                        name=DNSChannelName.DIRECT,
                        resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                    ),
                    DNSChannelName.PROXY: DNSChannel(
                        name=DNSChannelName.PROXY,
                        resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                    ),
                },
                proxy_resolution_channel="fakeip",
            )
            policy_path = Path(tmp) / "dns-policy.json"
            policy_path.write_text(json.dumps(policy.to_dict()), encoding="utf-8")
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")

            json_result = self.run_watchdog(
                ["dns", "status", "--json", "--resolv-conf-path", str(resolv_conf)],
                tmp,
            )
            data = json.loads(json_result.stdout)
            self.assertTrue(data["features"]["proxy_resolution_channel_active"])

            human_result = self.run_watchdog(
                ["dns", "status", "--resolv-conf-path", str(resolv_conf)],
                tmp,
            )
            self.assertIn("FakeIP: on", human_result.stdout)

    def test_dns_diagnose_json_reports_route_and_dns_channel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            RuleStore(Path(tmp) / "rules").add_group(
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="example-direct",
                            action="direct",
                            conditions={"domain": ["example.com"]},
                        )
                    ],
                )
            )
            DNSPolicyStore(Path(tmp) / "dns-policy.json").save(
                DNSPolicy(
                    channels={
                        DNSChannelName.DIRECT: DNSChannel(
                            name=DNSChannelName.DIRECT,
                            resolvers=[Resolver(uri="udp://1.1.1.1")],
                        )
                    }
                )
            )

            result = self.run_watchdog(
                ["dns", "diagnose", "--domain", "example.com", "--json"],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["confidence"], "definitive")
        self.assertEqual(data["route"]["action"], "direct")
        self.assertEqual(data["dns"]["channel"], "direct")
        self.assertEqual(data["dns"]["path"], "direct")
        self.assertEqual(data["route_diagnostic"]["route_action"], "direct")

    def test_dns_diagnose_uses_routing_state_default_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            StateManager(Path(tmp) / "state.toml").save(
                {
                    "routing_policy": "rule",
                    "capture_modes": "local_proxy",
                    "default_route_action": "block",
                    "active_mode": "global",
                }
            )

            result = self.run_watchdog(
                ["dns", "diagnose", "--domain", "unmatched.example", "--json"],
                tmp,
            )

        data = json.loads(result.stdout)
        self.assertEqual(data["route"]["action"], "block")
        self.assertEqual(data["route_diagnostic"]["routing"]["default_route_action"], "block")
        self.assertEqual(data["dns"]["path"], "blocked")

    def test_dns_diagnose_text_reports_app_policy_dns_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            AppPolicyStore(Path(tmp) / "app-policy.json").save(
                AppPolicy(
                    enabled=True,
                    rules=[
                        AppPolicyRule(
                            id="curl-block",
                            action="block",
                            match={"process_name": ["curl"]},
                        )
                    ],
                )
            )

            result = self.run_watchdog(
                ["dns", "diagnose", "--domain", "example.com", "--process-name", "curl"],
                tmp,
            )

        self.assertIn("configured policy only, not live traffic observation", result.stdout)
        self.assertIn("Route action: block", result.stdout)
        self.assertIn("DNS path: blocked", result.stdout)

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
            self.assertEqual(data["rollback_snapshot"]["path"], str(snapshot_path))
            self.assertEqual(data["rollback_snapshot"]["status"], "missing")
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
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")
            snapshot = _snapshot(resolv_conf)

            with patch("cli.main.detect_resolver_manager", return_value=_inventory(resolv_conf)):
                with patch("cli.main.SystemDNSStateManager") as manager_cls:
                    manager_cls.return_value.save_state.return_value = snapshot
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

    def test_dns_apply_json_reports_rollback_snapshot_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "dns-state.json"
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")
            snapshot = _snapshot(resolv_conf)

            with patch("cli.main.detect_resolver_manager", return_value=_inventory(resolv_conf)):
                with patch("cli.main.SystemDNSStateManager") as manager_cls:
                    manager_cls.return_value.save_state.return_value = snapshot
                    with patch("cli.main.DNSHijackController") as controller_cls:
                        controller_cls.return_value.apply.return_value = FakeApplyResult(snapshot)
                        with redirect_stdout(StringIO()) as stdout:
                            result = cli.main.main(
                                [
                                    "dns",
                                    "apply",
                                    "--yes",
                                    "--json",
                                    "--skip-entrypoint-check",
                                    "--snapshot-file",
                                    str(snapshot_path),
                                    "--resolv-conf-path",
                                    str(resolv_conf),
                                ]
                            )

        self.assertEqual(result, 0)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["rollback_snapshot"]["path"], str(snapshot_path))
        self.assertTrue(data["rollback_snapshot"]["will_create"])
        self.assertTrue(data["snapshot_saved"])

    def test_dns_apply_does_not_mutate_when_snapshot_save_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "missing-parent" / "dns-state.json"
            resolv_conf = Path(tmp) / "resolv.conf"
            resolv_conf.write_text("nameserver 203.0.113.53\n", encoding="utf-8")
            snapshot = _snapshot(resolv_conf)

            with patch("cli.main.detect_resolver_manager", return_value=_inventory(resolv_conf)):
                with patch("cli.main.SystemDNSStateManager") as manager_cls:
                    manager_cls.return_value.save_state.return_value = snapshot
                    with patch("cli.main._save_dns_snapshot", side_effect=DNSStateError("write failed")):
                        with patch("cli.main.DNSHijackController") as controller_cls:
                            with redirect_stderr(StringIO()):
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

            self.assertEqual(result, 70)
            controller_cls.return_value.apply.assert_not_called()

    def test_dns_apply_preserves_existing_rollback_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "dns-state.json"
            resolv_conf = Path(tmp) / "resolv.conf"
            original_snapshot = _snapshot(resolv_conf)
            snapshot_path.write_text(
                json.dumps(original_snapshot.to_dict()),
                encoding="utf-8",
            )
            resolv_conf.write_text("nameserver 127.0.0.1\n", encoding="utf-8")
            current_snapshot = DNSStateSnapshot(
                inventory=_inventory(resolv_conf),
                resolv_conf_content="nameserver 127.0.0.1\n",
            )

            with patch("cli.main.detect_resolver_manager", return_value=_inventory(resolv_conf)):
                with patch("cli.main.SystemDNSStateManager") as manager_cls:
                    manager_cls.return_value.save_state.return_value = current_snapshot
                    with patch("cli.main.DNSHijackController") as controller_cls:
                        controller_cls.return_value.apply.return_value = FakeApplyResult(current_snapshot)
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
            self.assertEqual(saved["resolv_conf_content"], "nameserver 203.0.113.53\n")
            manager_cls.return_value.save_state.assert_not_called()
            controller_cls.return_value.apply.assert_called_once()
            self.assertIsNone(controller_cls.return_value.apply.call_args.kwargs["snapshot"])

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
