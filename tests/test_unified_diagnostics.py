from __future__ import annotations

import subprocess
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config.app_config import DEFAULT_CONFIG
from diagnostics.unified import (
    ExitIPSnapshot,
    collect_unified_diagnostics,
    observe_route_tables,
)
from dns.models import DNSChannel, DNSChannelName, DNSPolicy, Resolver
from dns.resolver_inventory import ResolverInventory, ResolverManager
from models.connection_state import ConnectionState
from models.provider import Provider
from network_context.models import (
    ActionIntent,
    NetworkContextPolicy,
    NetworkContextTrigger,
    NetworkMatch,
    NetworkProfile,
)
from network_context.monitor import (
    ActiveNetwork,
    ConnectivityState,
    MonitorStatus,
    NetworkObservation,
)


def completed(args: list[str], stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout, stderr="")


class FakeRunner:
    def __init__(self, outputs: dict[tuple[str, ...], subprocess.CompletedProcess[str]]) -> None:
        self.outputs = outputs
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(args))
        try:
            return self.outputs[tuple(args)]
        except KeyError as exc:
            raise AssertionError(f"unexpected command: {args}") from exc


def which_ip_only(command: str) -> str | None:
    return "/usr/bin/ip" if command == "ip" else None


class UnifiedDiagnosticsTests(unittest.TestCase):
    def test_collects_structured_unified_diagnostics_without_support_export(self) -> None:
        app_config = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
        app_config["lan_sharing"].update(
            {
                "enabled": True,
                "mode": "gateway",
                "gateway_interface": "enp0s8",
                "gateway_client_cidr": "192.168.50.0/24",
                "firewall_managed": True,
            }
        )
        routing_state = {
            "routing_state_version": "1",
            "routing_policy": "global",
            "capture_modes": "local_proxy,tun",
            "default_route_action": "current",
            "active_mode": "tun",
        }
        dns_policy = DNSPolicy(
            channels={
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="udp://10.0.0.1")],
                )
            }
        )
        resolver_inventory = ResolverInventory(
            manager=ResolverManager.RESOLV_CONF,
            resolv_conf_path=Path("/tmp/resolv.conf"),
            nameservers=["203.0.113.53"],
            search_domains=["office.example"],
        )
        network_policy = NetworkContextPolicy(
            enabled=True,
            profiles=[
                NetworkProfile(
                    id="public-wifi",
                    label="Public Wi-Fi",
                    trust="untrusted",
                    matches=[NetworkMatch(kind="interface_type", value="wifi")],
                )
            ],
            triggers={
                NetworkContextTrigger.UNTRUSTED_NETWORK: ActionIntent(
                    enabled=True,
                    action="connect",
                    explanation="Connect when untrusted network policy is enabled.",
                    disable_hint="Disable untrusted network trigger.",
                    reversible=True,
                    reversal="Disconnect or return to manual mode.",
                )
            },
        )
        observation = NetworkObservation(
            status=MonitorStatus.OBSERVED,
            connectivity=ConnectivityState.ONLINE,
            active_networks=(
                ActiveNetwork(
                    source="test",
                    interface_name="wlp3s0",
                    interface_type="wifi",
                    ssid="Public Wi-Fi",
                ),
            ),
            default_route_interfaces=("wlp3s0",),
        )
        runner = FakeRunner(
            {
                ("ip", "-j", "route", "show", "table", "main"): completed(
                    ["ip"],
                    '[{"dst":"default","dev":"wlp3s0","gateway":"192.0.2.1"},'
                    '{"dst":"192.0.2.0/24","dev":"wlp3s0"}]',
                )
            }
        )

        diagnostics = collect_unified_diagnostics(
            app_config=app_config,
            routing_state=routing_state,
            dns_policy=dns_policy,
            resolver_inventory=resolver_inventory,
            providers=[
                Provider(
                    id="provider-a",
                    name="Provider A",
                    url="https://secret.example/sub",
                    last_updated=datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc),
                    profiles=["node-a"],
                    metadata={"traffic_used": "1 GB"},
                )
            ],
            runtime_state=ConnectionState(
                active_profile_id="node-a",
                mode="sing-box",
                tun_active=True,
                proxy_active=True,
                kill_switch_active=True,
                lan_gateway_active=True,
                lan_gateway_interface="enp0s8",
                lan_gateway_client_cidr="192.168.50.0/24",
                lan_gateway_dns_mode="manual",
                lan_gateway_status="applied",
                status="connected",
            ),
            network_policy=network_policy,
            network_observation=observation,
            runner=runner,
            which=which_ip_only,
            recent_failure_categories=["dns_policy:unavailable"],
        )

        data = diagnostics.to_dict()

        self.assertFalse(data["support_export_ready"])
        self.assertEqual(data["routing"]["routing_policy"], "global")
        self.assertEqual(data["capture"]["tun"]["runtime_status"], "active")
        self.assertEqual(data["route_tables"]["status"], "observed")
        self.assertEqual(data["route_tables"]["route_count"], 2)
        self.assertEqual(data["dns"]["policy"]["enabled_resolver_counts"]["proxy"], 1)
        self.assertEqual(data["dns"]["resolver_manager"]["nameserver_count"], 1)
        self.assertEqual(data["dns"]["resolver_manager"]["search_domain_count"], 1)
        self.assertEqual(
            data["dns"]["resolver_manager"]["nameservers"],
            ["<redacted-dns-server>"],
        )
        self.assertEqual(
            data["dns"]["resolver_manager"]["search_domains"],
            ["<redacted-dns-search-domain>"],
        )
        self.assertEqual(data["exit_ip"]["status"], "not_run")
        self.assertEqual(data["network_context"]["decision"]["trigger"], "untrusted_network")
        self.assertFalse(data["network_context"]["decision"]["runtime_action_executed"])
        self.assertEqual(data["lan"]["gateway"]["status"], "applied")
        self.assertEqual(data["lan"]["gateway"]["dns_honesty"], "manual-client-dns-only")
        self.assertFalse(data["providers"]["url_values_included"])
        self.assertEqual(
            data["providers"]["items"][0]["metadata_value_status"],
            "deferred-to-task-21.5",
        )
        rendered = repr(data)
        self.assertNotIn("secret.example", rendered)
        self.assertNotIn("Public Wi-Fi", rendered)
        self.assertNotIn("wlp3s0", rendered)
        self.assertNotIn("203.0.113.53", rendered)
        self.assertNotIn("office.example", rendered)
        self.assertIn("<redacted-interface>", rendered)
        self.assertIn("<redacted-lan-gateway-interface>", rendered)
        self.assertIn("dns_policy:unavailable", data["recent_failures"]["categories"])

    def test_route_table_observer_degrades_when_ip_is_missing(self) -> None:
        snapshot = observe_route_tables(runner=FakeRunner({}), which=lambda command: None)

        self.assertEqual(snapshot.status, "unsupported")
        self.assertIn("ip not found", " ".join(snapshot.diagnostics))

    def test_exit_ip_snapshot_defaults_to_not_run_without_public_ip_history(self) -> None:
        data = collect_unified_diagnostics(
            app_config={section: dict(values) for section, values in DEFAULT_CONFIG.items()},
            routing_state={},
            dns_policy=DNSPolicy(),
            resolver_inventory=None,
            providers=[],
            runtime_state=None,
            network_policy=NetworkContextPolicy(),
            network_observation=NetworkObservation(status=MonitorStatus.UNSUPPORTED),
            route_table_snapshot=observe_route_tables(
                runner=FakeRunner({}),
                which=lambda command: None,
            ),
            exit_ip=ExitIPSnapshot(),
        ).to_dict()

        self.assertEqual(data["exit_ip"]["status"], "not_run")
        self.assertEqual(data["exit_ip"]["public_ip"], "<not-observed-public-ip>")
        self.assertEqual(data["recent_failures"]["raw_events_included"], False)


if __name__ == "__main__":
    unittest.main()
