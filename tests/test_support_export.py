from __future__ import annotations

import json
import subprocess
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config.app_config import DEFAULT_CONFIG
from diagnostics.support_export import (
    SupportExportReviewRequired,
    build_redacted_support_export,
    redact_support_payload,
)
from diagnostics.unified import collect_unified_diagnostics
from dns.models import DNSChannel, DNSChannelName, DNSPolicy, Resolver
from dns.resolver_inventory import ResolverInventory, ResolverManager
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType
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


CANARY_VALUES = (
    "wdvpn_canary_secret_token_21_6",
    "wdvpn_canary_secret_quota_21_6",
    "wdvpn_canary_lan_password_21_6",
    "provider-canary.example",
    "Canary Provider Private",
    "canary-provider-id-21-6",
    "Cafe Canary SSID",
    "aa:bb:cc:dd:ee:ff",
    "wlan-canary0",
    "canary-gateway-fingerprint",
    "canary.internal.example",
    "198.51.100.99",
    "2001:db8::216",
    "10.66.77.0/24",
    "PRIVATEKEYCANARY216",
)


def completed(args: list[str], stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout, stderr="")


class FakeRunner:
    def __init__(self, outputs: dict[tuple[str, ...], subprocess.CompletedProcess[str]]) -> None:
        self.outputs = outputs

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        try:
            return self.outputs[tuple(args)]
        except KeyError as exc:
            raise AssertionError(f"unexpected command: {args}") from exc


def which_ip_only(command: str) -> str | None:
    return "/usr/bin/ip" if command == "ip" else None


def assert_no_canaries(testcase: unittest.TestCase, payload: dict[str, Any]) -> str:
    rendered = json.dumps(payload, sort_keys=True)
    for canary in CANARY_VALUES:
        testcase.assertNotIn(canary, rendered)
    return rendered


class SupportExportTests(unittest.TestCase):
    def test_support_export_requires_explicit_user_review(self) -> None:
        diagnostics = collect_unified_diagnostics(
            app_config={section: dict(values) for section, values in DEFAULT_CONFIG.items()},
            routing_state={},
            dns_policy=DNSPolicy(),
            resolver_inventory=None,
            providers=[],
            profiles=[],
            runtime_state=None,
            network_policy=NetworkContextPolicy(),
            network_observation=NetworkObservation(status=MonitorStatus.UNSUPPORTED),
            route_table_snapshot=None,
            which=lambda command: None,
        )

        with self.assertRaises(SupportExportReviewRequired):
            build_redacted_support_export(diagnostics)

    def test_support_export_redacts_seeded_operational_secrets(self) -> None:
        app_config = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
        app_config["lan_sharing"].update(
            {
                "enabled": True,
                "mode": "proxy",
                "bind_address": "198.51.100.99",
                "authentication_required": True,
            }
        )
        app_config["kill_switch"]["tunnel_interface"] = "wlan-canary0"
        dns_policy = DNSPolicy(
            channels={
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[
                        Resolver(
                            uri="https://canary.internal.example/dns-query"
                        )
                    ],
                )
            }
        )
        resolver_inventory = ResolverInventory(
            manager=ResolverManager.RESOLV_CONF,
            resolv_conf_path=Path("/tmp/canary-resolv.conf"),
            nameservers=["198.51.100.99", "2001:db8::216"],
            search_domains=["canary.internal.example"],
        )
        network_policy = NetworkContextPolicy(
            enabled=True,
            profiles=[
                NetworkProfile(
                    id="public-wifi",
                    label="Cafe Canary SSID",
                    trust="untrusted",
                    matches=[
                        NetworkMatch(
                            kind="raw_ssid",
                            value="Cafe Canary SSID",
                            explicit_consent=True,
                            consent_note="contains wdvpn_canary_secret_token_21_6",
                        )
                    ],
                )
            ],
            triggers={
                NetworkContextTrigger.UNTRUSTED_NETWORK: ActionIntent(
                    enabled=True,
                    action="connect",
                    explanation="Connect without exposing Cafe Canary SSID.",
                    disable_hint="Disable wdvpn_canary_secret_token_21_6 policy.",
                    reversible=True,
                    reversal="Return to manual mode.",
                )
            },
        )
        observation = NetworkObservation(
            status=MonitorStatus.OBSERVED,
            connectivity=ConnectivityState.ONLINE,
            active_networks=(
                ActiveNetwork(
                    source="test",
                    interface_name="wlan-canary0",
                    interface_type="wifi",
                    ssid="Cafe Canary SSID",
                    bssid="aa:bb:cc:dd:ee:ff",
                    gateway_identifier="canary-gateway-fingerprint",
                ),
            ),
            default_route_interfaces=("wlan-canary0",),
        )
        runner = FakeRunner(
            {
                ("ip", "-j", "route", "show", "table", "main"): completed(
                    ["ip"],
                    '[{"dst":"default","dev":"wlan-canary0","gateway":"198.51.100.99"}]',
                )
            }
        )

        diagnostics = collect_unified_diagnostics(
            app_config=app_config,
            routing_state={
                "routing_state_version": "1",
                "routing_policy": "global",
                "capture_modes": "local_proxy,tun",
                "default_route_action": "current",
                "active_mode": "tun",
            },
            dns_policy=dns_policy,
            resolver_inventory=resolver_inventory,
            providers=[
                Provider(
                    id="canary-provider-id-21-6",
                    name="Canary Provider Private",
                    url=(
                        "https://provider-canary.example/sub"
                        "?token=wdvpn_canary_secret_token_21_6"
                    ),
                    last_updated=datetime(2026, 7, 8, 12, 0, tzinfo=timezone.utc),
                    profiles=["profile-canary"],
                    metadata={
                        "traffic_used": "wdvpn_canary_secret_quota_21_6",
                        "traffic_limit": "10 GB",
                        "api_token": "wdvpn_canary_secret_token_21_6",
                    },
                )
            ],
            profiles=[
                Profile(
                    id="profile-canary",
                    name="Cafe Canary SSID",
                    protocol=ProtocolType.TROJAN,
                    config={
                        "host": "canary.internal.example",
                        "password": "wdvpn_canary_lan_password_21_6",
                    },
                    source=ProfileSource.SUBSCRIPTION,
                    provider_id="canary-provider-id-21-6",
                    enabled=True,
                    in_rotation_pool=True,
                    health_status="ok",
                )
            ],
            runtime_state=ConnectionState(
                active_profile_id="profile-canary",
                mode="sing-box",
                tun_active=True,
                proxy_active=True,
                kill_switch_active=True,
                lan_gateway_active=True,
                lan_gateway_interface="wlan-canary0",
                lan_gateway_client_cidr="10.66.77.0/24",
                lan_gateway_dns_mode="manual",
                lan_gateway_status="applied",
                status="connected",
            ),
            network_policy=network_policy,
            network_observation=observation,
            runner=runner,
            which=which_ip_only,
            recent_failure_categories=[
                "provider failure token=wdvpn_canary_secret_token_21_6",
            ],
        )

        export = build_redacted_support_export(diagnostics, user_reviewed=True).to_dict()
        rendered = assert_no_canaries(self, export)

        self.assertTrue(export["user_reviewed"])
        self.assertTrue(export["payload"]["support_export_ready"])
        self.assertFalse(export["redaction_guards"]["provider_urls_included"])
        self.assertIn("<redacted-provider-name>", rendered)
        self.assertIn("<redacted-interface>", rendered)
        self.assertIn("<redacted-secret>", rendered)
        self.assertIn("<redacted-cidr>", rendered)

    def test_recursive_redactor_catches_future_nested_secret_shapes(self) -> None:
        payload = {
            "provider": {
                "url": "https://provider-canary.example/sub?token=wdvpn_canary_secret_token_21_6",
                "metadata": {
                    "private_key": (
                        "-----BEGIN PRIVATE KEY-----\n"
                        "PRIVATEKEYCANARY216\n"
                        "-----END PRIVATE KEY-----"
                    ),
                },
            },
            "lan_credentials": {
                "username": "support-user",
                "password": "wdvpn_canary_lan_password_21_6",
            },
            "network": {
                "ssid": "Cafe Canary SSID",
                "bssid": "aa:bb:cc:dd:ee:ff",
                "interface_name": "wlan-canary0",
                "gateway_identifier": "canary-gateway-fingerprint",
                "client_cidr": "10.66.77.0/24",
                "public_ip": "2001:db8::216",
            },
            "notes": "Bearer wdvpn_canary_secret_token_21_6 at 198.51.100.99",
        }

        redacted = redact_support_payload(payload)
        rendered = assert_no_canaries(self, redacted)

        self.assertIn("<redacted-url>", rendered)
        self.assertIn("<redacted-credential>", rendered)
        self.assertIn("<redacted-private-key>", rendered)
        self.assertIn("<redacted-interface>", rendered)
        self.assertIn("<redacted-gateway>", rendered)


if __name__ == "__main__":
    unittest.main()
