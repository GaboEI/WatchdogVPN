from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app_policy.models import AppPolicy
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from diagnostics.chain_routes import (
    ChainDiagnosticStatus,
    diagnose_chain_route_action,
    diagnose_configured_chains,
)
from diagnostics.route_dns import diagnose_route_dns
from diagnostics.support_export import build_redacted_support_export
from diagnostics.unified import collect_unified_diagnostics
from dns.models import DNSChannel, DNSChannelName, DNSPolicy, Resolver
from models.profile import Profile, ProfileSource, ProtocolType
from node_groups.models import NodeGroup
from node_groups.store import NodeGroupStore
from route_chains.models import ChainHop, RouteChain, RouteChainDocument
from route_chains.runtime import ChainRuntimeResolver
from route_chains.store import RouteChainStore
from rules.models import Rule, RuleGroup
from rules.rule_engine import TrafficInfo


class ChainDiagnosticsTests(unittest.TestCase):
    def test_valid_profile_hop_chain_diagnostics_are_redacted_and_stable(self) -> None:
        with _stores() as stores:
            stores.profiles.add(_profile("secret-profile-token-1234567890abcdef"))
            document = RouteChainDocument(
                chains=[
                    RouteChain(
                        id="work-safe",
                        enabled=True,
                        description="sensitive local label",
                        hops=[
                            ChainHop(
                                type="profile",
                                target="secret-profile-token-1234567890abcdef",
                            )
                        ],
                    )
                ]
            )
            stores.chains.save(document)

            diagnostic = diagnose_chain_route_action(
                "chain:work-safe",
                chain_document=document,
                dns_policy=_dns_policy(),
                resolver=stores.resolver,
                config={},
            )

            data = diagnostic.to_dict()
            self.assertEqual(data["chain_id"], "work-safe")
            self.assertEqual(data["status"], "resolved")
            self.assertEqual(data["confidence"], "predicted")
            self.assertEqual(data["route_action_status"], "applies")
            self.assertEqual(data["dns_path_status"], "chain-owned")
            self.assertEqual(data["hop_order"][0]["hop_type"], "profile")
            self.assertEqual(data["hop_order"][0]["target"], "<redacted-profile-target>")
            self.assertNotIn("secret-profile-token", json.dumps(data))
            human = "\n".join(diagnostic.to_human_lines())
            self.assertIn("confidence: predicted", human)
            self.assertIn("live observation: not-observed", human)
            self.assertIn("vm validation: not-claimed", human)
            self.assertNotIn("secret-profile-token", human)

    def test_valid_group_hop_chain_diagnostics_show_safe_hop_order(self) -> None:
        with _stores() as stores:
            stores.profiles.add(_profile("selected-profile"))
            stores.groups.add(NodeGroup(name="private-group", member_profile_ids=["selected-profile"]))
            document = RouteChainDocument(
                chains=[
                    RouteChain(
                        id="work-safe",
                        enabled=True,
                        hops=[ChainHop(type="group", target="private-group")],
                    )
                ]
            )

            diagnostic = diagnose_chain_route_action(
                "chain:work-safe",
                chain_document=document,
                dns_policy=_dns_policy(),
                resolver=stores.resolver,
                config={},
            )

            data = diagnostic.to_dict()
            self.assertEqual(data["hop_order"][0]["index"], 1)
            self.assertEqual(data["hop_order"][0]["hop_type"], "group")
            self.assertEqual(data["hop_order"][0]["target"], "<redacted-group-target>")
            self.assertNotIn("private-group", json.dumps(data))

    def test_missing_disabled_missing_hop_empty_group_and_dns_unavailable(self) -> None:
        with _stores() as stores:
            stores.groups.add(NodeGroup(name="empty", member_profile_ids=[]))
            document = RouteChainDocument(
                chains=[
                    RouteChain(
                        id="disabled",
                        enabled=False,
                        hops=[ChainHop(type="profile", target="p1")],
                    ),
                    RouteChain(
                        id="missing-profile",
                        enabled=True,
                        hops=[ChainHop(type="profile", target="missing-profile")],
                    ),
                    RouteChain(
                        id="missing-group",
                        enabled=True,
                        hops=[ChainHop(type="group", target="missing-group")],
                    ),
                    RouteChain(
                        id="empty-group",
                        enabled=True,
                        hops=[ChainHop(type="group", target="empty")],
                    ),
                    RouteChain(
                        id="dns-down",
                        enabled=True,
                        hops=[ChainHop(type="profile", target="p2")],
                    ),
                ]
            )
            stores.profiles.add(_profile("p2"))

            cases = {
                "chain:missing": ("missing", ChainDiagnosticStatus.UNKNOWN.value, "missing_chain"),
                "chain:disabled": ("disabled", ChainDiagnosticStatus.UNAVAILABLE.value, "disabled_chain"),
                "chain:missing-profile": (
                    "missing-profile",
                    ChainDiagnosticStatus.PARTIAL.value,
                    "missing_profile",
                ),
                "chain:missing-group": (
                    "missing-group",
                    ChainDiagnosticStatus.PARTIAL.value,
                    "missing_group",
                ),
                "chain:empty-group": (
                    "empty-group",
                    ChainDiagnosticStatus.PARTIAL.value,
                    "empty_group_resolution",
                ),
            }
            for action, (_, status, reason) in cases.items():
                diagnostic = diagnose_chain_route_action(
                    action,
                    chain_document=document,
                    dns_policy=_dns_policy(),
                    resolver=stores.resolver,
                    config={},
                )
                data = diagnostic.to_dict()
                self.assertEqual(data["status"], status)
                self.assertEqual(data["confidence"], status)
                self.assertEqual(data["failure_reason"], reason)
                self.assertTrue(data["route_action_status"].startswith("fail-closed"))

            dns_down = diagnose_chain_route_action(
                "chain:dns-down",
                chain_document=document,
                dns_policy=DNSPolicy(),
                resolver=stores.resolver,
                config={},
            ).to_dict()
            self.assertEqual(dns_down["dns_path_status"], "unavailable")
            self.assertEqual(dns_down["failure_reason"], "dns_path_unavailable")

    def test_route_dns_and_unified_include_chain_diagnostics(self) -> None:
        with _stores() as stores:
            stores.profiles.add(_profile("profile-one"))
            document = RouteChainDocument(
                chains=[
                    RouteChain(
                        id="work-safe",
                        enabled=True,
                        hops=[ChainHop(type="profile", target="profile-one")],
                    )
                ]
            )
            group = RuleGroup(
                name="custom",
                rules=[
                    Rule(
                        id="chain",
                        action="chain:work-safe",
                        conditions={"domain": ["example.com"]},
                    )
                ],
            )
            chain_diag = diagnose_chain_route_action(
                "chain:work-safe",
                chain_document=document,
                dns_policy=_dns_policy(),
                resolver=stores.resolver,
                config={},
            )

            route_dns = diagnose_route_dns(
                traffic=TrafficInfo(domain="example.com"),
                rule_groups=[group],
                dns_policy=_dns_policy(),
                chain_diagnostic=chain_diag,
            ).to_dict()
            unified = collect_unified_diagnostics(
                app_config={},
                routing_state={
                    "routing_state_version": "1",
                    "routing_policy": "rule",
                    "capture_modes": "local_proxy",
                    "default_route_action": "current",
                },
                dns_policy=_dns_policy(),
                resolver_inventory=None,
                providers=[],
                profiles=[],
                rule_groups=[group],
                app_policy=AppPolicy(),
                chain_document=document,
                chain_resolver=stores.resolver,
                network_policy=None,
                network_observation=None,
                network_decision=None,
                route_table_snapshot=None,
                exit_ip=None,
                runner=_fake_runner,
                which=lambda _name: None,
            ).to_dict()

            self.assertEqual(route_dns["chain"]["chain_id"], "work-safe")
            self.assertEqual(route_dns["dns"]["path"], "tunnel-or-fakeip")
            self.assertEqual(
                unified["routing"]["chain_diagnostics"]["matched_chain_id"],
                None,
            )
            self.assertEqual(unified["routing"]["chain_diagnostics"]["items"][0]["chain_id"], "work-safe")

    def test_support_export_redacts_chain_diagnostics_canaries(self) -> None:
        with _stores() as stores:
            stores.profiles.add(_profile("secret-profile-token-1234567890abcdef"))
            document = RouteChainDocument(
                chains=[
                    RouteChain(
                        id="work-safe",
                        enabled=True,
                        hops=[
                            ChainHop(
                                type="profile",
                                target="secret-profile-token-1234567890abcdef",
                            )
                        ],
                    )
                ]
            )
            diagnostics = collect_unified_diagnostics(
                app_config={},
                routing_state={
                    "routing_state_version": "1",
                    "routing_policy": "global",
                    "capture_modes": "local_proxy",
                    "default_route_action": "chain:work-safe",
                },
                dns_policy=_dns_policy(),
                resolver_inventory=None,
                providers=[],
                profiles=[],
                rule_groups=[],
                app_policy=AppPolicy(),
                chain_document=document,
                chain_resolver=stores.resolver,
                network_policy=None,
                network_observation=None,
                network_decision=None,
                route_table_snapshot=None,
                exit_ip=None,
                runner=_fake_runner,
                which=lambda _name: None,
            )

            export = build_redacted_support_export(diagnostics, user_reviewed=True).to_dict()
            text = json.dumps(export)

            self.assertIn("work-safe", text)
            self.assertNotIn("secret-profile-token", text)
            self.assertNotIn("watchdogvpn-chain-work-safe-hop-1", text)


class _Stores:
    def __enter__(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        root = Path(self.tmpdir.name)
        self.profiles = ProfileStore(root / "profiles.json")
        self.providers = ProviderStore(root / "providers.json")
        self.groups = NodeGroupStore(root / "node_groups.json")
        self.chains = RouteChainStore(root / "chains.json")
        self.resolver = ChainRuntimeResolver(
            chain_store=self.chains,
            profile_store=self.profiles,
            node_group_store=self.groups,
            provider_store=self.providers,
        )
        return self

    def __exit__(self, exc_type, exc, tb):
        self.tmpdir.cleanup()


def _stores() -> _Stores:
    return _Stores()


def _profile(profile_id: str) -> Profile:
    return Profile(
        id=profile_id,
        name=profile_id,
        protocol=ProtocolType.VLESS,
        config={"host": f"{profile_id}.example", "port": 443, "uuid": profile_id},
        source=ProfileSource.MANUAL,
    )


def _dns_policy() -> DNSPolicy:
    return DNSPolicy(
        channels={
            DNSChannelName.PROXY: DNSChannel(
                name=DNSChannelName.PROXY,
                resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
            )
        }
    )


def _fake_runner(*args, **kwargs):
    raise OSError("not available")


if __name__ == "__main__":
    unittest.main()
