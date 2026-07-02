from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

from config.dns_policy_store import DNSPolicyStore
from config.persistence import PersistentStoreError
from config.profile_store import ProfileStore
from config.provider_store import ProviderLimitError, ProviderStore
from config.state_manager import ALLOWED_ACTIVE_MODES, StateManager
from dns.hijack import DNSHijackController, DNSHijackError
from dns.models import DNSChannelName, DNSMode, DNSPolicy
from dns.resolver_inventory import detect_resolver_manager
from dns.state_manager import (
    DNSStateError,
    DNSStateSnapshot,
    LocalDNSEntryPoint,
    SystemDNSStateManager,
)
from dns.tester import DNSTester
from models.profile import Profile
from models.provider import Provider
from parsers import ParseError
from providers.manual_provider import ManualProvider
from providers.subscription_provider import ProviderNotFoundError, SubscriptionProvider


DEFAULT_DNS_SNAPSHOT_FILE = Path.home() / ".config" / "watchdogvpn" / "dns-state.json"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 0
    try:
        return int(args.handler(args))
    except (ProviderLimitError, ProviderNotFoundError) as exc:
        _error(str(exc))
        return 65
    except ParseError as exc:
        _error(str(exc))
        return 65
    except FileNotFoundError as exc:
        _error(str(exc))
        return 66
    except PersistentStoreError as exc:
        _error(str(exc))
        return 70
    except (DNSHijackError, DNSStateError, OSError, ValueError) as exc:
        _error(str(exc))
        return 70


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchdog", description="WatchdogVPN command line")
    subparsers = parser.add_subparsers(dest="command")

    profile_parser = subparsers.add_parser("profile", help="Manage local profiles")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command")

    add_parser = profile_subparsers.add_parser("add", help="Add a manual profile")
    add_source = add_parser.add_mutually_exclusive_group(required=True)
    add_source.add_argument("--clipboard", action="store_true", help="Read profile content from clipboard")
    add_source.add_argument("--uri", help="Import one profile URI")
    add_source.add_argument("--file", help="Import profile content from file")
    add_source.add_argument("--text", action="store_true", help="Read profile content from stdin or editor")
    add_parser.set_defaults(handler=_profile_add)

    list_parser = profile_subparsers.add_parser("list", help="List saved profiles")
    list_parser.add_argument("--json", action="store_true", help="Print JSON")
    list_parser.add_argument("--pool", action="store_true", help="Show rotation pool only")
    list_parser.set_defaults(handler=_profile_list)

    remove_parser = profile_subparsers.add_parser("remove", help="Remove a saved profile")
    remove_parser.add_argument("profile_id")
    remove_parser.set_defaults(handler=_profile_remove)

    enable_parser = profile_subparsers.add_parser("enable", help="Enable a saved profile")
    enable_parser.add_argument("profile_id")
    enable_parser.set_defaults(handler=_profile_set_enabled)
    enable_parser.set_defaults(enabled=True)

    disable_parser = profile_subparsers.add_parser("disable", help="Disable a saved profile")
    disable_parser.add_argument("profile_id")
    disable_parser.set_defaults(handler=_profile_set_enabled)
    disable_parser.set_defaults(enabled=False)

    rotation_parser = profile_subparsers.add_parser("rotation", help="Change profile rotation-pool membership")
    rotation_parser.add_argument("profile_id")
    rotation_group = rotation_parser.add_mutually_exclusive_group(required=True)
    rotation_group.add_argument("--enable", action="store_true", help="Add profile to rotation pool")
    rotation_group.add_argument("--disable", action="store_true", help="Remove profile from rotation pool")
    rotation_parser.set_defaults(handler=_profile_rotation)

    provider_parser = subparsers.add_parser("provider", help="Manage external providers")
    provider_subparsers = provider_parser.add_subparsers(dest="provider_command")

    provider_add_parser = provider_subparsers.add_parser("add", help="Add an external provider")
    provider_add_parser.add_argument("url", nargs="?", help="External provider subscription URL")
    provider_add_parser.add_argument("--name", help="Free-form provider label")
    provider_add_parser.set_defaults(handler=_provider_add)

    provider_list_parser = provider_subparsers.add_parser("list", help="List external providers")
    provider_list_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_list_parser.set_defaults(handler=_provider_list)

    provider_stats_parser = provider_subparsers.add_parser("stats", help="Show provider statistics")
    provider_stats_parser.add_argument("provider_id")
    provider_stats_parser.add_argument("--json", action="store_true", help="Print JSON")
    provider_stats_parser.set_defaults(handler=_provider_stats)

    provider_update_parser = provider_subparsers.add_parser("update", help="Update provider nodes")
    provider_update_target = provider_update_parser.add_mutually_exclusive_group(required=True)
    provider_update_target.add_argument("provider_id", nargs="?", help="Provider ID")
    provider_update_target.add_argument("--all", action="store_true", help="Update all providers")
    provider_update_parser.set_defaults(handler=_provider_update)

    provider_remove_parser = provider_subparsers.add_parser("remove", help="Remove provider and owned nodes")
    provider_remove_parser.add_argument("provider_id")
    provider_remove_parser.set_defaults(handler=_provider_remove)

    provider_edit_parser = provider_subparsers.add_parser("edit", help="Edit provider metadata")
    provider_edit_parser.add_argument("provider_id")
    provider_edit_parser.add_argument("--name", help="New free-form provider label")
    provider_edit_parser.add_argument("--url", help="New subscription URL")
    provider_edit_parser.set_defaults(handler=_provider_edit)

    provider_rotation_parser = provider_subparsers.add_parser("rotation", help="Enable or disable provider rotation")
    provider_rotation_parser.add_argument("provider_id")
    provider_rotation_group = provider_rotation_parser.add_mutually_exclusive_group(required=True)
    provider_rotation_group.add_argument("--enable", action="store_true", help="Enable provider rotation")
    provider_rotation_group.add_argument("--disable", action="store_true", help="Disable provider rotation")
    provider_rotation_parser.set_defaults(handler=_provider_rotation)

    provider_node_parser = provider_subparsers.add_parser("node", help="Change provider node settings")
    provider_node_parser.add_argument("provider_id")
    provider_node_parser.add_argument("node_id")
    provider_node_parser.add_argument("--rotation", action="store_true", required=True)
    provider_node_group = provider_node_parser.add_mutually_exclusive_group(required=True)
    provider_node_group.add_argument("--enable", action="store_true", help="Enable node rotation")
    provider_node_group.add_argument("--disable", action="store_true", help="Disable node rotation")
    provider_node_parser.set_defaults(handler=_provider_node)

    dns_parser = subparsers.add_parser("dns", help="Manage DNS v2 policy and state")
    dns_subparsers = dns_parser.add_subparsers(dest="dns_command")

    dns_status_parser = dns_subparsers.add_parser("status", help="Show DNS v2 status")
    _add_dns_common_paths(dns_status_parser)
    dns_status_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_status_parser.set_defaults(handler=_dns_status)

    dns_test_parser = dns_subparsers.add_parser("test", help="Test DNS v2 resolvers")
    _add_dns_common_paths(dns_test_parser, include_resolv_conf=False, include_snapshot=False)
    dns_test_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_test_parser.add_argument("--auto", action="store_true", help="Test default auto setup candidates")
    dns_test_parser.add_argument("--domain", help="Override the policy test domain")
    dns_test_parser.add_argument("--timeout", type=float, default=3.0, help="Resolver probe timeout in seconds")
    dns_test_parser.set_defaults(handler=_dns_test)

    dns_apply_parser = dns_subparsers.add_parser("apply", help="Apply DNS v2 local entrypoint")
    _add_dns_common_paths(dns_apply_parser)
    dns_apply_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_apply_parser.add_argument("--dry-run", action="store_true", help="Print the apply plan without changing DNS")
    dns_apply_parser.add_argument("--yes", action="store_true", help="Confirm system DNS mutation")
    dns_apply_parser.add_argument("--systemd-link", help="systemd-resolved link name, for example tun0")
    dns_apply_parser.add_argument("--entrypoint-address", default="127.0.0.1", help="Local DNS entrypoint address")
    dns_apply_parser.add_argument("--entrypoint-port", type=int, default=53, help="Local DNS entrypoint port")
    dns_apply_parser.add_argument(
        "--skip-entrypoint-check",
        action="store_true",
        help="Skip local DNS entrypoint reachability check",
    )
    dns_apply_parser.add_argument(
        "--entrypoint-timeout",
        type=float,
        default=1.0,
        help="Local DNS entrypoint TCP check timeout in seconds",
    )
    dns_apply_parser.set_defaults(handler=_dns_apply)

    dns_reset_parser = dns_subparsers.add_parser("reset", help="Restore DNS from the saved v2 snapshot")
    _add_dns_common_paths(dns_reset_parser)
    dns_reset_parser.add_argument("--json", action="store_true", help="Print JSON")
    dns_reset_parser.add_argument("--yes", action="store_true", help="Confirm DNS restore")
    dns_reset_parser.set_defaults(handler=_dns_reset)

    config_parser = subparsers.add_parser("config", help="Manage WatchdogVPN connection mode")
    config_subparsers = config_parser.add_subparsers(dest="config_command")

    config_set_parser = config_subparsers.add_parser("set", help="Set a configuration value")
    config_set_subparsers = config_set_parser.add_subparsers(dest="config_set_target")

    config_set_mode_parser = config_set_subparsers.add_parser(
        "mode", help="Set the active connection mode"
    )
    config_set_mode_parser.add_argument(
        "mode", choices=sorted(ALLOWED_ACTIVE_MODES), help="New connection mode"
    )
    config_set_mode_parser.add_argument("--json", action="store_true", help="Print JSON")
    config_set_mode_parser.set_defaults(handler=_config_set_mode)

    return parser


def _profile_add(args: argparse.Namespace) -> int:
    provider = ManualProvider(rotation_prompt=_prompt_rotation_pool)
    if args.clipboard:
        profile = provider.from_clipboard()
        if profile is None:
            _error("clipboard does not contain supported profile content")
            return 66
    elif args.uri:
        profile = provider.from_uri(args.uri)
    elif args.file:
        profile = provider.from_file(args.file)
    elif args.text:
        profile = provider.from_text(_read_text_input())
    else:
        raise AssertionError("unreachable profile add source")

    imported = provider.last_imported or [profile]
    print(f"Imported {len(imported)} profile(s).")
    for item in imported:
        print(f"{item.id}\t{item.protocol.value}\t{item.name}\trotation={_on_off(item.in_rotation_pool)}")
    return 0


def _profile_list(args: argparse.Namespace) -> int:
    store = ProfileStore()
    profiles = store.get_rotation_pool() if args.pool else store.list()
    if args.json:
        print(json.dumps([profile.to_dict() for profile in profiles], indent=2, sort_keys=True))
        return 0
    if not profiles:
        print("No profiles found.")
        return 0
    print("ID\tProtocol\tSource\tEnabled\tRotation\tHealth\tName")
    for profile in profiles:
        print(
            "\t".join(
                [
                    profile.id,
                    profile.protocol.value,
                    profile.source.value,
                    _on_off(profile.enabled),
                    _on_off(profile.in_rotation_pool),
                    profile.health_status,
                    profile.name,
                ]
            )
        )
    return 0


def _profile_remove(args: argparse.Namespace) -> int:
    store = ProfileStore()
    profile = _require_profile(store, args.profile_id)
    store.remove(profile.id)
    print(f"Removed profile: {profile.id}")
    return 0


def _profile_set_enabled(args: argparse.Namespace) -> int:
    store = ProfileStore()
    profile = _require_profile(store, args.profile_id)
    profile.enabled = bool(args.enabled)
    store.update(profile)
    state = "enabled" if profile.enabled else "disabled"
    print(f"Profile {state}: {profile.id}")
    return 0


def _profile_rotation(args: argparse.Namespace) -> int:
    store = ProfileStore()
    profile = _require_profile(store, args.profile_id)
    profile.in_rotation_pool = bool(args.enable)
    store.update(profile)
    state = "enabled" if profile.in_rotation_pool else "disabled"
    print(f"Profile rotation {state}: {profile.id}")
    return 0


def _provider_add(args: argparse.Namespace) -> int:
    url = args.url or _prompt_required("Provider URL")
    name = args.name if args.name is not None else _prompt_optional("Provider name")
    provider = SubscriptionProvider().add(url, name)
    print(f"Added provider: {provider.id}")
    print(f"Name: {provider.name}")
    print(f"Profiles: {len(provider.profiles)}")
    return 0


def _provider_list(args: argparse.Namespace) -> int:
    providers = ProviderStore().list()
    summaries = [_provider_summary(provider) for provider in providers]
    if args.json:
        print(json.dumps(summaries, indent=2, sort_keys=True))
        return 0
    if not summaries:
        print("No providers found.")
        return 0
    print("ID\tName\tEnabled\tNodes\tLast update\tTraffic\tExpires")
    for summary in summaries:
        print(
            "\t".join(
                [
                    summary["id"],
                    summary["name"],
                    _on_off(bool(summary["rotation_enabled"])),
                    str(summary["node_count"]),
                    str(summary["last_updated"] or "-"),
                    str(summary["traffic"] or "-"),
                    str(summary["expires_at"] or "-"),
                ]
            )
        )
    return 0


def _provider_stats(args: argparse.Namespace) -> int:
    provider = _require_provider(ProviderStore(), args.provider_id)
    summary = _provider_summary(provider)
    profiles = [
        profile
        for profile in ProfileStore().list()
        if profile.provider_id == provider.id
    ]
    protocols: dict[str, int] = {}
    enabled_nodes = 0
    rotation_nodes = 0
    for profile in profiles:
        protocols[profile.protocol.value] = protocols.get(profile.protocol.value, 0) + 1
        enabled_nodes += 1 if profile.enabled else 0
        rotation_nodes += 1 if profile.in_rotation_pool else 0
    data = {
        **summary,
        "enabled_nodes": enabled_nodes,
        "rotation_nodes": rotation_nodes,
        "protocols": protocols,
    }
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0
    print(f"Provider: {provider.id}")
    print(f"Name: {provider.name}")
    print(f"URL: {_redact_url(provider.url)}")
    print(f"Rotation: {_on_off(provider.rotation_enabled)}")
    print(f"Nodes: {len(profiles)}")
    print(f"Enabled nodes: {enabled_nodes}")
    print(f"Rotation nodes: {rotation_nodes}")
    print(f"Last update: {provider.last_updated.isoformat() if provider.last_updated else '-'}")
    print(f"Traffic: {summary['traffic'] or '-'}")
    print(f"Expires: {summary['expires_at'] or '-'}")
    print(f"Protocols: {', '.join(f'{key}={value}' for key, value in sorted(protocols.items())) or '-'}")
    return 0


def _provider_update(args: argparse.Namespace) -> int:
    provider = SubscriptionProvider()
    if args.all:
        results = provider.update_all()
        for provider_id, result in results.items():
            print(f"{provider_id}\t{result}")
        return 0
    changes = provider.update(args.provider_id)
    print(f"Provider updated: {args.provider_id} changes={changes}")
    return 0


def _provider_remove(args: argparse.Namespace) -> int:
    _require_provider(ProviderStore(), args.provider_id)
    SubscriptionProvider().remove(args.provider_id)
    print(f"Removed provider: {args.provider_id}")
    return 0


def _provider_edit(args: argparse.Namespace) -> int:
    if args.name is None and args.url is None:
        raise ParseError("provider edit requires --name or --url")
    provider_store = ProviderStore()
    provider = _require_provider(provider_store, args.provider_id)
    if args.name is not None:
        provider.name = args.name
    if args.url is not None:
        provider.url = args.url
    provider_store.update(provider)
    print(f"Updated provider: {provider.id}")
    print(f"Name: {provider.name}")
    print(f"URL: {_redact_url(provider.url)}")
    return 0


def _provider_rotation(args: argparse.Namespace) -> int:
    provider_store = ProviderStore()
    provider = _require_provider(provider_store, args.provider_id)
    provider.rotation_enabled = bool(args.enable)
    provider_store.update(provider)
    state = "enabled" if provider.rotation_enabled else "disabled"
    print(f"Provider rotation {state}: {provider.id}")
    return 0


def _provider_node(args: argparse.Namespace) -> int:
    provider = _require_provider(ProviderStore(), args.provider_id)
    profile_store = ProfileStore()
    profile = _require_profile(profile_store, args.node_id)
    if profile.provider_id != provider.id:
        raise ParseError(f"node does not belong to provider: {args.node_id}")
    profile.in_rotation_pool = bool(args.enable)
    profile_store.update(profile)
    state = "enabled" if profile.in_rotation_pool else "disabled"
    print(f"Provider node rotation {state}: {profile.id}")
    return 0


def _config_set_mode(args: argparse.Namespace) -> int:
    manager = StateManager()
    manager.set("active_mode", args.mode)
    data = {"active_mode": args.mode}
    if args.json:
        _print_json(data)
    else:
        print(f"Active mode set to: {args.mode}")
    return 0


def _dns_status(args: argparse.Namespace) -> int:
    policy = _load_dns_policy(args)
    inventory = detect_resolver_manager(resolv_conf_path=Path(args.resolv_conf_path))
    data = _dns_status_data(policy, inventory.to_dict(), _dns_snapshot_path(args))
    if args.json:
        _print_json(data)
        return 0
    print(f"DNS mode: {policy.mode.value}")
    print(f"TUN hijack: {_on_off(policy.tun_hijack)}")
    print(f"Resolver manager: {data['resolver_manager']['manager']}")
    print(f"Nameservers: {', '.join(data['resolver_manager']['nameservers']) or '-'}")
    print(f"Channels: {data['channels']['configured']}/{data['channels']['total']}")
    print(f"Static IP: {_on_off(policy.static_ip_enabled)} ({len(policy.static_ips)} entries)")
    print(f"Rules: {_on_off(policy.rules_enabled)} ({len(policy.rules)} rules)")
    print(f"FakeIP: {policy.fakeip_inet4_range}, {policy.fakeip_inet6_range}")
    print(f"ECS direct: {_on_off(policy.ecs_direct_enabled)}")
    print(f"Snapshot: {data['snapshot']['path']} ({data['snapshot']['status']})")
    return 0


def _dns_test(args: argparse.Namespace) -> int:
    policy = _load_dns_policy(args)
    domain = args.domain or policy.test_domain
    tester = DNSTester(timeout=args.timeout)
    if args.auto or not policy.channels:
        recommendation = tester.recommend_auto_setup(test_domain=domain)
        data: dict[str, object] = {
            "mode": "auto",
            "test_domain": domain,
            "recommendation": recommendation.to_dict(),
        }
    else:
        channel_results = {
            name.value: tester.test_channel(channel, domain).to_dict()
            for name, channel in sorted(policy.channels.items(), key=lambda item: item[0].value)
        }
        data = {
            "mode": policy.mode.value,
            "test_domain": domain,
            "channel_results": channel_results,
        }
    if args.json:
        _print_json(data)
        return 0
    print(f"DNS test domain: {domain}")
    for channel, result in _dns_channel_results(data).items():
        ok_count = sum(1 for item in result["results"] if item["ok"])
        total = len(result["results"])
        print(f"{channel}: {ok_count}/{total} resolver(s) passed")
    return 0


def _dns_apply(args: argparse.Namespace) -> int:
    policy = _load_dns_policy(args)
    snapshot_path = _dns_snapshot_path(args)
    entrypoint = LocalDNSEntryPoint(
        address=args.entrypoint_address,
        port=int(args.entrypoint_port),
        systemd_link=args.systemd_link,
    )
    inventory = detect_resolver_manager(resolv_conf_path=Path(args.resolv_conf_path))
    plan = {
        "policy_mode": policy.mode.value,
        "tun_hijack": policy.tun_hijack,
        "resolver_manager": inventory.to_dict(),
        "entrypoint": {
            "address": entrypoint.address,
            "port": entrypoint.port,
            "systemd_link": entrypoint.systemd_link,
        },
        "snapshot_path": str(snapshot_path),
        "would_apply": policy.mode != DNSMode.OFF and policy.tun_hijack,
        "rollback_plan": "restore saved DNS state from snapshot",
    }
    if args.dry_run:
        return _dns_apply_output(args, {**plan, "status": "dry-run"})
    if not args.yes:
        raise ParseError("dns apply requires --yes or --dry-run")
    if plan["would_apply"] and not args.skip_entrypoint_check:
        _require_dns_entrypoint(entrypoint, timeout=float(args.entrypoint_timeout))

    manager = SystemDNSStateManager(resolv_conf_path=Path(args.resolv_conf_path))
    controller = DNSHijackController(manager, entrypoint=entrypoint)
    result = controller.apply(policy, systemd_link=args.systemd_link)
    if result.snapshot is not None:
        _save_dns_snapshot(snapshot_path, result.snapshot)
    data = {
        **plan,
        "status": "applied" if result.applied else "skipped",
        "reason": result.reason,
        "snapshot_saved": result.snapshot is not None,
    }
    return _dns_apply_output(args, data)


def _dns_reset(args: argparse.Namespace) -> int:
    if not args.yes:
        raise ParseError("dns reset requires --yes")
    snapshot_path = _dns_snapshot_path(args)
    snapshot = _load_dns_snapshot(snapshot_path)
    manager = SystemDNSStateManager(resolv_conf_path=Path(args.resolv_conf_path))
    manager.restore_state(snapshot)
    try:
        snapshot_path.unlink()
    except FileNotFoundError:
        pass
    data = {
        "status": "restored",
        "snapshot_path": str(snapshot_path),
        "resolver_manager": snapshot.inventory.manager.value,
    }
    if args.json:
        _print_json(data)
    else:
        print("DNS state restored.")
        print(f"Snapshot: {snapshot_path}")
    return 0


def _add_dns_common_paths(
    parser: argparse.ArgumentParser,
    include_resolv_conf: bool = True,
    include_snapshot: bool = True,
) -> None:
    parser.add_argument("--policy-file", help="DNS policy JSON file")
    if include_snapshot:
        parser.add_argument("--snapshot-file", help="DNS state snapshot JSON file")
    if include_resolv_conf:
        parser.add_argument("--resolv-conf-path", default="/etc/resolv.conf", help="resolv.conf path")


def _load_dns_policy(args: argparse.Namespace) -> DNSPolicy:
    path = Path(args.policy_file) if getattr(args, "policy_file", None) else None
    return DNSPolicyStore(path).load()


def _dns_snapshot_path(args: argparse.Namespace) -> Path:
    if getattr(args, "snapshot_file", None):
        return Path(args.snapshot_file)
    return Path(os.environ.get("WATCHDOGVPN_DNS_SNAPSHOT_FILE", DEFAULT_DNS_SNAPSHOT_FILE))


def _dns_status_data(
    policy: DNSPolicy,
    resolver_manager: dict[str, object],
    snapshot_path: Path,
) -> dict[str, object]:
    return {
        "policy": policy.to_dict(),
        "resolver_manager": resolver_manager,
        "channels": {
            "configured": len(policy.channels),
            "total": len(DNSChannelName),
            "names": sorted(name.value for name in policy.channels),
        },
        "features": {
            "tun_hijack": policy.tun_hijack,
            "resolve_inbound_domains": policy.resolve_inbound_domains,
            "static_ip_enabled": policy.static_ip_enabled,
            "rules_enabled": policy.rules_enabled,
            "ecs_direct_enabled": policy.ecs_direct_enabled,
            "proxy_resolution_channel": policy.proxy_resolution_channel,
        },
        "snapshot": {
            "path": str(snapshot_path),
            "status": "present" if snapshot_path.exists() else "missing",
        },
    }


def _dns_channel_results(data: dict[str, object]) -> dict[str, dict]:
    if "channel_results" in data:
        return dict(data["channel_results"])
    recommendation = data.get("recommendation", {})
    if not isinstance(recommendation, dict):
        return {}
    return dict(recommendation.get("channel_results", {}))


def _dns_apply_output(args: argparse.Namespace, data: dict[str, object]) -> int:
    if args.json:
        _print_json(data)
    else:
        print(f"DNS apply status: {data['status']}")
        print(f"Policy mode: {data['policy_mode']}")
        print(f"Would apply: {_on_off(bool(data['would_apply']))}")
        print(f"Entrypoint: {data['entrypoint']['address']}:{data['entrypoint']['port']}")
        print(f"Snapshot: {data['snapshot_path']}")
        if data.get("reason"):
            print(f"Reason: {data['reason']}")
    return 0


def _require_dns_entrypoint(entrypoint: LocalDNSEntryPoint, timeout: float) -> None:
    try:
        with socket.create_connection((entrypoint.address, entrypoint.port), timeout=timeout):
            return
    except OSError as exc:
        raise DNSStateError(
            "local DNS entrypoint is not reachable; start the DNS runtime first "
            "or use --dry-run"
        ) from exc


def _save_dns_snapshot(path: Path, snapshot: DNSStateSnapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(snapshot.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_dns_snapshot(path: Path) -> DNSStateSnapshot:
    if not path.exists():
        raise FileNotFoundError(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("dns snapshot file must contain a JSON object")
    return DNSStateSnapshot.from_dict(data)


def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _require_profile(store: ProfileStore, profile_id: str) -> Profile:
    profile = store.get(profile_id)
    if profile is None:
        raise ParseError(f"profile not found: {profile_id}")
    return profile


def _require_provider(store: ProviderStore, provider_id: str) -> Provider:
    provider = store.get(provider_id)
    if provider is None:
        raise ProviderNotFoundError(f"provider not found: {provider_id}")
    return provider


def _provider_summary(provider: Provider) -> dict:
    metadata = provider.metadata or {}
    return {
        "id": provider.id,
        "name": provider.name,
        "url": _redact_url(provider.url),
        "rotation_enabled": provider.rotation_enabled,
        "node_count": len(provider.profiles),
        "last_updated": provider.last_updated.isoformat() if provider.last_updated else None,
        "traffic": _traffic_label(metadata),
        "expires_at": metadata.get("expires_at") or metadata.get("expire") or metadata.get("expires"),
        "metadata": metadata,
    }


def _traffic_label(metadata: dict) -> str:
    used = metadata.get("traffic_used") or metadata.get("used")
    total = metadata.get("traffic_limit") or metadata.get("total")
    if used is not None and total is not None:
        return f"{used}/{total}"
    if used is not None:
        return str(used)
    return ""


def _read_text_input() -> str:
    if not sys.stdin.isatty():
        content = sys.stdin.read()
        if content.strip():
            return content
    editor = os.environ.get("EDITOR")
    if not editor:
        raise ParseError("profile add --text requires stdin content or EDITOR")
    with tempfile.NamedTemporaryFile("w+", suffix=".txt", encoding="utf-8") as temp:
        subprocess.run([editor, temp.name], check=False)
        temp.seek(0)
        content = temp.read()
    if not content.strip():
        raise ParseError("profile text input is empty")
    return content


def _prompt_required(label: str) -> str:
    if not sys.stdin.isatty():
        raise ParseError(f"{label} is required")
    value = input(f"{label}: ").strip()
    if not value:
        raise ParseError(f"{label} is required")
    return value


def _prompt_optional(label: str) -> str:
    if not sys.stdin.isatty():
        return ""
    return input(f"{label}: ").strip()


def _prompt_rotation_pool(profile: Profile) -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input(f"Add profile '{profile.name}' to the rotation pool? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def _on_off(value: bool) -> str:
    return "on" if value else "off"


def _redact_url(url: str) -> str:
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    host = rest.split("/", 1)[0]
    return f"{scheme}://{host}/<redacted>"


def _error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _exit() -> NoReturn:
    raise SystemExit(main())


if __name__ == "__main__":
    _exit()
