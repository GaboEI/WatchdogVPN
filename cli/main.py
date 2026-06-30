from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

from config.profile_store import ProfileStore
from config.provider_store import ProviderLimitError, ProviderStore
from models.profile import Profile
from models.provider import Provider
from parsers import ParseError
from providers.manual_provider import ManualProvider
from providers.subscription_provider import ProviderNotFoundError, SubscriptionProvider


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
