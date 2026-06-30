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
from models.profile import Profile
from parsers import ParseError
from providers.manual_provider import ManualProvider


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 0
    try:
        return int(args.handler(args))
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


def _require_profile(store: ProfileStore, profile_id: str) -> Profile:
    profile = store.get(profile_id)
    if profile is None:
        raise ParseError(f"profile not found: {profile_id}")
    return profile


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


def _prompt_rotation_pool(profile: Profile) -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input(f"Add profile '{profile.name}' to the rotation pool? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def _on_off(value: bool) -> str:
    return "on" if value else "off"


def _error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _exit() -> NoReturn:
    raise SystemExit(main())


if __name__ == "__main__":
    _exit()
