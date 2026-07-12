from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path

from config.profile_store import ProfileStore
from models.profile import Profile, ProfileSource, ProtocolType, profile_fingerprint
from parsers import (
    ParseError,
    is_amneziavpn_format,
    parse_amneziavpn,
    parse_clash_yaml,
    parse_hysteria2_yaml,
    parse_openvpn_config,
    parse_singbox_json,
    parse_uri,
    parse_wg_config,
)
from providers.base import BaseProvider

RotationPrompt = Callable[[Profile], bool]


class ManualProvider(BaseProvider):
    """Import user-provided profiles from clipboard, URI, text, or files."""

    def __init__(
        self,
        profile_store: ProfileStore | None = None,
        rotation_prompt: RotationPrompt | None = None,
    ) -> None:
        self.profile_store = profile_store or ProfileStore()
        self.rotation_prompt = rotation_prompt or self._prompt_rotation_pool
        self._last_imported: list[Profile] = []

    @property
    def last_imported(self) -> list[Profile]:
        return list(self._last_imported)

    def from_clipboard(self) -> Profile | None:
        text = self._read_clipboard_text()
        if not text:
            return None
        return self.from_text(text)

    def from_uri(self, uri: str) -> Profile:
        profile = parse_uri(uri)
        return self._save_profiles([profile])

    def from_text(self, text: str) -> Profile:
        profiles = self._parse_text(text)
        return self._save_profiles(profiles)

    def from_file(self, path: str) -> Profile:
        content = Path(path).read_text(encoding="utf-8")
        return self.from_text(content)

    def load_profiles(self) -> list[Profile]:
        return [profile for profile in self.profile_store.list() if profile.source == ProfileSource.MANUAL]

    def update(self) -> bool:
        return True

    def status(self) -> dict:
        profiles = self.load_profiles()
        return {
            "provider": "manual",
            "profiles": len(profiles),
            "last_imported": len(self._last_imported),
        }

    def _save_profiles(self, profiles: list[Profile]) -> Profile:
        if not profiles:
            raise ParseError("no profiles found in manual input")

        saved: list[Profile] = []
        for profile in profiles:
            profile.source = ProfileSource.MANUAL
            profile.provider_id = None
            duplicate = self._duplicate_profile(profile)
            if duplicate is not None:
                raise ParseError(f"profile already exists: {duplicate.id}")
            profile.id = self._unique_profile_id(profile.id)
            profile.in_rotation_pool = bool(self.rotation_prompt(profile))
            self.profile_store.add(profile)
            saved.append(profile)

        self._last_imported = saved
        return saved[0]

    def _duplicate_profile(self, profile: Profile) -> Profile | None:
        fingerprint = profile_fingerprint(profile)
        for existing in self.profile_store.list():
            if (
                existing.source == ProfileSource.MANUAL
                and profile_fingerprint(existing) == fingerprint
            ):
                return existing
        return None

    def _unique_profile_id(self, requested_id: str) -> str:
        base = (requested_id or "manual-profile").strip() or "manual-profile"
        candidate = base
        suffix = 2
        while self.profile_store.get(candidate) is not None:
            candidate = f"{base}-{suffix}"
            suffix += 1
        return candidate

    def _parse_text(self, text: str) -> list[Profile]:
        content = textwrap.dedent(text or "").strip()
        if not content:
            raise ParseError("manual input is empty")

        if is_amneziavpn_format(content):
            return self._require_profiles(parse_amneziavpn(content), "AmneziaVPN export")

        uri_lines = self._uri_lines(content)
        if uri_lines:
            return [parse_uri(line) for line in uri_lines]

        if content.lstrip().startswith("{"):
            profile = self._parse_watchdog_profile_json(content)
            if profile is not None:
                return [profile]
            return self._require_profiles(parse_singbox_json(content), "sing-box JSON")

        if self._looks_like_hysteria2_yaml(content):
            return [parse_hysteria2_yaml(content)]

        if "[Interface]" in content and "[Peer]" in content:
            return [parse_wg_config(content)]

        if self._looks_like_openvpn(content):
            return [parse_openvpn_config(content)]

        if self._looks_like_clash_yaml(content):
            return self._require_profiles(parse_clash_yaml(content), "Clash YAML")

        return self._fallback_parse(content)

    def _fallback_parse(self, content: str) -> list[Profile]:
        errors: list[str] = []
        for parser, label in (
            (parse_uri, "URI"),
            (parse_wg_config, "WireGuard config"),
            (parse_openvpn_config, "OpenVPN config"),
            (parse_singbox_json, "sing-box JSON"),
            (parse_hysteria2_yaml, "Hysteria2 YAML"),
            (parse_clash_yaml, "Clash YAML"),
        ):
            try:
                result = parser(content)
            except (ParseError, json.JSONDecodeError, ValueError) as exc:
                errors.append(f"{label}: {exc}")
                continue
            if isinstance(result, list):
                return self._require_profiles(result, label)
            return [result]
        raise ParseError(f"unsupported manual profile format ({'; '.join(errors)})")

    def _uri_lines(self, content: str) -> list[str]:
        lines = [
            line.strip()
            for line in content.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if not lines:
            return []
        if all("://" in line for line in lines):
            return lines
        return []

    def _looks_like_openvpn(self, content: str) -> bool:
        lines = [line.strip().lower() for line in content.splitlines()]
        return any(line.startswith("remote ") for line in lines)

    def _looks_like_clash_yaml(self, content: str) -> bool:
        return any(line.strip().startswith("proxies:") for line in content.splitlines())

    def _looks_like_hysteria2_yaml(self, content: str) -> bool:
        keys = {line.split(":", 1)[0].strip().lower() for line in content.splitlines() if ":" in line}
        return {"server", "auth"}.issubset(keys)

    def _parse_watchdog_profile_json(self, content: str) -> Profile | None:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        if {"id", "name", "protocol", "config", "source"}.issubset(data):
            try:
                profile = Profile.from_dict(data)
            except (KeyError, TypeError, ValueError) as exc:
                raise ParseError(f"invalid WatchdogVPN profile JSON: {exc}") from exc
            self._normalize_imported_profile(profile)
            return profile
        return None

    def _normalize_imported_profile(self, profile: Profile) -> None:
        if profile.protocol is ProtocolType.VMESS:
            vmess_id = profile.config.get("id")
            if vmess_id and not profile.config.get("uuid"):
                profile.config["uuid"] = vmess_id
        if profile.protocol is ProtocolType.WIREGUARD and profile.config.get("raw_config"):
            parsed = parse_wg_config(str(profile.config["raw_config"]))
            profile.config.update(parsed.config)

    def _require_profiles(self, profiles: list[Profile], label: str) -> list[Profile]:
        if not profiles:
            raise ParseError(f"{label} contains no supported profiles")
        return profiles

    def _read_clipboard_text(self) -> str | None:
        commands = (
            ("wl-paste", ["wl-paste", "-n"]),
            ("xclip", ["xclip", "-selection", "clipboard", "-o"]),
            ("xsel", ["xsel", "--clipboard", "--output"]),
            ("pbpaste", ["pbpaste"]),
        )
        for binary, command in commands:
            if shutil.which(binary) is None:
                continue
            result = subprocess.run(command, text=True, capture_output=True, check=False)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        return None

    def _prompt_rotation_pool(self, profile: Profile) -> bool:
        if not sys.stdin.isatty():
            return False
        answer = input(f"Add profile '{profile.name}' to the rotation pool? [y/N]: ").strip().lower()
        return answer in {"y", "yes"}
