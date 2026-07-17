from __future__ import annotations

import json
import os
import signal
import shutil
import subprocess
import sys
import textwrap
import time
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
from parsers.endpoint_policy import EndpointPolicyError, validate_profile_endpoint
from parsers.openvpn_safety import OpenVPNConfigValidationError, validate_openvpn_profile
from parsers.profile_schema import ProfileSemanticValidationError, validate_profile_semantics

RotationPrompt = Callable[[Profile], bool]

CLIPBOARD_HELPERS = (
    ("wl-paste", ["wl-paste", "-n"]),
    ("xclip", ["xclip", "-selection", "clipboard", "-o"]),
    ("xsel", ["xsel", "--clipboard", "--output"]),
    ("pbpaste", ["pbpaste"]),
)
CLIPBOARD_TIMEOUT_SECONDS = 2.0
CLIPBOARD_TERMINATION_GRACE_SECONDS = 0.25
CLIPBOARD_KILL_GRACE_SECONDS = 0.5
CLIPBOARD_GROUP_POLL_SECONDS = 0.01
PROC_ROOT = Path("/proc")


class ClipboardHelperTimeout(RuntimeError):
    """A clipboard helper exceeded its bounded execution window."""


class ClipboardHelperCleanupError(RuntimeError):
    """A clipboard helper process group could not be proven terminated."""


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
        return self._save_profiles(self.preview_file(path))

    def preview_file(self, path: str) -> list[Profile]:
        """Parse a local profile file without writing profile state."""

        content = Path(path).read_text(encoding="utf-8")
        return self._parse_text(content)

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

        for profile in profiles:
            try:
                validate_profile_endpoint(profile)
            except EndpointPolicyError as exc:
                raise ParseError(str(exc)) from exc

        for profile in profiles:
            profile.source = ProfileSource.MANUAL
            profile.provider_id = None
            profile.in_rotation_pool = bool(self.rotation_prompt(profile))

        def commit(current: list[Profile]) -> tuple[list[Profile], list[Profile]]:
            existing_by_fingerprint = {
                profile_fingerprint(profile): profile
                for profile in current
                if profile.source == ProfileSource.MANUAL
            }
            batch_fingerprints: set[str] = set()
            for profile in profiles:
                fingerprint = profile_fingerprint(profile)
                duplicate = existing_by_fingerprint.get(fingerprint)
                if duplicate is not None:
                    raise ParseError(f"profile already exists: {duplicate.id}")
                if fingerprint in batch_fingerprints:
                    raise ParseError("manual import contains duplicate profiles")
                batch_fingerprints.add(fingerprint)

            used_ids = {profile.id for profile in current}
            saved: list[Profile] = []
            for profile in profiles:
                profile.id = self._unique_profile_id_from_used_ids(profile.id, used_ids)
                try:
                    validate_profile_semantics(profile)
                except ProfileSemanticValidationError as exc:
                    raise ParseError(str(exc)) from exc
                used_ids.add(profile.id)
                saved.append(profile)
            return [*current, *saved], saved

        saved = self.profile_store.update_atomically(commit)

        self._last_imported = saved
        return saved[0]

    def _unique_profile_id_from_used_ids(self, requested_id: str, used_ids: set[str]) -> str:
        base = (requested_id or "manual-profile").strip() or "manual-profile"
        candidate = base
        suffix = 2
        while candidate in used_ids:
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
        if profile.protocol in {ProtocolType.OPENVPN, ProtocolType.OPENVPN_CLOAK}:
            try:
                validate_openvpn_profile(profile)
            except OpenVPNConfigValidationError as exc:
                raise ParseError(str(exc)) from exc

    def _require_profiles(self, profiles: list[Profile], label: str) -> list[Profile]:
        if not profiles:
            raise ParseError(f"{label} contains no supported profiles")
        return profiles

    def _read_clipboard_text(self) -> str | None:
        found_helpers: list[str] = []
        failed_helpers: list[str] = []
        timed_out_helpers: list[str] = []
        for binary, command in CLIPBOARD_HELPERS:
            if shutil.which(binary) is None:
                continue
            found_helpers.append(binary)
            try:
                result = self._run_clipboard_helper(command)
            except ClipboardHelperTimeout:
                timed_out_helpers.append(binary)
                continue
            except ClipboardHelperCleanupError as exc:
                raise ParseError(
                    f"clipboard unavailable: {binary} cleanup could not be verified; "
                    "inspect local processes, then use --file or --text"
                ) from exc
            except OSError:
                failed_helpers.append(f"{binary}=launch-error")
                continue
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            if result.returncode == 0:
                return None
            failed_helpers.append(f"{binary}=exit-{result.returncode}")

        if timed_out_helpers:
            helpers = ", ".join(timed_out_helpers)
            raise ParseError(
                "clipboard unavailable: helper timeout after "
                f"{CLIPBOARD_TIMEOUT_SECONDS:g}s ({helpers}); process groups were "
                "terminated; use --file or --text"
            )
        if failed_helpers:
            raise ParseError(
                "clipboard unavailable: helpers failed ("
                + ", ".join(failed_helpers)
                + "); verify the desktop clipboard service or use --file/--text"
            )
        if not found_helpers:
            raise ParseError(
                "clipboard unavailable: no supported helper found "
                "(wl-paste, xclip, xsel, pbpaste); install one or use --file/--text"
            )
        return None

    def _run_clipboard_helper(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        process = subprocess.Popen(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=CLIPBOARD_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            self._terminate_clipboard_process_group(process)
            stdout, stderr = process.communicate()
            raise ClipboardHelperTimeout(command[0]) from exc

        # A helper can exit after spawning a child that no longer holds its
        # pipes. Never return clipboard data until its private process group is
        # also gone.
        self._terminate_clipboard_process_group(process)
        return subprocess.CompletedProcess(
            command,
            process.returncode,
            stdout,
            stderr,
        )

    def _terminate_clipboard_process_group(self, process: subprocess.Popen[str]) -> None:
        process_group = process.pid
        if not self._signal_clipboard_process_group(process_group, signal.SIGTERM):
            self._reap_clipboard_helper(process)
            return

        self._wait_for_clipboard_helper(process, CLIPBOARD_TERMINATION_GRACE_SECONDS)
        if self._wait_for_process_group_exit(
            process_group,
            CLIPBOARD_TERMINATION_GRACE_SECONDS,
        ):
            return

        self._signal_clipboard_process_group(process_group, signal.SIGKILL)
        self._wait_for_clipboard_helper(process, CLIPBOARD_KILL_GRACE_SECONDS)
        if not self._wait_for_process_group_exit(
            process_group,
            CLIPBOARD_KILL_GRACE_SECONDS,
        ):
            raise ClipboardHelperCleanupError(
                f"clipboard helper process group {process_group} survived SIGKILL"
            )

    def _reap_clipboard_helper(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        self._wait_for_clipboard_helper(process, CLIPBOARD_TERMINATION_GRACE_SECONDS)

    def _wait_for_clipboard_helper(
        self,
        process: subprocess.Popen[str],
        timeout: float,
    ) -> None:
        if process.poll() is not None:
            return
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return

    def _wait_for_process_group_exit(self, process_group: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._process_group_has_live_members(process_group):
                return True
            time.sleep(CLIPBOARD_GROUP_POLL_SECONDS)
        return not self._process_group_has_live_members(process_group)

    def _process_group_has_live_members(self, process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError as exc:
            raise ClipboardHelperCleanupError(
                f"cannot inspect clipboard helper process group {process_group}"
            ) from exc

        linux_observation = self._linux_process_group_has_live_members(process_group)
        if linux_observation is not None:
            return linux_observation
        # Without a complete Linux /proc observation, retain the conservative
        # signal-based result. A cleanup is never certified from uncertainty.
        return True

    def _linux_process_group_has_live_members(self, process_group: int) -> bool | None:
        """Distinguish executable survivors from already-dead zombie entries.

        killpg(pgid, 0) continues to succeed while an orphaned descendant is a
        zombie awaiting collection by PID 1. Zombies have released code, file
        descriptors, sockets, and network influence; treating them as running
        makes cleanup depend on the host's PID-1 reaping latency. Any unreadable
        or malformed observation remains fail-closed via ``None``.
        """

        if not PROC_ROOT.is_dir():
            return None
        observed_member = False
        uncertain = False
        try:
            entries = list(PROC_ROOT.iterdir())
        except OSError:
            return None
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                stat_line = (entry / "stat").read_text(encoding="utf-8")
                closing_parenthesis = stat_line.rfind(")")
                if closing_parenthesis < 0:
                    uncertain = True
                    continue
                fields = stat_line[closing_parenthesis + 2 :].split()
                if len(fields) < 3:
                    uncertain = True
                    continue
                state = fields[0]
                member_group = int(fields[2])
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                uncertain = True
                continue
            if member_group != process_group:
                continue
            observed_member = True
            if state not in {"Z", "X", "x"}:
                return True
        if uncertain:
            return None
        if observed_member:
            return False
        # killpg observed the group but /proc saw no member. Treat the racing
        # observation as live and let the bounded poll retry it.
        return True

    def _signal_clipboard_process_group(self, process_group: int, sig: signal.Signals) -> bool:
        try:
            os.killpg(process_group, sig)
        except ProcessLookupError:
            return False
        except PermissionError as exc:
            raise ClipboardHelperCleanupError(
                f"cannot signal clipboard helper process group {process_group}"
            ) from exc
        return True

    def _prompt_rotation_pool(self, profile: Profile) -> bool:
        if not sys.stdin.isatty():
            return False
        answer = input(f"Add profile '{profile.name}' to the rotation pool? [y/N]: ").strip().lower()
        return answer in {"y", "yes"}
