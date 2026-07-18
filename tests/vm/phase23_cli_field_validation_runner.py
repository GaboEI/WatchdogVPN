#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from phase23_cli_field_validation_plan import ManifestError, _read_manifest, validate_manifest


GUARD_ENV = "WATCHDOGVPN_FIELD_VALIDATION"
BRANCH = "phase-23-cli-field-validation"
PROCESS_PATTERN = "sing-box|openvpn|ck-client|awg|wireguard|watchdog"
NORMAL_EGRESS_URL = "https://www.facebook.com/"
SOCKS_EGRESS_URL = "https://www.instagram.com/"
HTTP_EGRESS_URL = "https://www.youtube.com/"


class FieldValidationError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-._").lower()
    return slug[:80] or "command"


def _redact(text: str, secrets: list[str]) -> str:
    result = text
    for secret in secrets:
        if secret:
            result = result.replace(secret, "<redacted>")
    return result


def _json_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _text_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _extract_json_document(text: str) -> Any:
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, _end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        return value
    raise FieldValidationError("command output did not contain a JSON document")


class Runner:
    def __init__(
        self,
        plan: dict[str, Any],
        *,
        section: str,
        external_vpn_state: str,
        dry_run: bool,
        selected_protocols: list[str] | None,
    ) -> None:
        self.plan = plan
        self.section = section
        self.external_vpn_state = external_vpn_state
        self.dry_run = dry_run
        self.selected_protocol_names = selected_protocols
        self.evidence_dir = Path(str(plan["evidence_dir"]))
        self.command_index = 0
        self.failures: list[str] = []
        self.secrets: list[str] = []
        self.last_stdout = ""
        self.started_at = _utc_now()

    def selected_profiles(self) -> list[dict[str, Any]]:
        profiles = list(self.plan["profiles"])
        if self.selected_protocol_names is None:
            return profiles
        selected = {protocol.strip() for protocol in self.selected_protocol_names if protocol.strip()}
        available = {profile["protocol"] for profile in profiles}
        unknown = sorted(selected - available)
        if unknown:
            raise FieldValidationError(f"unknown protocol selection: {', '.join(unknown)}")
        selected_profiles = [profile for profile in profiles if profile["protocol"] in selected]
        if not selected_profiles:
            raise FieldValidationError("protocol selection did not match any manifest profiles")
        return selected_profiles

    def require_guard(self) -> None:
        if self.dry_run:
            return
        if os.environ.get(GUARD_ENV) != "1":
            raise FieldValidationError(
                f"refusing to run disruptive field validation without {GUARD_ENV}=1"
            )

    def section_dir(self, name: str | None = None) -> Path:
        label = name or self.section
        return self.evidence_dir / label

    def command_path(self, section: str, label: str) -> Path:
        self.command_index += 1
        return self.section_dir(section) / f"{self.command_index:03d}-{_slug(label)}.json"

    def run(
        self,
        section: str,
        label: str,
        command: list[str],
        *,
        timeout: int = 120,
        ok_codes: set[int] | None = None,
        display_command: list[str] | None = None,
        env: dict[str, str] | None = None,
        defer_failure: bool = False,
    ) -> int:
        ok_codes = ok_codes or {0}
        display = display_command or command
        record: dict[str, Any] = {
            "label": label,
            "section": section,
            "started_at": _utc_now(),
            "command": display,
            "dry_run": self.dry_run,
        }
        if self.dry_run:
            self.last_stdout = ""
            record.update({"returncode": None, "stdout": "", "stderr": "", "finished_at": _utc_now()})
            _json_write(self.command_path(section, label), record)
            print(f"PHASE23_DRY_RUN {section} {label}")
            return 0

        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            self.last_stdout = _redact(stdout, self.secrets)
            record.update(
                {
                    "returncode": "timeout",
                    "stdout": self.last_stdout,
                    "stderr": _redact(stderr, self.secrets),
                    "finished_at": _utc_now(),
                }
            )
            if not defer_failure:
                self.failures.append(f"{section}:{label}: timeout")
            record["status"] = "deferred" if defer_failure else "failed"
            _json_write(self.command_path(section, label), record)
            marker = "PHASE23_CMD_DEFERRED" if defer_failure else "PHASE23_CMD_TIMEOUT"
            print(f"{marker} {section} {label} timeout", file=sys.stderr)
            return 124

        stdout = _redact(completed.stdout, self.secrets)
        stderr = _redact(completed.stderr, self.secrets)
        self.last_stdout = stdout
        record.update(
            {
                "returncode": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "finished_at": _utc_now(),
            }
        )
        if completed.returncode not in ok_codes:
            if defer_failure:
                record["status"] = "deferred"
                print(
                    f"PHASE23_CMD_DEFERRED {section} {label} rc={completed.returncode}",
                    file=sys.stderr,
                )
            else:
                self.failures.append(f"{section}:{label}: rc={completed.returncode}")
                record["status"] = "failed"
                print(f"PHASE23_CMD_FAILED {section} {label} rc={completed.returncode}", file=sys.stderr)
        else:
            record["status"] = "ok"
            print(f"PHASE23_CMD_OK {section} {label}")
        _json_write(self.command_path(section, label), record)
        return completed.returncode

    def _in_progress_command_id(self) -> str | None:
        try:
            response = _extract_json_document(self.last_stdout)
        except FieldValidationError:
            return None
        if not isinstance(response, dict):
            return None
        payload = response.get("payload")
        if not isinstance(payload, dict) or payload.get("error_kind") != "command_in_progress":
            return None
        command_id = payload.get("command_id")
        if not isinstance(command_id, str):
            return None
        try:
            parsed = uuid.UUID(command_id)
        except ValueError:
            return None
        return command_id if str(parsed) == command_id.lower() else None

    def run_mutation(
        self,
        section: str,
        label: str,
        command: list[str],
        *,
        timeout: int = 180,
        ok_codes: set[int] | None = None,
        outcome_wait_seconds: int = 300,
        poll_interval_seconds: int = 5,
        record_failure: bool = True,
    ) -> int:
        """Run a daemon mutation and resolve a deferred result authoritatively."""

        accepted_codes = ok_codes or {0}
        returncode = self.run(
            section,
            label,
            command,
            timeout=timeout,
            ok_codes=accepted_codes,
            defer_failure=True,
        )
        if self.dry_run:
            return returncode

        command_id = self._in_progress_command_id()
        if command_id is None:
            if record_failure and returncode not in accepted_codes:
                self.failures.append(f"{section}:{label}: rc={returncode}")
            return returncode

        print(f"PHASE23_MUTATION_WAIT {section} {label}")
        deadline = time.monotonic() + outcome_wait_seconds
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            outcome_rc = self.run(
                section,
                f"{label}-outcome-{attempt}",
                ["watchdog", "command", "outcome", command_id, "--json"],
                timeout=60,
                ok_codes=accepted_codes,
                defer_failure=True,
            )
            if self._in_progress_command_id() is not None:
                time.sleep(poll_interval_seconds)
                continue
            if record_failure and outcome_rc not in accepted_codes:
                self.failures.append(f"{section}:{label}: final rc={outcome_rc}")
            return outcome_rc

        if record_failure:
            self.failures.append(
                f"{section}:{label}: authoritative outcome timeout after {outcome_wait_seconds}s"
            )
        print(f"PHASE23_MUTATION_TIMEOUT {section} {label}", file=sys.stderr)
        return 124

    def write_environment(self) -> None:
        text = "\n".join(
            [
                f"started_at={self.started_at}",
                f"host={socket.gethostname()}",
                f"section={self.section}",
                f"external_vpn_state={self.external_vpn_state}",
                f"evidence_dir={self.evidence_dir}",
                f"python={sys.version.split()[0]}",
                f"guard={GUARD_ENV}={os.environ.get(GUARD_ENV, '')}",
                "",
            ]
        )
        if not self.dry_run:
            _text_write(self.evidence_dir / "00-environment.txt", text)

    def snapshot(self, label: str) -> None:
        section = f"state-{label}"
        commands = [
            ("ip-rule", ["ip", "rule"]),
            ("ip-route", ["ip", "route"]),
            ("ip6-route", ["ip", "-6", "route"]),
            ("listeners", ["ss", "-H", "-ltnup"]),
            ("resolv-conf-sha256", ["sha256sum", "/etc/resolv.conf"]),
            ("nft-ruleset", ["sudo", "-n", "nft", "list", "ruleset"]),
            ("processes", ["pgrep", "-a", PROCESS_PATTERN]),
        ]
        for command_label, command in commands:
            self.run(section, f"{label}-{command_label}", command, ok_codes={0, 1}, timeout=30)

    def preflight(self) -> None:
        self.write_environment()
        self.run("preflight", "git-status", ["git", "status", "--short", "--branch"], timeout=30)
        self.run(
            "preflight",
            "git-rev-parse",
            ["git", "rev-parse", "HEAD", f"origin/{BRANCH}", "origin/main", "main"],
            timeout=30,
        )
        self.run("preflight", "update-installed-runtime", ["./update.sh", "--yes"], timeout=600)
        self.run("preflight", "restart-daemon-after-update", ["sudo", "systemctl", "restart", "watchdogvpn.service"], timeout=120)
        self.run("preflight", "daemon-active-after-restart", ["systemctl", "is-active", "watchdogvpn.service"], timeout=30)
        self.run("preflight", "watchdog-doctor", ["watchdog", "doctor", "--json"], timeout=180)
        self.run("preflight", "watchdog-status", ["watchdog", "status", "--json"], timeout=60)
        self.run("preflight", "profile-list", ["watchdog", "profile", "list", "--json"], timeout=60)
        self.run("preflight", "provider-list", ["watchdog", "provider", "list", "--json"], timeout=60)
        self.run("preflight", "dns-status", ["watchdog", "dns", "status", "--json"], timeout=60)
        self.run("preflight", "app-policy-status", ["watchdog", "app-policy", "status", "--json"], timeout=60)
        self.snapshot(f"baseline-{self.external_vpn_state}")

    def imports(self) -> None:
        profile_id_map: dict[str, str] = {}
        for profile in self.selected_profiles():
            rc = self.run(
                "profile-imports",
                f"import-{profile['protocol']}",
                ["watchdog", "profile", "add", "--file", profile["fixture_path"], "--json"],
                timeout=120,
            )
            if self.dry_run or rc != 0:
                continue
            try:
                payload = _extract_json_document(self.last_stdout)
                imported = payload.get("profiles", []) if isinstance(payload, dict) else []
            except FieldValidationError as exc:
                self.failures.append(f"profile-imports:import-{profile['protocol']}: {exc}")
                continue
            if not imported:
                self.failures.append(f"profile-imports:import-{profile['protocol']}: no imported profile in JSON")
                continue
            first = imported[0]
            actual_protocol = first.get("protocol")
            actual_id = first.get("id")
            if actual_protocol != profile["protocol"]:
                self.failures.append(
                    f"profile-imports:import-{profile['protocol']}: protocol mismatch "
                    f"expected={profile['protocol']} actual={actual_protocol}"
                )
                continue
            if not isinstance(actual_id, str) or not actual_id:
                self.failures.append(f"profile-imports:import-{profile['protocol']}: missing imported profile id")
                continue
            profile_id_map[profile["protocol"]] = actual_id
        self.run("profile-imports", "profile-list-after-import", ["watchdog", "profile", "list", "--json"])
        if profile_id_map and not self.dry_run:
            _json_write(self.evidence_dir / "phase23-profile-id-map.json", profile_id_map)

    def profile_id_for(self, profile: dict[str, Any]) -> str:
        profile_id_map_path = self.evidence_dir / "phase23-profile-id-map.json"
        if profile_id_map_path.is_file():
            profile_id_map = json.loads(profile_id_map_path.read_text(encoding="utf-8"))
            mapped = profile_id_map.get(profile["protocol"])
            if isinstance(mapped, str) and mapped:
                return mapped
        return str(profile["expected_id"])

    def resolved_profile_id(self, placeholder: str) -> str:
        # dns()/kill_switch()/rotation() only have a manifest placeholder
        # like "phase23-vless" (watchdog profile add never accepts a
        # caller-chosen id), the same gap phase23-profile-id-map.json
        # already fixed for protocols(). The protocol name is encoded in
        # the placeholder itself, so reuse the same map imports() wrote.
        protocol = placeholder.removeprefix("phase23-")
        profile_id_map_path = self.evidence_dir / "phase23-profile-id-map.json"
        if profile_id_map_path.is_file():
            try:
                profile_id_map = json.loads(profile_id_map_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return placeholder
            mapped = profile_id_map.get(protocol)
            if isinstance(mapped, str) and mapped:
                return mapped
        return placeholder

    def resolved_provider_ids(self) -> tuple[str, str]:
        provider = self.plan["provider"]
        provider_id = str(provider["expected_provider_id"])
        node_id = str(provider["expected_node_id"])
        provider_id_map_path = self.evidence_dir / "phase23-provider-id-map.json"
        if provider_id_map_path.is_file():
            try:
                provider_id_map = json.loads(provider_id_map_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return provider_id, node_id
            mapped_provider_id = provider_id_map.get("provider_id")
            mapped_node_id = provider_id_map.get("node_id")
            if isinstance(mapped_provider_id, str) and mapped_provider_id:
                provider_id = mapped_provider_id
            if isinstance(mapped_node_id, str) and mapped_node_id:
                node_id = mapped_node_id
        return provider_id, node_id

    def protocols(self) -> None:
        for profile in self.selected_profiles():
            profile_id = self.profile_id_for(profile)
            section = f"protocols-{self.external_vpn_state}-{profile['protocol']}"
            connect_rc = self.run_mutation(section, "connect", ["watchdog", "connect", profile_id, "--json"], timeout=180)
            if connect_rc != 0:
                self.run(section, "status-after-failed-connect", ["watchdog", "status", "--json"], timeout=60, ok_codes={0, 69, 70})
                self.snapshot(f"post-failed-connect-{self.external_vpn_state}-{profile['protocol']}")
                continue
            self.run(section, "status-connected", ["watchdog", "status", "--json"], timeout=60)
            capabilities = self.connected_capabilities()
            self.egress_probes(
                section,
                expect_normal=capabilities["tun_active"],
                expect_proxy=capabilities["proxy_active"],
            )
            self.run_mutation(section, "disconnect", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
            self.run(section, "status-disconnected", ["watchdog", "status", "--json"], timeout=60, ok_codes={0, 69})
            self.snapshot(f"post-{self.external_vpn_state}-{profile['protocol']}")

    def connected_capabilities(self) -> dict[str, bool]:
        if self.dry_run:
            return {"tun_active": True, "proxy_active": True}
        try:
            payload = _extract_json_document(self.last_stdout)
        except FieldValidationError:
            return {"tun_active": True, "proxy_active": True}
        if not isinstance(payload, dict):
            return {"tun_active": True, "proxy_active": True}
        lifecycle = payload.get("payload", {}).get("lifecycle", {})
        if not isinstance(lifecycle, dict):
            return {"tun_active": True, "proxy_active": True}
        return {
            "tun_active": bool(lifecycle.get("tun_active")),
            "proxy_active": bool(lifecycle.get("proxy_active")),
        }

    def egress_probes(self, section: str, *, expect_normal: bool = True, expect_proxy: bool = True) -> None:
        if expect_normal:
            self.run(
                section,
                "egress-normal",
                ["curl", "--fail", "--show-error", "--max-time", "20", NORMAL_EGRESS_URL],
                timeout=45,
            )
        else:
            print(f"PHASE23_SKIP {section} egress-normal tun_inactive")
        if expect_proxy:
            self.run(
                section,
                "egress-socks",
                ["curl", "--fail", "--show-error", "--max-time", "20", "--socks5-hostname", "127.0.0.1:2080", SOCKS_EGRESS_URL],
                timeout=45,
            )
            self.run(
                section,
                "egress-http",
                ["curl", "--fail", "--show-error", "--max-time", "20", "--proxy", "http://127.0.0.1:2081", HTTP_EGRESS_URL],
                timeout=45,
            )
        else:
            print(f"PHASE23_SKIP {section} egress-socks proxy_inactive")
            print(f"PHASE23_SKIP {section} egress-http proxy_inactive")

    def provider(self) -> None:
        # watchdog provider add/profile add do not accept a caller-chosen id -
        # WatchdogVPN always generates its own. A static expected_provider_id/
        # expected_node_id from the manifest is a placeholder that cannot
        # match a real first-time provider add, the same gap the profile
        # import path had before phase23-profile-id-map.json. Resolve both
        # ids dynamically from real command output instead.
        provider = self.plan["provider"]
        url_path = Path(provider["url_file"])
        if self.dry_run:
            provider_url = "<provider-url-from-file>"
        else:
            provider_url = url_path.read_text(encoding="utf-8").strip()
            if not provider_url:
                raise FieldValidationError(f"provider URL file is empty: {url_path}")
            self.secrets.append(provider_url)
        redacted_url = "<provider-url-from-file>"
        add_rc = self.run(
            "provider",
            "provider-add",
            ["watchdog", "provider", "add", provider_url, "--name", provider["name"], "--json"],
            display_command=["watchdog", "provider", "add", redacted_url, "--name", provider["name"], "--json"],
            timeout=240,
        )
        provider_id = provider["expected_provider_id"]
        if not self.dry_run and add_rc == 0:
            try:
                payload = _extract_json_document(self.last_stdout)
                real_id = payload.get("provider", {}).get("id") if isinstance(payload, dict) else None
            except FieldValidationError as exc:
                self.failures.append(f"provider:provider-add: {exc}")
                real_id = None
            if isinstance(real_id, str) and real_id:
                provider_id = real_id
            else:
                self.failures.append("provider:provider-add: missing added provider id in JSON")

        self.run("provider", "provider-list", ["watchdog", "provider", "list", "--json"], timeout=60)
        self.run("provider", "provider-stats", ["watchdog", "provider", "stats", provider_id, "--json"])
        self.run("provider", "provider-update", ["watchdog", "provider", "update", provider_id, "--json"], timeout=240)
        stats_rc = self.run(
            "provider", "provider-stats-after-update", ["watchdog", "provider", "stats", provider_id, "--json"]
        )

        node_ids = [provider["expected_node_id"]]
        if not self.dry_run and stats_rc == 0:
            list_rc = self.run(
                "provider", "profile-list-for-node-lookup", ["watchdog", "profile", "list", "--json"], timeout=60
            )
            if list_rc == 0:
                try:
                    profiles = _extract_json_document(self.last_stdout)
                except FieldValidationError as exc:
                    self.failures.append(f"provider:profile-list-for-node-lookup: {exc}")
                    profiles = []
                owned = [
                    item
                    for item in (profiles if isinstance(profiles, list) else [])
                    if isinstance(item, dict) and item.get("provider_id") == provider_id
                ]
                node_ids = sorted(
                    item["id"]
                    for item in owned
                    if isinstance(item.get("id"), str) and item["id"]
                )
                if node_ids:
                    _json_write(
                        self.evidence_dir / "phase23-provider-id-map.json",
                        {"provider_id": provider_id, "node_id": node_ids[0]},
                    )
                else:
                    self.failures.append("provider:profile-list-for-node-lookup: no owned node found for provider")

        connected_node_id = ""
        for attempt, node_id in enumerate(node_ids, start=1):
            connect_rc = self.run_mutation(
                "provider",
                f"connect-provider-node-{attempt}",
                ["watchdog", "connect", node_id, "--json"],
                timeout=180,
                record_failure=False,
            )
            if connect_rc == 0:
                connected_node_id = node_id
                break
            self.run(
                "provider",
                f"status-after-failed-provider-node-{attempt}",
                ["watchdog", "status", "--json"],
                timeout=60,
                ok_codes={0, 69, 70},
            )

        if connected_node_id:
            if not self.dry_run:
                _json_write(
                    self.evidence_dir / "phase23-provider-id-map.json",
                    {"provider_id": provider_id, "node_id": connected_node_id},
                )
            self.run("provider", "status-provider-node", ["watchdog", "status", "--json"], timeout=60)
            self.egress_probes("provider")
            self.run_mutation(
                "provider",
                "disconnect-provider-node",
                ["watchdog", "disconnect", "--json"],
                timeout=180,
                ok_codes={0, 70},
            )
        else:
            self.failures.append(
                f"provider:connect-provider-node: no provider-owned node connected (attempted={len(node_ids)})"
            )
        self.snapshot(f"post-provider-{self.external_vpn_state}")

    def app_policy(self) -> None:
        policy = self.plan["app_policy"]
        curl_binary = shutil.which("curl")
        if curl_binary is None:
            raise FieldValidationError("curl not found")
        curl_path = Path(curl_binary)
        for key in ("direct_probe_path", "vpn_probe_path", "block_probe_path"):
            link = Path(policy[key])
            if not self.dry_run:
                if link.exists() or link.is_symlink():
                    link.unlink()
                link.symlink_to(curl_path)
        section = "app-policy"
        self.run(section, "enable", ["watchdog", "app-policy", "enable", "--json"])
        self.run(section, "mode-blacklist", ["watchdog", "app-policy", "mode", "blacklist", "--json"])
        self.run(
            section,
            "add-direct",
            ["watchdog", "app-policy", "add", "--process-path", policy["direct_probe_path"], "--action", "direct", "--id", "phase23-direct", "--json"],
        )
        self.run(
            section,
            "add-current",
            ["watchdog", "app-policy", "add", "--process-path", policy["vpn_probe_path"], "--action", "current", "--id", "phase23-vpn", "--json"],
        )
        self.run(
            section,
            "add-block",
            ["watchdog", "app-policy", "add", "--process-path", policy["block_probe_path"], "--action", "block", "--id", "phase23-block", "--json"],
        )
        self.run(section, "status", ["watchdog", "app-policy", "status", "--json"])
        url = f"https://{self.plan['probe_domain']}"
        self.run(section, "direct-probe", [policy["direct_probe_path"], "--fail", "--show-error", "--max-time", "20", url], timeout=45)
        self.run(section, "current-probe", [policy["vpn_probe_path"], "--fail", "--show-error", "--max-time", "20", url], timeout=45)
        self.run(section, "block-probe", [policy["block_probe_path"], "--fail", "--show-error", "--max-time", "20", url], timeout=45, ok_codes={0, 6, 7, 28, 35, 56})
        self.run(section, "remove-direct", ["watchdog", "app-policy", "remove", "phase23-direct", "--json"], ok_codes={0, 65, 70})
        self.run(section, "remove-current", ["watchdog", "app-policy", "remove", "phase23-vpn", "--json"], ok_codes={0, 65, 70})
        self.run(section, "remove-block", ["watchdog", "app-policy", "remove", "phase23-block", "--json"], ok_codes={0, 65, 70})
        self.run(section, "disable", ["watchdog", "app-policy", "disable", "--json"], ok_codes={0, 70})
        self.snapshot(f"post-app-policy-{self.external_vpn_state}")

    def dns(self) -> None:
        # dns apply (non-dry-run) requires the local DNS entrypoint to
        # already be listening, which is only true while connected (TUN/DNS
        # hijack active) - "sudo watchdog dns apply --yes" against a disconnected
        # daemon fails closed with "local DNS entrypoint is not reachable",
        # by design, not a bug. Connect first so apply/reset actually
        # exercise the real runtime path instead of a precondition that
        # never holds standalone.
        section = "dns"
        profile_id = self.resolved_profile_id(self.plan["rotation"]["primary_profile_id"])
        self.run(section, "status-before", ["watchdog", "dns", "status", "--json"])
        self.run(section, "diagnose", ["watchdog", "dns", "diagnose", "--domain", self.plan["probe_domain"], "--json"])
        self.run(section, "apply-dry-run", ["watchdog", "dns", "apply", "--dry-run", "--json"])
        self.run_mutation(section, "connect-for-apply", ["watchdog", "connect", profile_id, "--json"], timeout=180)
        # --systemd-link is mandatory for a first-time apply against
        # systemd-resolved (dns/state_manager.py:_apply_systemd_resolved
        # raises "systemd-resolved apply requires a link name" without it)
        # and was missing from both the Task 23.1 M5.2 plan text and this
        # harness. "wdvpn-tun0" is the sing-box driver's real TUN interface
        # name (drivers/singbox_driver.py), matching what
        # docs/dns-cli.md's own example ("--systemd-link tun0") documents
        # for this exact command shape.
        self.run(
            section,
            "apply",
            ["sudo", "watchdog", "dns", "apply", "--yes", "--systemd-link", "wdvpn-tun0", "--json"],
            timeout=120,
        )
        self.run(section, "status-after-apply", ["watchdog", "dns", "status", "--json"])
        self.run(section, "resolver-probe", ["getent", "hosts", self.plan["probe_domain"]], timeout=45)
        self.run(section, "reset", ["sudo", "watchdog", "dns", "reset", "--yes", "--json"], timeout=120, ok_codes={0, 70})
        self.run_mutation(section, "disconnect-after-dns", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
        self.snapshot(f"post-dns-{self.external_vpn_state}")

    def kill_switch(self) -> None:
        profile_id = self.resolved_profile_id(self.plan["rotation"]["primary_profile_id"])
        section = "kill-switch"
        physical_interface = "phase23-physical-interface"
        route_rc = self.run(
            section,
            "physical-route-before-connect",
            ["ip", "-j", "route", "show", "default"],
            timeout=30,
        )
        if not self.dry_run and route_rc == 0:
            try:
                routes = json.loads(self.last_stdout)
                physical_interface = next(
                    route["dev"]
                    for route in routes
                    if isinstance(route, dict) and isinstance(route.get("dev"), str)
                )
            except (json.JSONDecodeError, KeyError, StopIteration, TypeError):
                self.failures.append(
                    "kill-switch:physical-route-before-connect: missing default interface"
                )
                return
        self.run(section, "enable", ["watchdog", "setup", "--yes", "--acknowledge-backup-warning", "--kill-switch", "enable", "--json"])
        try:
            connect_rc = self.run_mutation(
                section,
                "connect",
                ["watchdog", "connect", profile_id, "--json"],
                timeout=180,
            )
            if connect_rc == 0:
                self.run(section, "status-enabled", ["watchdog", "status", "--json"])
                self.egress_probes(section)
                helper = Path(__file__).with_name(
                    "phase23_kill_switch_controlled_failure.py"
                )
                self.run(
                    section,
                    "controlled-runtime-failure",
                    [
                        sys.executable,
                        str(helper),
                        "--physical-interface",
                        physical_interface,
                        "--probe-domain",
                        str(self.plan["probe_domain"]),
                        "--evidence-dir",
                        str(self.section_dir(section) / "controlled-failure-private"),
                    ],
                    timeout=120,
                )
        finally:
            self.run_mutation(
                section,
                "disconnect",
                ["watchdog", "disconnect", "--json"],
                timeout=180,
                ok_codes={0, 70},
            )
            self.run(
                section,
                "disable",
                [
                    "watchdog",
                    "setup",
                    "--yes",
                    "--acknowledge-backup-warning",
                    "--kill-switch",
                    "disable",
                    "--json",
                ],
            )
        self.run(
            section,
            "status-disabled",
            ["watchdog", "status", "--json"],
            ok_codes={0, 69},
        )
        self.run(
            section,
            "direct-egress-after-disable",
            [
                "curl",
                "--fail",
                "--show-error",
                "--max-time",
                "20",
                "https://github.com/",
            ],
            timeout=45,
        )
        if shutil.which("nft"):
            self.run(
                section,
                "nft-artifacts-absent",
                ["sudo", "-n", "nft", "list", "table", "inet", "watchdogvpn"],
                timeout=30,
                ok_codes={1},
            )
        if shutil.which("iptables"):
            self.run(
                section,
                "iptables-artifacts-absent",
                ["sudo", "-n", "iptables", "-S", "WATCHDOGVPN-OUTPUT"],
                timeout=30,
                ok_codes={1},
            )
        self.snapshot(f"post-kill-switch-{self.external_vpn_state}")

    def rotation(self) -> None:
        rotation = self.plan["rotation"]
        section = "rotation"
        primary_id = self.resolved_profile_id(rotation["primary_profile_id"])
        secondary_id = self.resolved_profile_id(rotation["secondary_profile_id"])
        provider_id, provider_node_id = self.resolved_provider_ids()
        all_failed_ids = [self.resolved_profile_id(pid) for pid in rotation["all_failed_profile_ids"]]
        self.run(section, "primary-rotation-on", ["watchdog", "profile", "rotation", primary_id, "--enable", "--json"])
        self.run(section, "secondary-rotation-on", ["watchdog", "profile", "rotation", secondary_id, "--enable", "--json"])
        self.run(section, "pool-list", ["watchdog", "profile", "list", "--pool", "--json"])
        self.run_mutation(section, "connect-primary", ["watchdog", "connect", primary_id, "--json"], timeout=180)
        self.run_mutation(section, "rotate-force", ["watchdog", "rotate", "--force", "--json"], timeout=180, ok_codes={0, 70})
        self.run(section, "status-after-rotate", ["watchdog", "status", "--json"], ok_codes={0, 69})
        self.run(section, "provider-rotation-on", ["watchdog", "provider", "rotation", provider_id, "--enable", "--json"], ok_codes={0, 65, 70})
        self.run(
            section,
            "provider-node-rotation-on",
            ["watchdog", "provider", "node", provider_id, provider_node_id, "--rotation", "--enable", "--json"],
            ok_codes={0, 65, 70},
        )
        self.run_mutation(section, "rotate-provider", ["watchdog", "rotate", "--force", "--json"], timeout=180, ok_codes={0, 70})
        # Disabling only the two manifest profiles is not "all failed" if a
        # provider with other rotation-eligible nodes is still enrolled
        # (confirmed live: rotate-force found a real provider node and
        # reported failure_or_degraded=false instead of failing closed).
        # Disable provider rotation too so this is a genuine no-candidates
        # scenario, matching M7.3's "every rotation candidate" intent.
        self.run(
            section,
            "provider-rotation-off-for-all-failed",
            ["watchdog", "provider", "rotation", provider_id, "--disable", "--json"],
            ok_codes={0, 65, 70},
        )
        for profile_id in all_failed_ids:
            self.run(section, f"disable-{profile_id}", ["watchdog", "profile", "disable", profile_id, "--json"], ok_codes={0, 65, 70})
        self.run_mutation(section, "rotate-all-failed", ["watchdog", "rotate", "--force", "--json"], timeout=180, ok_codes={0, 70})
        self.run(section, "status-all-failed", ["watchdog", "status", "--json"], ok_codes={0, 69})
        for profile_id in all_failed_ids:
            self.run(section, f"reenable-{profile_id}", ["watchdog", "profile", "enable", profile_id, "--json"], ok_codes={0, 65, 70})
        # Restore provider rotation to its pre-section state (off) rather
        # than leaving it enabled as a side effect of the earlier M7.2 step.
        self.run(
            section,
            "provider-rotation-restore-off",
            ["watchdog", "provider", "rotation", provider_id, "--disable", "--json"],
            ok_codes={0, 65, 70},
        )
        self.run_mutation(section, "disconnect", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
        self.snapshot(f"post-rotation-{self.external_vpn_state}")

    def manual_off(self) -> None:
        section = "manual-off"
        self.run_mutation(section, "disconnect-before-manual-off", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
        self.snapshot("pre-manual-off")
        self.run(section, "systemctl-stop", ["sudo", "systemctl", "stop", "watchdogvpn.service"], timeout=120, ok_codes={0, 3, 4, 5})
        self.run(section, "status-after-stop", ["watchdog", "status", "--json"], timeout=60, ok_codes={0, 69})
        self.snapshot("after-systemctl-stop")
        self.run(section, "systemctl-start", ["sudo", "systemctl", "start", "watchdogvpn.service"], timeout=120)
        self.run(section, "status-after-start", ["watchdog", "status", "--json"], timeout=60, ok_codes={0, 69})
        self.run(section, "panic-sleep", ["watchdog", "panic", "sleep"], timeout=180, ok_codes={0, 1})
        self.run(section, "panic-status", ["watchdog", "panic", "status"], timeout=60, ok_codes={0, 1})
        self.run(section, "panic-wake", ["watchdog", "panic", "wake"], timeout=180, ok_codes={0, 1})
        self.run(section, "status-after-panic-wake", ["watchdog", "status", "--json"], timeout=60, ok_codes={0, 69})
        self.snapshot("post-manual-off")
        self.write_reboot_runbook()

    def write_reboot_runbook(self) -> None:
        connected_profile_id = self.resolved_profile_id(self.plan["reboot"]["connected_profile_id"])
        path = self.evidence_dir / "10-reboot-manual-off" / "reboot-operator-steps.md"
        text = f"""# Phase 23 Reboot Operator Steps

Run these manually in the VM snapshot. Capture outputs in `10-reboot-manual-off/`.

## Reboot While Disconnected

```bash
watchdog disconnect --json
ip rule
ip route
ip -6 route
ss -H -ltnup
sha256sum /etc/resolv.conf
sudo nft list ruleset
sudo reboot
```

After the VM returns:

```bash
watchdog doctor --json
watchdog status --json
ip rule
ip route
ip -6 route
ss -H -ltnup
sha256sum /etc/resolv.conf
sudo nft list ruleset
```

## Reboot While Connected

```bash
watchdog connect {connected_profile_id} --json
watchdog status --json
ip rule
ip route
ip -6 route
ss -H -ltnup
sha256sum /etc/resolv.conf
sudo nft list ruleset
sudo reboot
```

After the VM returns:

```bash
watchdog doctor --json
watchdog status --json
curl --fail --show-error --max-time 20 https://{self.plan['probe_domain']}
watchdog disconnect --json
sudo watchdog dns reset --yes --json
watchdog panic wake
```
"""
        if not self.dry_run:
            _text_write(path, text)
        print(f"PHASE23_REBOOT_RUNBOOK={path}")

    def cleanup(self) -> None:
        section = "cleanup"
        self.run_mutation(section, "disconnect", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
        self.run(section, "dns-reset", ["sudo", "watchdog", "dns", "reset", "--yes", "--json"], timeout=120, ok_codes={0, 70})
        self.run(section, "app-policy-disable", ["watchdog", "app-policy", "disable", "--json"], ok_codes={0, 70})
        self.run(section, "panic-wake", ["watchdog", "panic", "wake"], timeout=180, ok_codes={0, 1})
        self.run(section, "status", ["watchdog", "status", "--json"], ok_codes={0, 69})
        self.run(section, "doctor", ["watchdog", "doctor", "--json"], timeout=180, ok_codes={0, 1})
        self.snapshot("final-cleanup")

    def write_summary(self) -> None:
        summary = {
            "section": self.section,
            "external_vpn_state": self.external_vpn_state,
            "started_at": self.started_at,
            "finished_at": _utc_now(),
            "dry_run": self.dry_run,
            "protocols": self.selected_protocol_names or "all",
            "failures": self.failures,
            "failure_count": len(self.failures),
        }
        if not self.dry_run:
            _json_write(self.evidence_dir / f"summary-{_slug(self.section)}-{int(time.time())}.json", summary)
        print("PHASE23_FIELD_SECTION_FAILED" if self.failures else "PHASE23_FIELD_SECTION_OK")
        print(json.dumps(summary, indent=2, sort_keys=True))

    def dispatch(self) -> int:
        self.require_guard()
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        if self.section in {"all", "preflight"}:
            self.preflight()
        if self.section in {"all", "imports"}:
            self.imports()
        if self.section in {"all", "protocols"}:
            self.protocols()
        if self.section in {"all", "provider"}:
            self.provider()
        if self.section in {"all", "app-policy"}:
            self.app_policy()
        if self.section in {"all", "dns"}:
            self.dns()
        if self.section in {"all", "kill-switch"}:
            self.kill_switch()
        if self.section in {"all", "rotation"}:
            self.rotation()
        if self.section in {"all", "manual-off"}:
            self.manual_off()
        if self.section in {"all", "cleanup"}:
            self.cleanup()
        self.write_summary()
        return 1 if self.failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Operator-run Phase 23 CLI field validation runner")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument(
        "--section",
        required=True,
        choices=[
            "all",
            "preflight",
            "imports",
            "protocols",
            "provider",
            "app-policy",
            "dns",
            "kill-switch",
            "rotation",
            "manual-off",
            "cleanup",
        ],
    )
    parser.add_argument("--external-vpn-state", choices=["absent", "present"], default="absent")
    parser.add_argument(
        "--protocols",
        help="comma-separated protocol subset for staged imports/protocol validation",
    )
    parser.add_argument("--dry-run", action="store_true", help="Write command records without executing commands")
    args = parser.parse_args()

    try:
        plan = validate_manifest(_read_manifest(args.manifest))
        runner = Runner(
            plan,
            section=args.section,
            external_vpn_state=args.external_vpn_state,
            dry_run=bool(args.dry_run),
            selected_protocols=args.protocols.split(",") if args.protocols else None,
        )
        return runner.dispatch()
    except (ManifestError, FieldValidationError, OSError, ValueError) as exc:
        print(f"PHASE23_FIELD_RUNNER_FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
