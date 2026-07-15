#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REQUIRED_PROTOCOLS: dict[str, str] = {
    "vless": "resilient",
    "vmess": "compatibility",
    "trojan": "resilient",
    "hysteria2": "resilient",
    "tuic": "compatibility",
    "shadowsocks": "compatibility",
    "wireguard": "compatibility",
    "amneziawg": "resilient",
    "openvpn": "compatibility",
    "openvpn_cloak": "resilient",
    "socks": "compatibility",
    "http": "compatibility",
}

REQUIRED_EXTERNAL_VPN_STATES = {"absent", "present"}


class ManifestError(ValueError):
    pass


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("manifest root must be an object")
    return data


def _require_str(data: dict[str, Any], key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{context}.{key} must be a non-empty string")
    return value.strip()


def _validate_profiles(data: dict[str, Any]) -> list[dict[str, str]]:
    raw_profiles = data.get("profiles")
    if not isinstance(raw_profiles, list):
        raise ManifestError("profiles must be a list")

    by_protocol: dict[str, dict[str, str]] = {}
    for index, raw_profile in enumerate(raw_profiles, start=1):
        if not isinstance(raw_profile, dict):
            raise ManifestError(f"profiles[{index}] must be an object")
        context = f"profiles[{index}]"
        protocol = _require_str(raw_profile, "protocol", context)
        expected_id = _require_str(raw_profile, "expected_id", context)
        expected_category = _require_str(raw_profile, "expected_category", context)
        fixture_path = _require_str(raw_profile, "fixture_path", context)

        if protocol not in REQUIRED_PROTOCOLS:
            supported = ", ".join(sorted(REQUIRED_PROTOCOLS))
            raise ManifestError(f"{context}.protocol unsupported: {protocol}; expected one of {supported}")
        required_category = REQUIRED_PROTOCOLS[protocol]
        if expected_category != required_category:
            raise ManifestError(
                f"{context}.expected_category for {protocol} must be {required_category}, got {expected_category}"
            )
        if protocol in by_protocol:
            raise ManifestError(f"duplicate protocol entry: {protocol}")
        by_protocol[protocol] = {
            "protocol": protocol,
            "expected_id": expected_id,
            "expected_category": expected_category,
            "fixture_path": fixture_path,
        }

    missing = sorted(set(REQUIRED_PROTOCOLS) - set(by_protocol))
    if missing:
        raise ManifestError(f"missing required protocol entries: {', '.join(missing)}")
    return [by_protocol[protocol] for protocol in REQUIRED_PROTOCOLS]


def _validate_provider(data: dict[str, Any]) -> dict[str, str]:
    raw_provider = data.get("provider")
    if not isinstance(raw_provider, dict):
        raise ManifestError("provider must be an object")
    return {
        "name": _require_str(raw_provider, "name", "provider"),
        "url_file": _require_str(raw_provider, "url_file", "provider"),
        "expected_provider_id": _require_str(raw_provider, "expected_provider_id", "provider"),
        "expected_node_id": _require_str(raw_provider, "expected_node_id", "provider"),
    }


def _validate_app_policy(data: dict[str, Any]) -> dict[str, str]:
    raw_policy = data.get("app_policy")
    if not isinstance(raw_policy, dict):
        raise ManifestError("app_policy must be an object")
    return {
        "direct_probe_path": _require_str(raw_policy, "direct_probe_path", "app_policy"),
        "vpn_probe_path": _require_str(raw_policy, "vpn_probe_path", "app_policy"),
        "block_probe_path": _require_str(raw_policy, "block_probe_path", "app_policy"),
    }


def _validate_rotation(data: dict[str, Any]) -> dict[str, Any]:
    raw_rotation = data.get("rotation")
    if not isinstance(raw_rotation, dict):
        raise ManifestError("rotation must be an object")
    all_failed = raw_rotation.get("all_failed_profile_ids")
    if not isinstance(all_failed, list) or not all(isinstance(item, str) and item.strip() for item in all_failed):
        raise ManifestError("rotation.all_failed_profile_ids must be a list of profile IDs")
    return {
        "primary_profile_id": _require_str(raw_rotation, "primary_profile_id", "rotation"),
        "secondary_profile_id": _require_str(raw_rotation, "secondary_profile_id", "rotation"),
        "all_failed_profile_ids": [item.strip() for item in all_failed],
    }


def _validate_reboot(data: dict[str, Any]) -> dict[str, str]:
    raw_reboot = data.get("reboot")
    if not isinstance(raw_reboot, dict):
        raise ManifestError("reboot must be an object")
    return {"connected_profile_id": _require_str(raw_reboot, "connected_profile_id", "reboot")}


def validate_manifest(data: dict[str, Any]) -> dict[str, Any]:
    evidence_dir = _require_str(data, "evidence_dir", "manifest")
    probe_domain = _require_str(data, "probe_domain", "manifest")

    raw_states = data.get("external_vpn_states")
    if not isinstance(raw_states, list):
        raise ManifestError("external_vpn_states must be a list")
    states = {item for item in raw_states if isinstance(item, str)}
    if states != REQUIRED_EXTERNAL_VPN_STATES:
        raise ManifestError("external_vpn_states must contain exactly: absent, present")

    return {
        "evidence_dir": evidence_dir,
        "probe_domain": probe_domain,
        "external_vpn_states": ["absent", "present"],
        "profiles": _validate_profiles(data),
        "provider": _validate_provider(data),
        "app_policy": _validate_app_policy(data),
        "rotation": _validate_rotation(data),
        "reboot": _validate_reboot(data),
    }


def _cmd(parts: list[str]) -> str:
    def quote(part: str) -> str:
        if not part:
            return "''"
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:=+-@")
        if all(char in allowed for char in part):
            return part
        return "'" + part.replace("'", "'\"'\"'") + "'"

    return " ".join(quote(part) for part in parts)


def _append_commands(lines: list[str], title: str, commands: list[list[str]]) -> None:
    lines.append(f"## {title}")
    lines.append("")
    lines.append("```bash")
    for command in commands:
        lines.append(_cmd(command))
    lines.append("```")
    lines.append("")


def _egress_probe_commands(probe_domain: str) -> list[list[str]]:
    url = f"https://{probe_domain}"
    return [
        ["curl", "--fail", "--show-error", "--max-time", "20", url],
        ["curl", "--fail", "--show-error", "--max-time", "20", "--socks5-hostname", "127.0.0.1:2080", url],
        ["curl", "--fail", "--show-error", "--max-time", "20", "--proxy", "http://127.0.0.1:2081", url],
    ]


def _append_raw_commands(lines: list[str], title: str, commands: list[str]) -> None:
    lines.append(f"## {title}")
    lines.append("")
    lines.append("```bash")
    lines.extend(commands)
    lines.append("```")
    lines.append("")


def build_runbook(plan: dict[str, Any]) -> str:
    evidence_dir = plan["evidence_dir"]
    probe_domain = plan["probe_domain"]
    provider = plan["provider"]
    app_policy = plan["app_policy"]
    rotation = plan["rotation"]
    reboot = plan["reboot"]

    lines: list[str] = [
        "# Phase 23 CLI Field Validation Runbook",
        "",
        "Generated from a local operator manifest. Review before execution.",
        "Do not paste secrets from fixture files, provider URLs or command output into chat.",
        "",
        f"Evidence directory: `{evidence_dir}`",
        f"Probe domain: `{probe_domain}`",
        "",
    ]

    _append_commands(
        lines,
        "M0 Preflight And Baseline",
        [
            ["mkdir", "-p", evidence_dir],
            ["git", "status", "--short", "--branch"],
            ["git", "rev-parse", "HEAD", "origin/phase-23-cli-field-validation"],
            ["./update.sh", "--yes"],
            ["watchdog", "doctor", "--json"],
            ["watchdog", "status", "--json"],
            ["watchdog", "profile", "list", "--json"],
            ["watchdog", "provider", "list", "--json"],
            ["watchdog", "dns", "status", "--json"],
            ["watchdog", "app-policy", "status", "--json"],
            ["ip", "rule"],
            ["ip", "route"],
            ["ip", "-6", "route"],
            ["ss", "-H", "-ltnup"],
            ["sha256sum", "/etc/resolv.conf"],
            ["sudo", "nft", "list", "ruleset"],
        ],
    )

    import_commands = [
        ["watchdog", "profile", "add", "--file", profile["fixture_path"], "--json"]
        for profile in plan["profiles"]
    ]
    import_commands.append(["watchdog", "profile", "list", "--json"])
    _append_commands(lines, "M1 Profile Import And Labeling", import_commands)

    for state in plan["external_vpn_states"]:
        commands: list[list[str]] = []
        for profile in plan["profiles"]:
            profile_id = profile["expected_id"]
            commands.extend(
                [
                    ["watchdog", "connect", profile_id, "--json"],
                    ["watchdog", "status", "--json"],
                    *_egress_probe_commands(probe_domain),
                    ["watchdog", "disconnect", "--json"],
                    ["watchdog", "status", "--json"],
                ]
            )
        _append_commands(lines, f"M2 Per-Protocol Connectivity External VPN {state}", commands)

    _append_raw_commands(
        lines,
        "M3 Provider Import Update And Node Connection",
        [
            f'PROVIDER_URL="$(tr -d \'\\n\' < {_cmd([provider["url_file"]])})"',
            f'watchdog provider add "$PROVIDER_URL" --name {_cmd([provider["name"]])} --json',
            "unset PROVIDER_URL",
            "watchdog provider list --json",
            f"watchdog provider stats {_cmd([provider['expected_provider_id']])} --json",
            f"watchdog provider update {_cmd([provider['expected_provider_id']])} --json",
            f"watchdog provider stats {_cmd([provider['expected_provider_id']])} --json",
            f"watchdog connect {_cmd([provider['expected_node_id']])} --json",
            "watchdog status --json",
            f"curl --fail --show-error --max-time 20 https://{probe_domain}",
            f"curl --fail --show-error --max-time 20 --socks5-hostname 127.0.0.1:2080 https://{probe_domain}",
            f"curl --fail --show-error --max-time 20 --proxy http://127.0.0.1:2081 https://{probe_domain}",
            "watchdog disconnect --json",
        ],
    )

    _append_raw_commands(
        lines,
        "M4 App Policy Direct VPN Block",
        [
            'CURL_BIN="$(command -v curl)"',
            f"ln -sf \"$CURL_BIN\" {_cmd([app_policy['direct_probe_path']])}",
            f"ln -sf \"$CURL_BIN\" {_cmd([app_policy['vpn_probe_path']])}",
            f"ln -sf \"$CURL_BIN\" {_cmd([app_policy['block_probe_path']])}",
            "watchdog app-policy enable --json",
            "watchdog app-policy mode blacklist --json",
            (
                "watchdog app-policy add --process-path "
                f"{_cmd([app_policy['direct_probe_path']])} "
                "--action direct --id phase23-direct --json"
            ),
            (
                "watchdog app-policy add --process-path "
                f"{_cmd([app_policy['vpn_probe_path']])} "
                "--action current --id phase23-vpn --json"
            ),
            (
                "watchdog app-policy add --process-path "
                f"{_cmd([app_policy['block_probe_path']])} "
                "--action block --id phase23-block --json"
            ),
            "watchdog app-policy status --json",
            f"{_cmd([app_policy['direct_probe_path']])} --fail --show-error --max-time 20 https://{probe_domain}",
            f"{_cmd([app_policy['vpn_probe_path']])} --fail --show-error --max-time 20 https://{probe_domain}",
            f"{_cmd([app_policy['block_probe_path']])} --fail --show-error --max-time 20 https://{probe_domain}",
            "watchdog app-policy remove phase23-direct --json",
            "watchdog app-policy remove phase23-vpn --json",
            "watchdog app-policy remove phase23-block --json",
            "watchdog app-policy disable --json",
        ],
    )

    _append_commands(
        lines,
        "M5 DNS Apply And Reset",
        [
            ["watchdog", "dns", "status", "--json"],
            ["watchdog", "dns", "diagnose", "--domain", probe_domain, "--json"],
            ["watchdog", "dns", "apply", "--dry-run", "--json"],
            ["watchdog", "dns", "apply", "--yes", "--json"],
            ["watchdog", "dns", "status", "--json"],
            ["watchdog", "dns", "reset", "--yes", "--json"],
        ],
    )

    _append_commands(
        lines,
        "M6 Kill Switch Enable Disable",
        [
            ["watchdog", "setup", "--yes", "--acknowledge-backup-warning", "--kill-switch", "enable", "--json"],
            ["watchdog", "connect", rotation["primary_profile_id"], "--json"],
            ["watchdog", "status", "--json"],
            ["watchdog", "disconnect", "--json"],
            ["watchdog", "setup", "--yes", "--acknowledge-backup-warning", "--kill-switch", "disable", "--json"],
            ["watchdog", "status", "--json"],
        ],
    )

    rotation_commands = [
        ["watchdog", "profile", "rotation", rotation["primary_profile_id"], "--enable", "--json"],
        ["watchdog", "profile", "rotation", rotation["secondary_profile_id"], "--enable", "--json"],
        ["watchdog", "profile", "list", "--pool", "--json"],
        ["watchdog", "connect", rotation["primary_profile_id"], "--json"],
        ["watchdog", "rotate", "--force", "--json"],
        ["watchdog", "status", "--json"],
        ["watchdog", "provider", "rotation", provider["expected_provider_id"], "--enable", "--json"],
        [
            "watchdog",
            "provider",
            "node",
            provider["expected_provider_id"],
            provider["expected_node_id"],
            "--rotation",
            "--enable",
            "--json",
        ],
        ["watchdog", "rotate", "--force", "--json"],
    ]
    for profile_id in rotation["all_failed_profile_ids"]:
        rotation_commands.append(["watchdog", "profile", "disable", profile_id, "--json"])
    rotation_commands.extend(
        [
            ["watchdog", "rotate", "--force", "--json"],
            ["watchdog", "status", "--json"],
        ]
    )
    _append_commands(lines, "M7 Rotation And All-Failed Behavior", rotation_commands)

    _append_commands(
        lines,
        "M8 Reboot And Manual-Off Behavior",
        [
            ["watchdog", "disconnect", "--json"],
            ["sudo", "reboot"],
            ["watchdog", "doctor", "--json"],
            ["watchdog", "status", "--json"],
            ["watchdog", "connect", reboot["connected_profile_id"], "--json"],
            ["sudo", "reboot"],
            ["watchdog", "doctor", "--json"],
            ["watchdog", "status", "--json"],
            ["sudo", "systemctl", "stop", "watchdogvpn.service"],
            ["watchdog", "status", "--json"],
            ["sudo", "systemctl", "start", "watchdogvpn.service"],
            ["watchdog", "status", "--json"],
            ["watchdog", "panic", "sleep"],
            ["watchdog", "panic", "status"],
            ["watchdog", "panic", "wake"],
            ["watchdog", "status", "--json"],
        ],
    )

    _append_commands(
        lines,
        "Cleanup",
        [
            ["watchdog", "disconnect", "--json"],
            ["watchdog", "dns", "reset", "--yes", "--json"],
            ["watchdog", "app-policy", "disable", "--json"],
            ["watchdog", "panic", "wake"],
            ["watchdog", "status", "--json"],
            ["watchdog", "doctor", "--json"],
            ["ip", "rule"],
            ["ip", "route"],
            ["ip", "-6", "route"],
            ["ss", "-H", "-ltnup"],
            ["sha256sum", "/etc/resolv.conf"],
            ["sudo", "nft", "list", "ruleset"],
        ],
    )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a Phase 23 CLI field manifest and write a runbook")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        plan = validate_manifest(_read_manifest(args.manifest))
    except ManifestError as exc:
        print(f"PHASE23_FIELD_MANIFEST_INVALID: {exc}")
        return 2

    args.output.write_text(build_runbook(plan), encoding="utf-8")
    print("PHASE23_FIELD_MANIFEST_OK")
    print(f"PHASE23_FIELD_RUNBOOK={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
