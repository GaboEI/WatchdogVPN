"""DNS v2 helpers for the WatchdogVPN TUI."""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any

DNS_CHANNELS = (
    "bootstrap_dns",
    "dns_server",
    "proxy_server",
    "direct",
    "proxy",
    "final",
)


def config_dir() -> Path:
    return Path(os.environ.get("WATCHDOGVPN_CONFIG_DIR", Path.home() / ".config" / "watchdogvpn"))


def policy_file() -> Path:
    return Path(os.environ.get("WATCHDOGVPN_DNS_POLICY_FILE", config_dir() / "dns-policy.json"))


def snapshot_file() -> Path:
    return Path(os.environ.get("WATCHDOGVPN_DNS_SNAPSHOT_FILE", config_dir() / "dns-state.json"))


def repo_root() -> Path | None:
    candidates = [
        os.environ.get("WATCHDOGVPN_REPO", ""),
        os.getcwd(),
        str(Path(__file__).resolve().parents[3]) if len(Path(__file__).resolve().parents) > 3 else "",
        str(Path.home() / "WatchdogVPN"),
        str(Path.home() / "watchdogvpn"),
    ]
    seen: set[Path] = set()
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser().resolve()
        if path in seen:
            continue
        seen.add(path)
        if (path / "bin" / "watchdog").is_file() and (path / "cli" / "main.py").is_file():
            return path
    return None


def core_available() -> bool:
    return repo_root() is not None


def load_policy() -> dict[str, Any]:
    path = policy_file()
    if not path.exists():
        return default_policy()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        policy = default_policy()
        policy["_status"] = f"unreadable: {exc}"
        return policy
    if not isinstance(data, dict):
        policy = default_policy()
        policy["_status"] = "invalid: expected object"
        return policy
    policy = default_policy()
    policy.update(data)
    policy["_status"] = "readable"
    return policy


def default_policy() -> dict[str, Any]:
    return {
        "_status": "default",
        "mode": "auto",
        "channels": {},
        "static_ips": [],
        "rules": [],
        "test_domain": "gstatic.com",
        "ttl": "12h",
        "tun_hijack": True,
        "resolve_inbound_domains": False,
        "static_ip_enabled": False,
        "rules_enabled": False,
        "ecs_direct_enabled": False,
        "ecs_direct_subnet": None,
        "proxy_resolution_channel": "fakeip",
        "fakeip_inet4_range": "198.18.0.0/15",
        "fakeip_inet6_range": "fc00::/18",
    }


def policy_rows() -> list[tuple[str, str]]:
    policy = load_policy()
    channels = policy.get("channels", {})
    static_ips = policy.get("static_ips", [])
    rules = policy.get("rules", [])
    return [
        ("Policy file", str(policy_file())),
        ("Policy status", str(policy.get("_status", "unknown"))),
        ("Core CLI", "available" if core_available() else "unavailable"),
        ("Mode", str(policy.get("mode", "auto"))),
        ("Test domain", str(policy.get("test_domain", "gstatic.com"))),
        ("TTL", str(policy.get("ttl", "12h"))),
        ("TUN hijack", _on_off(policy.get("tun_hijack", True))),
        ("Inbound domains", _on_off(policy.get("resolve_inbound_domains", False))),
        ("Channels", _channel_summary(channels)),
        ("Static IP", f"{_on_off(policy.get('static_ip_enabled', False))} ({len(static_ips)} entries)"),
        ("Rules", f"{_on_off(policy.get('rules_enabled', False))} ({len(rules)} rules)"),
        ("FakeIP", f"{policy.get('fakeip_inet4_range', '-')} / {policy.get('fakeip_inet6_range', '-')}"),
        ("Proxy DNS", str(policy.get("proxy_resolution_channel", "fakeip"))),
        ("ECS direct", _ecs_summary(policy)),
        ("Snapshot", "present" if snapshot_file().exists() else "missing"),
    ]


def channel_rows() -> list[tuple[str, str]]:
    channels = load_policy().get("channels", {})
    if not isinstance(channels, dict):
        channels = {}
    rows = []
    for name in DNS_CHANNELS:
        channel = channels.get(name, {})
        resolvers = channel.get("resolvers", []) if isinstance(channel, dict) else []
        enabled = [
            resolver
            for resolver in resolvers
            if isinstance(resolver, dict) and resolver.get("enabled", True)
        ]
        rows.append((name, f"{len(enabled)}/{len(resolvers)} enabled"))
    return rows


def status_command(json_output: bool = False) -> str:
    args = ["dns", "status"]
    if json_output:
        args.append("--json")
    return _watchdog_command(args, sudo=False)


def test_command(json_output: bool = False) -> str:
    args = ["dns", "test"]
    if json_output:
        args.append("--json")
    return _watchdog_command(args, sudo=False)


def apply_dry_run_command(json_output: bool = False) -> str:
    args = ["dns", "apply", "--dry-run"]
    if json_output:
        args.append("--json")
    return _watchdog_command(args, sudo=False)


def apply_command(systemd_link: str = "") -> str:
    args = ["dns", "apply", "--yes"]
    link = systemd_link.strip()
    if link:
        args.extend(["--systemd-link", link])
    return _watchdog_command(args, sudo=True)


def reset_command() -> str:
    return _watchdog_command(["dns", "reset", "--yes"], sudo=True)


def _watchdog_command(args: list[str], sudo: bool) -> str:
    root = repo_root()
    if root is None:
        return "printf '%s\\n' 'ERROR: WatchdogVPN v2 core CLI not found'"
    env_parts = [
        f"PYTHONPATH={shlex.quote(str(root))}",
        f"WATCHDOGVPN_DNS_POLICY_FILE={shlex.quote(str(policy_file()))}",
        f"WATCHDOGVPN_DNS_SNAPSHOT_FILE={shlex.quote(str(snapshot_file()))}",
    ]
    command = [str(root / "bin" / "watchdog"), *args]
    quoted = " ".join(shlex.quote(part) for part in command)
    if sudo:
        return "sudo -n env " + " ".join(env_parts) + " " + quoted
    return "env " + " ".join(env_parts) + " " + quoted


def _channel_summary(channels: Any) -> str:
    if not isinstance(channels, dict):
        return "0/6 configured"
    return f"{len(channels)}/{len(DNS_CHANNELS)} configured"


def _ecs_summary(policy: dict[str, Any]) -> str:
    enabled = _on_off(policy.get("ecs_direct_enabled", False))
    subnet = policy.get("ecs_direct_subnet")
    return f"{enabled} ({subnet})" if subnet else enabled


def _on_off(value: Any) -> str:
    return "on" if bool(value) else "off"

