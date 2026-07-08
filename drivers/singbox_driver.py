from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app_policy.models import AppPolicy
from config.state_manager import ALLOWED_ACTIVE_MODES
from dns.models import DNSChannelName, DNSPolicy
from dns.singbox import (
    build_dns_hijack_inbounds,
    build_dns_hijack_route,
    build_singbox_dns_config,
)
from config.lan_sharing import LANGatewayRuntimeConfig, LANProxyRuntimeConfig
from drivers.base import BaseDriver
from drivers.runtime_paths import cleanup_stale_runtime_dirs, make_runtime_dir, write_private_file
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType
from rules.models import SIMPLE_RULE_ACTIONS, RuleGroup
from rules.singbox import build_singbox_route_rules


RUNTIME_PREFIX = "watchdogvpn-singbox-"
CONFIG_NAME = "singbox.json"
LOG_NAME = "singbox.log"
PUBLIC_IP_ENDPOINT = "https://api.ipify.org"
DISABLE_BIND_VALUES = {"", "0", "false", "no", "off", "none"}
DEFAULT_RULE_TABLES = {"local", "main", "default"}
SING_BOX_AUTO_REDIRECT_MARKS = {"0x2023", "0x2024"}
LAN_GATEWAY_NFT_TABLE = "watchdogvpn_lan_gateway"
LAN_GATEWAY_FORWARD_CHAIN = "forward"
LAN_GATEWAY_POSTROUTING_CHAIN = "postrouting"
IPV4_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")
VIRTUAL_INTERFACE_PREFIXES = (
    "lo",
    "tun",
    "tap",
    "wg",
    "ppp",
    "tailscale",
    "zt",
    "docker",
    "br-",
    "veth",
    "virbr",
    "podman",
)


def _merge_route_config(config: dict[str, Any], route_config: dict[str, Any]) -> None:
    route = config.setdefault("route", {})
    route.setdefault("rules", [])
    route["rules"].extend(route_config.get("rules", []))
    if route_config.get("rule_set"):
        route.setdefault("rule_set", [])
        route["rule_set"].extend(route_config["rule_set"])


def _app_policy_dns_rules(
    app_policy: AppPolicy | None,
    dns_config: Any,
) -> list[dict[str, Any]]:
    if app_policy is None or not app_policy.enabled:
        return []

    direct_server = _first_dns_server(dns_config, DNSChannelName.DIRECT)
    proxy_server = dns_config.proxy_domain_resolver or _first_dns_server(
        dns_config,
        DNSChannelName.PROXY,
    )
    final_server = dns_config.config.get("final")

    rules: list[dict[str, Any]] = []
    for rule in app_policy.rules:
        if not rule.enabled:
            continue
        dns_rule: dict[str, Any] = {
            key: list(values) for key, values in rule.match.items()
        }
        action = rule.action.value if hasattr(rule.action, "value") else str(rule.action)
        if action == "block":
            dns_rule["action"] = "reject"
        elif action == "direct":
            if direct_server:
                dns_rule["server"] = direct_server
            else:
                dns_rule["action"] = "reject"
        elif proxy_server or final_server:
            dns_rule["server"] = proxy_server or final_server
        if "server" in dns_rule or "action" in dns_rule:
            rules.append(dns_rule)
    return rules


def _first_dns_server(dns_config: Any, channel_name: DNSChannelName) -> str | None:
    tags = dns_config.channel_servers.get(channel_name)
    return tags[0] if tags else None


@dataclass(slots=True)
class _BinaryPaths:
    sing_box: tuple[str, str, str] = (
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        os.path.expanduser("~/.local/bin/sing-box"),
    )


class SingBoxDriver(BaseDriver):
    """sing-box integration entry point.

    Handles binary/version checks, per-run config generation, process lifecycle,
    and proxy readiness validation for sing-box backed profiles.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()
        self._process: subprocess.Popen[str] | None = None
        self._active_profile: Profile | None = None
        self._connected_at: datetime | None = None
        self._active_mode: str = "global"
        self._tun_expected: bool = False
        self._runtime_dir: Path | None = None
        self._config_path: Path | None = None
        self._log_path: Path | None = None
        self._tun_rule_baseline: tuple[str, ...] = ()
        self._tun_cleanup_rule_prefs: tuple[str, ...] = ()
        self._tun_cleanup_route_tables: tuple[str, ...] = ()
        self._lan_gateway_active: LANGatewayRuntimeConfig | None = None
        self._lan_gateway_ip_forward_snapshot: str | None = None
        cleanup_stale_runtime_dirs(RUNTIME_PREFIX)

    def find_singbox_binary(self) -> str | None:
        env_binary = os.environ.get("WATCHDOGVPN_SINGBOX_BIN")
        if env_binary and os.path.exists(env_binary) and os.access(env_binary, os.X_OK):
            return env_binary
        for candidate in self.binaries.sing_box:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return shutil.which("sing-box")

    def check_version(self) -> str:
        binary = self.find_singbox_binary()
        if not binary:
            raise FileNotFoundError("sing-box binary not found")
        result = subprocess.run([binary, "version"], text=True, capture_output=True, check=False)
        output = (result.stdout or result.stderr or "").strip()
        if not output:
            raise RuntimeError("sing-box version output is empty")
        return output

    def is_available(self) -> bool:
        try:
            return bool(self.check_version())
        except (FileNotFoundError, RuntimeError):
            return False

    def _build_inbounds(
        self,
        lan_proxy: LANProxyRuntimeConfig | None = None,
    ) -> list[dict[str, Any]]:
        inbounds: list[dict[str, Any]] = [
            {
                "type": "socks",
                "tag": "watchdogvpn-socks-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            },
            {
                "type": "http",
                "tag": "watchdogvpn-http-in",
                "listen": "127.0.0.1",
                "listen_port": 2081,
            },
        ]
        if lan_proxy is not None:
            user = {
                "username": lan_proxy.username,
                "password": lan_proxy.password,
            }
            inbounds.extend(
                [
                    {
                        "type": "socks",
                        "tag": "watchdogvpn-lan-socks-in",
                        "listen": lan_proxy.bind_address,
                        "listen_port": lan_proxy.socks_port,
                        "users": [dict(user)],
                    },
                    {
                        "type": "http",
                        "tag": "watchdogvpn-lan-http-in",
                        "listen": lan_proxy.bind_address,
                        "listen_port": lan_proxy.http_port,
                        "users": [dict(user)],
                        "set_system_proxy": False,
                    },
                ]
            )
        return inbounds

    def _build_tun_inbound(self) -> dict[str, Any]:
        return {
            "type": "tun",
            "tag": "watchdogvpn-tun-in",
            "interface_name": "wdvpn-tun0",
            "address": ["172.19.0.1/30"],
            "auto_route": True,
            "strict_route": True,
            "auto_redirect": True,
            "stack": "system",
        }

    def _mode_requires_tun(self, mode: str, app_policy: AppPolicy | None = None) -> bool:
        return mode == "tun" or (mode == "rules" and app_policy is not None and app_policy.enabled)

    def _ensure_direct_outbound(
        self,
        config: dict[str, Any],
        domain_resolver: dict[str, Any] | None = None,
        bind_interface: str | None = None,
    ) -> dict[str, Any]:
        for outbound in config["outbounds"]:
            if outbound.get("tag") == "direct":
                if domain_resolver is not None:
                    outbound["domain_resolver"] = domain_resolver
                if bind_interface is not None:
                    outbound.setdefault("bind_interface", bind_interface)
                return outbound
        direct_outbound: dict[str, Any] = {"type": "direct", "tag": "direct"}
        if domain_resolver is not None:
            direct_outbound["domain_resolver"] = domain_resolver
        if bind_interface is not None:
            direct_outbound["bind_interface"] = bind_interface
        config["outbounds"].append(direct_outbound)
        return direct_outbound

    def _normalize_port(self, value: Any, default: int | None = None) -> int | None:
        if value is None:
            return default
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return default

    def _normalize_list(self, value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return [value]

    def _first_config_value(self, cfg: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            value = cfg.get(key)
            if value not in (None, ""):
                return value
        return None

    def _normalize_alpn(self, value: Any) -> list[str] | None:
        alpn = [str(item) for item in self._normalize_list(value) if str(item)]
        return alpn or None

    def _split_endpoint(self, endpoint: Any) -> tuple[str | None, int | None]:
        if not isinstance(endpoint, str) or not endpoint.strip():
            return None, None
        value = endpoint.strip()
        if value.startswith("[") and "]:" in value:
            host, port = value[1:].split("]:", 1)
            return host, self._normalize_port(port)
        if ":" not in value:
            return value, None
        host, port = value.rsplit(":", 1)
        return host, self._normalize_port(port)

    def _truthy_config(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return False

    def _vmess_tls_enabled(self, cfg: dict[str, Any]) -> bool:
        tls_value = cfg.get("tls")
        if isinstance(tls_value, bool):
            return tls_value
        if isinstance(tls_value, str):
            return tls_value.strip().lower() in {"1", "true", "yes", "on", "tls"}
        return False

    def _build_standard_tls_options(self, cfg: dict[str, Any], default_server: Any) -> dict[str, Any]:
        tls_options: dict[str, Any] = {
            "enabled": True,
            "server_name": self._first_config_value(cfg, "sni", "server_name") or default_server,
        }
        if self._truthy_config(self._first_config_value(cfg, "insecure", "allow_insecure", "allowInsecure")):
            tls_options["insecure"] = True
        fingerprint = self._first_config_value(cfg, "fingerprint", "fp")
        if fingerprint:
            tls_options["utls"] = {"enabled": True, "fingerprint": fingerprint}
        alpn = self._normalize_alpn(cfg.get("alpn"))
        if alpn:
            tls_options["alpn"] = alpn
        return tls_options

    def _build_v2ray_transport(self, cfg: dict[str, Any]) -> dict[str, Any] | None:
        network = str(self._first_config_value(cfg, "network", "net") or "tcp").lower()
        if network in {"", "tcp"}:
            return None

        transport: dict[str, Any] = {"type": network}
        if network in {"ws", "websocket"}:
            transport["type"] = "ws"
            path = cfg.get("path")
            if path:
                transport["path"] = path
            host_header = self._first_config_value(cfg, "transport_host", "host_header", "ws_host")
            if host_header:
                transport["headers"] = {"Host": host_header}
        elif network == "grpc":
            service_name = self._first_config_value(cfg, "service_name", "serviceName", "grpc_service_name")
            if service_name:
                transport["service_name"] = service_name
        elif network in {"http", "h2"}:
            transport["type"] = "http"
            path = cfg.get("path")
            if path:
                transport["path"] = path
            host_header = self._first_config_value(cfg, "transport_host", "host_header")
            if host_header:
                transport["host"] = self._normalize_list(host_header)
        return transport

    def _is_physical_interface(self, name: str) -> bool:
        return bool(name) and not name.startswith(VIRTUAL_INTERFACE_PREFIXES)

    def _detect_default_interface(self) -> str | None:
        if not shutil.which("ip"):
            return None
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" not in parts:
                continue
            interface = parts[parts.index("dev") + 1]
            if self._is_physical_interface(interface):
                return interface
        return None

    def _outbound_bind_interface(self, profile: Profile) -> str | None:
        configured = profile.config.get("bind_interface")
        if isinstance(configured, str):
            value = configured.strip()
            if value.lower() in DISABLE_BIND_VALUES:
                return None
            return value

        env_value = os.environ.get("WATCHDOGVPN_SINGBOX_BIND_INTERFACE", "auto").strip()
        if env_value.lower() in DISABLE_BIND_VALUES:
            return None
        if env_value.lower() != "auto":
            return env_value
        return self._detect_default_interface()

    def _apply_dialer_options(self, outbound: dict[str, Any], profile: Profile) -> dict[str, Any]:
        bind_interface = self._outbound_bind_interface(profile)
        if bind_interface:
            outbound["bind_interface"] = bind_interface
        return outbound

    def _protocol_to_outbound(self, profile: Profile) -> dict[str, Any]:
        cfg = profile.config
        if profile.protocol is ProtocolType.VLESS:
            outbound: dict[str, Any] = {
                "type": "vless",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "uuid": cfg.get("uuid") or profile.id,
                "flow": cfg.get("flow"),
                "network": cfg.get("network") or cfg.get("type") or "tcp",
            }
            security = cfg.get("security") or cfg.get("transport")
            if security:
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": cfg.get("sni") or cfg.get("server_name") or outbound["server"],
                    "utls": {"enabled": True, "fingerprint": cfg.get("fingerprint") or cfg.get("fp") or "chrome"},
                }
            reality_public_key = cfg.get("reality_public_key") or cfg.get("public_key") or cfg.get("pbk")
            short_id = cfg.get("short_id") or cfg.get("sid")
            if reality_public_key or short_id:
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": cfg.get("sni") or cfg.get("server_name") or outbound["server"],
                    "utls": {"enabled": True, "fingerprint": cfg.get("fingerprint") or cfg.get("fp") or "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": reality_public_key,
                        "short_id": short_id,
                    },
                }
            return outbound
        if profile.protocol is ProtocolType.VMESS:
            outbound = {
                "type": "vmess",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "uuid": cfg.get("uuid") or profile.id,
                "alter_id": self._normalize_port(self._first_config_value(cfg, "alter_id", "alterId", "aid"), 0) or 0,
                "security": self._first_config_value(cfg, "security", "scy") or "auto",
            }
            if self._vmess_tls_enabled(cfg):
                outbound["tls"] = self._build_standard_tls_options(cfg, outbound["server"])
            transport = self._build_v2ray_transport(cfg)
            if transport:
                outbound["transport"] = transport
            return outbound
        if profile.protocol is ProtocolType.TROJAN:
            tls_options = self._build_standard_tls_options(cfg, cfg.get("host") or cfg.get("server"))
            return {
                "type": "trojan",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "password": cfg.get("password") or profile.id,
                "tls": tls_options,
            }
        if profile.protocol is ProtocolType.HYSTERIA2:
            tls_options: dict[str, Any] = {
                "enabled": True,
                "server_name": cfg.get("sni") or cfg.get("server_name") or cfg.get("host") or cfg.get("server"),
            }
            if self._truthy_config(cfg.get("insecure") or cfg.get("allow_insecure") or cfg.get("allowInsecure")):
                tls_options["insecure"] = True
            alpn = cfg.get("alpn")
            if alpn:
                tls_options["alpn"] = alpn if isinstance(alpn, list) else [alpn]
            outbound = {
                "type": "hysteria2",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "password": cfg.get("password") or profile.id,
                "tls": tls_options,
            }
            up_mbps = self._normalize_port(cfg.get("up_mbps") or cfg.get("upload_mbps") or cfg.get("uploadMbps"))
            down_mbps = self._normalize_port(cfg.get("down_mbps") or cfg.get("download_mbps") or cfg.get("downloadMbps"))
            if up_mbps is not None:
                outbound["up_mbps"] = up_mbps
            if down_mbps is not None:
                outbound["down_mbps"] = down_mbps
            if cfg.get("obfs"):
                outbound["obfs"] = {"type": "salamander", "password": cfg["obfs"]}
            obfs_password = cfg.get("obfs_password") or cfg.get("obfs-password") or cfg.get("obfsPassword")
            if obfs_password:
                outbound["obfs"] = {"type": "salamander", "password": obfs_password}
            return outbound
        if profile.protocol is ProtocolType.TUIC:
            outbound = {
                "type": "tuic",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "uuid": cfg.get("uuid") or profile.id,
                "password": cfg.get("password") or profile.id,
                "congestion_control": cfg.get("congestion_control", "bbr"),
                "tls": self._build_standard_tls_options(cfg, cfg.get("host") or cfg.get("server")),
            }
            udp_relay_mode = self._first_config_value(cfg, "udp_relay_mode", "udpRelayMode")
            if udp_relay_mode:
                outbound["udp_relay_mode"] = udp_relay_mode
            return outbound
        if profile.protocol is ProtocolType.SHADOWSOCKS:
            return {
                "type": "shadowsocks",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "method": cfg.get("method", "chacha20-ietf-poly1305"),
                "password": cfg.get("password") or profile.id,
            }
        if profile.protocol is ProtocolType.WIREGUARD:
            endpoint_host, endpoint_port = self._split_endpoint(cfg.get("endpoint"))
            outbound = {
                "type": "wireguard",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server") or endpoint_host,
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")) or endpoint_port,
                "local_address": self._normalize_list(cfg.get("local_address") or cfg.get("address")),
                "private_key": cfg.get("private_key"),
                "peer_public_key": cfg.get("peer_public_key") or cfg.get("public_key"),
                "reserved": self._normalize_list(cfg.get("reserved")),
            }
            mtu = self._normalize_port(cfg.get("mtu"))
            if mtu is not None:
                outbound["mtu"] = mtu
            return outbound
        if profile.protocol is ProtocolType.SOCKS:
            outbound = {
                "type": "socks",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "version": cfg.get("version", "5"),
            }
            if cfg.get("username"):
                outbound["username"] = cfg["username"]
            if cfg.get("password"):
                outbound["password"] = cfg["password"]
            return outbound
        if profile.protocol is ProtocolType.HTTP:
            outbound = {
                "type": "http",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
            }
            if cfg.get("username"):
                outbound["username"] = cfg["username"]
            if cfg.get("password"):
                outbound["password"] = cfg["password"]
            return outbound
        raise ValueError(f"unsupported protocol for sing-box: {profile.protocol.value}")

    def _ensure_runtime_paths(self) -> tuple[Path, Path]:
        if self._runtime_dir is None:
            self._runtime_dir = make_runtime_dir(RUNTIME_PREFIX)
            self._config_path = self._runtime_dir / CONFIG_NAME
            self._log_path = self._runtime_dir / LOG_NAME
        return self._config_path, self._log_path  # type: ignore[return-value]

    def _write_config(self, config: dict[str, Any]) -> None:
        config_path, _ = self._ensure_runtime_paths()
        write_private_file(config_path, json.dumps(config, indent=2, sort_keys=True))

    def _cleanup_runtime(self) -> None:
        if self._runtime_dir is not None and self._runtime_dir.exists():
            shutil.rmtree(self._runtime_dir, ignore_errors=True)
        self._runtime_dir = None
        self._config_path = None
        self._log_path = None

    def _run_cleanup_command(self, command: list[str]) -> None:
        subprocess.run(
            command,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    def _run_capture_command(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    def _run_gateway_required(self, command: list[str]) -> bool:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if result.returncode == 0:
            return True
        detail = (result.stderr or result.stdout or "").strip()
        self._append_log(f"lan_gateway: command failed: {' '.join(command)} {detail}\n")
        return False

    def _gateway_nft_rule(self, *tokens: str) -> list[str]:
        return [
            "nft",
            "add",
            "rule",
            "inet",
            LAN_GATEWAY_NFT_TABLE,
            LAN_GATEWAY_FORWARD_CHAIN,
            *tokens,
        ]

    def _gateway_nat_rule(self, *tokens: str) -> list[str]:
        return [
            "nft",
            "add",
            "rule",
            "inet",
            LAN_GATEWAY_NFT_TABLE,
            LAN_GATEWAY_POSTROUTING_CHAIN,
            *tokens,
        ]

    def _read_ipv4_forward(self) -> str:
        try:
            return IPV4_FORWARD_PATH.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError("lan_gateway: cannot read net.ipv4.ip_forward") from exc

    def _write_ipv4_forward(self, value: str) -> None:
        try:
            IPV4_FORWARD_PATH.write_text(f"{value}\n", encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("lan_gateway: cannot write net.ipv4.ip_forward") from exc

    def _cleanup_lan_gateway(self, *, force_table: bool = False) -> None:
        gateway_state_seen = (
            self._lan_gateway_active is not None
            or self._lan_gateway_ip_forward_snapshot is not None
        )
        if not gateway_state_seen and not force_table:
            return
        if (gateway_state_seen or force_table) and shutil.which("nft"):
            self._run_cleanup_command(["nft", "delete", "table", "inet", LAN_GATEWAY_NFT_TABLE])
        if self._lan_gateway_ip_forward_snapshot is not None:
            try:
                self._write_ipv4_forward(self._lan_gateway_ip_forward_snapshot)
            except RuntimeError as exc:
                self._append_log(f"{exc}\n")
        self._lan_gateway_active = None
        self._lan_gateway_ip_forward_snapshot = None

    def _apply_lan_gateway(self, gateway: LANGatewayRuntimeConfig) -> bool:
        if not gateway.firewall_managed:
            self._append_log("lan_gateway: firewall_managed=false is not supported\n")
            return False
        if gateway.dns_mode != "manual":
            self._append_log("lan_gateway: only manual DNS mode is supported\n")
            return False
        if not self._tun_expected:
            self._append_log("lan_gateway: TUN capture is required\n")
            return False
        if not shutil.which("nft"):
            self._append_log("lan_gateway: nftables is required\n")
            return False

        self._cleanup_lan_gateway(force_table=True)
        try:
            self._lan_gateway_ip_forward_snapshot = self._read_ipv4_forward()
        except RuntimeError as exc:
            self._append_log(f"{exc}\n")
            return False

        commands = [
            ["nft", "add", "table", "inet", LAN_GATEWAY_NFT_TABLE],
            [
                "nft",
                "add",
                "chain",
                "inet",
                LAN_GATEWAY_NFT_TABLE,
                LAN_GATEWAY_FORWARD_CHAIN,
                "{",
                "type",
                "filter",
                "hook",
                "forward",
                "priority",
                "0;",
                "policy",
                "accept;",
                "}",
            ],
            [
                "nft",
                "add",
                "chain",
                "inet",
                LAN_GATEWAY_NFT_TABLE,
                LAN_GATEWAY_POSTROUTING_CHAIN,
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "srcnat;",
                "policy",
                "accept;",
                "}",
            ],
            self._gateway_nft_rule("ct", "state", "established,related", "accept"),
            self._gateway_nft_rule(
                "iifname",
                gateway.lan_interface,
                "oifname",
                gateway.tunnel_interface,
                "ip",
                "saddr",
                gateway.client_cidr,
                "accept",
            ),
            self._gateway_nft_rule("iifname", gateway.lan_interface, "reject"),
            self._gateway_nat_rule(
                "oifname",
                gateway.tunnel_interface,
                "ip",
                "saddr",
                gateway.client_cidr,
                "masquerade",
            ),
        ]
        for command in commands:
            if not self._run_gateway_required(command):
                self._cleanup_lan_gateway()
                return False
        try:
            self._write_ipv4_forward("1")
        except RuntimeError as exc:
            self._append_log(f"{exc}\n")
            self._cleanup_lan_gateway()
            return False
        self._lan_gateway_active = gateway
        return True

    def _ip_rule_lines(self) -> tuple[str, ...]:
        if not shutil.which("ip"):
            return ()
        result = self._run_capture_command(["ip", "rule", "show"])
        if result.returncode != 0:
            return ()
        return tuple(line.strip() for line in result.stdout.splitlines() if line.strip())

    def _route_table_output(self, table: str, ipv6: bool = False) -> str:
        if not shutil.which("ip"):
            return ""
        command = ["ip", "-6", "route", "show", "table", table] if ipv6 else [
            "ip",
            "route",
            "show",
            "table",
            table,
        ]
        result = self._run_capture_command(command)
        if result.returncode != 0:
            return ""
        return result.stdout

    def _route_table_looks_like_watchdogvpn(self, table: str) -> bool:
        output = "\n".join(
            [
                self._route_table_output(table, ipv6=False),
                self._route_table_output(table, ipv6=True),
            ]
        )
        return "wdvpn-tun0" in output or "172.19.0." in output

    def _rule_preference(self, line: str) -> str | None:
        match = re.match(r"^(\d+):", line)
        return match.group(1) if match else None

    def _rule_lookup_table(self, line: str) -> str | None:
        match = re.search(r"\blookup\s+(\S+)", line)
        if not match:
            return None
        table = match.group(1)
        if table in DEFAULT_RULE_TABLES:
            return None
        return table

    def _rule_goto_preference(self, line: str) -> str | None:
        match = re.search(r"\bgoto\s+(\d+)", line)
        return match.group(1) if match else None

    def _capture_tun_cleanup_state(self) -> None:
        current_rules = self._ip_rule_lines()
        if not current_rules:
            return

        baseline = set(self._tun_rule_baseline)
        candidate_rules = [
            line for line in current_rules if not baseline or line not in baseline
        ]
        prefs: set[str] = set()
        tables: set[str] = set()
        goto_targets: set[str] = set()
        candidate_has_singbox_marks = any(
            any(f"fwmark {mark}" in line for mark in SING_BOX_AUTO_REDIRECT_MARKS)
            for line in candidate_rules
        )

        for line in candidate_rules:
            pref = self._rule_preference(line)
            table = self._rule_lookup_table(line)
            if pref and any(f"fwmark {mark}" in line for mark in SING_BOX_AUTO_REDIRECT_MARKS):
                prefs.add(pref)
                if table is not None:
                    tables.add(table)
            elif candidate_has_singbox_marks and pref and table is not None:
                prefs.add(pref)
                tables.add(table)
            goto_pref = self._rule_goto_preference(line)
            if goto_pref is not None:
                goto_targets.add(goto_pref)

        for line in current_rules:
            pref = self._rule_preference(line)
            table = self._rule_lookup_table(line)
            if pref in goto_targets:
                prefs.add(pref)
            if table is not None and table in tables:
                prefs.add(pref)
            if table is not None and self._route_table_looks_like_watchdogvpn(table):
                if pref:
                    prefs.add(pref)
                tables.add(table)

        self._tun_cleanup_rule_prefs = tuple(sorted(prefs, key=int))
        self._tun_cleanup_route_tables = tuple(sorted(tables))

    def _discover_singbox_tun_residue(
        self,
        *,
        include_orphaned_auto_route_rule: bool = False,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        rules = self._ip_rule_lines()
        prefs: set[str] = set()
        tables: set[str] = set()
        goto_targets: set[str] = set()

        for line in rules:
            pref = self._rule_preference(line)
            if pref is None:
                continue
            if any(f"fwmark {mark}" in line for mark in SING_BOX_AUTO_REDIRECT_MARKS):
                prefs.add(pref)
                table = self._rule_lookup_table(line)
                if table is not None:
                    tables.add(table)
                goto_pref = self._rule_goto_preference(line)
                if goto_pref is not None:
                    goto_targets.add(goto_pref)

        for line in rules:
            pref = self._rule_preference(line)
            table = self._rule_lookup_table(line)
            if pref in goto_targets:
                prefs.add(pref)
            if table is not None and table in tables:
                prefs.add(pref)
            if table is not None and self._route_table_looks_like_watchdogvpn(table):
                prefs.add(pref)
                tables.add(table)
            if (
                include_orphaned_auto_route_rule
                and pref == "1"
                and table is not None
                and table.isdigit()
            ):
                prefs.add(pref)
                tables.add(table)

        return tuple(sorted(prefs, key=int)), tuple(sorted(tables))

    def _singbox_process_alive(self) -> bool:
        if not shutil.which("pgrep"):
            return False
        result = self._run_capture_command(["pgrep", "-x", "sing-box"])
        return result.returncode == 0 and bool(result.stdout.strip())

    def _clear_tun_cleanup_state(self) -> None:
        self._tun_rule_baseline = ()
        self._tun_cleanup_rule_prefs = ()
        self._tun_cleanup_route_tables = ()

    def reconcile_stale_tun_state(self) -> None:
        """Clean orphaned sing-box TUN state when no sing-box process is alive."""
        if self._singbox_process_alive():
            return
        rule_prefs, route_tables = self._discover_singbox_tun_residue(
            include_orphaned_auto_route_rule=True,
        )
        if not rule_prefs and not route_tables:
            return
        self._tun_cleanup_rule_prefs = rule_prefs
        self._tun_cleanup_route_tables = route_tables
        self._cleanup_tun_residue()

    def _cleanup_tun_residue(self) -> None:
        """Best-effort cleanup for sing-box TUN state after child crashes."""
        rule_prefs = self._tun_cleanup_rule_prefs
        route_tables = self._tun_cleanup_route_tables
        if not rule_prefs and not route_tables:
            rule_prefs, route_tables = self._discover_singbox_tun_residue()

        if (rule_prefs or route_tables) and shutil.which("nft"):
            self._run_cleanup_command(["nft", "delete", "table", "inet", "sing-box"])

        if shutil.which("ip"):
            for preference in rule_prefs:
                self._run_cleanup_command(["ip", "rule", "del", "pref", preference])
            for table in route_tables:
                self._run_cleanup_command(["ip", "route", "flush", "table", table])
                self._run_cleanup_command(["ip", "-6", "route", "flush", "table", table])
        self._clear_tun_cleanup_state()

    def _append_log(self, message: str) -> None:
        _, log_path = self._ensure_runtime_paths()
        with log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(message)

    def _port_open(self, host: str, port: int, timeout: float = 1.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _wait_for_proxy_port(self, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._port_open("127.0.0.1", 2080) or self._port_open("127.0.0.1", 2081):
                return True
            time.sleep(0.1)
        return False

    def _tun_interface_active(self) -> bool:
        if not shutil.which("ip"):
            return False
        result = subprocess.run(
            ["ip", "-o", "link", "show", "wdvpn-tun0"],
            text=True,
            capture_output=True,
            check=False,
        )
        return result.returncode == 0 and "UP" in result.stdout

    def _wait_for_tun_interface(self, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._tun_interface_active():
                return True
            time.sleep(0.1)
        return False

    def _singbox_auto_redirect_ready(self) -> bool:
        if not shutil.which("nft"):
            return False
        result = self._run_capture_command(["nft", "list", "table", "inet", "sing-box"])
        if result.returncode != 0:
            return False
        output = result.stdout
        if "table inet sing-box" not in output:
            return False
        chain_count = len(re.findall(r"\bchain\s+\S+", output))
        has_base_hook = "hook output" in output or "hook prerouting" in output
        return chain_count >= 2 and has_base_hook

    def _wait_for_tun_auto_redirect_ready(self, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            process = self._process
            if process is None or process.poll() is not None:
                self._append_log("health_check: sing-box exited before TUN auto_redirect readiness\n")
                return False
            if self._singbox_auto_redirect_ready():
                return process.poll() is None
            time.sleep(0.1)
        return False

    def _http_via_proxy(self, target_url: str, timeout: int = 5) -> bool:
        if not shutil.which("curl"):
            self._append_log("health_check: curl not found\n")
            return False
        result = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                str(timeout),
                "--socks5-hostname",
                "127.0.0.1:2080",
                target_url,
            ],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            error = (result.stderr or "").strip()
            message = f"health_check: curl exited {result.returncode}"
            if error:
                message += f": {error}"
            self._append_log(f"{message}\n")
        return result.returncode == 0

    def _public_ip_via_proxy(self, timeout: int = 5) -> str | None:
        if not shutil.which("curl"):
            self._append_log("health_check: curl not found for public IP check\n")
            return None
        result = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                str(timeout),
                "--socks5-hostname",
                "127.0.0.1:2080",
                PUBLIC_IP_ENDPOINT,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        output = (result.stdout or "").strip()
        error = (result.stderr or "").strip()
        if result.returncode == 0 and output:
            self._append_log(f"health_check: public_ip_via_proxy={output}\n")
            return output
        message = f"health_check: public IP check exited {result.returncode}"
        if error:
            message += f": {error}"
        self._append_log(f"{message}\n")
        return None

    def generate_singbox_config(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups: list[RuleGroup] | None = None,
        app_policy: AppPolicy | None = None,
        final_policy: str = "current_profile",
        rule_set_tags: dict[str, str] | None = None,
        rule_set_declarations: list[dict[str, str]] | None = None,
        lan_proxy: LANProxyRuntimeConfig | None = None,
    ) -> dict[str, Any]:
        if mode not in ALLOWED_ACTIVE_MODES:
            raise ValueError(f"unsupported connection mode: {mode!r}")
        if final_policy not in SIMPLE_RULE_ACTIONS:
            raise ValueError(f"unsupported final_policy: {final_policy!r}")

        outbound = self._protocol_to_outbound(profile)
        self._apply_dialer_options(outbound, profile)
        config: dict[str, Any] = {
            "log": {"level": "warning"},
            "inbounds": self._build_inbounds(lan_proxy),
            "outbounds": [outbound],
        }
        if self._mode_requires_tun(mode, app_policy):
            config["inbounds"].append(self._build_tun_inbound())
        if dns_policy is not None:
            dns_config = build_singbox_dns_config(dns_policy, outbound["tag"])
            if dns_config is not None:
                dns_config.config["rules"] = [
                    *_app_policy_dns_rules(
                        app_policy if mode == "rules" else None,
                        dns_config,
                    ),
                    *dns_config.config.get("rules", []),
                ]
                config["dns"] = dns_config.config
                config["inbounds"].extend(build_dns_hijack_inbounds(dns_policy))
                hijack_route = build_dns_hijack_route(dns_policy)
                if hijack_route is not None:
                    _merge_route_config(config, hijack_route)
                # The profile's own outbound must resolve its own server
                # hostname via a resolver that does not itself dial through
                # this same outbound — otherwise resolving the server's
                # hostname requires the tunnel, which requires resolving the
                # server's hostname first (sing-box correctly rejects this as
                # a DNS query loopback). FakeIP is also unsafe here: it is a
                # synthetic placeholder meant for client-facing DNS
                # interception, not a real dialable address for an
                # outbound's own connection target. Both failure modes were
                # confirmed via live traffic reproduction with sing-box
                # debug logs (Task 12.5) — prefer the direct/bootstrap
                # channel (never proxied), and only fall back to "final" if
                # it does not resolve to the proxy channel itself.
                outbound_resolver: str | None = None
                for bootstrap_channel in (DNSChannelName.DIRECT, DNSChannelName.BOOTSTRAP):
                    tags = dns_config.channel_servers.get(bootstrap_channel)
                    if tags:
                        outbound_resolver = tags[0]
                        break
                if outbound_resolver is None:
                    final_resolver = dns_config.config.get("final")
                    proxy_tags = dns_config.channel_servers.get(DNSChannelName.PROXY, ())
                    if final_resolver and final_resolver not in proxy_tags:
                        outbound_resolver = final_resolver
                if outbound_resolver:
                    outbound["domain_resolver"] = outbound_resolver
                    config.setdefault("route", {}).setdefault(
                        "default_domain_resolver", outbound_resolver
                    )
                needs_direct_outbound = dns_config.direct_domain_resolver is not None or any(
                    name != DNSChannelName.PROXY for name in dns_config.channel_servers
                )
                if needs_direct_outbound:
                    self._ensure_direct_outbound(
                        config,
                        dns_config.direct_domain_resolver,
                        bind_interface=self._outbound_bind_interface(profile),
                    )

        # "rules" mode evaluates the loaded rule groups; every other mode
        # routes everything to the current outbound ("direct" mode further
        # overrides the effective final policy to "direct" instead of
        # whatever final_policy the caller passed). Merged AFTER the DNS
        # hijack route above so the hijack rule (scoped to its own inbound
        # tags) is checked before this block's unconditional catch-all rule
        # — reversing that order would make the hijack rule unreachable.
        if mode == "rules":
            effective_groups = groups or []
            effective_final_policy = final_policy
        else:
            effective_groups = []
            effective_final_policy = "direct" if mode == "direct" else "current_profile"
        if mode in {"rules", "direct"}:
            self._ensure_direct_outbound(
                config, bind_interface=self._outbound_bind_interface(profile)
            )
        mode_route_rules = build_singbox_route_rules(
            effective_groups,
            current_outbound_tag=outbound["tag"],
            app_policy=app_policy if mode == "rules" else None,
            final_policy=effective_final_policy,
            rule_set_tags=rule_set_tags if mode == "rules" else None,
        )
        route_config: dict[str, Any] = {"rules": mode_route_rules}
        if mode == "rules" and rule_set_declarations:
            route_config["rule_set"] = list(rule_set_declarations)
        _merge_route_config(config, route_config)

        self._write_config(config)
        return config

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups: list[RuleGroup] | None = None,
        app_policy: AppPolicy | None = None,
        final_policy: str = "current_profile",
        rule_set_tags: dict[str, str] | None = None,
        rule_set_declarations: list[dict[str, str]] | None = None,
        lan_proxy: LANProxyRuntimeConfig | None = None,
        lan_gateway: LANGatewayRuntimeConfig | None = None,
    ) -> bool:
        binary = self.find_singbox_binary()
        if not binary:
            return False
        tun_expected = self._mode_requires_tun(mode, app_policy)
        self._clear_tun_cleanup_state()
        if tun_expected:
            self._tun_rule_baseline = self._ip_rule_lines()
        config_kwargs: dict[str, Any] = {
            "dns_policy": dns_policy,
            "mode": mode,
            "groups": groups,
            "app_policy": app_policy,
            "final_policy": final_policy,
            "rule_set_tags": rule_set_tags,
            "rule_set_declarations": rule_set_declarations,
        }
        if lan_proxy is not None:
            config_kwargs["lan_proxy"] = lan_proxy
        self.generate_singbox_config(profile, **config_kwargs)
        config_path, log_path = self._ensure_runtime_paths()
        log_file = log_path.open("w", encoding="utf-8")
        self._process = subprocess.Popen(
            [binary, "run", "-c", str(config_path)],
            text=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        log_file.close()
        self._active_profile = profile
        self._active_mode = mode
        self._tun_expected = tun_expected
        if self._process.poll() is None and self.health_check() == "ok":
            if self._tun_expected:
                self._capture_tun_cleanup_state()
            if lan_gateway is not None and not self._apply_lan_gateway(lan_gateway):
                self._connected_at = None
                self._active_profile = None
                self.disconnect()
                return False
            self._connected_at = datetime.now(timezone.utc)
            return True
        self._connected_at = None
        self._active_profile = None
        if self._tun_expected:
            self._capture_tun_cleanup_state()
        self.disconnect()
        return False

    def disconnect(self) -> bool:
        process = self._process
        cleanup_tun_residue = self._tun_expected
        if cleanup_tun_residue:
            self._capture_tun_cleanup_state()
        self._process = None
        self._active_profile = None
        self._connected_at = None
        self._active_mode = "global"
        self._tun_expected = False
        stopped = True
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        stopped = False
                        return False
        finally:
            self._cleanup_lan_gateway()
            process_stopped = process is None or process.poll() is not None
            if cleanup_tun_residue and process_stopped:
                self._cleanup_tun_residue()
            self._cleanup_runtime()
        return stopped

    def health_check(self) -> str:
        process = self._process
        if process is None or process.poll() is not None:
            return "down"

        ports_ok = self._wait_for_proxy_port()
        if not ports_ok:
            self._append_log("health_check: local proxy ports are not responding\n")
            return "degraded"

        if self._tun_expected:
            if not self._wait_for_tun_interface():
                self._append_log("health_check: TUN interface is not active\n")
                return "degraded"
            if self._wait_for_tun_auto_redirect_ready():
                return "ok"
            self._append_log("health_check: TUN auto_redirect nftables state is not ready\n")
            return "degraded"

        proxy_ok = self._http_via_proxy("https://example.com")
        public_ip = self._public_ip_via_proxy() if proxy_ok else None
        if proxy_ok and public_ip:
            return "ok"
        return "degraded"

    def status(self) -> ConnectionState:
        process = self._process
        if process is None:
            return ConnectionState(status="standby")
        if process.poll() is None:
            profile_id = self._active_profile.id if self._active_profile else ""
            tun_active = self._tun_expected and self._tun_interface_active()
            return ConnectionState(
                active_profile_id=profile_id,
                connected_at=self._connected_at,
                mode="sing-box",
                tun_active=tun_active,
                proxy_active=True,
                lan_gateway_active=self._lan_gateway_active is not None,
                lan_gateway_interface=(
                    self._lan_gateway_active.lan_interface if self._lan_gateway_active else ""
                ),
                lan_gateway_client_cidr=(
                    self._lan_gateway_active.client_cidr if self._lan_gateway_active else ""
                ),
                lan_gateway_dns_mode=(
                    self._lan_gateway_active.dns_mode if self._lan_gateway_active else ""
                ),
                status="connected",
            )
        if self._tun_expected:
            self._capture_tun_cleanup_state()
            self._cleanup_tun_residue()
        self._process = None
        self._active_profile = None
        self._connected_at = None
        self._active_mode = "global"
        self._tun_expected = False
        self._cleanup_runtime()
        return ConnectionState(status="standby")
