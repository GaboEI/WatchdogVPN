from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config.state_manager import ALLOWED_ACTIVE_MODES
from dns.models import DNSPolicy
from dns.singbox import (
    build_dns_hijack_inbounds,
    build_dns_hijack_route,
    build_singbox_dns_config,
)
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
        self._runtime_dir: Path | None = None
        self._config_path: Path | None = None
        self._log_path: Path | None = None
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

    def _build_inbounds(self) -> list[dict[str, Any]]:
        return [
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

    def _build_tun_inbound(self) -> dict[str, Any]:
        return {
            "type": "tun",
            "tag": "watchdogvpn-tun-in",
            "interface_name": "wdvpn-tun0",
            "address": ["172.19.0.1/30"],
            "auto_route": True,
            "stack": "system",
        }

    def _ensure_direct_outbound(
        self, config: dict[str, Any], domain_resolver: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        for outbound in config["outbounds"]:
            if outbound.get("tag") == "direct":
                if domain_resolver is not None:
                    outbound["domain_resolver"] = domain_resolver
                return outbound
        direct_outbound: dict[str, Any] = {"type": "direct", "tag": "direct"}
        if domain_resolver is not None:
            direct_outbound["domain_resolver"] = domain_resolver
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
        final_policy: str = "current_profile",
    ) -> dict[str, Any]:
        if mode not in ALLOWED_ACTIVE_MODES:
            raise ValueError(f"unsupported connection mode: {mode!r}")
        if final_policy not in SIMPLE_RULE_ACTIONS:
            raise ValueError(f"unsupported final_policy: {final_policy!r}")

        outbound = self._protocol_to_outbound(profile)
        self._apply_dialer_options(outbound, profile)
        config: dict[str, Any] = {
            "log": {"level": "warning"},
            "inbounds": self._build_inbounds(),
            "outbounds": [outbound],
        }
        if mode == "tun":
            config["inbounds"].append(self._build_tun_inbound())
        if dns_policy is not None:
            dns_config = build_singbox_dns_config(dns_policy, outbound["tag"])
            if dns_config is not None:
                config["dns"] = dns_config.config
                config["inbounds"].extend(build_dns_hijack_inbounds(dns_policy))
                hijack_route = build_dns_hijack_route(dns_policy)
                if hijack_route is not None:
                    _merge_route_config(config, hijack_route)
                if dns_config.proxy_domain_resolver is not None:
                    outbound["domain_resolver"] = dns_config.proxy_domain_resolver
                if dns_config.direct_domain_resolver is not None:
                    self._ensure_direct_outbound(config, dns_config.direct_domain_resolver)

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
            self._ensure_direct_outbound(config)
        mode_route_rules = build_singbox_route_rules(
            effective_groups,
            current_outbound_tag=outbound["tag"],
            final_policy=effective_final_policy,
        )
        _merge_route_config(config, {"rules": mode_route_rules})

        self._write_config(config)
        return config

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups: list[RuleGroup] | None = None,
        final_policy: str = "current_profile",
    ) -> bool:
        binary = self.find_singbox_binary()
        if not binary:
            return False
        self.generate_singbox_config(
            profile,
            dns_policy=dns_policy,
            mode=mode,
            groups=groups,
            final_policy=final_policy,
        )
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
        if self._process.poll() is None and self.health_check() == "ok":
            self._connected_at = datetime.now(timezone.utc)
            return True
        self._connected_at = None
        self._active_profile = None
        self.disconnect()
        return False

    def disconnect(self) -> bool:
        process = self._process
        self._process = None
        self._active_profile = None
        self._connected_at = None
        self._active_mode = "global"
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

        if self._active_mode == "tun":
            if self._wait_for_tun_interface():
                return "ok"
            self._append_log("health_check: TUN interface is not active\n")
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
            tun_active = self._active_mode == "tun" and self._tun_interface_active()
            return ConnectionState(
                active_profile_id=profile_id,
                connected_at=self._connected_at,
                mode="sing-box",
                tun_active=tun_active,
                proxy_active=self._active_mode != "tun",
                status="connected",
            )
        return ConnectionState(status="standby")
