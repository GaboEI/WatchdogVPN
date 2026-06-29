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

from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType


CONFIG_PATH = Path("/tmp/watchdogvpn_singbox.json")
LOG_PATH = Path("/tmp/watchdogvpn_singbox.log")


@dataclass(slots=True)
class _BinaryPaths:
    sing_box: tuple[str, str, str] = (
        "/usr/local/bin/sing-box",
        "/usr/bin/sing-box",
        os.path.expanduser("~/.local/bin/sing-box"),
    )


class SingBoxDriver(BaseDriver):
    """sing-box integration entry point.

    Task 4.1 only covers binary detection and version inspection. Process
    management and connectivity logic are intentionally deferred to later tasks.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()
        self._process: subprocess.Popen[str] | None = None
        self._active_profile: Profile | None = None
        self._connected_at: datetime | None = None

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
        return self.find_singbox_binary() is not None

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

    def _normalize_port(self, value: Any, default: int | None = None) -> int | None:
        if value is None:
            return default
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return default

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
            return {
                "type": "vmess",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "uuid": cfg.get("uuid") or profile.id,
                "alter_id": self._normalize_port(cfg.get("alter_id"), 0) or 0,
                "security": cfg.get("security", "auto"),
            }
        if profile.protocol is ProtocolType.TROJAN:
            return {
                "type": "trojan",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "password": cfg.get("password") or profile.id,
                "tls": {
                    "enabled": True,
                    "server_name": cfg.get("sni") or cfg.get("server_name") or cfg.get("host") or cfg.get("server"),
                },
            }
        if profile.protocol is ProtocolType.HYSTERIA2:
            outbound = {
                "type": "hysteria2",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "password": cfg.get("password") or profile.id,
                "tls": {
                    "enabled": True,
                    "server_name": cfg.get("sni") or cfg.get("server_name") or cfg.get("host") or cfg.get("server"),
                },
            }
            if cfg.get("obfs"):
                outbound["obfs"] = {"type": "salamander", "password": cfg["obfs"]}
            return outbound
        if profile.protocol is ProtocolType.TUIC:
            return {
                "type": "tuic",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "uuid": cfg.get("uuid") or profile.id,
                "password": cfg.get("password") or profile.id,
                "congestion_control": cfg.get("congestion_control", "bbr"),
                "tls": {
                    "enabled": True,
                    "server_name": cfg.get("sni") or cfg.get("server_name") or cfg.get("host") or cfg.get("server"),
                },
            }
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
            return {
                "type": "wireguard",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "local_address": cfg.get("local_address") or cfg.get("address") or [],
                "private_key": cfg.get("private_key"),
                "peer_public_key": cfg.get("public_key"),
                "reserved": cfg.get("reserved", []),
            }
        if profile.protocol is ProtocolType.SOCKS:
            return {
                "type": "socks",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "version": cfg.get("version", "5"),
                "username": cfg.get("username"),
                "password": cfg.get("password"),
            }
        if profile.protocol is ProtocolType.HTTP:
            return {
                "type": "http",
                "tag": profile.name,
                "server": cfg.get("host") or cfg.get("server"),
                "server_port": self._normalize_port(cfg.get("port") or cfg.get("server_port")),
                "username": cfg.get("username"),
                "password": cfg.get("password"),
            }
        raise ValueError(f"unsupported protocol for sing-box: {profile.protocol.value}")

    def _write_config(self, config: dict[str, Any]) -> None:
        CONFIG_PATH.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")

    def _cleanup_config(self) -> None:
        if CONFIG_PATH.exists():
            CONFIG_PATH.unlink()

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

    def _http_via_proxy(self, target_url: str, timeout: int = 5) -> bool:
        if not shutil.which("curl"):
            with LOG_PATH.open("a", encoding="utf-8") as log_file:
                log_file.write("health_check: curl not found\n")
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
            with LOG_PATH.open("a", encoding="utf-8") as log_file:
                log_file.write(f"health_check: curl exited {result.returncode}")
                if error:
                    log_file.write(f": {error}")
                log_file.write("\n")
        return result.returncode == 0

    def generate_singbox_config(self, profile: Profile) -> dict[str, Any]:
        config = {
            "log": {"level": "warning"},
            "inbounds": self._build_inbounds(),
            "outbounds": [self._protocol_to_outbound(profile)],
        }
        self._write_config(config)
        return config

    def connect(self, profile: Profile) -> bool:
        binary = self.find_singbox_binary()
        if not binary:
            return False
        self.generate_singbox_config(profile)
        log_file = LOG_PATH.open("w", encoding="utf-8")
        self._process = subprocess.Popen(
            [binary, "run", "-c", str(CONFIG_PATH)],
            text=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        log_file.close()
        self._active_profile = profile
        if self._process.poll() is None:
            self._connected_at = datetime.now(timezone.utc)
            return True
        self._connected_at = None
        return False

    def disconnect(self) -> bool:
        process = self._process
        self._process = None
        self._active_profile = None
        self._connected_at = None
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            self._cleanup_config()
        return True

    def health_check(self) -> str:
        process = self._process
        if process is None or process.poll() is not None:
            return "down"

        ports_ok = self._wait_for_proxy_port()
        if not ports_ok:
            with LOG_PATH.open("a", encoding="utf-8") as log_file:
                log_file.write("health_check: local proxy ports are not responding\n")
            return "degraded"

        proxy_ok = self._http_via_proxy("https://example.com")
        if proxy_ok:
            return "ok"
        return "degraded"

    def status(self) -> ConnectionState:
        process = self._process
        if process is None:
            return ConnectionState(status="standby")
        if process.poll() is None:
            profile_id = self._active_profile.id if self._active_profile else ""
            return ConnectionState(
                active_profile_id=profile_id,
                connected_at=self._connected_at,
                mode="sing-box",
                tun_active=True,
                proxy_active=True,
                status="connected",
            )
        return ConnectionState(status="standby")
