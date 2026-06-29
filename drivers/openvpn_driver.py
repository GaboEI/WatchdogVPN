from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType


CONFIG_PATH = Path("/tmp/watchdogvpn_openvpn.conf")
LOG_PATH = Path("/tmp/watchdogvpn_openvpn.log")


@dataclass(slots=True)
class _BinaryPaths:
    openvpn: tuple[str, str, str, str] = (
        "/usr/sbin/openvpn",
        "/usr/bin/openvpn",
        "/usr/local/sbin/openvpn",
        "/usr/local/bin/openvpn",
    )


class OpenVPNDriver(BaseDriver):
    """Compatibility driver for plain OpenVPN profiles.

    Plain OpenVPN is intentionally not treated as a resilient anti-DPI protocol.
    OpenVPN+Cloak/OverCloud belongs to the later wrapped-driver phase.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()
        self._process: subprocess.Popen[str] | None = None
        self._active_profile: Profile | None = None
        self._connected_at: datetime | None = None

    def find_openvpn_binary(self) -> str | None:
        env_binary = os.environ.get("WATCHDOGVPN_OPENVPN_BIN")
        if env_binary and os.path.exists(env_binary) and os.access(env_binary, os.X_OK):
            return env_binary
        for candidate in self.binaries.openvpn:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return shutil.which("openvpn")

    def check_version(self) -> str:
        binary = self.find_openvpn_binary()
        if not binary:
            raise FileNotFoundError("openvpn binary not found")
        result = subprocess.run([binary, "--version"], text=True, capture_output=True, check=False)
        output = (result.stdout or result.stderr or "").strip()
        if not output:
            raise RuntimeError("openvpn version output is empty")
        return output

    def is_available(self) -> bool:
        return self.find_openvpn_binary() is not None

    def generate_openvpn_config(self, profile: Profile) -> str:
        if profile.protocol is not ProtocolType.OPENVPN:
            raise ValueError(f"unsupported protocol for OpenVPN driver: {profile.protocol.value}")
        wrapper = profile.config.get("wrapper") or profile.config.get("transport_wrapper")
        if wrapper:
            raise ValueError("wrapped OpenVPN profiles are not handled by the plain OpenVPN driver")
        raw_config = str(profile.config.get("raw_config") or "").strip()
        if not raw_config:
            raise ValueError("OpenVPN profile requires raw_config")
        CONFIG_PATH.write_text(f"{raw_config}\n", encoding="utf-8")
        return raw_config

    def _cleanup_config(self) -> None:
        if CONFIG_PATH.exists():
            CONFIG_PATH.unlink()

    def _vpn_interface_active(self, profile: Profile | None = None) -> bool:
        if not shutil.which("ip"):
            return False
        result = subprocess.run(["ip", "-o", "link", "show"], text=True, capture_output=True, check=False)
        if result.returncode != 0:
            return False
        configured_dev = ""
        if profile is not None:
            configured_dev = str(profile.config.get("dev") or "").strip()
        for line in result.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) < 2:
                continue
            interface = parts[1].strip()
            if configured_dev and interface == configured_dev:
                return True
            if not configured_dev and (interface.startswith("tun") or interface.startswith("tap")):
                return True
        return False

    def connect(self, profile: Profile) -> bool:
        binary = self.find_openvpn_binary()
        if not binary:
            return False
        self.generate_openvpn_config(profile)
        log_file = LOG_PATH.open("w", encoding="utf-8")
        self._process = subprocess.Popen(
            [binary, "--config", str(CONFIG_PATH)],
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
        if self._vpn_interface_active(self._active_profile):
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
                mode="openvpn",
                tun_active=self._vpn_interface_active(self._active_profile),
                proxy_active=False,
                status="connected",
            )
        return ConnectionState(status="standby")
