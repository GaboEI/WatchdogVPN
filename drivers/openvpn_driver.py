from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from drivers.base import BaseDriver
from drivers.runtime_paths import cleanup_stale_runtime_dirs, make_runtime_dir, write_private_file
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType


RUNTIME_PREFIX = "watchdogvpn-openvpn-"
CONFIG_NAME = "openvpn.conf"
LOG_NAME = "openvpn.log"
CONNECT_READY_TIMEOUT_SECONDS = 10.0


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
        self._runtime_dir: Path | None = None
        self._config_path: Path | None = None
        self._log_path: Path | None = None
        cleanup_stale_runtime_dirs(RUNTIME_PREFIX)

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
        try:
            return bool(self.check_version())
        except (FileNotFoundError, RuntimeError):
            return False

    def _ensure_runtime_paths(self) -> tuple[Path, Path]:
        if self._runtime_dir is None:
            self._runtime_dir = make_runtime_dir(RUNTIME_PREFIX)
            self._config_path = self._runtime_dir / CONFIG_NAME
            self._log_path = self._runtime_dir / LOG_NAME
        return self._config_path, self._log_path  # type: ignore[return-value]

    def generate_openvpn_config(self, profile: Profile) -> str:
        if profile.protocol is not ProtocolType.OPENVPN:
            raise ValueError(f"unsupported protocol for OpenVPN driver: {profile.protocol.value}")
        wrapper = profile.config.get("wrapper") or profile.config.get("transport_wrapper")
        if wrapper:
            raise ValueError("wrapped OpenVPN profiles are not handled by the plain OpenVPN driver")
        raw_config = str(profile.config.get("raw_config") or "").strip()
        if not raw_config:
            raise ValueError("OpenVPN profile requires raw_config")
        config_path, _ = self._ensure_runtime_paths()
        write_private_file(config_path, f"{raw_config}\n")
        return raw_config

    def _cleanup_runtime(self) -> None:
        if self._runtime_dir is not None and self._runtime_dir.exists():
            shutil.rmtree(self._runtime_dir, ignore_errors=True)
        self._runtime_dir = None
        self._config_path = None
        self._log_path = None

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
        config_path, log_path = self._ensure_runtime_paths()
        log_file = log_path.open("w", encoding="utf-8")
        self._process = subprocess.Popen(
            [binary, "--config", str(config_path)],
            text=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        log_file.close()
        self._active_profile = profile
        if self._wait_for_ready(profile):
            self._connected_at = datetime.now(timezone.utc)
            return True
        self._connected_at = None
        self._active_profile = None
        self.disconnect()
        return False

    def _wait_for_ready(self, profile: Profile) -> bool:
        deadline = time.monotonic() + CONNECT_READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            process = self._process
            if process is None or process.poll() is not None:
                return False
            if self._vpn_interface_active(profile):
                return True
            time.sleep(0.25)
        return False

    def disconnect(self) -> bool:
        process = self._process
        self._process = None
        self._active_profile = None
        self._connected_at = None
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
