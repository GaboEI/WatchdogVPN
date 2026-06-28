from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType


@dataclass(slots=True)
class _BinaryPaths:
    vpnctl: str = "/usr/local/bin/vpnctl"
    truth: str = "/usr/local/bin/vpn_truth_check"
    adguard_cli: str = "/usr/local/bin/adguardvpn-cli"


class AdGuardDriver(BaseDriver):
    """Legacy AdGuard VPN integration.

    This driver preserves the existing AdGuard-based workflow and wraps the
    current shell/runtime commands without changing their behavior. It is kept
    as a compatibility path while the v2 architecture moves toward generic
    drivers and providers.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()

    def _env_path(self, name: str, default: str) -> str:
        return os.environ.get(name, default)

    def _resolve_binary(self, path: str, fallback: str) -> str:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
        resolved = shutil.which(fallback)
        if resolved:
            return resolved
        return path

    def _vpnctl(self) -> str:
        return self._resolve_binary(self.binaries.vpnctl, "vpnctl")

    def _truth(self) -> str:
        return self._resolve_binary(self.binaries.truth, "vpn_truth_check")

    def _adguard_cli(self) -> str:
        return self._resolve_binary(self.binaries.adguard_cli, "adguardvpn-cli")

    def _run(self, args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, text=True, capture_output=True, check=check)

    def _truth_data(self) -> dict[str, str]:
        result = self._run([self._truth(), "--shell"])
        data: dict[str, str] = {}
        if result.stdout:
            for line in result.stdout.splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                data[key.strip().upper()] = value.strip()
        return data

    def _manual_off_state(self) -> str:
        result = self._run([self._vpnctl(), "status"])
        return result.stdout or ""

    def _location_from_profile(self, profile: Profile) -> str:
        for key in ("location", "iso", "country", "region", "name", "id"):
            value = profile.config.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return profile.name.strip()

    def connect(self, profile: Profile) -> bool:
        if profile.protocol is not ProtocolType.ADGUARD:
            return False
        location = self._location_from_profile(profile)
        if not location:
            return False
        result = self._run([self._vpnctl(), "connect", location])
        return result.returncode == 0

    def disconnect(self) -> bool:
        result = self._run([self._vpnctl(), "disconnect"])
        return result.returncode == 0

    def health_check(self) -> str:
        data = self._truth_data()
        status = data.get("STATUS", "DOWN").upper()
        if status == "UP":
            return "ok"
        if status == "DEGRADED":
            return "degraded"
        return "down"

    def status(self) -> ConnectionState:
        data = self._truth_data()
        status = data.get("STATUS", "DOWN").lower()
        tun_active = data.get("TUN", "DOWN").upper() == "UP"
        proxy_active = status == "up"
        state = "connected" if status == "up" else "reconnecting" if status == "degraded" else "standby"
        return ConnectionState(
            active_profile_id="",
            mode="adguard",
            tun_active=tun_active,
            proxy_active=proxy_active,
            kill_switch_active=False,
            status=state,
        )

    def is_available(self) -> bool:
        return bool(shutil.which("vpnctl") or os.path.exists(self.binaries.vpnctl)) and bool(
            shutil.which("vpn_truth_check") or os.path.exists(self.binaries.truth)
        ) and bool(shutil.which("adguardvpn-cli") or os.path.exists(self.binaries.adguard_cli))
