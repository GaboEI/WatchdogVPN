from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType


CONFIG_PATH = Path("/tmp/watchdogvpn_awg.conf")
LOG_PATH = Path("/tmp/watchdogvpn_awg.log")
INTERFACE_NAME = "watchdogvpn_awg"
HANDSHAKE_TIMEOUT_SECONDS = 180


@dataclass(slots=True)
class _BinaryPaths:
    awg_quick: tuple[str, ...] = (
        "/usr/local/bin/awg-quick",
        "/usr/bin/awg-quick",
        "/usr/local/bin/amneziawg-quick",
        "/usr/bin/amneziawg-quick",
    )
    wg_quick: tuple[str, ...] = (
        "/usr/local/bin/wg-quick",
        "/usr/bin/wg-quick",
    )
    awg: tuple[str, ...] = (
        "/usr/local/bin/awg",
        "/usr/bin/awg",
    )
    wg: tuple[str, ...] = (
        "/usr/local/bin/wg",
        "/usr/bin/wg",
    )


class AmneziaWGDriver(BaseDriver):
    """Driver nativo para perfiles AmneziaWG.

    Usa amneziawg-quick (preferido) o wg-quick (fallback) para gestionar
    la interfaz WireGuard con extensiones de ofuscación AmneziaWG.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()
        self._active_profile: Profile | None = None
        self._connected_at: datetime | None = None

    def _find_binary(self, candidates: tuple[str, ...], which_name: str) -> str | None:
        for candidate in candidates:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return shutil.which(which_name)

    def find_quick_tool(self) -> str | None:
        env_binary = os.environ.get("WATCHDOGVPN_AMNEZIAWG_BIN")
        if env_binary and os.path.exists(env_binary) and os.access(env_binary, os.X_OK):
            return env_binary
        awg_quick = self._find_binary(self.binaries.awg_quick, "awg-quick")
        if awg_quick:
            return awg_quick
        return self._find_binary(self.binaries.wg_quick, "wg-quick")

    def find_wg_tool(self) -> str | None:
        awg = self._find_binary(self.binaries.awg, "awg")
        if awg:
            return awg
        return self._find_binary(self.binaries.wg, "wg")

    def get_tool(self) -> str:
        tool = self.find_quick_tool()
        if not tool:
            raise FileNotFoundError("amneziawg-quick ni wg-quick encontrados")
        return tool

    def check_version(self) -> str:
        wg_tool = self.find_wg_tool()
        if not wg_tool:
            raise FileNotFoundError("awg ni wg encontrados")
        result = subprocess.run(
            [wg_tool, "--version"],
            text=True,
            capture_output=True,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip()
        if not output:
            raise RuntimeError("wg version output is empty")
        return output

    def is_available(self) -> bool:
        return self.find_quick_tool() is not None

    def _strip_empty_keys(self, raw: str) -> str:
        lines: list[str] = []
        for line in raw.splitlines():
            stripped = line.strip()
            if "=" in stripped and not stripped.startswith("["):
                _, _, value = stripped.partition("=")
                if not value.strip():
                    continue
            lines.append(line)
        return "\n".join(lines)

    def _write_config(self, profile: Profile) -> None:
        if profile.protocol is not ProtocolType.AMNEZIAWG:
            raise ValueError(f"protocolo no soportado por AmneziaWG driver: {profile.protocol.value}")
        raw = str(profile.config.get("raw") or "").strip()
        if not raw:
            raise ValueError("perfil AmneziaWG requiere raw config")
        cleaned = self._strip_empty_keys(raw)
        CONFIG_PATH.write_text(f"{cleaned}\n", encoding="utf-8")
        CONFIG_PATH.chmod(0o600)

    def _cleanup_config(self) -> None:
        if CONFIG_PATH.exists():
            CONFIG_PATH.unlink()

    def _interface_exists(self) -> bool:
        if not shutil.which("ip"):
            return False
        result = subprocess.run(
            ["ip", "link", "show", INTERFACE_NAME],
            text=True,
            capture_output=True,
            check=False,
        )
        return result.returncode == 0

    def _reset_log(self) -> None:
        try:
            LOG_PATH.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            LOG_PATH.write_text("", encoding="utf-8")
        except OSError:
            pass

    def _log(self, message: str) -> None:
        try:
            with LOG_PATH.open("a", encoding="utf-8") as f:
                f.write(f"{message}\n")
        except OSError:
            pass

    def connect(self, profile: Profile) -> bool:
        tool = self.find_quick_tool()
        if not tool:
            return False
        self._write_config(profile)
        self._reset_log()
        result = subprocess.run(
            [tool, "up", str(CONFIG_PATH)],
            text=True,
            capture_output=True,
            check=False,
        )
        self._log(f"connect: {tool} up {CONFIG_PATH}")
        if result.stdout:
            self._log(result.stdout.rstrip())
        if result.stderr:
            self._log(result.stderr.rstrip())

        if result.returncode != 0:
            self._log(f"connect: falló con código {result.returncode}")
            self._cleanup_config()
            return False

        self._active_profile = profile
        self._connected_at = datetime.now(timezone.utc)
        return self._interface_exists()

    def disconnect(self) -> bool:
        try:
            tool = self.find_quick_tool()
            if tool and CONFIG_PATH.exists():
                result = subprocess.run(
                    [tool, "down", str(CONFIG_PATH)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self._log(f"disconnect: {tool} down")
                if result.stderr:
                    self._log(result.stderr.rstrip())
        finally:
            self._active_profile = None
            self._connected_at = None
            self._cleanup_config()
        return not self._interface_exists()

    def _latest_handshake_age(self) -> int | None:
        wg_tool = self.find_wg_tool()
        if not wg_tool:
            return None
        result = subprocess.run(
            [wg_tool, "show", INTERFACE_NAME, "latest-handshakes"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                try:
                    timestamp = int(parts[1])
                    if timestamp == 0:
                        return None
                    return int(time.time()) - timestamp
                except ValueError:
                    continue
        return None

    def _ping_through_interface(self, target: str = "1.1.1.1", timeout: int = 3) -> bool:
        if not shutil.which("ping"):
            return False
        result = subprocess.run(
            ["ping", "-I", INTERFACE_NAME, "-c", "1", "-W", str(timeout), target],
            text=True,
            capture_output=True,
            check=False,
        )
        return result.returncode == 0

    def health_check(self) -> str:
        if not self._interface_exists():
            return "down"
        age = self._latest_handshake_age()
        if age is None or age > HANDSHAKE_TIMEOUT_SECONDS:
            return "degraded"
        if self._ping_through_interface():
            return "ok"
        return "degraded"

    def status(self) -> ConnectionState:
        if not self._interface_exists():
            return ConnectionState(status="standby")
        profile_id = self._active_profile.id if self._active_profile else ""
        return ConnectionState(
            active_profile_id=profile_id,
            connected_at=self._connected_at,
            mode="amneziawg",
            tun_active=True,
            proxy_active=False,
            status="connected",
        )
