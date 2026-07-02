from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from dns.models import DNSPolicy
from drivers.base import BaseDriver
from drivers.runtime_paths import cleanup_stale_runtime_dirs, make_runtime_dir, write_private_file
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType


RUNTIME_PREFIX = "watchdogvpn-awg-"
CONFIG_NAME = "awg.conf"
LOG_NAME = "awg.log"
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
    """Native driver for AmneziaWG profiles.

    Uses amneziawg-quick (preferred) or wg-quick (fallback) to manage
    the WireGuard interface with AmneziaWG obfuscation extensions.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()
        self._active_profile: Profile | None = None
        self._connected_at: datetime | None = None
        self._runtime_dir: Path | None = None
        self._config_path: Path | None = None
        self._log_path: Path | None = None
        cleanup_stale_runtime_dirs(RUNTIME_PREFIX)

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
            raise FileNotFoundError("neither amneziawg-quick nor wg-quick was found")
        return tool

    def check_version(self) -> str:
        wg_tool = self.find_wg_tool()
        if not wg_tool:
            raise FileNotFoundError("neither awg nor wg was found")
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
        if self.find_quick_tool() is None:
            return False
        try:
            return bool(self.check_version())
        except (FileNotFoundError, RuntimeError):
            return False

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

    def _ensure_runtime_paths(self) -> tuple[Path, Path]:
        if self._runtime_dir is None:
            self._runtime_dir = make_runtime_dir(RUNTIME_PREFIX)
            self._config_path = self._runtime_dir / CONFIG_NAME
            self._log_path = self._runtime_dir / LOG_NAME
        return self._config_path, self._log_path  # type: ignore[return-value]

    def _write_config(self, profile: Profile) -> None:
        if profile.protocol is not ProtocolType.AMNEZIAWG:
            raise ValueError(f"unsupported protocol for AmneziaWG driver: {profile.protocol.value}")
        raw = str(profile.config.get("raw") or "").strip()
        if not raw:
            raise ValueError("AmneziaWG profile requires raw config")
        cleaned = self._strip_empty_keys(raw)
        config_path, _ = self._ensure_runtime_paths()
        write_private_file(config_path, f"{cleaned}\n")

    def _cleanup_runtime(self) -> None:
        if self._runtime_dir is not None and self._runtime_dir.exists():
            shutil.rmtree(self._runtime_dir, ignore_errors=True)
        self._runtime_dir = None
        self._config_path = None
        self._log_path = None

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

    def _delete_interface(self) -> bool:
        if not shutil.which("ip"):
            return False
        result = subprocess.run(
            ["ip", "link", "delete", INTERFACE_NAME],
            text=True,
            capture_output=True,
            check=False,
        )
        return result.returncode == 0 or not self._interface_exists()

    def _reset_log(self) -> None:
        _, log_path = self._ensure_runtime_paths()
        try:
            log_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            write_private_file(log_path, "")
        except OSError:
            pass

    def _log(self, message: str) -> None:
        _, log_path = self._ensure_runtime_paths()
        try:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(f"{message}\n")
        except OSError:
            pass

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups=None,
        final_policy: str = "current_profile",
    ) -> bool:
        tool = self.find_quick_tool()
        if not tool:
            return False
        if self._interface_exists() and not self._delete_interface():
            return False
        self._write_config(profile)
        self._reset_log()
        config_path, _ = self._ensure_runtime_paths()
        result = subprocess.run(
            [tool, "up", str(config_path)],
            text=True,
            capture_output=True,
            check=False,
        )
        self._log(f"connect: {tool} up {config_path}")
        if result.stdout:
            self._log(result.stdout.rstrip())
        if result.stderr:
            self._log(result.stderr.rstrip())

        if result.returncode != 0:
            self._log(f"connect: failed with code {result.returncode}")
            self._cleanup_runtime()
            return False

        self._active_profile = profile
        if self._interface_exists():
            self._connected_at = datetime.now(timezone.utc)
            return True
        self._active_profile = None
        self._connected_at = None
        self.disconnect()
        return False

    def disconnect(self) -> bool:
        try:
            tool = self.find_quick_tool()
            config_path = self._config_path
            if tool and config_path is not None and config_path.exists():
                result = subprocess.run(
                    [tool, "down", str(config_path)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self._log(f"disconnect: {tool} down")
                if result.stderr:
                    self._log(result.stderr.rstrip())
            if self._interface_exists():
                self._delete_interface()
        finally:
            self._active_profile = None
            self._connected_at = None
            self._cleanup_runtime()
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
        if self._active_profile is None:
            return "down"
        if not self._interface_exists():
            return "down"
        age = self._latest_handshake_age()
        if age is None or age > HANDSHAKE_TIMEOUT_SECONDS:
            return "degraded"
        if self._ping_through_interface():
            return "ok"
        return "degraded"

    def status(self) -> ConnectionState:
        if self._active_profile is None or not self._interface_exists():
            return ConnectionState(status="standby")
        return ConnectionState(
            active_profile_id=self._active_profile.id,
            connected_at=self._connected_at,
            mode="amneziawg",
            tun_active=True,
            proxy_active=False,
            status="connected",
        )
