from __future__ import annotations

import json
import os
import os.path
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


RUNTIME_PREFIX = "watchdogvpn-openvpn-cloak-"
OC_OVPN_CONFIG_NAME = "openvpn.conf"
CLOAK_CONFIG_NAME = "cloak.json"
OC_OVPN_LOG_NAME = "openvpn.log"
CLOAK_LOG_NAME = "cloak.log"

_CLOAK_STARTUP_WAIT = 1.5
CONNECT_READY_TIMEOUT_SECONDS = 15.0


@dataclass(slots=True)
class _BinaryPaths:
    openvpn: tuple[str, ...] = (
        "/usr/sbin/openvpn",
        "/usr/bin/openvpn",
        "/usr/local/sbin/openvpn",
        "/usr/local/bin/openvpn",
    )
    ck_client: tuple[str, ...] = (
        "/usr/local/bin/ck-client",
        "/usr/bin/ck-client",
        "/opt/cloak/ck-client",
    )


class OpenVPNCloakDriver(BaseDriver):
    """Driver for OpenVPN profiles wrapped in Cloak transport.

    Manages two simultaneous processes: ck-client (local tunnel) and openvpn
    (connected through that tunnel). Sequence: ck-client first, wait for
    startup, then openvpn. Cleanup: openvpn first, then ck-client.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()
        self._ck_process: subprocess.Popen[str] | None = None
        self._openvpn_process: subprocess.Popen[str] | None = None
        self._active_profile: Profile | None = None
        self._connected_at: datetime | None = None
        self._runtime_dir: Path | None = None
        self._ovpn_config_path: Path | None = None
        self._cloak_config_path: Path | None = None
        self._ovpn_log_path: Path | None = None
        self._cloak_log_path: Path | None = None
        cleanup_stale_runtime_dirs(RUNTIME_PREFIX)

    def _find_binary(self, candidates: tuple[str, ...], which_name: str) -> str | None:
        for candidate in candidates:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return shutil.which(which_name)

    def find_openvpn_binary(self) -> str | None:
        env_binary = os.environ.get("WATCHDOGVPN_OPENVPN_BIN")
        if env_binary and os.path.exists(env_binary) and os.access(env_binary, os.X_OK):
            return env_binary
        return self._find_binary(self.binaries.openvpn, "openvpn")

    def find_ck_client_binary(self) -> str | None:
        env_binary = os.environ.get("WATCHDOGVPN_CK_CLIENT_BIN")
        if env_binary and os.path.exists(env_binary) and os.access(env_binary, os.X_OK):
            return env_binary
        return self._find_binary(self.binaries.ck_client, "ck-client")

    def is_available(self) -> bool:
        try:
            return bool(self.check_version())
        except (FileNotFoundError, RuntimeError):
            return False

    def check_version(self) -> str:
        openvpn_binary = self.find_openvpn_binary()
        ck_binary = self.find_ck_client_binary()
        if not openvpn_binary:
            raise FileNotFoundError("openvpn binary not found")
        if not ck_binary:
            raise FileNotFoundError("ck-client binary not found")
        openvpn_version = self._version_output(openvpn_binary, ("--version",))
        ck_version = self._version_output(ck_binary, ("-v",), ("--version",))
        if not openvpn_version:
            raise RuntimeError("openvpn version output is empty")
        if not ck_version:
            raise RuntimeError("ck-client version output is empty")
        return f"{openvpn_version}\n{ck_version}"

    def _version_output(self, binary: str, *arg_sets: tuple[str, ...]) -> str:
        for args in arg_sets:
            result = subprocess.run(
                [binary, *args],
                text=True,
                capture_output=True,
                check=False,
            )
            output = (result.stdout or result.stderr or "").strip()
            if output:
                return output
        return ""

    def _ensure_runtime_paths(self) -> tuple[Path, Path, Path, Path]:
        if self._runtime_dir is None:
            self._runtime_dir = make_runtime_dir(RUNTIME_PREFIX)
            self._ovpn_config_path = self._runtime_dir / OC_OVPN_CONFIG_NAME
            self._cloak_config_path = self._runtime_dir / CLOAK_CONFIG_NAME
            self._ovpn_log_path = self._runtime_dir / OC_OVPN_LOG_NAME
            self._cloak_log_path = self._runtime_dir / CLOAK_LOG_NAME
        return (
            self._ovpn_config_path,
            self._cloak_config_path,
            self._ovpn_log_path,
            self._cloak_log_path,
        )  # type: ignore[return-value]

    def _write_configs(self, profile: Profile) -> None:
        if profile.protocol is not ProtocolType.OPENVPN_CLOAK:
            raise ValueError(
                f"unsupported protocol for OpenVPNCloakDriver: {profile.protocol.value}"
            )
        raw_config = str(profile.config.get("raw_config") or "").strip()
        if not raw_config:
            raise ValueError("OPENVPN_CLOAK profile requires raw_config")

        cloak_config = profile.config.get("cloak_config")
        if not cloak_config:
            raise ValueError("OPENVPN_CLOAK profile requires cloak_config")

        if isinstance(cloak_config, dict):
            cloak_json = json.dumps(cloak_config, indent=2)
        else:
            try:
                json.loads(str(cloak_config))
            except json.JSONDecodeError as exc:
                raise ValueError(f"cloak_config is not valid JSON: {exc}") from exc
            cloak_json = str(cloak_config)

        ovpn_config_path, cloak_config_path, _, _ = self._ensure_runtime_paths()
        write_private_file(ovpn_config_path, f"{raw_config}\n")
        write_private_file(cloak_config_path, cloak_json)

    def _cleanup_configs(self) -> None:
        if self._runtime_dir is not None and self._runtime_dir.exists():
            shutil.rmtree(self._runtime_dir, ignore_errors=True)
        self._runtime_dir = None
        self._ovpn_config_path = None
        self._cloak_config_path = None
        self._ovpn_log_path = None
        self._cloak_log_path = None

    def _reset_logs(self) -> None:
        _, _, ovpn_log_path, cloak_log_path = self._ensure_runtime_paths()
        for path in (cloak_log_path, ovpn_log_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            try:
                path.write_text("", encoding="utf-8")
            except OSError:
                pass

    def _stop_process(self, process: subprocess.Popen[str] | None) -> bool:
        if process is None or process.poll() is not None:
            return True
        process.terminate()
        try:
            process.wait(timeout=5)
            return True
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=5)
                return True
            except subprocess.TimeoutExpired:
                return False

    def _vpn_interface_active(self) -> bool:
        if not shutil.which("ip"):
            return False
        result = subprocess.run(
            ["ip", "-o", "link", "show"], text=True, capture_output=True, check=False
        )
        if result.returncode != 0:
            return False
        for line in result.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                iface = parts[1].strip()
                if iface.startswith("tun") or iface.startswith("tap"):
                    return True
        return False

    def connect(self, profile: Profile, dns_policy: DNSPolicy | None = None) -> bool:
        openvpn_bin = self.find_openvpn_binary()
        ck_bin = self.find_ck_client_binary()
        if not openvpn_bin or not ck_bin:
            return False

        self._write_configs(profile)
        self._reset_logs()
        ovpn_config_path, cloak_config_path, ovpn_log_path, cloak_log_path = self._ensure_runtime_paths()

        try:
            ck_log = cloak_log_path.open("w", encoding="utf-8")
        except OSError:
            ck_log = open(os.devnull, "w")
        self._ck_process = subprocess.Popen(
            [ck_bin, "-c", str(cloak_config_path)],
            text=True,
            stdout=ck_log,
            stderr=subprocess.STDOUT,
        )
        ck_log.close()

        time.sleep(_CLOAK_STARTUP_WAIT)

        if self._ck_process.poll() is not None:
            self._cleanup_all()
            return False

        try:
            ovpn_log = ovpn_log_path.open("w", encoding="utf-8")
        except OSError:
            ovpn_log = open(os.devnull, "w")
        self._openvpn_process = subprocess.Popen(
            [openvpn_bin, "--config", str(ovpn_config_path)],
            text=True,
            stdout=ovpn_log,
            stderr=subprocess.STDOUT,
        )
        ovpn_log.close()

        self._active_profile = profile
        if self._wait_for_ready():
            self._connected_at = datetime.now(timezone.utc)
            return True

        self._cleanup_all()
        return False

    def _wait_for_ready(self) -> bool:
        deadline = time.monotonic() + CONNECT_READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            ck = self._ck_process
            ovpn = self._openvpn_process
            if ck is None or ovpn is None:
                return False
            if ck.poll() is not None or ovpn.poll() is not None:
                return False
            if self._vpn_interface_active():
                return True
            time.sleep(0.25)
        return False

    def _cleanup_all(self) -> None:
        self._stop_process(self._openvpn_process)
        self._stop_process(self._ck_process)
        self._openvpn_process = None
        self._ck_process = None
        self._active_profile = None
        self._connected_at = None
        self._cleanup_configs()

    def disconnect(self) -> bool:
        openvpn_stopped = True
        ck_stopped = True
        try:
            openvpn_stopped = self._stop_process(self._openvpn_process)
            ck_stopped = self._stop_process(self._ck_process)
        finally:
            self._openvpn_process = None
            self._ck_process = None
            self._active_profile = None
            self._connected_at = None
            self._cleanup_configs()
        return openvpn_stopped and ck_stopped

    def health_check(self) -> str:
        ck = self._ck_process
        ovpn = self._openvpn_process
        if ck is None or ovpn is None:
            return "down"
        if ck.poll() is not None or ovpn.poll() is not None:
            return "down"
        if self._vpn_interface_active():
            return "ok"
        return "degraded"

    def status(self) -> ConnectionState:
        ck = self._ck_process
        ovpn = self._openvpn_process
        if ck is None or ovpn is None:
            return ConnectionState(status="standby")
        if ck.poll() is not None or ovpn.poll() is not None:
            return ConnectionState(status="standby")
        profile_id = self._active_profile.id if self._active_profile else ""
        return ConnectionState(
            active_profile_id=profile_id,
            connected_at=self._connected_at,
            mode="openvpn_cloak",
            tun_active=self._vpn_interface_active(),
            proxy_active=False,
            status="connected",
        )
