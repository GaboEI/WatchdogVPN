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
from drivers.base import BaseDriver, ReentrantConnectGuard
from drivers.openvpn_process import build_openvpn_command
from drivers.runtime_paths import (
    any_recorded_child_alive,
    cleanup_stale_runtime_dirs,
    kill_all_recorded_children,
    make_runtime_dir,
    record_child_process,
    write_private_file,
)
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType
from parsers.openvpn_safety import validate_openvpn_profile


RUNTIME_PREFIX = "watchdogvpn-openvpn-cloak-"
OC_OVPN_CONFIG_NAME = "openvpn.conf"
CLOAK_CONFIG_NAME = "cloak.json"
OC_OVPN_LOG_NAME = "openvpn.log"
OC_OVPN_STATUS_NAME = "openvpn.status"
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


class OpenVPNCloakDriver(BaseDriver, ReentrantConnectGuard):
    """Driver for OpenVPN profiles wrapped in Cloak transport.

    Manages two simultaneous processes: ck-client (local tunnel) and openvpn
    (connected through that tunnel). Sequence: ck-client first, wait for
    startup, then openvpn. Cleanup: openvpn first, then ck-client.
    """

    policy_capabilities = frozenset()

    def _has_existing_connection(self) -> bool:
        return self._ck_process is not None or self._openvpn_process is not None

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
        self._ovpn_status_path: Path | None = None
        self._expected_interface = ""
        self._expected_device_type = ""
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
            self._ovpn_status_path = self._runtime_dir / OC_OVPN_STATUS_NAME
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

        validate_openvpn_profile(profile)
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
        self._ovpn_status_path = None
        self._expected_interface = ""
        self._expected_device_type = ""

    def _reset_logs(self) -> None:
        _, _, ovpn_log_path, cloak_log_path = self._ensure_runtime_paths()
        status_path = self._ovpn_status_path
        if status_path is not None:
            try:
                status_path.unlink(missing_ok=True)
            except OSError:
                pass
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
                if self._expected_interface:
                    if iface == self._expected_interface:
                        return True
                    continue
                if iface.startswith("tun") or iface.startswith("tap"):
                    return True
        return False

    def _configure_readiness(self, profile: Profile) -> tuple[str, ...]:
        if self._runtime_dir is None or self._ovpn_status_path is None:
            raise RuntimeError("OpenVPN+Cloak runtime paths are unavailable")
        configured_type = str(profile.config.get("dev_type") or "").strip().lower()
        configured_dev = str(profile.config.get("dev") or "").strip().lower()
        self._expected_device_type = (
            "tap" if configured_type == "tap" or configured_dev.startswith("tap") else "tun"
        )
        token = self._runtime_dir.name.rsplit("-", 1)[-1].replace("_", "")[:10]
        self._expected_interface = f"wd{self._expected_device_type}{token}"
        return (
            "--dev",
            self._expected_interface,
            "--dev-type",
            self._expected_device_type,
            "--status",
            str(self._ovpn_status_path),
            "1",
            "--status-version",
            "3",
        )

    def _readiness_evidence_ready(self) -> bool:
        if (
            not self._expected_interface
            or self._ovpn_status_path is None
            or self._ovpn_log_path is None
        ):
            return False
        try:
            status = self._ovpn_status_path.read_text(encoding="utf-8", errors="replace")
            log = self._ovpn_log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return "OpenVPN" in status and "Initialization Sequence Completed" in log

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups=None,
        app_policy=None,
        final_policy: str = "current_profile",
        rule_set_tags: dict[str, str] | None = None,
        rule_set_declarations: list[dict[str, str]] | None = None,
        chain_runtime_plans=None,
        lan_proxy=None,
        lan_gateway=None,
        capture_modes=None,
    ) -> bool:
        self._ensure_disconnected_before_connect()
        openvpn_bin = self.find_openvpn_binary()
        ck_bin = self.find_ck_client_binary()
        if not openvpn_bin or not ck_bin:
            return False

        self._write_configs(profile)
        self._reset_logs()
        ovpn_config_path, cloak_config_path, ovpn_log_path, cloak_log_path = self._ensure_runtime_paths()
        readiness_options = self._configure_readiness(profile)

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
        record_child_process(self._runtime_dir, "ck_process", self._ck_process.pid, Path(ck_bin).name)

        time.sleep(_CLOAK_STARTUP_WAIT)

        if self._ck_process.poll() is not None:
            self._cleanup_all()
            return False

        try:
            ovpn_log = ovpn_log_path.open("w", encoding="utf-8")
        except OSError:
            ovpn_log = open(os.devnull, "w")
        self._openvpn_process = subprocess.Popen(
            build_openvpn_command(openvpn_bin, ovpn_config_path, runtime_options=readiness_options),
            text=True,
            stdout=ovpn_log,
            stderr=subprocess.STDOUT,
        )
        ovpn_log.close()
        record_child_process(
            self._runtime_dir, "openvpn_process", self._openvpn_process.pid, Path(openvpn_bin).name
        )

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
            if self._vpn_interface_active() and self._readiness_evidence_ready():
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
        kill_all_recorded_children(RUNTIME_PREFIX)
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
            # Best-effort sweep of every child this driver type has ever
            # recorded, not just the two this instance held a reference to -
            # catches anything orphaned by a past bug or crash too.
            kill_all_recorded_children(RUNTIME_PREFIX)
            self._cleanup_configs()
        return openvpn_stopped and ck_stopped

    def health_check(self) -> str:
        ck = self._ck_process
        ovpn = self._openvpn_process
        if ck is None or ovpn is None:
            return "down"
        if ck.poll() is not None or ovpn.poll() is not None:
            return "down"
        if self._vpn_interface_active() and self._readiness_evidence_ready():
            return "ok"
        return "degraded"

    def status(self) -> ConnectionState:
        ck = self._ck_process
        ovpn = self._openvpn_process
        if ck is None or ovpn is None:
            # No in-memory reference does not mean nothing is running: a
            # past reconnect bug, a crash between spawn and this call, or a
            # daemon restart could all leave a real interface/process
            # behind. Report the mismatch honestly instead of confidently
            # lying "standby" - status() never takes action on it, that is
            # disconnect()'s job.
            if self._vpn_interface_active() or any_recorded_child_alive(RUNTIME_PREFIX):
                return ConnectionState(status="runtime_mismatch")
            return ConnectionState(status="standby")
        if ck.poll() is not None or ovpn.poll() is not None:
            self._ck_process = None
            self._openvpn_process = None
            self._active_profile = None
            self._connected_at = None
            self._cleanup_configs()
            return ConnectionState(status="standby")
        ready = self._vpn_interface_active() and self._readiness_evidence_ready()
        profile_id = self._active_profile.id if self._active_profile else ""
        return ConnectionState(
            active_profile_id=profile_id,
            connected_at=self._connected_at,
            mode="openvpn_cloak",
            tun_active=ready,
            proxy_active=False,
            status="connected" if ready else "runtime_mismatch",
            last_failure_reason="OpenVPN readiness evidence is incomplete" if not ready else "",
        )
