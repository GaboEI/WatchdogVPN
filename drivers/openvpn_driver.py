from __future__ import annotations

import os
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


RUNTIME_PREFIX = "watchdogvpn-openvpn-"
CONFIG_NAME = "openvpn.conf"
LOG_NAME = "openvpn.log"
STATUS_NAME = "openvpn.status"
CONNECT_READY_TIMEOUT_SECONDS = 10.0


@dataclass(slots=True)
class _BinaryPaths:
    openvpn: tuple[str, str, str, str] = (
        "/usr/sbin/openvpn",
        "/usr/bin/openvpn",
        "/usr/local/sbin/openvpn",
        "/usr/local/bin/openvpn",
    )


class OpenVPNDriver(BaseDriver, ReentrantConnectGuard):
    """Compatibility driver for plain OpenVPN profiles.

    Plain OpenVPN is intentionally not treated as a resilient anti-DPI protocol.
    OpenVPN+Cloak/OverCloud belongs to the later wrapped-driver phase.
    """

    policy_capabilities = frozenset()

    def _has_existing_connection(self) -> bool:
        return self._process is not None

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()
        self._process: subprocess.Popen[str] | None = None
        self._active_profile: Profile | None = None
        self._connected_at: datetime | None = None
        self._runtime_dir: Path | None = None
        self._config_path: Path | None = None
        self._log_path: Path | None = None
        self._status_path: Path | None = None
        self._expected_interface = ""
        self._expected_device_type = ""
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
            self._status_path = self._runtime_dir / STATUS_NAME
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
        validate_openvpn_profile(profile)
        config_path, _ = self._ensure_runtime_paths()
        write_private_file(config_path, f"{raw_config}\n")
        return raw_config

    def _cleanup_runtime(self) -> None:
        if self._runtime_dir is not None and self._runtime_dir.exists():
            shutil.rmtree(self._runtime_dir, ignore_errors=True)
        self._runtime_dir = None
        self._config_path = None
        self._log_path = None
        self._status_path = None
        self._expected_interface = ""
        self._expected_device_type = ""

    def _vpn_interface_active(self, profile: Profile | None = None) -> bool:
        if not shutil.which("ip"):
            return False
        result = subprocess.run(["ip", "-o", "link", "show"], text=True, capture_output=True, check=False)
        if result.returncode != 0:
            return False
        configured_dev = self._expected_interface
        if not configured_dev and profile is not None:
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

    def _configure_readiness(self, profile: Profile) -> tuple[str, ...]:
        if self._runtime_dir is None or self._status_path is None:
            raise RuntimeError("OpenVPN runtime paths are unavailable")
        configured_type = str(profile.config.get("dev_type") or "").strip().lower()
        configured_dev = str(profile.config.get("dev") or "").strip().lower()
        self._expected_device_type = (
            "tap" if configured_type == "tap" or configured_dev.startswith("tap") else "tun"
        )
        token = self._runtime_dir.name.rsplit("-", 1)[-1].replace("_", "")[:10]
        # The name must literally start with "tun"/"tap" - OpenVPN 2.6 rejects
        # a server PUSH_REPLY with topology-subnet ifconfig options on a
        # differently-prefixed --dev name ("problem with tun vs. tap
        # setting"), even with an explicit --dev-type. Confirmed live: a
        # "wdtun..." name crashed post-handshake, "tunwd..." completed.
        self._expected_interface = f"{self._expected_device_type}wd{token}"
        return (
            "--dev",
            self._expected_interface,
            "--dev-type",
            self._expected_device_type,
            "--status",
            str(self._status_path),
            "1",
            "--status-version",
            "3",
        )

    def _readiness_evidence_ready(self) -> bool:
        if not self._expected_interface or self._status_path is None or self._log_path is None:
            return False
        try:
            status = self._status_path.read_text(encoding="utf-8", errors="replace")
            log = self._log_path.read_text(encoding="utf-8", errors="replace")
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
        if not self._ensure_disconnected_before_connect():
            self.last_error = "existing OpenVPN runtime teardown failed"
            return False
        binary = self.find_openvpn_binary()
        if not binary:
            return False
        self.generate_openvpn_config(profile)
        config_path, log_path = self._ensure_runtime_paths()
        readiness_options = self._configure_readiness(profile)
        try:
            self._status_path.unlink(missing_ok=True)
        except OSError:
            pass
        log_file = log_path.open("w", encoding="utf-8")
        self._process = subprocess.Popen(
            build_openvpn_command(binary, config_path, runtime_options=readiness_options),
            text=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        log_file.close()
        record_child_process(self._runtime_dir, "process", self._process.pid, Path(binary).name)
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
            if self._vpn_interface_active(profile) and self._readiness_evidence_ready():
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
            # Best-effort sweep of every child this driver type has ever
            # recorded, not just the one this instance held a reference to -
            # catches anything orphaned by a past bug or crash too.
            kill_all_recorded_children(RUNTIME_PREFIX)
            self._cleanup_runtime()
        return stopped

    def health_check(self) -> str:
        process = self._process
        if process is None or process.poll() is not None:
            return "down"
        if self._vpn_interface_active(self._active_profile) and self._readiness_evidence_ready():
            return "ok"
        return "degraded"

    def status(self) -> ConnectionState:
        process = self._process
        if process is None:
            # No in-memory reference does not mean nothing is running: a
            # past reconnect bug, a crash between spawn and this call, or a
            # daemon restart could all leave a real interface/process
            # behind. Report the mismatch honestly instead of confidently
            # lying "standby" - status() never takes action on it, that is
            # disconnect()'s job.
            if self._vpn_interface_active(self._active_profile) or any_recorded_child_alive(RUNTIME_PREFIX):
                return ConnectionState(status="runtime_mismatch")
            return ConnectionState(status="standby")
        if process.poll() is None:
            profile_id = self._active_profile.id if self._active_profile else ""
            ready = (
                self._vpn_interface_active(self._active_profile)
                and self._readiness_evidence_ready()
            )
            return ConnectionState(
                active_profile_id=profile_id,
                connected_at=self._connected_at,
                mode="openvpn",
                tun_active=ready,
                proxy_active=False,
                status="connected" if ready else "runtime_mismatch",
                last_failure_reason="OpenVPN readiness evidence is incomplete" if not ready else "",
            )
        self._process = None
        self._active_profile = None
        self._connected_at = None
        self._cleanup_runtime()
        return ConnectionState(status="standby")
