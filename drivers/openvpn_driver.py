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
from parsers.openvpn_safety import validate_openvpn_profile, validated_openvpn_remote_host


RUNTIME_PREFIX = "watchdogvpn-openvpn-"
CONFIG_NAME = "openvpn.conf"
LOG_NAME = "openvpn.log"
STATUS_NAME = "openvpn.status"
CONNECT_READY_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class _DefaultPath:
    """Expected safe forwarding path derived from the current default route."""

    gateway: str | None
    interface: str | None
    onlink: bool


def _route_flag_value(tokens: list[str], flag: str) -> tuple[bool, str | None]:
    """Return ``(present, value)`` for a single-valued route keyword."""
    if flag not in tokens:
        return (False, None)
    index = tokens.index(flag)
    if index + 1 >= len(tokens):
        return (True, None)
    return (True, tokens[index + 1])


def _default_path_from_tokens(tokens: list[str]) -> _DefaultPath | None:
    """Parse gateway, interface and onlink semantics from default-route tokens.

    Returns ``None`` for a malformed default route (a ``via``/``dev`` keyword
    with no following value) so the caller can fail closed instead of guessing.
    """
    has_via, gateway = _route_flag_value(tokens, "via")
    has_dev, interface = _route_flag_value(tokens, "dev")
    if (has_via and not gateway) or (has_dev and not interface):
        return None
    return _DefaultPath(
        gateway=gateway if has_via else None,
        interface=interface if has_dev else None,
        onlink="onlink" in tokens,
    )


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
        self._owned_endpoint_route: str | None = None
        self.last_error = ""
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

    def _validate_profile_without_runtime(self, profile: Profile) -> bool:
        try:
            if profile.protocol is not ProtocolType.OPENVPN:
                raise ValueError(f"unsupported protocol for OpenVPN driver: {profile.protocol.value}")
            wrapper = profile.config.get("wrapper") or profile.config.get("transport_wrapper")
            if wrapper:
                raise ValueError("wrapped OpenVPN profiles are not handled by the plain OpenVPN driver")
            if not str(profile.config.get("raw_config") or "").strip():
                raise ValueError("OpenVPN profile requires raw_config")
            validate_openvpn_profile(profile)
        except ValueError as exc:
            self.last_error = str(exc)
            return False
        return self._validate_single_ipv4_remote_endpoint(profile)

    def preflight_profile(self, profile: Profile) -> None:
        """Validate the candidate profile before any runtime teardown or mutation."""
        old_error = self.last_error
        if self._validate_profile_without_runtime(profile):
            self.last_error = old_error
            return
        raise ValueError(self.last_error or "OpenVPN profile preflight failed")

    def _cleanup_runtime(self) -> None:
        if self._runtime_dir is not None and self._runtime_dir.exists():
            shutil.rmtree(self._runtime_dir, ignore_errors=True)
        self._runtime_dir = None
        self._config_path = None
        self._log_path = None
        self._status_path = None
        self._expected_interface = ""
        self._expected_device_type = ""

    def _remote_host(self, profile: Profile) -> str:
        try:
            return validated_openvpn_remote_host(profile)
        except ValueError:
            return ""

    def _validate_single_ipv4_remote_endpoint(self, profile: Profile) -> bool:
        try:
            validated_openvpn_remote_host(profile)
        except ValueError as exc:
            self.last_error = str(exc)
            return False
        return True

    def _default_route_tokens(self) -> list[str] | None:
        if not shutil.which("ip"):
            return None
        result = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        line = next((item.strip() for item in result.stdout.splitlines() if item.strip()), "")
        return line.split() if line else None

    def _protect_remote_endpoint_route(self, profile: Profile) -> bool:
        if not self._validate_single_ipv4_remote_endpoint(profile):
            return False
        host = self._remote_host(profile)
        route = f"{host}/32"
        tokens = self._default_route_tokens()
        if not tokens:
            self.last_error = "OpenVPN endpoint route could not resolve the default route"
            return False
        expected = _default_path_from_tokens(tokens)
        if expected is None:
            self.last_error = "OpenVPN endpoint route default path is malformed"
            return False
        command = ["ip", "route", "add", route]
        if expected.gateway is not None:
            command.extend(["via", expected.gateway])
        if expected.interface is not None:
            command.extend(["dev", expected.interface])
        if expected.onlink:
            command.append("onlink")
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if result.returncode == 0:
            self._owned_endpoint_route = route
            return True
        stderr = (result.stderr or "").lower()
        if "file exists" in stderr:
            return self._existing_endpoint_route_is_safe(host, expected)
        self.last_error = "OpenVPN endpoint route protection failed"
        return False

    def _endpoint_route_resolution(self, host: str) -> list[str] | None:
        """Return the tokens of the kernel's effective resolution for an endpoint."""
        if not shutil.which("ip"):
            return None
        result = subprocess.run(
            ["ip", "-4", "route", "get", host],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        line = next((item.strip() for item in (result.stdout or "").splitlines() if item.strip()), "")
        return line.split() if line else None

    def _existing_endpoint_route_is_safe(self, host: str, expected: _DefaultPath) -> bool:
        """Accept a pre-existing endpoint route only if it follows the default path.

        A route that cannot be resolved, has no outbound interface, or uses a
        different interface/gateway than the current default route is reported
        fail-closed. The route is never marked as owned, so cleanup never
        deletes a route this attempt did not create.
        """
        if expected.interface is None:
            self.last_error = "OpenVPN endpoint route verification has no default interface"
            return False
        tokens = self._endpoint_route_resolution(host)
        if not tokens:
            self.last_error = "OpenVPN endpoint route could not be verified against the default route"
            return False
        has_dev, interface = _route_flag_value(tokens, "dev")
        has_via, gateway = _route_flag_value(tokens, "via")
        if not has_dev or not interface:
            self.last_error = "OpenVPN endpoint route verification found no outbound interface"
            return False
        if interface != expected.interface:
            self.last_error = (
                "OpenVPN endpoint route points to a different interface than the default route"
            )
            return False
        if expected.gateway is None:
            if has_via and gateway:
                self.last_error = (
                    "OpenVPN endpoint route uses a gateway the default route does not"
                )
                return False
        elif not has_via or gateway != expected.gateway:
            self.last_error = "OpenVPN endpoint route does not follow the default route gateway"
            return False
        return True

    def _cleanup_endpoint_route(self) -> None:
        route = self._owned_endpoint_route
        self._owned_endpoint_route = None
        if route and shutil.which("ip"):
            subprocess.run(["ip", "route", "delete", route], text=True, capture_output=True, check=False)

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

    def egress_interface(self) -> str | None:
        if self._active_profile is None:
            return None
        if not self._expected_interface:
            return None
        if not self._vpn_interface_active(self._active_profile):
            return None
        return self._expected_interface

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
        self.last_error = ""
        if not self._validate_profile_without_runtime(profile):
            return False
        if not self._ensure_disconnected_before_connect():
            self.last_error = "existing OpenVPN runtime teardown failed"
            return False
        binary = self.find_openvpn_binary()
        if not binary:
            self.last_error = "required binary not found: openvpn"
            return False
        self.generate_openvpn_config(profile)
        config_path, log_path = self._ensure_runtime_paths()
        runtime_dir = self._runtime_dir
        status_path = self._status_path
        if runtime_dir is None or status_path is None:
            self.last_error = "OpenVPN runtime paths are unavailable"
            self._cleanup_runtime()
            return False
        try:
            if not self._protect_remote_endpoint_route(profile):
                self._rollback_startup()
                return False
            readiness_options = self._configure_readiness(profile)
            try:
                status_path.unlink(missing_ok=True)
            except OSError:
                pass
            log_file = log_path.open("w", encoding="utf-8")
            try:
                self._process = subprocess.Popen(
                    build_openvpn_command(binary, config_path, runtime_options=readiness_options),
                    text=True,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                )
            finally:
                log_file.close()
            record_child_process(runtime_dir, "process", self._process.pid, Path(binary).name)
            self._active_profile = profile
            if self._wait_for_ready(profile):
                self._connected_at = datetime.now(timezone.utc)
                return True
            self._connected_at = None
            self.last_error = "OpenVPN readiness timed out or process exited"
            self._rollback_startup()
            return False
        except Exception as exc:
            self._rollback_startup()
            self.last_error = f"OpenVPN startup failed: {exc}"
            return False

    def _rollback_startup(self) -> None:
        """Undo every effect of a failed startup attempt.

        Stops any spawned process, removes the endpoint route this attempt owns
        and clears runtime and in-memory state, so the driver is immediately
        reusable and no route or process residue survives the failure.
        """
        try:
            self.disconnect()
        except Exception:
            pass
        finally:
            self._process = None
            self._active_profile = None
            self._connected_at = None
            self._cleanup_endpoint_route()
            self._cleanup_runtime()

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
            self._cleanup_endpoint_route()
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
        self._cleanup_endpoint_route()
        self._cleanup_runtime()
        return ConnectionState(status="standby")
