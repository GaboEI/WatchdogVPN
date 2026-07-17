from __future__ import annotations

import json
import ipaddress
import logging
import os
import os.path
import re
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
    recorded_children_terminated,
    record_child_process,
    write_private_file,
)
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType
from parsers.openvpn_safety import validate_openvpn_profile

LOGGER = logging.getLogger(__name__)


RUNTIME_PREFIX = "watchdogvpn-openvpn-cloak-"
OC_OVPN_CONFIG_NAME = "openvpn.conf"
CLOAK_CONFIG_NAME = "cloak.json"
OC_OVPN_LOG_NAME = "openvpn.log"
OC_OVPN_STATUS_NAME = "openvpn.status"
CLOAK_LOG_NAME = "cloak.log"
ROUTE_SNAPSHOT_NAME = "routes.before"

_CLOAK_STARTUP_WAIT = 1.5
CONNECT_READY_TIMEOUT_SECONDS = 15.0

_PRESERVED_REMOTE_RE = re.compile(
    r"Preserving recently used remote address: \[(?:AF_INET|AF_INET6)\](\S+)"
)
_ADDED_ROUTE_RE = re.compile(
    r"net_route_v[46]_add: (\S+)(?: via (\S+))? dev \S+ table \d+ metric (-?\d+)"
)


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
        self._route_snapshot_path: Path | None = None
        self._route_snapshot_captured = False
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
            self._route_snapshot_path = self._runtime_dir / ROUTE_SNAPSHOT_NAME
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
        self._route_snapshot_path = None
        self._route_snapshot_captured = False
        self._expected_interface = ""
        self._expected_device_type = ""

    def _reset_logs(self) -> bool:
        """Create empty private logs or fail before either child can start."""
        _, _, ovpn_log_path, cloak_log_path = self._ensure_runtime_paths()
        status_path = self._ovpn_status_path
        if status_path is not None:
            try:
                status_path.unlink(missing_ok=True)
            except OSError:
                return False
        for path in (cloak_log_path, ovpn_log_path):
            try:
                path.unlink(missing_ok=True)
                path.write_text("", encoding="utf-8")
            except OSError:
                return False
        return True

    def _current_route_lines(self) -> set[str] | None:
        """Return normalized kernel routes, or None when they cannot be read."""
        result = subprocess.run(
            ["ip", "-o", "route", "show"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return None
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}

    def _capture_route_snapshot(self) -> bool:
        """Durably record the pre-connect route state before OpenVPN starts.

        OpenVPN creates a host route for its current remote endpoint so its
        control channel survives a default-route change. If OpenVPN is killed,
        it cannot remove that route itself. The snapshot lets teardown remove
        only a route that this connection demonstrably added, never a route
        that was already present or belongs to another component.
        """
        if self._route_snapshot_path is None or not shutil.which("ip"):
            return False
        routes = self._current_route_lines()
        if routes is None:
            return False
        try:
            write_private_file(self._route_snapshot_path, "\n".join(sorted(routes)) + "\n")
        except OSError:
            return False
        self._route_snapshot_captured = True
        return True

    def _owned_route_selectors(self) -> set[tuple[str, str | None, int | None]] | None:
        """Return log-proven route identities created by this OpenVPN generation."""
        if self._ovpn_log_path is None:
            return None
        try:
            log = self._ovpn_log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        selectors: set[tuple[str, str | None, int | None]] = set()
        for token in _PRESERVED_REMOTE_RE.findall(log):
            candidate = token.rstrip(",")
            while candidate:
                try:
                    selectors.add((str(ipaddress.ip_address(candidate)), None, None))
                    break
                except ValueError:
                    candidate, separator, _port = candidate.rpartition(":")
                    if not separator:
                        break
        for destination, gateway, metric_text in _ADDED_ROUTE_RE.findall(log):
            try:
                normalized_destination = str(
                    ipaddress.ip_address(destination.split("/", 1)[0])
                )
                metric = int(metric_text)
            except ValueError:
                continue
            selectors.add(
                (
                    normalized_destination,
                    gateway if gateway and gateway != "0.0.0.0" else None,
                    metric if metric >= 0 else None,
                )
            )
        return selectors

    @staticmethod
    def _route_destination(route: str) -> str | None:
        destination = route.split(maxsplit=1)[0].split("/", 1)[0]
        try:
            return str(ipaddress.ip_address(destination))
        except ValueError:
            return None

    @classmethod
    def _route_matches_selector(
        cls, route: str, selector: tuple[str, str | None, int | None]
    ) -> bool:
        destination, gateway, metric = selector
        tokens = route.split()
        if cls._route_destination(route) != destination:
            return False
        if gateway is not None and (
            "via" not in tokens or tokens[tokens.index("via") + 1] != gateway
        ):
            return False
        if metric is not None and (
            "metric" not in tokens or tokens[tokens.index("metric") + 1] != str(metric)
        ):
            return False
        return True

    def _cleanup_openvpn_endpoint_routes(self) -> bool:
        """Remove only this generation's orphaned OpenVPN-owned routes.

        Route identity comes from OpenVPN's own log and every deletion is limited
        to a route absent from the pre-connect snapshot. This includes server
        routes which OpenVPN adds after the Cloak transport is ready; a SIGKILL
        prevents OpenVPN from removing them itself. Ambiguity is retained as
        runtime evidence instead of deleting a possibly unrelated route.
        """
        if not self._route_snapshot_captured:
            return True
        if self._route_snapshot_path is None or not shutil.which("ip"):
            return False
        try:
            baseline = {
                line.strip()
                for line in self._route_snapshot_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if line.strip()
            }
        except OSError:
            return False
        selectors = self._owned_route_selectors()
        if selectors is None:
            return False
        if not selectors:
            return True
        current = self._current_route_lines()
        if current is None:
            return False
        orphaned = {
            route
            for route in current - baseline
            if any(self._route_matches_selector(route, selector) for selector in selectors)
        }
        for route in orphaned:
            result = subprocess.run(
                ["ip", "route", "del", *route.split()],
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                return False
        remaining = self._current_route_lines()
        if remaining is None:
            return False
        return not {
            route
            for route in remaining - baseline
            if any(self._route_matches_selector(route, selector) for selector in selectors)
        }

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
        # The name must literally start with "tun"/"tap" - OpenVPN 2.6 rejects
        # a server PUSH_REPLY with topology-subnet ifconfig options on a
        # differently-prefixed --dev name ("problem with tun vs. tap
        # setting"), even with an explicit --dev-type. Confirmed live on the
        # plain OpenVPN driver's identical naming scheme: a "wdtun..." name
        # crashed post-handshake, "tunwd..." completed. This driver shares
        # the same server-push exposure even though it wasn't observed
        # tripping here today.
        self._expected_interface = f"{self._expected_device_type}wd{token}"
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

    def _startup_failure(self) -> bool:
        """Rollback a failed startup without hiding uncertain cleanup evidence."""
        try:
            self._teardown_children()
        except Exception:
            # A teardown exception must not turn a failed connect into a
            # caller-visible crash. R-10 state is intentionally retained when
            # cleanup cannot complete or be verified.
            pass
        return False

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
            self.last_error = "existing OpenVPN+Cloak runtime teardown failed"
            return False
        openvpn_bin = self.find_openvpn_binary()
        ck_bin = self.find_ck_client_binary()
        if not openvpn_bin or not ck_bin:
            missing = [
                name
                for name, path in (("openvpn", openvpn_bin), ("ck-client", ck_bin))
                if not path
            ]
            self.last_error = f"required binary not found: {', '.join(missing)}"
            LOGGER.warning(
                "openvpn_cloak_connect_missing_binary missing=%s", ",".join(missing)
            )
            return False

        try:
            self._write_configs(profile)
            if not self._reset_logs():
                return self._startup_failure()
            (
                ovpn_config_path,
                cloak_config_path,
                ovpn_log_path,
                cloak_log_path,
            ) = self._ensure_runtime_paths()
            readiness_options = self._configure_readiness(profile)
            if not self._capture_route_snapshot():
                return self._startup_failure()

            with cloak_log_path.open("w", encoding="utf-8") as ck_log:
                self._ck_process = subprocess.Popen(
                    [ck_bin, "-c", str(cloak_config_path)],
                    text=True,
                    stdout=ck_log,
                    stderr=subprocess.STDOUT,
                )
            record_child_process(
                self._runtime_dir,
                "ck_process",
                self._ck_process.pid,
                Path(ck_bin).name,
            )

            time.sleep(_CLOAK_STARTUP_WAIT)
            if self._ck_process.poll() is not None:
                return self._startup_failure()

            with ovpn_log_path.open("w", encoding="utf-8") as ovpn_log:
                self._openvpn_process = subprocess.Popen(
                    build_openvpn_command(
                        openvpn_bin,
                        ovpn_config_path,
                        runtime_options=readiness_options,
                    ),
                    text=True,
                    stdout=ovpn_log,
                    stderr=subprocess.STDOUT,
                )
            record_child_process(
                self._runtime_dir,
                "openvpn_process",
                self._openvpn_process.pid,
                Path(openvpn_bin).name,
            )

            self._active_profile = profile
            if self._wait_for_ready():
                self._connected_at = datetime.now(timezone.utc)
                return True
        except Exception:
            # Every post-binary startup stage is transactional. The teardown
            # itself stays fail-closed: if it cannot prove cleanup, R-10 keeps
            # ownership and durable evidence for a later explicit recovery.
            return self._startup_failure()

        return self._startup_failure()

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

    def _cleanup_expected_interface(self) -> bool:
        """Delete only this generation's exact OpenVPN interface and routes."""
        if not self._expected_interface:
            return True
        if not shutil.which("ip"):
            return False
        subprocess.run(
            ["ip", "link", "delete", "dev", self._expected_interface],
            text=True,
            capture_output=True,
            check=False,
        )
        return not self._vpn_interface_active()

    def _teardown_children(self) -> bool:
        """Stop both children without discarding evidence on any uncertainty."""
        openvpn_was_started = self._openvpn_process is not None
        openvpn_stopped = self._stop_process(self._openvpn_process)
        ck_stopped = self._stop_process(self._ck_process)
        if not openvpn_stopped or not ck_stopped:
            return False

        kill_all_recorded_children(RUNTIME_PREFIX)
        if self._runtime_dir is not None and not recorded_children_terminated(self._runtime_dir):
            return False
        if openvpn_was_started and not self._cleanup_expected_interface():
            return False
        if openvpn_was_started and not self._cleanup_openvpn_endpoint_routes():
            return False

        self._openvpn_process = None
        self._ck_process = None
        self._active_profile = None
        self._connected_at = None
        self._cleanup_configs()
        return True

    def _cleanup_all(self) -> bool:
        return self._teardown_children()

    def disconnect(self) -> bool:
        return self._teardown_children()

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
            exited_children = []
            if ck.poll() is not None:
                exited_children.append("ck-client")
            if ovpn.poll() is not None:
                exited_children.append("openvpn")
            return ConnectionState(
                status="runtime_mismatch",
                last_failure_reason="OpenVPN+Cloak child exited: " + ", ".join(exited_children),
            )
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
