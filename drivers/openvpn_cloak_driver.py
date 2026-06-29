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

from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProtocolType


OC_OVPN_CONFIG_PATH = Path("/tmp/watchdogvpn_oc.conf")
CLOAK_CONFIG_PATH = Path("/tmp/watchdogvpn_cloak.json")
OC_OVPN_LOG_PATH = Path("/tmp/watchdogvpn_oc_ovpn.log")
CLOAK_LOG_PATH = Path("/tmp/watchdogvpn_oc_cloak.log")

_CLOAK_STARTUP_WAIT = 1.5


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
    """Driver para perfiles OpenVPN envueltos en transporte Cloak.

    Gestiona dos procesos simultáneos: ck-client (túnel local) y openvpn
    (conecta a través de ese túnel). Secuencia: ck-client primero → esperar
    arranque → openvpn. Limpieza: openvpn primero → ck-client.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()
        self._ck_process: subprocess.Popen[str] | None = None
        self._openvpn_process: subprocess.Popen[str] | None = None
        self._active_profile: Profile | None = None
        self._connected_at: datetime | None = None

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
        return self.find_openvpn_binary() is not None and self.find_ck_client_binary() is not None

    def check_version(self) -> str:
        binary = self.find_openvpn_binary()
        if not binary:
            raise FileNotFoundError("openvpn binary no encontrado")
        result = subprocess.run([binary, "--version"], text=True, capture_output=True, check=False)
        output = (result.stdout or result.stderr or "").strip()
        if not output:
            raise RuntimeError("openvpn version output vacío")
        return output

    def _write_configs(self, profile: Profile) -> None:
        if profile.protocol is not ProtocolType.OPENVPN_CLOAK:
            raise ValueError(
                f"protocolo no soportado por OpenVPNCloakDriver: {profile.protocol.value}"
            )
        raw_config = str(profile.config.get("raw_config") or "").strip()
        if not raw_config:
            raise ValueError("perfil OPENVPN_CLOAK requiere raw_config")

        cloak_config = profile.config.get("cloak_config")
        if not cloak_config:
            raise ValueError("perfil OPENVPN_CLOAK requiere cloak_config")

        if isinstance(cloak_config, dict):
            cloak_json = json.dumps(cloak_config, indent=2)
        else:
            try:
                json.loads(str(cloak_config))
            except json.JSONDecodeError as exc:
                raise ValueError(f"cloak_config no es JSON válido: {exc}") from exc
            cloak_json = str(cloak_config)

        OC_OVPN_CONFIG_PATH.write_text(f"{raw_config}\n", encoding="utf-8")
        OC_OVPN_CONFIG_PATH.chmod(0o600)
        CLOAK_CONFIG_PATH.write_text(cloak_json, encoding="utf-8")
        CLOAK_CONFIG_PATH.chmod(0o600)

    def _cleanup_configs(self) -> None:
        OC_OVPN_CONFIG_PATH.unlink(missing_ok=True)
        CLOAK_CONFIG_PATH.unlink(missing_ok=True)

    def _reset_logs(self) -> None:
        for path in (CLOAK_LOG_PATH, OC_OVPN_LOG_PATH):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            try:
                path.write_text("", encoding="utf-8")
            except OSError:
                pass

    def _stop_process(self, process: subprocess.Popen[str] | None) -> None:
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

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

    def connect(self, profile: Profile) -> bool:
        openvpn_bin = self.find_openvpn_binary()
        ck_bin = self.find_ck_client_binary()
        if not openvpn_bin or not ck_bin:
            return False

        self._write_configs(profile)
        self._reset_logs()

        try:
            ck_log = CLOAK_LOG_PATH.open("w", encoding="utf-8")
        except OSError:
            ck_log = open(os.devnull, "w")
        self._ck_process = subprocess.Popen(
            [ck_bin, "-c", str(CLOAK_CONFIG_PATH)],
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
            ovpn_log = OC_OVPN_LOG_PATH.open("w", encoding="utf-8")
        except OSError:
            ovpn_log = open(os.devnull, "w")
        self._openvpn_process = subprocess.Popen(
            [openvpn_bin, "--config", str(OC_OVPN_CONFIG_PATH)],
            text=True,
            stdout=ovpn_log,
            stderr=subprocess.STDOUT,
        )
        ovpn_log.close()

        self._active_profile = profile
        if self._openvpn_process.poll() is None:
            self._connected_at = datetime.now(timezone.utc)
            return True

        self._cleanup_all()
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
        try:
            self._stop_process(self._openvpn_process)
            self._stop_process(self._ck_process)
        finally:
            self._openvpn_process = None
            self._ck_process = None
            self._active_profile = None
            self._connected_at = None
            self._cleanup_configs()
        return True

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
