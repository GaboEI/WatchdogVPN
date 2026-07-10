from __future__ import annotations

import os
import re
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
INTERFACE_NAME = "watchdogvpn_awg"
CONFIG_NAME = f"{INTERFACE_NAME}.conf"
LOG_NAME = "awg.log"
HANDSHAKE_TIMEOUT_SECONDS = 180
MAX_ERROR_DETAIL_LENGTH = 500
SECRET_LINE_RE = re.compile(r"^\s*(?:PrivateKey|PresharedKey)\s*=", re.IGNORECASE)
ROUTE_TABLE = "51820"
INTERFACE_CONFIG_KEYS = {
    "address",
    "dns",
    "mtu",
    "table",
    "preup",
    "postup",
    "predown",
    "postdown",
    "saveconfig",
}


@dataclass(slots=True)
class _BinaryPaths:
    awg: tuple[str, ...] = (
        "/usr/local/bin/awg",
        "/usr/bin/awg",
    )
    amneziawg_go: tuple[str, ...] = (
        "/usr/local/bin/amneziawg-go",
        "/usr/bin/amneziawg-go",
    )
    ip: tuple[str, ...] = (
        "/usr/sbin/ip",
        "/usr/bin/ip",
        "/sbin/ip",
        "/bin/ip",
    )


@dataclass(slots=True)
class _ParsedConfig:
    stripped_config: str
    addresses: list[str]
    allowed_ips: list[str]
    mtu: str | None
    table: str


class AmneziaWGDriver(BaseDriver):
    """Native driver for AmneziaWG profiles.

    Uses awg directly so the daemon never depends on sudo-driven quick scripts.
    When the kernel module is unavailable, amneziawg-go is used as the supported
    userspace implementation. Standard WireGuard tooling is not a valid runtime
    fallback for real AmneziaWG exports.
    """

    def __init__(self, binaries: _BinaryPaths | None = None) -> None:
        self.binaries = binaries or _BinaryPaths()
        self._active_profile: Profile | None = None
        self._connected_at: datetime | None = None
        self._runtime_dir: Path | None = None
        self._config_path: Path | None = None
        self._log_path: Path | None = None
        self._userspace_process: subprocess.Popen[str] | None = None
        self.last_error = ""
        cleanup_stale_runtime_dirs(RUNTIME_PREFIX)

    def _find_binary(self, candidates: tuple[str, ...], which_name: str) -> str | None:
        for candidate in candidates:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return shutil.which(which_name)

    def find_wg_tool(self) -> str | None:
        env_binary = os.environ.get("WATCHDOGVPN_AMNEZIAWG_BIN")
        if env_binary and os.path.exists(env_binary) and os.access(env_binary, os.X_OK):
            return env_binary
        return self._find_binary(self.binaries.awg, "awg")

    def find_userspace_tool(self) -> str | None:
        env_binary = os.environ.get("WATCHDOGVPN_AMNEZIAWG_GO_BIN")
        if env_binary and os.path.exists(env_binary) and os.access(env_binary, os.X_OK):
            return env_binary
        return self._find_binary(self.binaries.amneziawg_go, "amneziawg-go")

    def find_ip_tool(self) -> str | None:
        return self._find_binary(self.binaries.ip, "ip")

    def get_tool(self) -> str:
        tool = self.find_wg_tool()
        if not tool:
            raise FileNotFoundError("awg was not found")
        return tool

    def check_version(self) -> str:
        wg_tool = self.find_wg_tool()
        if not wg_tool:
            raise FileNotFoundError("awg was not found")
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
        if self.find_ip_tool() is None:
            return False
        if self.find_userspace_tool() is None and not self._kernel_module_loaded():
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

    def _split_csv_value(self, value: str) -> list[str]:
        return [item.strip() for item in value.split(",") if item.strip()]

    def _parse_config(self, raw: str) -> _ParsedConfig:
        addresses: list[str] = []
        allowed_ips: list[str] = []
        stripped_lines: list[str] = []
        section = ""
        mtu: str | None = None
        table = "auto"

        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                stripped_lines.append(line)
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped.strip("[]").strip().lower()
                stripped_lines.append(line)
                continue
            if "=" not in stripped:
                stripped_lines.append(line)
                continue

            key, _, value = stripped.partition("=")
            normalized_key = key.strip().lower()
            clean_value = value.strip()
            if section == "interface" and normalized_key in INTERFACE_CONFIG_KEYS:
                if normalized_key == "address":
                    addresses.extend(self._split_csv_value(clean_value))
                elif normalized_key == "mtu":
                    mtu = clean_value
                elif normalized_key == "table":
                    table = clean_value.lower() or "auto"
                continue
            if section == "peer" and normalized_key == "allowedips":
                allowed_ips.extend(self._split_csv_value(clean_value))
            if clean_value:
                stripped_lines.append(line)

        return _ParsedConfig(
            stripped_config="\n".join(stripped_lines).strip(),
            addresses=addresses,
            allowed_ips=allowed_ips,
            mtu=mtu,
            table=table,
        )

    def _ensure_runtime_paths(self) -> tuple[Path, Path]:
        if self._runtime_dir is None:
            self._runtime_dir = make_runtime_dir(RUNTIME_PREFIX)
            self._config_path = self._runtime_dir / CONFIG_NAME
            self._log_path = self._runtime_dir / LOG_NAME
        return self._config_path, self._log_path  # type: ignore[return-value]

    def _write_config(self, profile: Profile) -> _ParsedConfig:
        if profile.protocol is not ProtocolType.AMNEZIAWG:
            raise ValueError(f"unsupported protocol for AmneziaWG driver: {profile.protocol.value}")
        raw = str(profile.config.get("raw") or "").strip()
        if not raw:
            raise ValueError("AmneziaWG profile requires raw config")
        cleaned = self._strip_empty_keys(raw)
        parsed = self._parse_config(cleaned)
        if not parsed.stripped_config:
            raise ValueError("AmneziaWG profile has no awg runtime config")
        if not parsed.addresses:
            raise ValueError("AmneziaWG profile requires Interface Address")
        config_path, _ = self._ensure_runtime_paths()
        write_private_file(config_path, f"{parsed.stripped_config}\n")
        return parsed

    def _cleanup_runtime(self) -> None:
        if self._runtime_dir is not None and self._runtime_dir.exists():
            shutil.rmtree(self._runtime_dir, ignore_errors=True)
        self._runtime_dir = None
        self._config_path = None
        self._log_path = None

    def _kernel_module_loaded(self) -> bool:
        return Path("/sys/module/amneziawg").exists()

    def _interface_exists(self) -> bool:
        ip_tool = self.find_ip_tool()
        if not ip_tool:
            return False
        result = subprocess.run(
            [ip_tool, "link", "show", INTERFACE_NAME],
            text=True,
            capture_output=True,
            check=False,
        )
        return result.returncode == 0

    def _delete_interface(self) -> bool:
        ip_tool = self.find_ip_tool()
        if not ip_tool:
            return False
        result = subprocess.run(
            [ip_tool, "link", "delete", INTERFACE_NAME],
            text=True,
            capture_output=True,
            check=False,
        )
        return result.returncode == 0 or not self._interface_exists()

    def _run(
        self,
        args: list[str],
        *,
        input_text: str | None = None,
        success_codes: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )
        self._log(f"run: {' '.join(args)} -> {result.returncode}")
        if result.stdout:
            self._log(result.stdout.rstrip())
        if result.stderr:
            self._log(result.stderr.rstrip())
        if result.returncode not in success_codes:
            detail = (
                f"{Path(args[0]).name} command failed with code {result.returncode}: {' '.join(args)}\n"
                f"stdout:\n{result.stdout.strip()}\n"
                f"stderr:\n{result.stderr.strip()}"
            )
            raise RuntimeError(detail)
        return result

    def _wait_for_interface(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._interface_exists():
                return True
            process = self._userspace_process
            if process is not None and process.poll() is not None:
                return False
            time.sleep(0.1)
        return self._interface_exists()

    def _start_userspace_interface(self) -> bool:
        userspace_tool = self.find_userspace_tool()
        if not userspace_tool:
            return False
        _, log_path = self._ensure_runtime_paths()
        log_file = log_path.open("a", encoding="utf-8")
        try:
            self._userspace_process = subprocess.Popen(
                [userspace_tool, INTERFACE_NAME],
                text=True,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
        finally:
            log_file.close()
        self._log(f"connect: started {userspace_tool} {INTERFACE_NAME}")
        return self._wait_for_interface()

    def _create_interface(self) -> None:
        ip_tool = self.find_ip_tool()
        if not ip_tool:
            raise RuntimeError("ip command was not found")
        result = subprocess.run(
            [ip_tool, "link", "add", INTERFACE_NAME, "type", "amneziawg"],
            text=True,
            capture_output=True,
            check=False,
        )
        self._log(f"run: {ip_tool} link add {INTERFACE_NAME} type amneziawg -> {result.returncode}")
        if result.stderr:
            self._log(result.stderr.rstrip())
        if result.returncode == 0:
            return
        if self._start_userspace_interface():
            return
        detail = (
            f"amneziawg interface creation failed with code {result.returncode}\n"
            f"stdout:\n{result.stdout.strip()}\n"
            f"stderr:\n{result.stderr.strip()}"
        )
        raise RuntimeError(detail)

    def _configure_interface(self, parsed: _ParsedConfig) -> None:
        ip_tool = self.find_ip_tool()
        awg_tool = self.find_wg_tool()
        if not ip_tool:
            raise RuntimeError("ip command was not found")
        if not awg_tool:
            raise RuntimeError("awg was not found")
        config_path, _ = self._ensure_runtime_paths()
        self._run([awg_tool, "setconf", INTERFACE_NAME, str(config_path)])
        for address in parsed.addresses:
            family = "-6" if ":" in address else "-4"
            self._run([ip_tool, family, "address", "add", address, "dev", INTERFACE_NAME])
        mtu = parsed.mtu or "1420"
        self._run([ip_tool, "link", "set", "mtu", mtu, "up", "dev", INTERFACE_NAME])
        if parsed.table != "off":
            self._configure_routes(parsed.allowed_ips)

    def _route_family(self, cidr: str) -> str:
        return "-6" if ":" in cidr else "-4"

    def _configure_routes(self, allowed_ips: list[str]) -> None:
        ip_tool = self.find_ip_tool()
        awg_tool = self.find_wg_tool()
        if not ip_tool or not awg_tool:
            raise RuntimeError("AmneziaWG route tools are missing")
        default_v4 = "0.0.0.0/0" in allowed_ips
        default_v6 = "::/0" in allowed_ips
        if default_v4 or default_v6:
            self._run([awg_tool, "set", INTERFACE_NAME, "fwmark", ROUTE_TABLE])
        if default_v4:
            self._run([ip_tool, "-4", "route", "add", "0.0.0.0/0", "dev", INTERFACE_NAME, "table", ROUTE_TABLE])
            self._run([ip_tool, "-4", "rule", "add", "not", "fwmark", ROUTE_TABLE, "table", ROUTE_TABLE])
            self._run([ip_tool, "-4", "rule", "add", "table", "main", "suppress_prefixlength", "0"])
            self._run(["sysctl", "-q", "net.ipv4.conf.all.src_valid_mark=1"])
        if default_v6:
            self._run([ip_tool, "-6", "route", "add", "::/0", "dev", INTERFACE_NAME, "table", ROUTE_TABLE])
            self._run([ip_tool, "-6", "rule", "add", "not", "fwmark", ROUTE_TABLE, "table", ROUTE_TABLE])
            self._run([ip_tool, "-6", "rule", "add", "table", "main", "suppress_prefixlength", "0"])
        for cidr in allowed_ips:
            if cidr in {"0.0.0.0/0", "::/0"}:
                continue
            self._run([ip_tool, self._route_family(cidr), "route", "add", cidr, "dev", INTERFACE_NAME])

    def _cleanup_routes(self) -> None:
        ip_tool = self.find_ip_tool()
        if not ip_tool:
            return
        cleanup_commands = [
            [ip_tool, "-4", "rule", "delete", "not", "fwmark", ROUTE_TABLE, "table", ROUTE_TABLE],
            [ip_tool, "-4", "rule", "delete", "table", "main", "suppress_prefixlength", "0"],
            [ip_tool, "-4", "route", "flush", "table", ROUTE_TABLE],
            [ip_tool, "-6", "rule", "delete", "not", "fwmark", ROUTE_TABLE, "table", ROUTE_TABLE],
            [ip_tool, "-6", "rule", "delete", "table", "main", "suppress_prefixlength", "0"],
            [ip_tool, "-6", "route", "flush", "table", ROUTE_TABLE],
        ]
        for command in cleanup_commands:
            self._run(command, success_codes=(0, 1, 2))

    def _stop_userspace_process(self) -> bool:
        process = self._userspace_process
        self._userspace_process = None
        if process is None:
            return True
        if process.poll() is not None:
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

    def _sanitize_error_detail(self, text: str) -> str:
        safe_lines: list[str] = []
        for line in text.splitlines():
            if SECRET_LINE_RE.match(line):
                safe_lines.append("<redacted secret key line>")
            else:
                safe_lines.append(line)
        safe = "\n".join(safe_lines).strip()
        if len(safe) > MAX_ERROR_DETAIL_LENGTH:
            return f"{safe[:MAX_ERROR_DETAIL_LENGTH]}..."
        return safe

    def _set_last_error(self, message: str) -> None:
        self.last_error = self._sanitize_error_detail(message)

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
    ) -> bool:
        self.last_error = ""
        if not self.find_ip_tool():
            self._set_last_error("ip command was not found")
            return False
        if not self.find_wg_tool():
            self._set_last_error("awg was not found")
            return False
        if self._interface_exists() and not self._delete_interface():
            self._set_last_error(f"stale interface could not be deleted: {INTERFACE_NAME}")
            return False
        try:
            parsed = self._write_config(profile)
            self._reset_log()
            self._cleanup_routes()
            self._create_interface()
            self._configure_interface(parsed)
        except (OSError, RuntimeError, ValueError) as exc:
            self._set_last_error(str(exc))
            self._log(f"connect: {self.last_error}")
            self.disconnect()
            self._cleanup_runtime()
            return False

        self._active_profile = profile
        if self._interface_exists():
            self._connected_at = datetime.now(timezone.utc)
            return True
        self._active_profile = None
        self._connected_at = None
        self._set_last_error(f"interface was not created after native AmneziaWG bring-up: {INTERFACE_NAME}")
        self.disconnect()
        return False

    def disconnect(self) -> bool:
        stopped = True
        try:
            if self._runtime_dir is not None or self._interface_exists() or self._userspace_process is not None:
                self._cleanup_routes()
            if self._interface_exists():
                stopped = self._delete_interface()
            stopped = self._stop_userspace_process() and stopped
        finally:
            self._active_profile = None
            self._connected_at = None
            self._cleanup_runtime()
        return stopped and not self._interface_exists()

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
