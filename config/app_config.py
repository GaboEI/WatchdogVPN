from __future__ import annotations

import ipaddress
from copy import deepcopy
import os
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

try:
    import tomli_w  # pyrefly: ignore [missing-import]
except ModuleNotFoundError:  # pragma: no cover
    tomli_w = None  # type: ignore

from config.paths import resolve_config_dir
from config.persistence import (
    PersistentStoreError,
    PersistentValidationError,
    atomic_write_text,
    file_lock,
    strict_bool,
    strict_int,
)
from rotation.health_targets import (
    DEFAULT_HEALTH_TARGETS,
    DEFAULT_SUCCESS_QUORUM,
    validate_success_quorum,
    validate_targets,
)


DEFAULT_CONFIG: dict[str, dict[str, Any]] = {
    "watchdog": {
        "check_interval_seconds": 30,
        "reconnect_attempts": 3,
        "reconnect_backoff_seconds": 10,
    },
    "kill_switch": {
        "enabled": False,
        "block_ipv6": True,
        "allow_lan": True,
        "tunnel_interface": "wdvpn-tun0",
        "on_manual_disconnect": "disable",
    },
    "dns": {
        "mode": "auto",
    },
    "rotation": {
        "enabled": False,
        "health_status_cooldown_seconds": 300,
        "max_backoff_interval_seconds": 300,
        "scheduled_interval_hours": 0,
        "health_targets": list(DEFAULT_HEALTH_TARGETS),
        "health_success_quorum": DEFAULT_SUCCESS_QUORUM,
        "test_timeout_seconds": 5,
        "latency_max_stale_seconds": 300,
    },
    "lan_sharing": {
        "enabled": False,
        "mode": "disabled",
        "bind_address": "",
        "socks_port": 2080,
        "http_port": 2081,
        "authentication_required": True,
        "firewall_managed": False,
        "gateway_interface": "",
        "gateway_client_cidr": "",
        "gateway_dns_mode": "manual",
    },
}

CONFIG_BOOL_FIELDS = {
    ("kill_switch", "enabled"),
    ("kill_switch", "block_ipv6"),
    ("kill_switch", "allow_lan"),
    ("rotation", "enabled"),
    ("lan_sharing", "enabled"),
    ("lan_sharing", "authentication_required"),
    ("lan_sharing", "firewall_managed"),
}
CONFIG_INT_FIELDS = {
    ("watchdog", "check_interval_seconds"),
    ("watchdog", "reconnect_attempts"),
    ("watchdog", "reconnect_backoff_seconds"),
    ("rotation", "health_status_cooldown_seconds"),
    ("rotation", "max_backoff_interval_seconds"),
    ("rotation", "scheduled_interval_hours"),
    ("rotation", "test_timeout_seconds"),
    ("rotation", "health_success_quorum"),
    ("rotation", "latency_max_stale_seconds"),
    ("lan_sharing", "socks_port"),
    ("lan_sharing", "http_port"),
}
CONFIG_STRING_FIELDS = {
    ("kill_switch", "tunnel_interface"),
    ("kill_switch", "on_manual_disconnect"),
    ("dns", "mode"),
    ("lan_sharing", "mode"),
    ("lan_sharing", "bind_address"),
    ("lan_sharing", "gateway_interface"),
    ("lan_sharing", "gateway_client_cidr"),
    ("lan_sharing", "gateway_dns_mode"),
}

CONFIG_STRING_LIST_FIELDS = {("rotation", "health_targets")}

MIN_WATCHDOG_CHECK_INTERVAL_SECONDS = 5


def _config_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_CONFIG_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / "config.toml"


class AppConfig:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _config_path()

    def load(self) -> dict[str, Any]:
        with file_lock(self.path):
            return self._load_unlocked()

    def _load_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            return deepcopy(DEFAULT_CONFIG)
        try:
            with self.path.open("rb") as handle:
                data = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise PersistentStoreError(f"invalid TOML in {self.path}: {exc}") from exc
        except OSError as exc:
            raise PersistentStoreError(f"cannot read {self.path}: {exc}") from exc
        if not isinstance(data, dict):
            raise PersistentValidationError(f"{self.path} must contain TOML tables")
        rotation = data.get("rotation")
        if isinstance(rotation, dict) and "test_url" in rotation:
            legacy_test_url = rotation.pop("test_url")
            if "health_targets" not in rotation:
                rotation["health_targets"] = [
                    legacy_test_url,
                    *[target for target in DEFAULT_CONFIG["rotation"]["health_targets"] if target != legacy_test_url],
                ]
        merged = deepcopy(DEFAULT_CONFIG)
        for section, values in data.items():
            if isinstance(values, dict):
                merged.setdefault(section, {}).update(values)
            else:
                raise PersistentValidationError(f"{section} in {self.path} must be a table")
        return _validate_config(merged, self.path)

    def save(self, config: dict[str, Any]) -> None:
        with file_lock(self.path):
            self._save_unlocked(config)

    def _save_unlocked(self, config: dict[str, Any]) -> None:
        payload = deepcopy(DEFAULT_CONFIG)
        for section, values in config.items():
            if isinstance(values, dict):
                payload.setdefault(section, {}).update(values)
            else:
                raise PersistentValidationError(f"{section} in {self.path} must be a table")
        payload = _validate_config(payload, self.path)
        if tomli_w is None:  # pragma: no cover
            lines: list[str] = []
            for section, values in payload.items():
                lines.append(f"[{section}]")
                for key, value in values.items():
                    if isinstance(value, bool):
                        rendered = "true" if value else "false"
                    elif isinstance(value, (int, float)):
                        rendered = str(value)
                    elif isinstance(value, list):
                        rendered = "[" + ", ".join('"' + item + '"' for item in value) + "]"
                    else:
                        rendered = f'"{value}"'
                    lines.append(f"{key} = {rendered}")
                lines.append("")
            atomic_write_text(self.path, "\n".join(lines).rstrip() + "\n")
            return
        atomic_write_text(self.path, tomli_w.dumps(payload))


def _validate_config(config: dict[str, Any], path: Path) -> dict[str, Any]:
    validated: dict[str, dict[str, Any]] = {}
    allowed_sections = set(DEFAULT_CONFIG)
    for section, values in config.items():
        if section not in allowed_sections:
            raise PersistentValidationError(f"{path} contains unsupported config section: {section}")
        if not isinstance(values, dict):
            raise PersistentValidationError(f"{section} in {path} must be a table")
        validated[section] = {}
        allowed_keys = set(DEFAULT_CONFIG[section])
        for key, value in values.items():
            if key not in allowed_keys:
                raise PersistentValidationError(
                    f"{path} contains unsupported config field: {section}.{key}"
                )
            field = (section, key)
            if field in CONFIG_BOOL_FIELDS:
                validated[section][key] = strict_bool(value, f"{section}.{key}")
            elif field in CONFIG_INT_FIELDS:
                number = strict_int(value, f"{section}.{key}")
                if number < 0:
                    raise PersistentValidationError(f"{section}.{key} must not be negative")
                validated[section][key] = number
            elif field in CONFIG_STRING_FIELDS:
                if not isinstance(value, str):
                    raise PersistentValidationError(f"{section}.{key} must be a string")
                validated[section][key] = value
            elif field in CONFIG_STRING_LIST_FIELDS:
                try:
                    validated[section][key] = list(validate_targets(value, f"{section}.{key}"))
                except ValueError as exc:
                    raise PersistentValidationError(str(exc)) from exc
            else:
                validated[section][key] = value

    policy = validated["kill_switch"]["on_manual_disconnect"]
    if policy not in {"disable", "keep"}:
        raise PersistentValidationError("kill_switch.on_manual_disconnect must be 'disable' or 'keep'")
    if validated["dns"]["mode"] not in {"auto", "off", "custom", "advanced"}:
        raise PersistentValidationError("dns.mode must be one of: auto, off, custom, advanced")
    check_interval = validated["watchdog"]["check_interval_seconds"]
    if check_interval < MIN_WATCHDOG_CHECK_INTERVAL_SECONDS:
        raise PersistentValidationError(
            f"watchdog.check_interval_seconds must be at least "
            f"{MIN_WATCHDOG_CHECK_INTERVAL_SECONDS}"
        )
    try:
        validated["rotation"]["health_success_quorum"] = validate_success_quorum(
            validated["rotation"]["health_success_quorum"],
            validated["rotation"]["health_targets"],
        )
    except ValueError as exc:
        raise PersistentValidationError(str(exc)) from exc
    if validated["rotation"]["test_timeout_seconds"] < 1:
        raise PersistentValidationError("rotation.test_timeout_seconds must be at least 1")
    _validate_lan_sharing(validated["lan_sharing"])
    return validated


def _validate_lan_sharing(config: dict[str, Any]) -> None:
    mode = config["mode"]
    if mode not in {"disabled", "proxy", "gateway"}:
        raise PersistentValidationError("lan_sharing.mode must be one of: disabled, proxy, gateway")

    socks_port = config["socks_port"]
    http_port = config["http_port"]
    for key, port in (("socks_port", socks_port), ("http_port", http_port)):
        if port < 1 or port > 65535:
            raise PersistentValidationError(f"lan_sharing.{key} must be between 1 and 65535")
    if socks_port == http_port:
        raise PersistentValidationError("lan_sharing.socks_port and lan_sharing.http_port must differ")

    bind_address = config["bind_address"].strip()
    config["bind_address"] = bind_address
    if bind_address:
        _validate_lan_bind_address(bind_address)

    gateway_interface = config["gateway_interface"].strip()
    config["gateway_interface"] = gateway_interface
    if gateway_interface:
        _validate_gateway_interface(gateway_interface)
    gateway_client_cidr = config["gateway_client_cidr"].strip()
    config["gateway_client_cidr"] = gateway_client_cidr
    if gateway_client_cidr:
        _validate_gateway_client_cidr(gateway_client_cidr)
    gateway_dns_mode = config["gateway_dns_mode"].strip()
    config["gateway_dns_mode"] = gateway_dns_mode
    if gateway_dns_mode not in {"manual"}:
        raise PersistentValidationError("lan_sharing.gateway_dns_mode must be manual")

    if not config["enabled"]:
        return

    if mode == "proxy":
        _validate_enabled_lan_proxy(config, bind_address)
        return
    if mode == "gateway":
        _validate_enabled_lan_gateway(config, gateway_interface, gateway_client_cidr)
        return
    raise PersistentValidationError("lan_sharing.enabled requires lan_sharing.mode = 'proxy' or 'gateway'")


def _validate_enabled_lan_proxy(config: dict[str, Any], bind_address: str) -> None:
    if not bind_address:
        raise PersistentValidationError("lan_sharing.enabled requires an explicit bind_address")
    address = ipaddress.ip_address(bind_address)
    if address.is_loopback:
        raise PersistentValidationError("lan_sharing.bind_address must be a non-loopback LAN address when enabled")
    if not config["authentication_required"]:
        raise PersistentValidationError("lan_sharing.enabled requires authentication_required = true")


def _validate_enabled_lan_gateway(
    config: dict[str, Any],
    gateway_interface: str,
    gateway_client_cidr: str,
) -> None:
    if not gateway_interface:
        raise PersistentValidationError("lan_sharing.gateway mode requires gateway_interface")
    if not gateway_client_cidr:
        raise PersistentValidationError("lan_sharing.gateway mode requires gateway_client_cidr")
    if not config["firewall_managed"]:
        raise PersistentValidationError("lan_sharing.gateway mode requires firewall_managed = true")


def _validate_lan_bind_address(value: str) -> None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PersistentValidationError("lan_sharing.bind_address must be an IP address") from exc
    if address.is_unspecified:
        if os.environ.get("WATCHDOGVPN_TEST_ALLOW_WILDCARD_LAN_BIND") == "1":
            return
        raise PersistentValidationError("lan_sharing.bind_address must not be a wildcard address")
    if address.is_multicast:
        raise PersistentValidationError("lan_sharing.bind_address must not be multicast")


def _validate_gateway_interface(value: str) -> None:
    if value in {"lo", "all", "*"}:
        raise PersistentValidationError("lan_sharing.gateway_interface must be a concrete non-loopback interface")
    if any(char.isspace() for char in value):
        raise PersistentValidationError("lan_sharing.gateway_interface must not contain whitespace")
    if "/" in value or "\x00" in value:
        raise PersistentValidationError("lan_sharing.gateway_interface contains invalid characters")


def _validate_gateway_client_cidr(value: str) -> None:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise PersistentValidationError("lan_sharing.gateway_client_cidr must be an IP network") from exc
    if network.version != 4:
        raise PersistentValidationError("lan_sharing.gateway_client_cidr must be IPv4")
    if network.prefixlen == 0:
        raise PersistentValidationError("lan_sharing.gateway_client_cidr must not be 0.0.0.0/0")
    if network.is_loopback:
        raise PersistentValidationError("lan_sharing.gateway_client_cidr must not be loopback")
    if network.is_multicast:
        raise PersistentValidationError("lan_sharing.gateway_client_cidr must not be multicast")
