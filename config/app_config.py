from __future__ import annotations

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
    },
}

CONFIG_BOOL_FIELDS = {
    ("kill_switch", "enabled"),
    ("kill_switch", "block_ipv6"),
    ("kill_switch", "allow_lan"),
    ("rotation", "enabled"),
}
CONFIG_INT_FIELDS = {
    ("watchdog", "check_interval_seconds"),
    ("watchdog", "reconnect_attempts"),
    ("watchdog", "reconnect_backoff_seconds"),
    ("rotation", "health_status_cooldown_seconds"),
    ("rotation", "max_backoff_interval_seconds"),
}
CONFIG_STRING_FIELDS = {
    ("kill_switch", "tunnel_interface"),
    ("kill_switch", "on_manual_disconnect"),
    ("dns", "mode"),
}


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
            return {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
        try:
            with self.path.open("rb") as handle:
                data = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise PersistentStoreError(f"invalid TOML in {self.path}: {exc}") from exc
        except OSError as exc:
            raise PersistentStoreError(f"cannot read {self.path}: {exc}") from exc
        if not isinstance(data, dict):
            raise PersistentValidationError(f"{self.path} must contain TOML tables")
        merged = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
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
            else:
                validated[section][key] = value

    policy = validated["kill_switch"]["on_manual_disconnect"]
    if policy not in {"disable", "keep"}:
        raise PersistentValidationError("kill_switch.on_manual_disconnect must be 'disable' or 'keep'")
    if validated["dns"]["mode"] not in {"auto", "off", "custom", "advanced"}:
        raise PersistentValidationError("dns.mode must be one of: auto, off, custom, advanced")
    return validated
