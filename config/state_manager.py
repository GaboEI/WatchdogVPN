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

from config.persistence import (
    PersistentStoreError,
    PersistentValidationError,
    atomic_write_text,
    file_lock,
    strict_bool,
)


DEFAULT_STATE = {
    "app_autostart_enabled": False,
    "vpn_autoconnect_enabled": False,
    "vpn_desired_state": "off",
    "active_profile_id": "",
    "active_mode": "rules",
    "language_mode": "system",
    "selected_language": "en",
}

ALLOWED_VPN_DESIRED_STATES = {"on", "off"}
ALLOWED_ACTIVE_MODES = {"rules", "global", "direct", "tun", "proxy"}
ALLOWED_LANGUAGE_MODES = {"system", "manual"}
STATE_BOOL_FIELDS = {"app_autostart_enabled", "vpn_autoconnect_enabled"}
STATE_STRING_FIELDS = {
    "vpn_desired_state",
    "active_profile_id",
    "active_mode",
    "language_mode",
    "selected_language",
}


def _state_path() -> Path:
    base = Path(os.environ.get("WATCHDOGVPN_STATE_DIR", Path.home() / ".config" / "watchdogvpn"))
    return Path(os.environ.get("WATCHDOGVPN_STATE_FILE", base / "state.toml"))


class StateManager:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _state_path()

    def load(self) -> dict[str, Any]:
        with file_lock(self.path):
            return self._load_unlocked()

    def _load_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            return dict(DEFAULT_STATE)
        try:
            with self.path.open("rb") as handle:
                data = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise PersistentStoreError(f"invalid TOML in {self.path}: {exc}") from exc
        except OSError as exc:
            raise PersistentStoreError(f"cannot read {self.path}: {exc}") from exc
        if not isinstance(data, dict):
            raise PersistentValidationError(f"{self.path} must contain a TOML table")
        state = dict(DEFAULT_STATE)
        state.update(data)
        return _validate_state(state, self.path)

    def save(self, state: dict[str, Any]) -> None:
        with file_lock(self.path):
            self._save_unlocked(state)

    def _save_unlocked(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(DEFAULT_STATE)
        payload.update(state)
        payload = _validate_state(payload, self.path)
        if tomli_w is None:  # pragma: no cover
            lines = []
            for key, value in payload.items():
                if isinstance(value, bool):
                    rendered = "true" if value else "false"
                else:
                    rendered = f'"{value}"'
                lines.append(f"{key} = {rendered}")
            atomic_write_text(self.path, "\n".join(lines) + "\n")
            return
        atomic_write_text(self.path, tomli_w.dumps(payload))

    def set(self, key: str, value: Any) -> None:
        with file_lock(self.path):
            state = self._load_unlocked()
            state[key] = value
            self._save_unlocked(state)

    def get(self, key: str, default: Any = None) -> Any:
        return self.load().get(key, default)


def _validate_state(state: dict[str, Any], path: Path) -> dict[str, Any]:
    validated = dict(DEFAULT_STATE)
    for key, value in state.items():
        if key in STATE_BOOL_FIELDS:
            validated[key] = strict_bool(value, key)
        elif key in STATE_STRING_FIELDS:
            if not isinstance(value, str):
                raise PersistentValidationError(f"{key} in {path} must be a string")
            validated[key] = value
        else:
            raise PersistentValidationError(f"{path} contains unsupported state field: {key}")

    if validated["vpn_desired_state"] not in ALLOWED_VPN_DESIRED_STATES:
        raise PersistentValidationError("vpn_desired_state must be 'on' or 'off'")
    if validated["active_mode"] not in ALLOWED_ACTIVE_MODES:
        raise PersistentValidationError("active_mode must be one of: rules, global, direct, tun, proxy")
    if validated["language_mode"] not in ALLOWED_LANGUAGE_MODES:
        raise PersistentValidationError("language_mode must be 'system' or 'manual'")
    if not validated["selected_language"]:
        raise PersistentValidationError("selected_language must not be empty")
    return validated
