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
)


DEFAULT_STATE = {
    "app_autostart_enabled": False,
    "vpn_autoconnect_enabled": False,
    "vpn_desired_state": "off",
    "active_profile_id": "",
    "routing_state_version": "1",
    "routing_policy": "rule",
    "capture_modes": "local_proxy",
    "default_route_action": "current",
    "active_mode": "rules",
    "language_mode": "system",
    "selected_language": "en",
}

ALLOWED_VPN_DESIRED_STATES = {"on", "off"}
ALLOWED_ACTIVE_MODES = {"rules", "global", "direct", "tun", "proxy"}
SUPPORTED_ROUTING_STATE_VERSION = "1"
ALLOWED_ROUTING_POLICIES = {"rule", "global"}
ALLOWED_CAPTURE_MODES = {"local_proxy", "tun", "system_proxy"}
ALLOWED_DEFAULT_ROUTE_ACTIONS = {"current", "direct", "block"}
ALLOWED_LANGUAGE_MODES = {"system", "manual"}
STATE_BOOL_FIELDS = {"app_autostart_enabled", "vpn_autoconnect_enabled"}
STATE_STRING_FIELDS = {
    "vpn_desired_state",
    "active_profile_id",
    "routing_state_version",
    "routing_policy",
    "capture_modes",
    "default_route_action",
    "active_mode",
    "language_mode",
    "selected_language",
}
ROUTING_STATE_FIELDS = {
    "routing_state_version",
    "routing_policy",
    "capture_modes",
    "default_route_action",
}
LEGACY_MODE_TO_ROUTING_STATE = {
    "rules": {
        "routing_state_version": SUPPORTED_ROUTING_STATE_VERSION,
        "routing_policy": "rule",
        "capture_modes": "local_proxy",
        "default_route_action": "current",
    },
    "global": {
        "routing_state_version": SUPPORTED_ROUTING_STATE_VERSION,
        "routing_policy": "global",
        "capture_modes": "local_proxy",
        "default_route_action": "current",
    },
    "direct": {
        "routing_state_version": SUPPORTED_ROUTING_STATE_VERSION,
        "routing_policy": "global",
        "capture_modes": "local_proxy",
        "default_route_action": "direct",
    },
    "tun": {
        "routing_state_version": SUPPORTED_ROUTING_STATE_VERSION,
        "routing_policy": "global",
        "capture_modes": "local_proxy,tun",
        "default_route_action": "current",
    },
    "proxy": {
        "routing_state_version": SUPPORTED_ROUTING_STATE_VERSION,
        "routing_policy": "global",
        "capture_modes": "local_proxy",
        "default_route_action": "current",
    },
}


def _state_path() -> Path:
    file_override = os.environ.get("WATCHDOGVPN_STATE_FILE")
    if file_override:
        return Path(file_override)
    dir_override = os.environ.get("WATCHDOGVPN_STATE_DIR")
    if dir_override:
        return Path(dir_override) / "state.toml"
    return resolve_config_dir() / "state.toml"


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
        return _validate_state(data, self.path)

    def save(self, state: dict[str, Any]) -> None:
        with file_lock(self.path):
            self._save_unlocked(state)

    def _save_unlocked(self, state: dict[str, Any]) -> None:
        payload = _validate_state(state, self.path)
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
            if key == "active_mode":
                state.update(routing_state_from_legacy_mode(str(value)))
            self._save_unlocked(state)

    def get(self, key: str, default: Any = None) -> Any:
        return self.load().get(key, default)


def _validate_state(state: dict[str, Any], path: Path) -> dict[str, Any]:
    has_routing_state = any(key in state for key in ROUTING_STATE_FIELDS)
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
    if not has_routing_state:
        validated.update(routing_state_from_legacy_mode(validated["active_mode"]))
    else:
        _validate_routing_fields(validated, path)
        validated["active_mode"] = compatibility_active_mode_for_routing_state(
            validated,
            fallback=validated["active_mode"],
        )
    if validated["language_mode"] not in ALLOWED_LANGUAGE_MODES:
        raise PersistentValidationError("language_mode must be 'system' or 'manual'")
    if not validated["selected_language"]:
        raise PersistentValidationError("selected_language must not be empty")
    return validated


def routing_state_from_legacy_mode(mode: str) -> dict[str, str]:
    if mode not in LEGACY_MODE_TO_ROUTING_STATE:
        raise PersistentValidationError("active_mode must be one of: rules, global, direct, tun, proxy")
    return dict(LEGACY_MODE_TO_ROUTING_STATE[mode])


def parse_capture_modes(value: str) -> tuple[str, ...]:
    modes = tuple(item.strip() for item in value.split(",") if item.strip())
    if len(set(modes)) != len(modes):
        raise PersistentValidationError("capture_modes must not contain duplicate entries")
    unknown = sorted(set(modes) - ALLOWED_CAPTURE_MODES)
    if unknown:
        joined = ", ".join(unknown)
        raise PersistentValidationError(f"capture_modes contains unsupported entries: {joined}")
    if "system_proxy" in modes and "local_proxy" not in modes:
        raise PersistentValidationError("system_proxy capture requires local_proxy")
    return modes


def _validate_routing_fields(state: dict[str, Any], path: Path) -> None:
    if state["routing_state_version"] != SUPPORTED_ROUTING_STATE_VERSION:
        raise PersistentValidationError(
            f"unsupported routing_state_version in {path}: {state['routing_state_version']}"
        )
    if state["routing_policy"] not in ALLOWED_ROUTING_POLICIES:
        raise PersistentValidationError("routing_policy must be one of: rule, global")
    if state["default_route_action"] not in ALLOWED_DEFAULT_ROUTE_ACTIONS:
        raise PersistentValidationError("default_route_action must be one of: current, direct, block")
    parse_capture_modes(state["capture_modes"])


def compatibility_active_mode_for_routing_state(
    state: dict[str, Any],
    *,
    fallback: str = "global",
) -> str:
    if fallback in ALLOWED_ACTIVE_MODES:
        fallback_state = routing_state_from_legacy_mode(fallback)
        if (
            fallback_state["routing_policy"] == state.get("routing_policy")
            and fallback_state["capture_modes"] == state.get("capture_modes")
            and fallback_state["default_route_action"] == state.get("default_route_action")
        ):
            return fallback
    try:
        return rollback_active_mode_for_routing_state(state)
    except PersistentValidationError:
        if fallback in ALLOWED_ACTIVE_MODES:
            return fallback
        return "global"


def rollback_active_mode_for_routing_state(state: dict[str, Any]) -> str:
    routing_policy = str(state.get("routing_policy", ""))
    capture_modes = parse_capture_modes(str(state.get("capture_modes", "")))
    default_action = str(state.get("default_route_action", ""))

    if routing_policy == "rule" and default_action == "current" and "tun" not in capture_modes:
        return "rules"
    if routing_policy == "global" and capture_modes == ("local_proxy",) and default_action == "current":
        return "global"
    if routing_policy == "global" and capture_modes == ("local_proxy",) and default_action == "direct":
        return "direct"
    if routing_policy == "global" and "tun" in capture_modes and default_action == "current":
        return "tun"
    raise PersistentValidationError("routing state has no exact legacy active_mode equivalent")
