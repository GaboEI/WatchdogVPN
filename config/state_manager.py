from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

try:
    import tomli_w
except ModuleNotFoundError:  # pragma: no cover
    tomli_w = None  # type: ignore


DEFAULT_STATE = {
    "app_autostart_enabled": False,
    "vpn_autoconnect_enabled": False,
    "vpn_desired_state": "off",
    "active_profile_id": "",
    "active_mode": "rules",
    "language_mode": "system",
    "selected_language": "en",
}


def _state_path() -> Path:
    base = Path(os.environ.get("WATCHDOGVPN_STATE_DIR", Path.home() / ".config" / "watchdogvpn"))
    return Path(os.environ.get("WATCHDOGVPN_STATE_FILE", base / "state.toml"))


class StateManager:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _state_path()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return dict(DEFAULT_STATE)
        with self.path.open("rb") as handle:
            data = tomllib.load(handle)
        state = dict(DEFAULT_STATE)
        state.update(data)
        return state

    def save(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(DEFAULT_STATE)
        payload.update(state)
        if tomli_w is None:  # pragma: no cover
            lines = []
            for key, value in payload.items():
                if isinstance(value, bool):
                    rendered = "true" if value else "false"
                else:
                    rendered = f'"{value}"'
                lines.append(f"{key} = {rendered}")
            self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return
        with self.path.open("wb") as handle:
            handle.write(tomli_w.dumps(payload).encode("utf-8"))

    def set(self, key: str, value: Any) -> None:
        state = self.load()
        state[key] = value
        self.save(state)

    def get(self, key: str, default: Any = None) -> Any:
        return self.load().get(key, default)

