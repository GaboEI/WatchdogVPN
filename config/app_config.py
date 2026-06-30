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


DEFAULT_CONFIG: dict[str, dict[str, Any]] = {
    "watchdog": {
        "check_interval_seconds": 30,
        "reconnect_attempts": 3,
        "reconnect_backoff_seconds": 10,
    },
    "kill_switch": {
        "enabled": False,
        "block_ipv6": True,
    },
    "dns": {
        "mode": "auto",
    },
    "rotation": {
        "enabled": False,
        "health_status_cooldown_seconds": 300,
        "max_backoff_interval_seconds": 300,
    },
    "adguard": {
        "enabled": False,
        "legacy_mode": True,
    },
}


def _config_path() -> Path:
    base = Path(os.environ.get("WATCHDOGVPN_CONFIG_DIR", Path.home() / ".config" / "watchdogvpn"))
    return Path(os.environ.get("WATCHDOGVPN_CONFIG_FILE", base / "config.toml"))


class AppConfig:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _config_path()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
        with self.path.open("rb") as handle:
            data = tomllib.load(handle)
        merged = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
        for section, values in data.items():
            if isinstance(values, dict):
                merged.setdefault(section, {}).update(values)
        return merged

    def save(self, config: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
        for section, values in config.items():
            if isinstance(values, dict):
                payload.setdefault(section, {}).update(values)
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
            self.path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
            return
        with self.path.open("wb") as handle:
            handle.write(tomli_w.dumps(payload).encode("utf-8"))

