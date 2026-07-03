from __future__ import annotations

import os
import pwd
from pathlib import Path


CONFIG_DIR_ENV = "WATCHDOGVPN_CONFIG_DIR"
SERVICE_USER = "watchdogvpn"
SYSTEM_CONFIG_DIR = Path("/var/lib/watchdogvpn")
MIGRATION_MARKER = ".migrated"


def resolve_config_dir() -> Path:
    """Return the shared WatchdogVPN state/config directory."""
    if override := os.environ.get(CONFIG_DIR_ENV):
        return Path(override)
    if _running_as_service_user():
        return SYSTEM_CONFIG_DIR
    if _migration_marker_exists():
        return SYSTEM_CONFIG_DIR
    return _user_config_dir()


def _running_as_service_user() -> bool:
    try:
        return pwd.getpwuid(os.getuid()).pw_name == SERVICE_USER
    except KeyError:
        return False


def _user_config_dir() -> Path:
    return Path.home() / ".config" / "watchdogvpn"


def _migration_marker_exists() -> bool:
    marker = SYSTEM_CONFIG_DIR / MIGRATION_MARKER
    try:
        return marker.exists()
    except PermissionError as exc:
        raise PermissionError(
            "Permission denied reading WatchdogVPN shared state. Your user must be in the "
            "'watchdogvpn' group and the shared state directory must be group-accessible. "
            "Try: sudo usermod -aG watchdogvpn $USER, then log out and back in; or rerun "
            "./install.sh to repair shared-state permissions."
        ) from exc
