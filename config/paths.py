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
    if (SYSTEM_CONFIG_DIR / MIGRATION_MARKER).exists():
        return SYSTEM_CONFIG_DIR
    return _user_config_dir()


def _running_as_service_user() -> bool:
    try:
        return pwd.getpwuid(os.getuid()).pw_name == SERVICE_USER
    except KeyError:
        return False


def _user_config_dir() -> Path:
    return Path.home() / ".config" / "watchdogvpn"
