from __future__ import annotations

import os
import sys
from typing import TextIO


ANSI_STYLES = {
    "bold": "1",
    "dim": "2",
    "green": "32",
    "yellow": "33",
    "red": "31",
    "cyan": "36",
}


SUCCESS_WORDS = {
    "active",
    "applied",
    "clean",
    "connected",
    "enabled",
    "ok",
    "on",
    "present",
    "protected",
    "reachable",
    "restored",
    "verified",
    "yes",
}
WARNING_WORDS = {
    "degraded",
    "dry-run",
    "missing",
    "not-found",
    "nothing-to-restore",
    "partial",
    "skipped",
    "standby",
    "unknown",
}
ERROR_WORDS = {
    "blocked",
    "dirty",
    "down",
    "failed",
    "kill_switch_active",
    "kill_switch_failed",
    "runtime mismatch",
    "runtime_mismatch",
    "unreachable",
    "unsafe",
}


def color_enabled(*, no_color: bool = False, stream: TextIO | None = None) -> bool:
    output = stream or sys.stdout
    return not no_color and "NO_COLOR" not in os.environ and output.isatty()


def style(text: object, style_name: str, *, no_color: bool = False, stream: TextIO | None = None) -> str:
    value = str(text)
    code = ANSI_STYLES.get(style_name)
    if code is None or not color_enabled(no_color=no_color, stream=stream):
        return value
    return f"\033[{code}m{value}\033[0m"


def semantic(text: object, *, no_color: bool = False, stream: TextIO | None = None) -> str:
    value = str(text)
    normalized = value.strip().lower()
    if normalized in SUCCESS_WORDS:
        return style(value, "green", no_color=no_color, stream=stream)
    if normalized in WARNING_WORDS:
        return style(value, "yellow", no_color=no_color, stream=stream)
    if normalized in ERROR_WORDS:
        return style(value, "red", no_color=no_color, stream=stream)
    return value


def command(text: object, *, no_color: bool = False, stream: TextIO | None = None) -> str:
    return style(text, "cyan", no_color=no_color, stream=stream)


def warning_label(text: object = "Warning", *, no_color: bool = False, stream: TextIO | None = None) -> str:
    return style(text, "yellow", no_color=no_color, stream=stream)


def error_label(text: object = "error", *, no_color: bool = False, stream: TextIO | None = None) -> str:
    return style(text, "red", no_color=no_color, stream=stream)
