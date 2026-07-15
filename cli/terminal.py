from __future__ import annotations

import shutil

from terminal_safety import (
    pad_to_width,
    strip_terminal_sequences,
    terminal_safe_text,
    truncate_to_width,
    visible_width,
    wrap_to_width,
)


DEFAULT_TERMINAL_WIDTH = 80
MIN_TERMINAL_WIDTH = 20
MAX_TERMINAL_WIDTH = 512

def terminal_width() -> int:
    """Return a bounded terminal width while honoring COLUMNS."""

    try:
        columns = shutil.get_terminal_size(
            fallback=(DEFAULT_TERMINAL_WIDTH, 24),
        ).columns
    except (OSError, ValueError):
        columns = DEFAULT_TERMINAL_WIDTH
    return min(max(columns, MIN_TERMINAL_WIDTH), MAX_TERMINAL_WIDTH)


def strip_ansi(value: object) -> str:
    """Compatibility alias for the full terminal-control sanitizer."""

    return strip_terminal_sequences(value)
