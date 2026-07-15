"""Terminal capability and resize primitives for the interactive TUI.

This module keeps capability decisions explicit: cursor-addressed rendering is
only valid for an interactive ANSI terminal, while a `TERM=dumb` or redirected
session must receive plain literal text instead of escape sequences.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import shutil
import sys


MIN_COLUMNS = 40
MIN_ROWS = 12
WIDE_COLUMNS = 76


@dataclass(frozen=True)
class TerminalCapabilities:
    interactive: bool
    ansi: bool
    mouse: bool
    columns: int
    rows: int

    @property
    def layout(self) -> str:
        if not self.interactive or not self.ansi:
            return "plain"
        if self.columns < MIN_COLUMNS or self.rows < MIN_ROWS:
            return "too-small"
        if self.columns < WIDE_COLUMNS:
            return "compact"
        return "wide"


def detect_terminal(
    *,
    stdin=None,
    stdout=None,
    environ: dict[str, str] | None = None,
    size_getter=shutil.get_terminal_size,
) -> TerminalCapabilities:
    """Return the public terminal contract without emitting control bytes."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    environ = os.environ if environ is None else environ
    size = size_getter((120, 30))
    interactive = bool(getattr(stdin, "isatty", lambda: False)()) and bool(
        getattr(stdout, "isatty", lambda: False)()
    )
    term = environ.get("TERM", "").strip().lower()
    ansi = interactive and term not in ("", "dumb", "unknown")
    return TerminalCapabilities(
        interactive=interactive,
        ansi=ansi,
        mouse=ansi,
        columns=max(0, int(size.columns)),
        rows=max(0, int(size.lines)),
    )


def plain_terminal_message(capabilities: TerminalCapabilities) -> str:
    """Explain why interactive rendering was declined using plain text only."""
    if not capabilities.interactive:
        return "VPN requiere una terminal interactiva."
    if not capabilities.ansi:
        return "VPN requiere un terminal ANSI; TERM=dumb usa salida literal."
    return (
        f"VPN requiere al menos {MIN_COLUMNS} columnas y {MIN_ROWS} filas "
        f"(actual: {capabilities.columns}x{capabilities.rows})."
    )
