from __future__ import annotations

import re
import shutil
import unicodedata


DEFAULT_TERMINAL_WIDTH = 80
MIN_TERMINAL_WIDTH = 20
MAX_TERMINAL_WIDTH = 512

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def terminal_width() -> int:
    """Return a bounded terminal width while honoring COLUMNS."""

    try:
        columns = shutil.get_terminal_size(
            fallback=(DEFAULT_TERMINAL_WIDTH, 24),
        ).columns
    except (OSError, ValueError):
        columns = DEFAULT_TERMINAL_WIDTH
    return min(max(columns, MIN_TERMINAL_WIDTH), MAX_TERMINAL_WIDTH)


def terminal_safe_text(value: object) -> str:
    """Normalize untrusted values before writing them to a terminal."""

    normalized: list[str] = []
    previous_was_space = False
    for character in str(value):
        if character.isspace():
            if normalized and not previous_was_space:
                normalized.append(" ")
            previous_was_space = True
            continue
        if unicodedata.category(character).startswith("C"):
            normalized.append("?")
        else:
            normalized.append(character)
        previous_was_space = False
    return "".join(normalized).strip()


def visible_width(value: object) -> int:
    """Return terminal display width, excluding ANSI style sequences."""

    plain = strip_ansi(value)
    return sum(_character_width(character) for character in plain)


def strip_ansi(value: object) -> str:
    """Remove ANSI styling sequences from terminal text."""

    return _ANSI_ESCAPE_RE.sub("", str(value))


def truncate_to_width(value: object, width: int, *, ellipsis: str = "...") -> str:
    """Return safe text constrained to a terminal display width."""

    safe = terminal_safe_text(value)
    if width <= 0:
        return ""
    if visible_width(safe) <= width:
        return safe

    suffix = ellipsis
    suffix_width = visible_width(suffix)
    if suffix_width >= width:
        return _prefix_for_width(suffix, width)[0]
    prefix, _ = _prefix_for_width(safe, width - suffix_width)
    return prefix + suffix


def pad_to_width(value: object, width: int) -> str:
    """Right-pad a value according to terminal display width."""

    text = str(value)
    return text + (" " * max(width - visible_width(text), 0))


def wrap_to_width(
    value: object,
    width: int,
    *,
    initial_indent: str = "",
    subsequent_indent: str = "",
) -> list[str]:
    """Wrap safe text without exceeding the requested display width."""

    safe = terminal_safe_text(value)
    bounded_width = max(width, 1)
    if not safe:
        return [""]

    lines: list[str] = []
    words = safe.split(" ")
    first_line = True
    content = ""

    def current_indent() -> str:
        indent = initial_indent if first_line else subsequent_indent
        return _prefix_for_width(indent, bounded_width)[0]

    def available_width() -> int:
        return max(bounded_width - visible_width(current_indent()), 1)

    def emit() -> None:
        nonlocal content, first_line
        lines.append(current_indent() + content)
        content = ""
        first_line = False

    for word in words:
        while word:
            candidate = word if not content else f"{content} {word}"
            if visible_width(candidate) <= available_width():
                content = candidate
                word = ""
                continue
            if content:
                emit()
                continue
            piece, remainder = _prefix_for_width(word, available_width())
            if not piece:
                piece, remainder = word[0], word[1:]
            content = piece
            word = remainder
            if word:
                emit()

    if content or not lines:
        emit()
    return lines


def _prefix_for_width(value: str, width: int) -> tuple[str, str]:
    used = 0
    index = 0
    for index, character in enumerate(value):
        character_width = _character_width(character)
        if used + character_width > width:
            return value[:index], value[index:]
        used += character_width
    return value, ""


def _character_width(character: str) -> int:
    if unicodedata.combining(character):
        return 0
    if unicodedata.east_asian_width(character) in {"F", "W"}:
        return 2
    return 1
