"""Terminal-safe text normalization and dependency-free cell geometry.

All values handled here are treated as untrusted text.  Terminal styling is
emitted separately by trusted renderers; embedded CSI, OSC, DCS, SOS, PM, APC,
ISO-2022 escapes, C0, and C1 controls are therefore never preserved.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator


ESC = "\x1b"
BEL = "\x07"
ST = "\x9c"
ZWJ = "\u200d"
VS16 = "\ufe0f"

_STRING_CONTROL_STARTS = {"P", "X", "]", "^", "_"}
_C1_STRING_CONTROL_STARTS = {0x90, 0x98, 0x9D, 0x9E, 0x9F}


def strip_terminal_sequences(value: object) -> str:
    """Remove terminal escape/control sequences without executing semantics."""

    source = str(value)
    output: list[str] = []
    index = 0
    while index < len(source):
        character = source[index]
        codepoint = ord(character)

        if character == ESC:
            index = _consume_escape(source, index)
            continue
        if codepoint == 0x9B:
            index = _consume_csi(source, index + 1)
            continue
        if codepoint in _C1_STRING_CONTROL_STARTS:
            index = _consume_control_string(source, index + 1)
            continue
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            if character in "\t\n\v\f\r":
                output.append(" ")
            index += 1
            continue
        if unicodedata.category(character) == "Cs":
            index += 1
            continue
        if unicodedata.category(character) == "Cf" and character != ZWJ:
            index += 1
            continue

        output.append(character)
        index += 1
    return "".join(output)


def terminal_safe_text(value: object) -> str:
    """Return compact single-line text safe for a human terminal."""

    return " ".join(strip_terminal_sequences(value).split())


def visible_width(value: object) -> int:
    """Return the rendered terminal-cell width of text, ignoring controls."""

    plain = strip_terminal_sequences(value)
    return sum(_cluster_width(cluster) for cluster in _grapheme_clusters(plain))


def clip_to_width(value: object, width: int) -> str:
    """Sanitize and clip text to complete display clusters without a suffix."""

    safe = strip_terminal_sequences(value)
    return _prefix_for_width(safe, max(width, 0))[0]


def truncate_to_width(value: object, width: int, *, ellipsis: str = "...") -> str:
    """Return compact safe text constrained to a terminal display width."""

    safe = terminal_safe_text(value)
    if width <= 0:
        return ""
    if visible_width(safe) <= width:
        return safe

    suffix = terminal_safe_text(ellipsis)
    suffix_width = visible_width(suffix)
    if suffix_width >= width:
        return _prefix_for_width(suffix, width)[0]
    prefix, _ = _prefix_for_width(safe, width - suffix_width)
    return prefix + suffix


def pad_to_width(value: object, width: int) -> str:
    """Sanitize and right-pad text according to terminal display cells."""

    text = terminal_safe_text(value)
    return text + (" " * max(width - visible_width(text), 0))


def wrap_to_width(
    value: object,
    width: int,
    *,
    initial_indent: str = "",
    subsequent_indent: str = "",
) -> list[str]:
    """Wrap compact safe text without exceeding the requested cell width."""

    safe = terminal_safe_text(value)
    bounded_width = max(width, 1)
    if not safe:
        return [""]

    lines: list[str] = []
    words = safe.split(" ")
    first_line = True
    content = ""

    def current_indent() -> str:
        # Indentation is layout data: sanitize controls but preserve its
        # leading spaces.  Compacting it would corrupt callers that splice a
        # styled command into the reserved prefix after wrapping.
        indent = strip_terminal_sequences(
            initial_indent if first_line else subsequent_indent
        )
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
                # A two-cell cluster in a one-cell content area is discarded;
                # emitting it would violate the panel boundary.
                first_cluster = next(_grapheme_clusters(word))
                word = word[len(first_cluster) :]
                continue
            content = piece
            word = remainder
            if word:
                emit()

    if content or not lines:
        emit()
    return lines


def _consume_escape(source: str, start: int) -> int:
    index = start + 1
    if index >= len(source):
        return index
    introducer = source[index]
    if introducer == "[":
        return _consume_csi(source, index + 1)
    if introducer in _STRING_CONTROL_STARTS:
        return _consume_control_string(source, index + 1)

    # Generic ISO-2022/VT escape: intermediates followed by one final byte.
    index += 1
    while index < len(source) and 0x20 <= ord(source[index]) <= 0x2F:
        index += 1
    if index < len(source) and 0x30 <= ord(source[index]) <= 0x7E:
        index += 1
    return index


def _consume_csi(source: str, index: int) -> int:
    while index < len(source):
        codepoint = ord(source[index])
        index += 1
        if 0x40 <= codepoint <= 0x7E:
            return index
        if not 0x20 <= codepoint <= 0x3F:
            return index
    return index


def _consume_control_string(source: str, index: int) -> int:
    while index < len(source):
        if source[index] == BEL or source[index] == ST:
            return index + 1
        if source[index] == ESC and index + 1 < len(source) and source[index + 1] == "\\":
            return index + 2
        index += 1
    return index


def _grapheme_clusters(value: str) -> Iterator[str]:
    index = 0
    while index < len(value):
        start = index
        index += 1

        if _is_regional_indicator(value[start]):
            if index < len(value) and _is_regional_indicator(value[index]):
                index += 1
            yield value[start:index]
            continue

        index = _consume_extensions(value, index)
        while index < len(value) and value[index] == ZWJ:
            if index + 1 >= len(value):
                index += 1
                break
            index += 2
            index = _consume_extensions(value, index)
        yield value[start:index]


def _consume_extensions(value: str, index: int) -> int:
    while index < len(value):
        character = value[index]
        if (
            unicodedata.combining(character)
            or _is_variation_selector(character)
            or _is_emoji_modifier(character)
            or _is_emoji_tag(character)
        ):
            index += 1
            continue
        break
    return index


def _cluster_width(cluster: str) -> int:
    if not cluster:
        return 0
    if _is_regional_indicator(cluster[0]):
        return 2 if len(cluster) >= 2 else 1

    widths = [_codepoint_width(character) for character in cluster]
    base_width = max(widths, default=0) if ZWJ in cluster else sum(widths)
    if "\u20e3" in cluster or VS16 in cluster or any(
        _is_emoji_modifier(character) for character in cluster
    ):
        return max(base_width, 2)
    return base_width


def _prefix_for_width(value: str, width: int) -> tuple[str, str]:
    used = 0
    index = 0
    for cluster in _grapheme_clusters(value):
        cluster_width = _cluster_width(cluster)
        if used + cluster_width > width:
            return value[:index], value[index:]
        used += cluster_width
        index += len(cluster)
    return value, ""


def _codepoint_width(character: str) -> int:
    if (
        unicodedata.combining(character)
        or character == ZWJ
        or _is_variation_selector(character)
        or _is_emoji_modifier(character)
        or _is_emoji_tag(character)
    ):
        return 0
    if unicodedata.category(character).startswith("C"):
        return 0
    if unicodedata.east_asian_width(character) in {"F", "W"}:
        return 2
    return 1


def _is_variation_selector(character: str) -> bool:
    codepoint = ord(character)
    return 0xFE00 <= codepoint <= 0xFE0F or 0xE0100 <= codepoint <= 0xE01EF


def _is_emoji_modifier(character: str) -> bool:
    return 0x1F3FB <= ord(character) <= 0x1F3FF


def _is_regional_indicator(character: str) -> bool:
    return 0x1F1E6 <= ord(character) <= 0x1F1FF


def _is_emoji_tag(character: str) -> bool:
    return 0xE0020 <= ord(character) <= 0xE007F
