"""Pure formatting helpers for the WatchdogVPN TUI."""

from terminal_safety import (
    clip_to_width,
    pad_to_width,
    strip_terminal_sequences,
    terminal_safe_text,
    truncate_to_width,
    visible_width,
)


def strip_ansi(text: str) -> str:
    """Compatibility alias that removes every terminal-control sequence."""

    return strip_terminal_sequences(text)


def format_span(seconds: int) -> str:
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days > 0:
        return f"{days}d {hours:02}h {minutes:02}m {secs:02}s"
    if hours > 0:
        return f"{hours}h {minutes:02}m {secs:02}s"
    if minutes > 0:
        return f"{minutes}m {secs:02}s"
    return f"{secs}s"


def display_vpn_status(status: str) -> str:
    mapping = {
        "UP": "ACTIVO",
        "DEGRADED": "DEGRADADO",
        "DOWN": "DESACTIVADO",
    }
    return mapping.get((status or "").strip().upper(), status or "DESCONOCIDO")
