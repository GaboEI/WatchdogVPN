"""Pure formatting helpers for the WatchdogVPN TUI."""

import re


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1B\[[0-9;]*[A-Za-z]", "", text)


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
