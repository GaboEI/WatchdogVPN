"""Parser utilities for WatchdogVPN connection inputs."""

from .uri import ParseError, detect_scheme, parse_uri

__all__ = [
    "ParseError",
    "detect_scheme",
    "parse_uri",
]

