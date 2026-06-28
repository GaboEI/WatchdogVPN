"""Parser utilities for WatchdogVPN connection inputs."""

from .uri import ParseError, detect_scheme, parse_uri
from .wg_config import parse_wg_config

__all__ = [
    "ParseError",
    "detect_scheme",
    "parse_uri",
    "parse_wg_config",
]
