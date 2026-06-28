"""Parser utilities for WatchdogVPN connection inputs."""

from .clash_yaml import parse_clash_yaml
from .singbox_json import parse_singbox_json
from .uri import ParseError, detect_scheme, parse_uri
from .wg_config import parse_wg_config

__all__ = [
    "ParseError",
    "detect_scheme",
    "parse_clash_yaml",
    "parse_singbox_json",
    "parse_uri",
    "parse_wg_config",
]
