"""Parser utilities for WatchdogVPN connection inputs."""

from .amneziavpn_format import is_amneziavpn_format, parse_amneziavpn
from .clash_yaml import parse_clash_yaml
from .openvpn_config import parse_openvpn_config
from .singbox_json import parse_singbox_json
from .subscription import fetch_and_parse
from .uri import ParseError, detect_scheme, parse_uri
from .wg_config import parse_wg_config

__all__ = [
    "ParseError",
    "detect_scheme",
    "fetch_and_parse",
    "is_amneziavpn_format",
    "parse_amneziavpn",
    "parse_clash_yaml",
    "parse_openvpn_config",
    "parse_singbox_json",
    "parse_uri",
    "parse_wg_config",
]
