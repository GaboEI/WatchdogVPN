"""Parser utilities for WatchdogVPN connection inputs."""

from .amneziavpn_format import is_amneziavpn_format, parse_amneziavpn
from .clash_yaml import parse_clash_yaml
from .hysteria2_yaml import parse_hysteria2_yaml
from .openvpn_config import parse_openvpn_config
from .singbox_json import parse_singbox_json
from .subscription import (
    SubscriptionFetchResult,
    fetch_and_parse,
    fetch_subscription,
    validate_subscription_url,
)
from .uri import ParseError, detect_scheme, parse_uri
from .wg_config import parse_wg_config

__all__ = [
    "ParseError",
    "SubscriptionFetchResult",
    "detect_scheme",
    "fetch_and_parse",
    "fetch_subscription",
    "is_amneziavpn_format",
    "parse_amneziavpn",
    "parse_clash_yaml",
    "parse_hysteria2_yaml",
    "parse_openvpn_config",
    "parse_singbox_json",
    "parse_uri",
    "parse_wg_config",
    "validate_subscription_url",
]
