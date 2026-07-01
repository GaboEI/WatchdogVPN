from .models import (
    DNSChannel,
    DNSChannelName,
    DNSMode,
    DNSPolicy,
    DNSRule,
    DNSRuleAction,
    Resolver,
    StaticIPEntry,
)
from .presets import RESOLVER_PRESETS, ResolverPreset, get_resolver_preset
from .resolver_parser import (
    ParsedResolver,
    ResolverParseError,
    ResolverTransport,
    parse_resolver_uri,
    validate_resolver_uri,
)
from .resolver_inventory import ResolverInventory, ResolverManager, detect_resolver_manager
from .tester import (
    DEFAULT_TEST_DOMAIN,
    AutoSetupRecommendation,
    ChannelTestResult,
    DNSTester,
    ResolverTestResult,
    default_auto_channel_candidates,
)

__all__ = [
    "AutoSetupRecommendation",
    "ChannelTestResult",
    "DNSChannel",
    "DNSChannelName",
    "DNSMode",
    "DNSPolicy",
    "DNSRule",
    "DNSRuleAction",
    "ParsedResolver",
    "RESOLVER_PRESETS",
    "DEFAULT_TEST_DOMAIN",
    "DNSTester",
    "Resolver",
    "ResolverInventory",
    "ResolverManager",
    "ResolverParseError",
    "ResolverPreset",
    "ResolverTestResult",
    "ResolverTransport",
    "StaticIPEntry",
    "default_auto_channel_candidates",
    "detect_resolver_manager",
    "get_resolver_preset",
    "parse_resolver_uri",
    "validate_resolver_uri",
]
