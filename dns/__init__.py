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
from .capabilities import SINGBOX_BACKED_PROTOCOLS, supports_fakeip
from .hijack import DNSHijackApplyResult, DNSHijackController, DNSHijackError
from .presets import RESOLVER_PRESETS, ResolverPreset, get_resolver_preset
from .resolver_parser import (
    ParsedResolver,
    ResolverParseError,
    ResolverTransport,
    parse_resolver_uri,
    validate_resolver_uri,
)
from .resolver_inventory import ResolverInventory, ResolverManager, detect_resolver_manager
from .state_manager import (
    DNSStateError,
    DNSStateSnapshot,
    LocalDNSEntryPoint,
    NetworkManagerConnectionState,
    SystemDNSStateManager,
)
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
    "DNSHijackApplyResult",
    "DNSHijackController",
    "DNSHijackError",
    "DNSMode",
    "DNSPolicy",
    "DNSRule",
    "DNSRuleAction",
    "DNSStateError",
    "DNSStateSnapshot",
    "ParsedResolver",
    "RESOLVER_PRESETS",
    "DEFAULT_TEST_DOMAIN",
    "DNSTester",
    "LocalDNSEntryPoint",
    "NetworkManagerConnectionState",
    "Resolver",
    "ResolverInventory",
    "ResolverManager",
    "ResolverParseError",
    "ResolverPreset",
    "ResolverTestResult",
    "ResolverTransport",
    "SINGBOX_BACKED_PROTOCOLS",
    "StaticIPEntry",
    "SystemDNSStateManager",
    "default_auto_channel_candidates",
    "detect_resolver_manager",
    "get_resolver_preset",
    "parse_resolver_uri",
    "supports_fakeip",
    "validate_resolver_uri",
]
