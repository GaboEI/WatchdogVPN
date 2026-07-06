from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from config.persistence import reject_unknown_keys, strict_bool, strict_int

from .resolver_parser import validate_resolver_uri


MAX_RESOLVERS_PER_CHANNEL = 4
DEFAULT_FAKEIP_INET4_RANGE = "198.18.0.0/15"
DEFAULT_FAKEIP_INET6_RANGE = "fc00::/18"
ALLOWED_PROXY_RESOLUTION_CHANNELS = {"fakeip", "proxy", "direct", "final"}
ALLOWED_DNS_CHANNEL_STRATEGIES = {"auto"}
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DNS_RULE_PATTERN_TYPES = {
    "domain",
    "suffix",
    "keyword",
    "regex",
    "geosite",
    "rule_set",
}
RESOLVER_FIELDS = {"uri", "label", "enabled", "metadata"}
DNS_CHANNEL_FIELDS = {"name", "resolvers", "strategy"}
STATIC_IP_ENTRY_FIELDS = {"domain", "ip", "enabled"}
DNS_RULE_FIELDS = {"id", "pattern", "action", "channel", "enabled", "priority"}
DNS_POLICY_FIELDS = {
    "mode",
    "channels",
    "static_ips",
    "rules",
    "test_domain",
    "ttl",
    "tun_hijack",
    "resolve_inbound_domains",
    "static_ip_enabled",
    "rules_enabled",
    "ecs_direct_enabled",
    "ecs_direct_subnet",
    "proxy_resolution_channel",
    "fakeip_inet4_range",
    "fakeip_inet6_range",
}


class DNSMode(str, Enum):
    AUTO = "auto"
    OFF = "off"
    CUSTOM = "custom"
    ADVANCED = "advanced"


class DNSChannelName(str, Enum):
    BOOTSTRAP = "bootstrap_dns"
    DNS_SERVER = "dns_server"
    PROXY_SERVER = "proxy_server"
    DIRECT = "direct"
    PROXY = "proxy"
    FINAL = "final"


class DNSRuleAction(str, Enum):
    USE_CHANNEL = "use_channel"
    REJECT = "reject"


@dataclass(slots=True)
class Resolver:
    uri: str
    label: str | None = None
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.uri = str(self.uri).strip()
        if not self.uri:
            raise ValueError("resolver uri must not be empty")
        validate_resolver_uri(self.uri)
        if self.label is not None:
            self.label = str(self.label).strip() or None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | str) -> "Resolver":
        if isinstance(data, str):
            return cls(uri=data)
        reject_unknown_keys(data, RESOLVER_FIELDS, "resolver")
        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("resolver metadata must be an object")
        return cls(
            uri=str(data["uri"]),
            label=data.get("label"),
            enabled=strict_bool(data.get("enabled", True), "resolver.enabled"),
            metadata=dict(metadata),
        )


@dataclass(slots=True)
class DNSChannel:
    name: DNSChannelName
    resolvers: list[Resolver] = field(default_factory=list)
    strategy: str = "auto"

    def __post_init__(self) -> None:
        self.name = DNSChannelName(self.name)
        self.resolvers = [
            resolver if isinstance(resolver, Resolver) else Resolver.from_dict(resolver)
            for resolver in self.resolvers
        ]
        if len(self.resolvers) > MAX_RESOLVERS_PER_CHANNEL:
            raise ValueError("dns channel supports at most 4 resolvers")
        self.strategy = str(self.strategy)
        if self.strategy not in ALLOWED_DNS_CHANNEL_STRATEGIES:
            raise ValueError(
                "unsupported dns channel strategy; resolver racing is not supported"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "resolvers": [resolver.to_dict() for resolver in self.resolvers],
            "strategy": self.strategy,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DNSChannel":
        reject_unknown_keys(data, DNS_CHANNEL_FIELDS, "dns channel")
        resolvers = data.get("resolvers", [])
        if not isinstance(resolvers, list):
            raise ValueError("dns channel resolvers must be a list")
        return cls(
            name=DNSChannelName(data["name"]),
            resolvers=[Resolver.from_dict(item) for item in resolvers],
            strategy=str(data.get("strategy", "auto")),
        )


@dataclass(slots=True)
class StaticIPEntry:
    domain: str
    ip: str
    enabled: bool = True

    def __post_init__(self) -> None:
        self.domain = str(self.domain).strip().lower().rstrip(".")
        self.ip = str(self.ip).strip()
        if not self.domain:
            raise ValueError("static ip domain must not be empty")
        if not self.ip:
            raise ValueError("static ip address must not be empty")
        _validate_domain_name(self.domain)
        try:
            ipaddress.ip_address(self.ip)
        except ValueError as exc:
            raise ValueError("static ip address must be a valid IP address") from exc

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StaticIPEntry":
        reject_unknown_keys(data, STATIC_IP_ENTRY_FIELDS, "static ip entry")
        return cls(
            domain=str(data["domain"]),
            ip=str(data["ip"]),
            enabled=strict_bool(data.get("enabled", True), "static_ip.enabled"),
        )


@dataclass(slots=True)
class DNSRule:
    id: str
    pattern: str
    action: DNSRuleAction = DNSRuleAction.USE_CHANNEL
    channel: DNSChannelName | None = None
    enabled: bool = True
    priority: int = 100

    def __post_init__(self) -> None:
        self.id = str(self.id).strip()
        self.pattern = str(self.pattern).strip()
        self.action = DNSRuleAction(self.action)
        self.channel = DNSChannelName(self.channel) if self.channel is not None else None
        self.priority = int(self.priority)
        if not self.id:
            raise ValueError("dns rule id must not be empty")
        if not self.pattern:
            raise ValueError("dns rule pattern must not be empty")
        if self.action == DNSRuleAction.USE_CHANNEL and self.channel is None:
            raise ValueError("dns rule channel is required for use_channel action")
        _validate_dns_rule_pattern(self.pattern)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "pattern": self.pattern,
            "action": self.action.value,
            "channel": self.channel.value if self.channel else None,
            "enabled": self.enabled,
            "priority": self.priority,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DNSRule":
        reject_unknown_keys(data, DNS_RULE_FIELDS, "dns rule")
        return cls(
            id=str(data["id"]),
            pattern=str(data["pattern"]),
            action=DNSRuleAction(data.get("action", DNSRuleAction.USE_CHANNEL.value)),
            channel=data.get("channel"),
            enabled=strict_bool(data.get("enabled", True), "dns_rule.enabled"),
            priority=strict_int(data.get("priority", 100), "dns_rule.priority"),
        )


@dataclass(slots=True)
class DNSPolicy:
    mode: DNSMode = DNSMode.AUTO
    channels: dict[DNSChannelName, DNSChannel] = field(default_factory=dict)
    static_ips: list[StaticIPEntry] = field(default_factory=list)
    rules: list[DNSRule] = field(default_factory=list)
    test_domain: str = "gstatic.com"
    ttl: str = "12h"
    tun_hijack: bool = True
    resolve_inbound_domains: bool = False
    static_ip_enabled: bool = False
    rules_enabled: bool = False
    ecs_direct_enabled: bool = False
    ecs_direct_subnet: str | None = None
    proxy_resolution_channel: str = "fakeip"
    fakeip_inet4_range: str = DEFAULT_FAKEIP_INET4_RANGE
    fakeip_inet6_range: str = DEFAULT_FAKEIP_INET6_RANGE

    def __post_init__(self) -> None:
        self.mode = DNSMode(self.mode)
        self.channels = {
            DNSChannelName(name): (
                channel if isinstance(channel, DNSChannel) else DNSChannel.from_dict(channel)
            )
            for name, channel in self.channels.items()
        }
        for name, channel in self.channels.items():
            if channel.name != name:
                raise ValueError("dns channel key must match channel name")
        self.static_ips = [
            entry if isinstance(entry, StaticIPEntry) else StaticIPEntry.from_dict(entry)
            for entry in self.static_ips
        ]
        self.rules = [
            rule if isinstance(rule, DNSRule) else DNSRule.from_dict(rule)
            for rule in self.rules
        ]
        self.test_domain = str(self.test_domain).strip().lower().rstrip(".")
        self.ttl = str(self.ttl).strip()
        self.proxy_resolution_channel = str(self.proxy_resolution_channel).strip()
        if self.ecs_direct_subnet is not None:
            self.ecs_direct_subnet = str(self.ecs_direct_subnet).strip() or None
        self.fakeip_inet4_range = str(self.fakeip_inet4_range).strip()
        self.fakeip_inet6_range = str(self.fakeip_inet6_range).strip()
        if not self.test_domain:
            raise ValueError("dns test domain must not be empty")
        if not self.ttl:
            raise ValueError("dns ttl must not be empty")
        if self.proxy_resolution_channel not in ALLOWED_PROXY_RESOLUTION_CHANNELS:
            raise ValueError("unsupported proxy resolution channel")
        if self.ecs_direct_enabled and self.ecs_direct_subnet is None:
            raise ValueError("ecs direct subnet is required when ECS is enabled")
        if self.ecs_direct_subnet is not None:
            self._validate_ecs_subnet(self.ecs_direct_subnet)
        self._validate_ip_network(self.fakeip_inet4_range, version=4)
        self._validate_ip_network(self.fakeip_inet6_range, version=6)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "channels": {
                name.value: channel.to_dict() for name, channel in self.channels.items()
            },
            "static_ips": [entry.to_dict() for entry in self.static_ips],
            "rules": [rule.to_dict() for rule in self.rules],
            "test_domain": self.test_domain,
            "ttl": self.ttl,
            "tun_hijack": self.tun_hijack,
            "resolve_inbound_domains": self.resolve_inbound_domains,
            "static_ip_enabled": self.static_ip_enabled,
            "rules_enabled": self.rules_enabled,
            "ecs_direct_enabled": self.ecs_direct_enabled,
            "ecs_direct_subnet": self.ecs_direct_subnet,
            "proxy_resolution_channel": self.proxy_resolution_channel,
            "fakeip_inet4_range": self.fakeip_inet4_range,
            "fakeip_inet6_range": self.fakeip_inet6_range,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DNSPolicy":
        reject_unknown_keys(data, DNS_POLICY_FIELDS, "dns policy")
        raw_channels = data.get("channels", {})
        if not isinstance(raw_channels, dict):
            raise ValueError("dns policy channels must be an object")
        static_ips = data.get("static_ips", [])
        rules = data.get("rules", [])
        if not isinstance(static_ips, list):
            raise ValueError("dns policy static_ips must be a list")
        if not isinstance(rules, list):
            raise ValueError("dns policy rules must be a list")
        channels = {
            DNSChannelName(name): DNSChannel.from_dict({**dict(value), "name": name})
            for name, value in raw_channels.items()
        }
        return cls(
            mode=DNSMode(data.get("mode", DNSMode.AUTO.value)),
            channels=channels,
            static_ips=[
                StaticIPEntry.from_dict(item) for item in static_ips
            ],
            rules=[DNSRule.from_dict(item) for item in rules],
            test_domain=str(data.get("test_domain", "gstatic.com")),
            ttl=str(data.get("ttl", "12h")),
            tun_hijack=strict_bool(data.get("tun_hijack", True), "dns_policy.tun_hijack"),
            resolve_inbound_domains=strict_bool(
                data.get("resolve_inbound_domains", False),
                "dns_policy.resolve_inbound_domains",
            ),
            static_ip_enabled=strict_bool(
                data.get("static_ip_enabled", False),
                "dns_policy.static_ip_enabled",
            ),
            rules_enabled=strict_bool(data.get("rules_enabled", False), "dns_policy.rules_enabled"),
            ecs_direct_enabled=strict_bool(
                data.get("ecs_direct_enabled", False),
                "dns_policy.ecs_direct_enabled",
            ),
            ecs_direct_subnet=data.get("ecs_direct_subnet"),
            proxy_resolution_channel=str(
                data.get("proxy_resolution_channel", "fakeip")
            ),
            fakeip_inet4_range=str(
                data.get("fakeip_inet4_range", DEFAULT_FAKEIP_INET4_RANGE)
            ),
            fakeip_inet6_range=str(
                data.get("fakeip_inet6_range", DEFAULT_FAKEIP_INET6_RANGE)
            ),
        )

    @staticmethod
    def _validate_ip_network(value: str, version: int) -> None:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ValueError("invalid FakeIP range") from exc
        if network.version != version:
            raise ValueError("FakeIP range IP version mismatch")

    @staticmethod
    def _validate_ecs_subnet(value: str) -> None:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("invalid ECS direct subnet") from exc


def _validate_domain_name(domain: str) -> None:
    if len(domain) > 253:
        raise ValueError("domain name is too long")
    labels = domain.split(".")
    if len(labels) < 2:
        raise ValueError("domain name must be fully qualified")
    if any(not label or not DOMAIN_LABEL_RE.match(label) for label in labels):
        raise ValueError("invalid domain name")


def _validate_dns_rule_pattern(pattern: str) -> None:
    if ":" not in pattern:
        raise ValueError("dns rule pattern must include a type prefix")
    pattern_type, value = pattern.split(":", 1)
    pattern_type = pattern_type.strip()
    value = value.strip()
    if pattern_type not in DNS_RULE_PATTERN_TYPES:
        raise ValueError("unsupported dns rule pattern type")
    if not value:
        raise ValueError("dns rule pattern value must not be empty")
    if pattern_type in {"domain", "suffix"}:
        _validate_domain_name(value.lower().rstrip("."))
    elif pattern_type == "regex":
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError("invalid dns rule regex pattern") from exc
