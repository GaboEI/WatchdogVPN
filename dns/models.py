from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from .resolver_parser import validate_resolver_uri


MAX_RESOLVERS_PER_CHANNEL = 4
DEFAULT_FAKEIP_INET4_RANGE = "198.18.0.0/15"
DEFAULT_FAKEIP_INET6_RANGE = "fc00::/18"
ALLOWED_PROXY_RESOLUTION_CHANNELS = {"fakeip", "proxy", "direct", "final"}


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
        return cls(
            uri=str(data["uri"]),
            label=data.get("label"),
            enabled=bool(data.get("enabled", True)),
            metadata=dict(data.get("metadata", {})),
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "resolvers": [resolver.to_dict() for resolver in self.resolvers],
            "strategy": self.strategy,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DNSChannel":
        return cls(
            name=DNSChannelName(data["name"]),
            resolvers=[Resolver.from_dict(item) for item in data.get("resolvers", [])],
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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StaticIPEntry":
        return cls(
            domain=str(data["domain"]),
            ip=str(data["ip"]),
            enabled=bool(data.get("enabled", True)),
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
        return cls(
            id=str(data["id"]),
            pattern=str(data["pattern"]),
            action=DNSRuleAction(data.get("action", DNSRuleAction.USE_CHANNEL.value)),
            channel=data.get("channel"),
            enabled=bool(data.get("enabled", True)),
            priority=int(data.get("priority", 100)),
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
        self.fakeip_inet4_range = str(self.fakeip_inet4_range).strip()
        self.fakeip_inet6_range = str(self.fakeip_inet6_range).strip()
        if not self.test_domain:
            raise ValueError("dns test domain must not be empty")
        if not self.ttl:
            raise ValueError("dns ttl must not be empty")
        if self.proxy_resolution_channel not in ALLOWED_PROXY_RESOLUTION_CHANNELS:
            raise ValueError("unsupported proxy resolution channel")
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
            "proxy_resolution_channel": self.proxy_resolution_channel,
            "fakeip_inet4_range": self.fakeip_inet4_range,
            "fakeip_inet6_range": self.fakeip_inet6_range,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DNSPolicy":
        raw_channels = data.get("channels", {})
        channels = {
            DNSChannelName(name): DNSChannel.from_dict({**dict(value), "name": name})
            for name, value in raw_channels.items()
        }
        return cls(
            mode=DNSMode(data.get("mode", DNSMode.AUTO.value)),
            channels=channels,
            static_ips=[
                StaticIPEntry.from_dict(item) for item in data.get("static_ips", [])
            ],
            rules=[DNSRule.from_dict(item) for item in data.get("rules", [])],
            test_domain=str(data.get("test_domain", "gstatic.com")),
            ttl=str(data.get("ttl", "12h")),
            tun_hijack=bool(data.get("tun_hijack", True)),
            resolve_inbound_domains=bool(data.get("resolve_inbound_domains", False)),
            static_ip_enabled=bool(data.get("static_ip_enabled", False)),
            rules_enabled=bool(data.get("rules_enabled", False)),
            ecs_direct_enabled=bool(data.get("ecs_direct_enabled", False)),
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
