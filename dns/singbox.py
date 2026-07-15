from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from .models import (
    DNSChannelName,
    DNSMode,
    DNSPolicy,
    DNSRule,
    DNSRuleAction,
    Resolver,
)
from .resolver_parser import ParsedResolver, ResolverTransport, parse_resolver_uri


CHANNEL_TAGS = {
    DNSChannelName.BOOTSTRAP: "bootstrap",
    DNSChannelName.DNS_SERVER: "dns-server",
    DNSChannelName.PROXY_SERVER: "proxy-server",
    DNSChannelName.DIRECT: "direct",
    DNSChannelName.PROXY: "proxy",
    DNSChannelName.FINAL: "final",
}
DNS_HIJACK_INBOUND_TAGS = (
    "watchdogvpn-dns-udp-in",
    "watchdogvpn-dns-tcp-in",
)
FAKEIP_SERVER_TAG = "watchdogvpn-fakeip"
STATIC_IP_SERVER_TAG = "watchdogvpn-static-ip"


@dataclass(frozen=True, slots=True)
class SingBoxDNSConfig:
    config: dict[str, Any]
    channel_servers: dict[DNSChannelName, tuple[str, ...]]
    direct_domain_resolver: dict[str, Any] | str | None = None
    proxy_domain_resolver: str | None = None


def build_singbox_dns_config(
    policy: DNSPolicy,
    proxy_outbound_tag: str,
) -> SingBoxDNSConfig | None:
    if policy.mode == DNSMode.OFF:
        return None

    servers: list[dict[str, Any]] = []
    channel_servers: dict[DNSChannelName, tuple[str, ...]] = {}
    bootstrap_tag = _planned_bootstrap_tag(policy)
    for channel_name, channel in policy.channels.items():
        tags: list[str] = []
        for index, resolver in enumerate(channel.resolvers):
            if not resolver.enabled:
                continue
            tag = _server_tag(channel_name, index)
            server = _resolver_to_singbox_server(
                resolver,
                tag,
                channel_name,
                proxy_outbound_tag,
                bootstrap_tag,
            )
            servers.append(server)
            tags.append(tag)
        if tags:
            channel_servers[channel_name] = tuple(tags)

    if not servers:
        return None

    if _static_ip_enabled(policy):
        servers.insert(0, _static_ip_server(policy))
    if _fakeip_enabled(policy, channel_servers):
        servers.append(_fakeip_server(policy))

    _validate_domain_resolver_graph(servers)

    direct_server = _first_tag(channel_servers, DNSChannelName.DIRECT)
    proxy_server = _first_tag(channel_servers, DNSChannelName.PROXY)

    direct_dr: dict[str, Any] | str | None = None
    if direct_server:
        if policy.ecs_direct_enabled and policy.ecs_direct_subnet:
            direct_dr = {"server": direct_server, "client_subnet": policy.ecs_direct_subnet}
        else:
            direct_dr = direct_server

    proxy_dr: str | None = None
    if _fakeip_enabled(policy, channel_servers):
        proxy_dr = FAKEIP_SERVER_TAG
    elif proxy_server:
        proxy_dr = proxy_server

    dns_config: dict[str, Any] = {
        "servers": servers,
        "rules": _build_channel_rules(policy, channel_servers),
        "final": _final_server(channel_servers),
    }
    return SingBoxDNSConfig(
        config=dns_config,
        channel_servers=channel_servers,
        direct_domain_resolver=direct_dr,
        proxy_domain_resolver=proxy_dr,
    )


def build_dns_hijack_inbounds(policy: DNSPolicy) -> list[dict[str, Any]]:
    if policy.mode == DNSMode.OFF or not policy.tun_hijack:
        return []
    return [
        {
            "type": "direct",
            "tag": DNS_HIJACK_INBOUND_TAGS[0],
            "listen": "127.0.0.1",
            "listen_port": 53,
            "network": "udp",
            "override_address": "1.1.1.1",
            "override_port": 53,
        },
        {
            "type": "direct",
            "tag": DNS_HIJACK_INBOUND_TAGS[1],
            "listen": "127.0.0.1",
            "listen_port": 53,
            "network": "tcp",
            "override_address": "1.1.1.1",
            "override_port": 53,
        },
    ]


def build_dns_hijack_route(policy: DNSPolicy) -> dict[str, Any] | None:
    if policy.mode == DNSMode.OFF or not policy.tun_hijack:
        return None
    return {
        "rules": [
            # A TUN's auto_route/strict_route captures system DNS queries
            # addressed to the real LAN resolver (e.g. the router), not to
            # our loopback listeners below — that traffic only reaches
            # sing-box's own router via the tun inbound itself, so it needs
            # protocol sniffing plus a destination-independent "protocol:
            # dns" match to be hijacked. Without this, DNS queries silently
            # fell through to the catch-all rule and got forwarded to the
            # VPN outbound as if bound for a real, routable address —
            # black-holing all DNS resolution (confirmed via live traffic
            # reproduction with sing-box debug logs, Task 12.5).
            {"action": "sniff"},
            {"protocol": ["dns"], "action": "hijack-dns"},
            {
                "inbound": list(DNS_HIJACK_INBOUND_TAGS),
                "action": "hijack-dns",
            },
        ]
    }


def _server_tag(channel_name: DNSChannelName, index: int) -> str:
    return f"watchdogvpn-{CHANNEL_TAGS[channel_name]}-{index + 1}"


def _planned_bootstrap_tag(policy: DNSPolicy) -> str | None:
    """Return an independently resolvable bootstrap server tag, if configured."""
    bootstrap = policy.channels.get(DNSChannelName.BOOTSTRAP)
    if bootstrap is None:
        return None
    for index, resolver in enumerate(bootstrap.resolvers):
        if not resolver.enabled:
            continue
        parsed = parse_resolver_uri(resolver.uri)
        if not _resolver_needs_domain_resolver(parsed):
            return _server_tag(DNSChannelName.BOOTSTRAP, index)
    return None


def _resolver_to_singbox_server(
    resolver: Resolver,
    tag: str,
    channel_name: DNSChannelName,
    proxy_outbound_tag: str,
    bootstrap_tag: str | None,
) -> dict[str, Any]:
    parsed = parse_resolver_uri(resolver.uri)
    server = _parsed_resolver_to_server(parsed, tag)
    if _resolver_needs_domain_resolver(parsed):
        if bootstrap_tag is None:
            raise ValueError(
                "hostname DNS resolver requires an enabled bootstrap resolver "
                "using an IP address, local, or DHCP transport"
            )
        server["domain_resolver"] = bootstrap_tag
    if channel_name == DNSChannelName.PROXY:
        server["detour"] = proxy_outbound_tag
    elif parsed.transport not in (ResolverTransport.LOCAL, ResolverTransport.DHCP):
        # Non-proxy channels must dial out via the "direct" outbound instead
        # of sing-box's default dispatch. Under strict_route/auto_route TUN
        # hardening, an undetoured DNS server query gets recaptured by the
        # tunnel's own system-wide route redirect, black-holing DNS
        # resolution (confirmed via live traffic reproduction, Task 12.5).
        server["detour"] = "direct"
    return server


def _parsed_resolver_to_server(parsed: ParsedResolver, tag: str) -> dict[str, Any]:
    if parsed.transport == ResolverTransport.LOCAL:
        return {"type": "local", "tag": tag}
    if parsed.transport == ResolverTransport.DHCP:
        return {"type": "dhcp", "tag": tag}
    if parsed.transport == ResolverTransport.UDP:
        return _network_server(parsed, tag, "udp", 53)
    if parsed.transport == ResolverTransport.TCP:
        return _network_server(parsed, tag, "tcp", 53)
    if parsed.transport == ResolverTransport.TLS:
        return _network_server(parsed, tag, "tls", 853)
    if parsed.transport == ResolverTransport.HTTPS:
        server = _network_server(parsed, tag, "https", 443)
        server["path"] = parsed.path or "/dns-query"
        return server
    raise ValueError(f"unsupported resolver transport: {parsed.transport}")


def _network_server(
    parsed: ParsedResolver,
    tag: str,
    server_type: str,
    default_port: int,
) -> dict[str, Any]:
    if parsed.host is None:
        raise ValueError("network DNS resolver requires a host")
    return {
        "type": server_type,
        "tag": tag,
        "server": parsed.host,
        "server_port": parsed.port or default_port,
    }


def _fakeip_enabled(
    policy: DNSPolicy,
    channel_servers: dict[DNSChannelName, tuple[str, ...]],
) -> bool:
    return fakeip_policy_ready(policy) and DNSChannelName.PROXY in channel_servers


def fakeip_policy_ready(policy: DNSPolicy) -> bool:
    proxy_channel = policy.channels.get(DNSChannelName.PROXY)
    return (
        policy.mode != DNSMode.OFF
        and policy.proxy_resolution_channel == "fakeip"
        and proxy_channel is not None
        and any(resolver.enabled for resolver in proxy_channel.resolvers)
    )


def _fakeip_server(policy: DNSPolicy) -> dict[str, Any]:
    return {
        "type": "fakeip",
        "tag": FAKEIP_SERVER_TAG,
        "inet4_range": policy.fakeip_inet4_range,
        "inet6_range": policy.fakeip_inet6_range,
    }


def _static_ip_enabled(policy: DNSPolicy) -> bool:
    return policy.mode != DNSMode.OFF and policy.static_ip_enabled and any(
        entry.enabled for entry in policy.static_ips
    )


def _static_ip_server(policy: DNSPolicy) -> dict[str, Any]:
    predefined: dict[str, str | list[str]] = {}
    for entry in policy.static_ips:
        if not entry.enabled:
            continue
        existing = predefined.get(entry.domain)
        if existing is None:
            predefined[entry.domain] = entry.ip
        elif isinstance(existing, list):
            existing.append(entry.ip)
        else:
            predefined[entry.domain] = [existing, entry.ip]
    return {
        "type": "hosts",
        "tag": STATIC_IP_SERVER_TAG,
        "predefined": predefined,
    }


def _resolver_needs_domain_resolver(parsed: ParsedResolver) -> bool:
    if parsed.host is None:
        return False
    try:
        ipaddress.ip_address(parsed.host)
    except ValueError:
        return True
    return False


def _validate_domain_resolver_graph(servers: list[dict[str, Any]]) -> None:
    """Reject unresolved and cyclic sing-box DNS server dependencies."""
    server_tags = {
        server.get("tag")
        for server in servers
        if isinstance(server.get("tag"), str) and server["tag"]
    }
    dependencies: dict[str, str] = {}
    for server in servers:
        tag = server.get("tag")
        domain_resolver = server.get("domain_resolver")
        if domain_resolver is None:
            continue
        if not isinstance(tag, str) or not tag:
            raise ValueError("DNS server dependency has no valid server tag")
        if not isinstance(domain_resolver, str) or not domain_resolver:
            raise ValueError(
                f"DNS server {tag} has an invalid domain resolver dependency"
            )
        if domain_resolver not in server_tags:
            raise ValueError(
                f"DNS server {tag} references unknown domain resolver {domain_resolver}"
            )
        dependencies[tag] = domain_resolver

    states: dict[str, int] = {}

    def visit(tag: str, path: list[str]) -> None:
        state = states.get(tag, 0)
        if state == 1:
            cycle_start = path.index(tag)
            cycle = path[cycle_start:] + [tag]
            raise ValueError(
                "DNS domain resolver dependency cycle: " + " -> ".join(cycle)
            )
        if state == 2:
            return
        states[tag] = 1
        dependency = dependencies.get(tag)
        if dependency is not None:
            visit(dependency, path + [tag])
        states[tag] = 2

    for tag in dependencies:
        visit(tag, [])


def _build_channel_rules(
    policy: DNSPolicy,
    channel_servers: dict[DNSChannelName, tuple[str, ...]],
) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    if _static_ip_enabled(policy):
        rules.append(_static_ip_rule(policy))
    rules.extend(_dns_diversion_rules(policy, channel_servers))
    return rules


def _static_ip_rule(policy: DNSPolicy) -> dict[str, Any]:
    domains = []
    seen: set[str] = set()
    for entry in policy.static_ips:
        if not entry.enabled or entry.domain in seen:
            continue
        domains.append(entry.domain)
        seen.add(entry.domain)
    return {
        "domain": domains,
        "server": STATIC_IP_SERVER_TAG,
    }


def _dns_diversion_rules(
    policy: DNSPolicy,
    channel_servers: dict[DNSChannelName, tuple[str, ...]],
) -> list[dict[str, Any]]:
    if policy.mode == DNSMode.OFF or not policy.rules_enabled:
        return []
    rules: list[dict[str, Any]] = []
    indexed_rules = enumerate(policy.rules)
    for _, rule in sorted(indexed_rules, key=lambda item: (item[1].priority, item[0])):
        if not rule.enabled:
            continue
        rules.append(_dns_diversion_rule(rule, channel_servers, policy=policy))
    return rules


def _dns_diversion_rule(
    rule: DNSRule,
    channel_servers: dict[DNSChannelName, tuple[str, ...]],
    *,
    policy: DNSPolicy,
) -> dict[str, Any]:
    singbox_rule = _dns_rule_match_fields(rule.pattern)
    if rule.action == DNSRuleAction.REJECT:
        singbox_rule["action"] = "reject"
        return singbox_rule
    if rule.channel is None:
        raise ValueError("dns diversion rule channel is required")
    server = _dns_rule_channel_server(policy, channel_servers, rule.channel)
    if server is None:
        raise ValueError(
            f"dns diversion rule channel has no server: {rule.channel.value}"
        )
    singbox_rule["server"] = server
    return singbox_rule


def _dns_rule_channel_server(
    policy: DNSPolicy,
    channel_servers: dict[DNSChannelName, tuple[str, ...]],
    channel: DNSChannelName,
) -> str | None:
    if channel == DNSChannelName.PROXY and _fakeip_enabled(policy, channel_servers):
        return FAKEIP_SERVER_TAG
    return _first_tag(channel_servers, channel)


def _dns_rule_match_fields(pattern: str) -> dict[str, Any]:
    pattern_type, value = pattern.split(":", 1)
    value = value.strip()
    if pattern_type == "domain":
        return {"domain": [value.lower().rstrip(".")]}
    if pattern_type == "suffix":
        return {"domain_suffix": [value.lower().rstrip(".")]}
    if pattern_type == "keyword":
        return {"domain_keyword": [value]}
    if pattern_type == "regex":
        return {"domain_regex": [value]}
    if pattern_type == "geosite":
        return {"geosite": [value]}
    if pattern_type == "rule_set":
        return {"rule_set": [value]}
    raise ValueError("unsupported dns rule pattern type")


def _final_server(channel_servers: dict[DNSChannelName, tuple[str, ...]]) -> str:
    final = _first_tag(channel_servers, DNSChannelName.FINAL)
    if final:
        return final
    proxy = _first_tag(channel_servers, DNSChannelName.PROXY)
    if proxy:
        return proxy
    direct = _first_tag(channel_servers, DNSChannelName.DIRECT)
    if direct:
        return direct
    return next(iter(next(iter(channel_servers.values()))))


def _first_tag(
    channel_servers: dict[DNSChannelName, tuple[str, ...]],
    channel_name: DNSChannelName,
) -> str | None:
    tags = channel_servers.get(channel_name)
    return tags[0] if tags else None
