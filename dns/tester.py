from __future__ import annotations

import http.client
import secrets
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence

from .models import (
    MAX_RESOLVERS_PER_CHANNEL,
    DNSChannel,
    DNSChannelName,
    DNSMode,
    DNSPolicy,
    Resolver,
)
from .resolver_parser import ParsedResolver, ResolverTransport, parse_resolver_uri


DEFAULT_TEST_DOMAIN = "gstatic.com"
DEFAULT_TIMEOUT_SECONDS = 3.0


class ResolverProbe(Protocol):
    def __call__(
        self,
        resolver: Resolver,
        test_domain: str,
        timeout: float,
    ) -> "ResolverTestResult":
        ...


@dataclass(frozen=True, slots=True)
class ResolverTestResult:
    resolver: Resolver
    ok: bool
    latency_ms: float | None = None
    error: str | None = None
    test_domain: str = DEFAULT_TEST_DOMAIN

    def to_dict(self) -> dict[str, object]:
        return {
            "resolver": self.resolver.to_dict(),
            "ok": self.ok,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "test_domain": self.test_domain,
        }


@dataclass(frozen=True, slots=True)
class ChannelTestResult:
    channel: DNSChannelName
    results: tuple[ResolverTestResult, ...]
    selected: tuple[Resolver, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "channel": self.channel.value,
            "results": [result.to_dict() for result in self.results],
            "selected": [resolver.to_dict() for resolver in self.selected],
        }


@dataclass(frozen=True, slots=True)
class AutoSetupRecommendation:
    policy: DNSPolicy
    channel_results: dict[DNSChannelName, ChannelTestResult] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "policy": self.policy.to_dict(),
            "channel_results": {
                channel.value: result.to_dict()
                for channel, result in self.channel_results.items()
            },
        }


class DefaultResolverProbe:
    def __call__(
        self,
        resolver: Resolver,
        test_domain: str,
        timeout: float,
    ) -> ResolverTestResult:
        started = time.perf_counter()
        try:
            parsed = parse_resolver_uri(resolver.uri)
            _probe_resolver(parsed, test_domain, timeout)
        except Exception as exc:  # pragma: no cover - exercised through fakes
            return ResolverTestResult(
                resolver=resolver,
                ok=False,
                error=str(exc),
                test_domain=test_domain,
            )
        latency_ms = (time.perf_counter() - started) * 1000
        return ResolverTestResult(
            resolver=resolver,
            ok=True,
            latency_ms=round(latency_ms, 3),
            test_domain=test_domain,
        )


class DNSTester:
    def __init__(
        self,
        probe: ResolverProbe | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_workers: int = MAX_RESOLVERS_PER_CHANNEL,
    ) -> None:
        self.probe = probe or DefaultResolverProbe()
        self.timeout = float(timeout)
        self.max_workers = max(1, min(int(max_workers), MAX_RESOLVERS_PER_CHANNEL))

    def test_resolver(
        self,
        resolver: Resolver,
        test_domain: str = DEFAULT_TEST_DOMAIN,
    ) -> ResolverTestResult:
        return self.probe(resolver, _normalize_domain(test_domain), self.timeout)

    def rank_resolvers(
        self,
        resolvers: Sequence[Resolver],
        test_domain: str = DEFAULT_TEST_DOMAIN,
    ) -> tuple[ResolverTestResult, ...]:
        candidates = [resolver for resolver in resolvers if resolver.enabled]
        candidates = candidates[:MAX_RESOLVERS_PER_CHANNEL]
        if not candidates:
            return ()

        domain = _normalize_domain(test_domain)
        workers = min(self.max_workers, len(candidates))
        results: list[ResolverTestResult] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.probe, resolver, domain, self.timeout): resolver
                for resolver in candidates
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append(
                        ResolverTestResult(
                            resolver=futures[future],
                            ok=False,
                            error=str(exc),
                            test_domain=domain,
                        )
                    )
        return tuple(sorted(results, key=_result_sort_key))

    def test_channel(
        self,
        channel: DNSChannel,
        test_domain: str = DEFAULT_TEST_DOMAIN,
    ) -> ChannelTestResult:
        ranked = self.rank_resolvers(channel.resolvers, test_domain)
        selected = tuple(result.resolver for result in ranked if result.ok)
        return ChannelTestResult(
            channel=channel.name,
            results=ranked,
            selected=selected,
        )

    def recommend_auto_setup(
        self,
        channel_candidates: Mapping[DNSChannelName, Sequence[Resolver]] | None = None,
        test_domain: str = DEFAULT_TEST_DOMAIN,
    ) -> AutoSetupRecommendation:
        domain = _normalize_domain(test_domain)
        candidates = channel_candidates or default_auto_channel_candidates()
        channel_results: dict[DNSChannelName, ChannelTestResult] = {}
        policy_channels: dict[DNSChannelName, DNSChannel] = {}

        for channel_name in DNSChannelName:
            channel = DNSChannel(
                name=channel_name,
                resolvers=list(candidates.get(channel_name, ())),
            )
            result = self.test_channel(channel, domain)
            channel_results[channel_name] = result
            if result.selected:
                policy_channels[channel_name] = DNSChannel(
                    name=channel_name,
                    resolvers=list(result.selected),
                )

        policy = DNSPolicy(
            mode=DNSMode.AUTO,
            channels=policy_channels,
            test_domain=domain,
        )
        return AutoSetupRecommendation(policy=policy, channel_results=channel_results)


def default_auto_channel_candidates() -> dict[DNSChannelName, tuple[Resolver, ...]]:
    local_candidates = (
        Resolver(uri="local"),
        Resolver(uri="dhcp://auto"),
    )
    public_candidates = (
        Resolver(uri="https://1.1.1.1/dns-query", label="Cloudflare DoH"),
        Resolver(uri="https://9.9.9.9/dns-query", label="Quad9 DoH"),
        Resolver(uri="tls://1.1.1.1", label="Cloudflare TLS"),
        Resolver(uri="tls://dns.quad9.net", label="Quad9 TLS"),
    )
    return {
        DNSChannelName.BOOTSTRAP: local_candidates,
        DNSChannelName.DNS_SERVER: local_candidates,
        DNSChannelName.PROXY_SERVER: local_candidates,
        DNSChannelName.DIRECT: local_candidates,
        DNSChannelName.PROXY: public_candidates,
        DNSChannelName.FINAL: public_candidates,
    }


def _result_sort_key(result: ResolverTestResult) -> tuple[int, float, str]:
    latency = result.latency_ms if result.latency_ms is not None else float("inf")
    return (0 if result.ok else 1, latency, result.resolver.uri)


def _normalize_domain(domain: str) -> str:
    normalized = str(domain).strip().lower().rstrip(".")
    if not normalized:
        raise ValueError("dns test domain must not be empty")
    return normalized


def _probe_resolver(
    parsed: ParsedResolver,
    test_domain: str,
    timeout: float,
) -> None:
    if parsed.transport in {ResolverTransport.LOCAL, ResolverTransport.DHCP}:
        socket.getaddrinfo(test_domain, None)
        return
    query_id = secrets.randbits(16)
    query = _build_dns_query(test_domain, query_id)
    if parsed.transport == ResolverTransport.UDP:
        response = _send_udp_query(parsed, query, timeout)
    elif parsed.transport == ResolverTransport.TCP:
        response = _send_tcp_query(parsed, query, timeout)
    elif parsed.transport == ResolverTransport.TLS:
        response = _send_tls_query(parsed, query, timeout)
    elif parsed.transport == ResolverTransport.HTTPS:
        response = _send_https_query(parsed, query, timeout)
    else:  # pragma: no cover - enum guard
        raise ValueError(f"unsupported resolver transport: {parsed.transport}")
    _validate_dns_response(response, query_id)


def _build_dns_query(domain: str, query_id: int) -> bytes:
    labels = domain.encode("ascii").split(b".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("dns test domain is invalid")
    question = b"".join(bytes([len(label)]) + label for label in labels)
    question += b"\x00"
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    qtype_a = 1
    qclass_in = 1
    return header + question + struct.pack("!HH", qtype_a, qclass_in)


def _validate_dns_response(response: bytes, query_id: int) -> None:
    if len(response) < 12:
        raise ValueError("dns response is too short")
    response_id, flags, _qdcount, _ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH",
        response[:12],
    )
    if response_id != query_id:
        raise ValueError("dns response id does not match query")
    if flags & 0x8000 == 0:
        raise ValueError("dns response is not marked as a response")
    rcode = flags & 0x000F
    if rcode not in {0, 3}:
        raise ValueError(f"dns resolver returned error rcode {rcode}")


def _send_udp_query(parsed: ParsedResolver, query: bytes, timeout: float) -> bytes:
    assert parsed.host is not None
    port = parsed.port or 53
    family = socket.AF_INET6 if ":" in parsed.host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (parsed.host, port))
        response, _addr = sock.recvfrom(4096)
        return response


def _send_tcp_query(parsed: ParsedResolver, query: bytes, timeout: float) -> bytes:
    assert parsed.host is not None
    port = parsed.port or 53
    with socket.create_connection((parsed.host, port), timeout=timeout) as sock:
        return _send_stream_query(sock, query)


def _send_tls_query(parsed: ParsedResolver, query: bytes, timeout: float) -> bytes:
    assert parsed.host is not None
    port = parsed.port or 853
    context = ssl.create_default_context()
    with socket.create_connection((parsed.host, port), timeout=timeout) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=parsed.host) as tls_sock:
            tls_sock.settimeout(timeout)
            return _send_stream_query(tls_sock, query)


def _send_stream_query(sock: socket.socket, query: bytes) -> bytes:
    sock.sendall(struct.pack("!H", len(query)) + query)
    length_data = _recv_exact(sock, 2)
    expected = struct.unpack("!H", length_data)[0]
    return _recv_exact(sock, expected)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ValueError("dns stream closed before full response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_https_query(parsed: ParsedResolver, query: bytes, timeout: float) -> bytes:
    assert parsed.host is not None
    assert parsed.path is not None
    connection = http.client.HTTPSConnection(
        parsed.host,
        parsed.port or 443,
        timeout=timeout,
    )
    try:
        connection.request(
            "POST",
            parsed.path,
            body=query,
            headers={
                "Accept": "application/dns-message",
                "Content-Type": "application/dns-message",
            },
        )
        response = connection.getresponse()
        payload = response.read()
        if response.status != 200:
            raise ValueError(f"doh resolver returned HTTP {response.status}")
        return payload
    finally:
        connection.close()
