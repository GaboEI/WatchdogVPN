"""Shared hostile-endpoint policy for imported VPN profiles."""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
import time
from typing import Any

from models.profile import Profile, ProtocolType
from parsers.openvpn_safety import validated_openvpn_remote_host


class EndpointPolicyError(ValueError):
    """Raised when an untrusted endpoint is not safe for remote use."""


Resolver = Callable[..., list[tuple[Any, ...]]]


@dataclass(frozen=True, slots=True)
class EndpointResolution:
    """A short-lived, policy-validated endpoint resolution lease."""

    host: str
    addresses: tuple[str, ...]
    expires_at: float


class EndpointResolutionCache:
    """Keep validated global addresses available while the kill switch is active."""

    def __init__(
        self,
        ttl_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("endpoint resolution cache TTL must be positive")
        self._ttl_seconds = float(ttl_seconds)
        self._clock = clock
        self._entries: dict[str, EndpointResolution] = {}

    def get(self, host: object) -> EndpointResolution | None:
        key = _normalise_host(host)
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires_at <= self._clock():
            self._entries.pop(key, None)
            return None
        return entry

    def resolve(self, host: object, *, resolver: Resolver = socket.getaddrinfo) -> EndpointResolution:
        normalised = _normalise_host(host)
        cached = self.get(normalised)
        if cached is not None:
            return cached
        addresses = _resolved_addresses(normalised, resolver)
        unsafe = sorted(
            str(address)
            for address in addresses
            if not getattr(address, "is_global", False)
        )
        if unsafe:
            raise EndpointPolicyError(
                f"endpoint {normalised!r} resolves to a non-global address: {', '.join(unsafe)}"
            )
        entry = EndpointResolution(
            host=normalised,
            addresses=tuple(sorted(str(address) for address in addresses)),
            expires_at=self._clock() + self._ttl_seconds,
        )
        self._entries[normalised] = entry
        return entry

    def put(self, host: object, addresses: tuple[str, ...] | list[str]) -> EndpointResolution:
        normalised = _normalise_host(host)
        try:
            parsed = tuple(sorted({str(ipaddress.ip_address(address)) for address in addresses}))
        except (TypeError, ValueError) as exc:
            raise EndpointPolicyError(
                f"endpoint resolution returned an invalid address for {normalised!r}"
            ) from exc
        if not parsed:
            raise EndpointPolicyError(f"endpoint resolution returned no addresses for {normalised!r}")
        unsafe = sorted(address for address in parsed if not ipaddress.ip_address(address).is_global)
        if unsafe:
            raise EndpointPolicyError(
                f"endpoint {normalised!r} resolves to a non-global address: {', '.join(unsafe)}"
            )
        entry = EndpointResolution(
            host=normalised,
            addresses=parsed,
            expires_at=self._clock() + self._ttl_seconds,
        )
        self._entries[normalised] = entry
        return entry

    def invalidate(self, host: object) -> None:
        self._entries.pop(_normalise_host(host), None)

    def clear(self) -> None:
        self._entries.clear()


def _normalise_host(value: object) -> str:
    host = str(value or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.rstrip(".")
    if not host or any(character.isspace() for character in host) or "\x00" in host:
        raise EndpointPolicyError("endpoint host is empty or malformed")
    return host


def _resolved_addresses(host: str, resolver: Resolver) -> set[ipaddress._BaseAddress]:
    try:
        rows = resolver(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise EndpointPolicyError(f"endpoint resolution failed for {host!r}") from exc
    addresses: set[ipaddress._BaseAddress] = set()
    for row in rows:
        try:
            raw_address = str(row[4][0]).split("%", 1)[0]
            addresses.add(ipaddress.ip_address(raw_address))
        except (IndexError, TypeError, ValueError) as exc:
            raise EndpointPolicyError(f"resolver returned an invalid address for {host!r}") from exc
    if not addresses:
        raise EndpointPolicyError(f"endpoint resolution returned no addresses for {host!r}")
    return addresses


def canonicalize_remote_endpoint(
    host: object,
    *,
    resolver: Resolver = socket.getaddrinfo,
    require_resolution: bool = False,
    resolve_hostnames: bool = True,
    allow_captured_fakeip_ranges: tuple[str, ...] = (),
) -> str:
    """Return a safe endpoint host, resolving DNS when the caller requires it.

    Import paths validate literal addresses and local hostnames without making
    a DNS decision that can change between import and connection. Runtime
    paths pass ``require_resolution=True`` and therefore validate every answer
    immediately before opening the tunnel.
    """
    normalised = _normalise_host(host)
    if normalised.lower() in {"localhost", "localhost.localdomain"}:
        raise EndpointPolicyError(f"endpoint {normalised!r} is a local hostname")
    try:
        literal = ipaddress.ip_address(normalised)
    except ValueError:
        literal = None
    if literal is not None:
        if not getattr(literal, "is_global", False):
            raise EndpointPolicyError(
                f"endpoint {normalised!r} resolves to a non-global address: {literal}"
            )
        return normalised
    if not (resolve_hostnames or require_resolution):
        return normalised
    try:
        addresses = _resolved_addresses(normalised, resolver)
    except EndpointPolicyError:
        if require_resolution:
            raise
        return normalised
    unsafe = sorted(str(address) for address in addresses if not getattr(address, "is_global", False))
    if unsafe:
        fakeip_networks = tuple(ipaddress.ip_network(item, strict=False) for item in allow_captured_fakeip_ranges)
        if fakeip_networks and all(
            any(address in network for network in fakeip_networks) for address in addresses
        ):
            return normalised
        raise EndpointPolicyError(
            f"endpoint {normalised!r} resolves to a non-global address: {', '.join(unsafe)}"
        )
    return normalised


def profile_endpoint_host(profile: Profile) -> object | None:
    """Return the endpoint field used by supported runtime drivers."""
    if profile.protocol is ProtocolType.OPENVPN:
        return validated_openvpn_remote_host(profile)
    config = profile.config
    for key in ("host", "server"):
        value = config.get(key)
        if isinstance(value, str) and value.strip():
            return value
    endpoint = config.get("endpoint")
    if isinstance(endpoint, str) and endpoint.strip():
        raw = endpoint.strip()
        if raw.startswith("[") and "]" in raw:
            return raw[1:raw.index("]")]
        return raw.rsplit(":", 1)[0] if ":" in raw else raw
    return None


def validate_profile_endpoint(
    profile: Profile,
    *,
    resolver: Resolver = socket.getaddrinfo,
    require_resolution: bool = False,
    resolve_hostnames: bool = False,
    allow_captured_fakeip_ranges: tuple[str, ...] = (),
    resolution_cache: EndpointResolutionCache | None = None,
    allow_live_resolution: bool = True,
) -> str:
    try:
        host = profile_endpoint_host(profile)
    except ValueError as exc:
        raise EndpointPolicyError(str(exc)) from exc
    if host is None:
        raise EndpointPolicyError("profile has no remote endpoint host")
    if require_resolution and resolution_cache is not None:
        try:
            literal = ipaddress.ip_address(_normalise_host(host))
        except ValueError:
            literal = None
        if literal is not None:
            if not literal.is_global:
                raise EndpointPolicyError(
                    f"endpoint {literal} resolves to a non-global address: {literal}"
                )
            return str(literal)
        cached = resolution_cache.get(host)
        if cached is None:
            if not allow_live_resolution:
                raise EndpointPolicyError(
                    f"no fresh validated resolution for endpoint {host!r} while runtime is active"
                )
            resolution_cache.resolve(host, resolver=resolver)
        return _normalise_host(host)
    return canonicalize_remote_endpoint(
        host,
        resolver=resolver,
        require_resolution=require_resolution,
        resolve_hostnames=resolve_hostnames,
        allow_captured_fakeip_ranges=allow_captured_fakeip_ranges,
    )
