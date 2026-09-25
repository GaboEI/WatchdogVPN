"""Shared hostile-endpoint policy for imported VPN profiles."""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import Any

from models.profile import Profile, ProtocolType
from parsers.openvpn_safety import validated_openvpn_remote_host


class EndpointPolicyError(ValueError):
    """Raised when an untrusted endpoint is not safe for remote use."""


Resolver = Callable[..., list[tuple[Any, ...]]]


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
) -> str:
    try:
        host = profile_endpoint_host(profile)
    except ValueError as exc:
        raise EndpointPolicyError(str(exc)) from exc
    if host is None:
        raise EndpointPolicyError("profile has no remote endpoint host")
    return canonicalize_remote_endpoint(
        host,
        resolver=resolver,
        require_resolution=require_resolution,
        resolve_hostnames=resolve_hostnames,
        allow_captured_fakeip_ranges=allow_captured_fakeip_ranges,
    )
