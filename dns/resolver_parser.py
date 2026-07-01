from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit


class ResolverTransport(str, Enum):
    LOCAL = "local"
    DHCP = "dhcp"
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"
    HTTPS = "https"


class ResolverParseError(ValueError):
    pass


_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9-]{1,63}$")


@dataclass(frozen=True, slots=True)
class ParsedResolver:
    uri: str
    transport: ResolverTransport
    host: str | None = None
    port: int | None = None
    path: str | None = None

    @property
    def is_local(self) -> bool:
        return self.transport in {ResolverTransport.LOCAL, ResolverTransport.DHCP}


def parse_resolver_uri(uri: str) -> ParsedResolver:
    raw = str(uri).strip()
    if raw == "local":
        return ParsedResolver(uri="local", transport=ResolverTransport.LOCAL)
    if raw == "dhcp://auto":
        return ParsedResolver(uri="dhcp://auto", transport=ResolverTransport.DHCP)
    if not raw:
        raise ResolverParseError("resolver uri must not be empty")

    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in {"udp", "tcp", "tls", "https"}:
        raise ResolverParseError(f"unsupported resolver transport: {scheme or '<none>'}")
    if parts.username or parts.password:
        raise ResolverParseError("resolver uri must not contain credentials")
    if not parts.hostname:
        raise ResolverParseError("resolver uri must include a host")
    if parts.fragment:
        raise ResolverParseError("resolver uri must not include a fragment")
    if parts.query:
        raise ResolverParseError("resolver uri must not include a query string")

    host = parts.hostname.strip().lower()
    port = _parse_port(parts)

    if scheme in {"udp", "tcp"}:
        _require_ip(host)
        if parts.path not in {"", "/"}:
            raise ResolverParseError(f"{scheme} resolver uri must not include a path")
    elif scheme == "tls":
        _require_host_or_ip(host)
        if parts.path not in {"", "/"}:
            raise ResolverParseError("tls resolver uri must not include a path")
    elif scheme == "https":
        _require_host_or_ip(host)
        if not parts.path or parts.path == "/":
            raise ResolverParseError("https resolver uri must include a path")

    return ParsedResolver(
        uri=raw,
        transport=ResolverTransport(scheme),
        host=host,
        port=port,
        path=parts.path or None,
    )


def validate_resolver_uri(uri: str) -> None:
    parse_resolver_uri(uri)


def _parse_port(parts) -> int | None:
    try:
        port = parts.port
    except ValueError as exc:
        raise ResolverParseError("resolver uri port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ResolverParseError("resolver uri port is out of range")
    return port


def _require_ip(host: str) -> None:
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise ResolverParseError("resolver host must be an IP address") from exc


def _require_host_or_ip(host: str) -> None:
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if not _valid_hostname(host):
        raise ResolverParseError("resolver host must be a valid hostname or IP address")


def _valid_hostname(host: str) -> bool:
    if len(host) > 253 or host.endswith("."):
        return False
    labels = host.split(".")
    if any(not label for label in labels):
        return False
    for label in labels:
        if not _HOSTNAME_RE.match(label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True
