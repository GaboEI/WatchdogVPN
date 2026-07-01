from __future__ import annotations

from dataclasses import dataclass

from .models import Resolver
from .resolver_parser import validate_resolver_uri


@dataclass(frozen=True, slots=True)
class ResolverPreset:
    id: str
    label: str
    resolvers: tuple[Resolver, ...]
    description: str = ""
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("resolver preset id must not be empty")
        if not self.label.strip():
            raise ValueError("resolver preset label must not be empty")
        if not self.resolvers:
            raise ValueError("resolver preset must include at least one resolver")
        for resolver in self.resolvers:
            validate_resolver_uri(resolver.uri)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "label": self.label,
            "resolvers": [resolver.to_dict() for resolver in self.resolvers],
            "description": self.description,
            "tags": list(self.tags),
        }


RESOLVER_PRESETS: tuple[ResolverPreset, ...] = (
    ResolverPreset(
        id="local",
        label="Local",
        resolvers=(Resolver(uri="local"),),
        description="Use the current local resolver.",
        tags=("local",),
    ),
    ResolverPreset(
        id="dhcp-auto",
        label="DHCP automatic",
        resolvers=(Resolver(uri="dhcp://auto"),),
        description="Use DNS servers supplied by the active network.",
        tags=("local", "dhcp"),
    ),
    ResolverPreset(
        id="cloudflare-doh",
        label="Cloudflare DoH",
        resolvers=(Resolver(uri="https://1.1.1.1/dns-query"),),
        description="Cloudflare public DNS over HTTPS.",
        tags=("public", "doh"),
    ),
    ResolverPreset(
        id="cloudflare-tls",
        label="Cloudflare TLS",
        resolvers=(Resolver(uri="tls://1.1.1.1"),),
        description="Cloudflare public DNS over TLS.",
        tags=("public", "dot"),
    ),
    ResolverPreset(
        id="quad9-doh",
        label="Quad9 DoH",
        resolvers=(Resolver(uri="https://9.9.9.9/dns-query"),),
        description="Quad9 public DNS over HTTPS.",
        tags=("public", "doh"),
    ),
    ResolverPreset(
        id="google-doh",
        label="Google DoH",
        resolvers=(Resolver(uri="https://8.8.8.8/dns-query"),),
        description="Google public DNS over HTTPS.",
        tags=("public", "doh"),
    ),
    ResolverPreset(
        id="adguard-doh",
        label="AdGuard DoH",
        resolvers=(Resolver(uri="https://dns.adguard-dns.com/dns-query"),),
        description="AdGuard public DNS over HTTPS.",
        tags=("public", "doh"),
    ),
    ResolverPreset(
        id="adguard-tls",
        label="AdGuard TLS",
        resolvers=(Resolver(uri="tls://dns.adguard-dns.com"),),
        description="AdGuard public DNS over TLS.",
        tags=("public", "dot"),
    ),
)


def get_resolver_preset(preset_id: str) -> ResolverPreset | None:
    wanted = preset_id.strip()
    for preset in RESOLVER_PRESETS:
        if preset.id == wanted:
            return preset
    return None
