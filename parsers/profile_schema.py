"""Protocol semantic validation for untrusted connection profiles.

Syntax and endpoint policy are necessary but insufficient: a profile can be
well-formed while still causing the runtime to emit an unusable configuration.
This module defines the fields each supported protocol needs before it may be
persisted or rendered for sing-box.
"""
from __future__ import annotations

from typing import Any

from models.profile import Profile, ProtocolType


class ProfileSemanticValidationError(ValueError):
    """Raised when a profile is syntactically valid but cannot be used safely."""


_NETWORK_PROTOCOLS = {
    ProtocolType.VLESS,
    ProtocolType.VMESS,
    ProtocolType.TROJAN,
    ProtocolType.HYSTERIA2,
    ProtocolType.TUIC,
    ProtocolType.SHADOWSOCKS,
    ProtocolType.SOCKS,
    ProtocolType.HTTP,
}
_UUID_PROTOCOLS = {ProtocolType.VLESS, ProtocolType.VMESS}


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require_identifier(profile: Profile) -> None:
    if not _nonempty_string(profile.id):
        raise ProfileSemanticValidationError("profile identifier is empty")
    if not _nonempty_string(profile.name):
        raise ProfileSemanticValidationError("profile name is empty")


def _require_field(profile: Profile, field: str) -> None:
    if not _nonempty_string(profile.config.get(field)):
        raise ProfileSemanticValidationError(
            f"{profile.protocol.value} profile requires a non-empty {field}"
        )


def _validate_port(value: object, label: str) -> None:
    if isinstance(value, bool):
        raise ProfileSemanticValidationError(f"{label} must be an integer between 1 and 65535")
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        raise ProfileSemanticValidationError(f"{label} must be an integer between 1 and 65535")
    if not 1 <= port <= 65535:
        raise ProfileSemanticValidationError(f"{label} must be between 1 and 65535")


def _validate_config_ports(profile: Profile, keys: tuple[str, ...], *, required: bool) -> None:
    values = [(key, profile.config.get(key)) for key in keys if profile.config.get(key) not in (None, "")]
    if required and not values:
        raise ProfileSemanticValidationError(f"{profile.protocol.value} profile requires a port")
    for key, value in values:
        _validate_port(value, f"{profile.protocol.value} {key}")


def _wireguard_endpoint_port(endpoint: object) -> object | None:
    if not _nonempty_string(endpoint):
        return None
    value = endpoint.strip()
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1 or not value[closing + 1 :].startswith(":"):
            return None
        return value[closing + 2 :]
    if ":" not in value:
        return None
    _host, port = value.rsplit(":", 1)
    return port


def _validate_wireguard(profile: Profile) -> None:
    _require_field(profile, "private_key")
    _require_field(profile, "public_key")
    cfg = profile.config
    endpoint = cfg.get("endpoint")
    if endpoint not in (None, ""):
        endpoint_port = _wireguard_endpoint_port(endpoint)
        if endpoint_port is None:
            raise ProfileSemanticValidationError(
                f"{profile.protocol.value} endpoint must include a port"
            )
        _validate_port(endpoint_port, f"{profile.protocol.value} endpoint port")
    else:
        _require_remote_host(profile)
        _validate_config_ports(profile, ("port", "server_port"), required=True)
        return
    _validate_config_ports(profile, ("port", "server_port"), required=False)


def _require_remote_host(profile: Profile) -> None:
    if not any(_nonempty_string(profile.config.get(key)) for key in ("host", "server")):
        raise ProfileSemanticValidationError(f"{profile.protocol.value} profile requires a remote host")


def validate_profile_semantics(profile: Profile) -> None:
    """Reject profiles missing fields required by their runtime protocol.

    This intentionally does not derive any runtime value. In particular, a
    display identifier is never an acceptable replacement for a credential.
    """
    _require_identifier(profile)
    protocol = profile.protocol

    if protocol in _NETWORK_PROTOCOLS:
        _require_remote_host(profile)
        _validate_config_ports(profile, ("port", "server_port"), required=True)

    if protocol in _UUID_PROTOCOLS:
        _require_field(profile, "uuid")
    elif protocol in {ProtocolType.TROJAN, ProtocolType.HYSTERIA2}:
        _require_field(profile, "password")
    elif protocol is ProtocolType.TUIC:
        _require_field(profile, "uuid")
        _require_field(profile, "password")
    elif protocol is ProtocolType.SHADOWSOCKS:
        _require_field(profile, "method")
        _require_field(profile, "password")
    elif protocol in {ProtocolType.WIREGUARD, ProtocolType.AMNEZIAWG}:
        _validate_wireguard(profile)
    elif protocol in {ProtocolType.OPENVPN, ProtocolType.OPENVPN_CLOAK}:
        _require_field(profile, "raw_config")
        _validate_config_ports(profile, ("port", "server_port"), required=False)
