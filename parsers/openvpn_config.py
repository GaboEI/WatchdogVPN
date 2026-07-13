from __future__ import annotations

from typing import Any

from models.profile import Profile, ProfileSource, ProtocolType
from parsers.openvpn_safety import OpenVPNConfigValidationError, validate_openvpn_config
from parsers.uri import ParseError



def _first_arg(directives: dict[str, list[list[str]]], key: str, index: int = 0) -> str | None:
    values = directives.get(key)
    if not values or len(values[0]) <= index:
        return None
    return values[0][index]


def _profile_name(remote_host: str | None, remote_port: str | None) -> str:
    if remote_host and remote_port:
        return f"openvpn-{remote_host}-{remote_port}"
    if remote_host:
        return f"openvpn-{remote_host}"
    return "openvpn"


def parse_openvpn_config(text: str) -> Profile:
    raw_config = (text or "").strip()
    if not raw_config:
        raise ParseError("OpenVPN config is empty")

    try:
        directives = validate_openvpn_config(raw_config)
    except OpenVPNConfigValidationError as exc:
        raise ParseError(str(exc)) from exc

    remote = directives.get("remote", [])
    if not remote:
        raise ParseError("OpenVPN config requires a remote directive")

    remote_host = remote[0][0] if len(remote[0]) >= 1 else None
    remote_port = remote[0][1] if len(remote[0]) >= 2 else None
    if not remote_host:
        raise ParseError("OpenVPN remote directive requires host")

    config: dict[str, Any] = {
        "raw_config": raw_config,
        "directives": directives,
        "host": remote_host,
        "compatibility_category": "standard",
    }
    if remote_port and remote_port.isdigit():
        config["port"] = int(remote_port)
    elif remote_port:
        config["port"] = remote_port

    proto = _first_arg(directives, "proto")
    if proto:
        config["proto"] = proto
    dev = _first_arg(directives, "dev")
    if dev:
        config["dev"] = dev

    name = _profile_name(remote_host, remote_port)
    return Profile(
        id=name,
        name=name,
        protocol=ProtocolType.OPENVPN,
        config=config,
        source=ProfileSource.MANUAL,
    )
