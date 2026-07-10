"""Parser for the AmneziaVPN export format (vpn://).

Binary format:
  vpn://<base64url>
  base64url -> 4 bytes BE (decompressed size) + zlib(JSON)

The JSON has this structure:
  {
    "containers": [{"container": "...", "cloak": {...}, "openvpn": {...}}, ...],
    "defaultContainer": "...",
    "hostName": "...",
    "dns1": "...",
    "dns2": "...",
    ...
  }
"""
from __future__ import annotations

import base64
import json
import re
import struct
import zlib
from typing import Any

from models.profile import Profile, ProfileSource, ProtocolType
from parsers.uri import ParseError

_VPN_PREFIX = "vpn://"
_DNS_PLACEHOLDER = re.compile(r"\$PRIMARY_DNS|\$SECONDARY_DNS")

_CONTAINER_PARSERS: dict[str, str] = {
    "amnezia-openvpn-cloak": "openvpn_cloak",
    "amnezia-awg2": "amneziawg",
}


def is_amneziavpn_format(text: str) -> bool:
    return (text or "").strip().startswith(_VPN_PREFIX)


def _decode_payload(raw: str) -> dict[str, Any]:
    """Decode the base64url payload from the vpn:// format.

    The first 4 bytes are the decompressed size (uint32 big-endian).
    The rest is a zlib stream.
    """
    b64 = raw.strip().removeprefix(_VPN_PREFIX)
    padded = b64.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        data = base64.b64decode(padded)
    except Exception as exc:
        raise ParseError(f"amneziavpn: invalid base64: {exc}") from exc

    if len(data) < 4:
        raise ParseError("amneziavpn: payload too short")

    expected_size = struct.unpack(">I", data[:4])[0]
    try:
        decompressed = zlib.decompress(data[4:])
    except zlib.error as exc:
        raise ParseError(f"amneziavpn: decompression error: {exc}") from exc

    if len(decompressed) != expected_size:
        raise ParseError(
            f"amneziavpn: decompressed size {len(decompressed)} != {expected_size}"
        )

    try:
        return json.loads(decompressed)
    except json.JSONDecodeError as exc:
        raise ParseError(f"amneziavpn: invalid JSON: {exc}") from exc


def _substitute_dns(config_text: str, dns1: str, dns2: str) -> str:
    """Replace $PRIMARY_DNS and $SECONDARY_DNS in the OpenVPN config."""
    result = config_text.replace("$PRIMARY_DNS", dns1)
    result = result.replace("$SECONDARY_DNS", dns2)
    return result


def _extract_local_port(ovpn_config: str) -> str:
    """Extract the port from `remote 127.0.0.1 <port>` in the OpenVPN config."""
    for line in ovpn_config.splitlines():
        parts = line.strip().split()
        if (
            len(parts) >= 3
            and parts[0].lower() == "remote"
            and parts[1].startswith("127.")
        ):
            return parts[2]
    return "1194"


def _parse_openvpn_cloak(
    container: dict[str, Any],
    host: str,
    dns1: str,
    dns2: str,
    description: str,
) -> Profile:
    ovpn_section = container.get("openvpn") or {}
    cloak_section = container.get("cloak") or {}

    try:
        ovpn_inner = json.loads(ovpn_section.get("last_config") or "{}")
    except json.JSONDecodeError as exc:
        raise ParseError(f"amneziavpn: invalid openvpn.last_config JSON: {exc}") from exc

    raw_config = ovpn_inner.get("config") or ""
    if not raw_config.strip():
        raise ParseError("amneziavpn: empty openvpn config")

    raw_config = _substitute_dns(raw_config, dns1 or "1.1.1.1", dns2 or "1.0.0.1")

    try:
        cloak_conf: dict[str, Any] = json.loads(cloak_section.get("last_config") or "{}")
    except json.JSONDecodeError as exc:
        raise ParseError(f"amneziavpn: invalid cloak.last_config JSON: {exc}") from exc

    local_port = _extract_local_port(raw_config)
    cloak_conf.setdefault("LocalHost", "127.0.0.1")
    cloak_conf.setdefault("LocalPort", local_port)

    client_id = ovpn_inner.get("clientId") or ""
    profile_id = f"oc-{host}-{client_id[:8]}" if client_id else f"oc-{host}"
    name = description or f"openvpn-cloak-{host}"

    return Profile(
        id=profile_id,
        name=name,
        protocol=ProtocolType.OPENVPN_CLOAK,
        config={
            "raw_config": raw_config,
            "cloak_config": cloak_conf,
            "wrapper": "cloak",
            "host": host,
            "client_id": client_id,
        },
        source=ProfileSource.MANUAL,
    )


def _parse_amneziawg(
    container: dict[str, Any],
    host: str,
    description: str,
) -> Profile:
    awg_section = container.get("awg") or {}
    try:
        awg_config: dict[str, Any] = json.loads(awg_section.get("last_config") or "{}")
    except json.JSONDecodeError as exc:
        raise ParseError(f"amneziavpn: invalid awg.last_config JSON: {exc}") from exc

    raw_config = awg_config.get("config") or ""
    if not raw_config.strip():
        raise ParseError("amneziavpn: empty amneziawg config")

    client_id = awg_config.get("clientId") or ""
    profile_id = f"awg-{host}-{client_id[:8]}" if client_id else f"awg-{host}"
    name = description or f"amneziawg-{host}"

    return Profile(
        id=profile_id,
        name=name,
        protocol=ProtocolType.AMNEZIAWG,
        config={
            "raw": raw_config,
            "host": host,
            "client_id": client_id,
            "port": awg_config.get("port") or awg_section.get("port"),
        },
        source=ProfileSource.MANUAL,
    )


def parse_amneziavpn(text: str) -> list[Profile]:
    """Parse an AmneziaVPN export file (vpn://) and return profiles."""
    if not is_amneziavpn_format(text):
        raise ParseError("amneziavpn: does not start with vpn://")

    payload = _decode_payload(text)
    containers = payload.get("containers") or []
    if not containers:
        raise ParseError("amneziavpn: profile contains no containers")

    host = payload.get("hostName") or ""
    dns1 = payload.get("dns1") or "1.1.1.1"
    dns2 = payload.get("dns2") or "1.0.0.1"
    description = payload.get("description") or ""

    profiles: list[Profile] = []
    for container in containers:
        container_type = container.get("container") or ""
        if container_type == "amnezia-openvpn-cloak":
            try:
                profile = _parse_openvpn_cloak(container, host, dns1, dns2, description)
                profiles.append(profile)
            except ParseError:
                raise
        elif container_type == "amnezia-awg2":
            profiles.append(_parse_amneziawg(container, host, description))
        # Other container types are ignored for now.

    if not profiles:
        raise ParseError(
            f"amneziavpn: no supported container found "
            f"(containers: {[c.get('container') for c in containers]})"
        )

    return profiles
