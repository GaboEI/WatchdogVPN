from __future__ import annotations

import re
from typing import Any

from models.profile import Profile, ProfileSource, ProtocolType
from parsers.uri import ParseError


_SECTION_RE = re.compile(r"^\[(?P<section>[^\]]+)\]\s*$")
_KEYVAL_RE = re.compile(r"^(?P<key>[A-Za-z0-9_]+)\s*=\s*(?P<value>.+?)\s*$")
_OBFUSCATION_KEYS = {"jc", "jmin", "jmax", "s1", "s2", "h1", "h2"}


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def _parse_lines(text: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current = None
    for raw_line in (text or "").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        section_match = _SECTION_RE.match(line)
        if section_match:
            current = section_match.group("section").strip().lower()
            sections.setdefault(current, {})
            continue
        if current is None:
            continue
        match = _KEYVAL_RE.match(line)
        if not match:
            continue
        key = match.group("key").strip().lower()
        value = _strip_quotes(match.group("value"))
        sections.setdefault(current, {})[key] = value
    return sections


def _is_amneziawg(sections: dict[str, dict[str, str]]) -> bool:
    interface = sections.get("interface", {})
    peer = sections.get("peer", {})
    keys = {k.lower() for k in interface} | {k.lower() for k in peer}
    return bool(keys & _OBFUSCATION_KEYS)


def parse_wg_config(text: str) -> Profile:
    sections = _parse_lines(text)
    interface = sections.get("interface", {})
    peer = sections.get("peer", {})

    if not interface:
        raise ParseError("WireGuard config missing [Interface] section")
    if not peer:
        raise ParseError("WireGuard config missing [Peer] section")

    private_key = interface.get("privatekey") or interface.get("private_key")
    public_key = peer.get("publickey") or peer.get("public_key")
    endpoint = peer.get("endpoint")
    allowed_ips = peer.get("allowedips") or peer.get("allowed_ips")

    if not private_key:
        raise ParseError("WireGuard config missing Interface.PrivateKey")
    if not public_key:
        raise ParseError("WireGuard config missing Peer.PublicKey")
    if not endpoint:
        raise ParseError("WireGuard config missing Peer.Endpoint")

    protocol = ProtocolType.AMNEZIAWG if _is_amneziawg(sections) else ProtocolType.WIREGUARD
    config: dict[str, Any] = {
        "interface": interface,
        "peer": peer,
        "private_key": private_key,
        "public_key": public_key,
        "endpoint": endpoint,
        "raw": (text or "").strip(),
    }
    if allowed_ips:
        config["allowed_ips"] = allowed_ips
    if "address" in interface:
        config["address"] = interface["address"]
    if "dns" in interface:
        config["dns"] = interface["dns"]
    if "mtu" in interface:
        config["mtu"] = interface["mtu"]
    if "persistentkeepalive" in peer:
        config["persistent_keepalive"] = peer["persistentkeepalive"]

    name = interface.get("address") or endpoint
    return Profile(
        id=str(name),
        name=str(name),
        protocol=protocol,
        config=config,
        source=ProfileSource.MANUAL,
    )
