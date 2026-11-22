from __future__ import annotations

import json
from typing import Any

from models.profile import Profile, ProfileSource, ProtocolType
from parsers.uri import ParseError
from parsers.endpoint_policy import EndpointPolicyError, validate_profile_endpoint
from parsers.profile_schema import ProfileSemanticValidationError, validate_profile_semantics


_TYPE_TO_PROTOCOL: dict[str, ProtocolType] = {
    "vless": ProtocolType.VLESS,
    "vmess": ProtocolType.VMESS,
    "trojan": ProtocolType.TROJAN,
    "hysteria2": ProtocolType.HYSTERIA2,
    "hy2": ProtocolType.HYSTERIA2,
    "tuic": ProtocolType.TUIC,
    "shadowsocks": ProtocolType.SHADOWSOCKS,
    "ss": ProtocolType.SHADOWSOCKS,
    "wireguard": ProtocolType.WIREGUARD,
    "wg": ProtocolType.WIREGUARD,
    "socks": ProtocolType.SOCKS,
    "http": ProtocolType.HTTP,
}


# Root arrays of a sing-box object that carry node entries. The order is the
# deterministic extraction order: ``outbounds`` first, then ``endpoints``.
SINGBOX_NODE_ARRAYS = ("outbounds", "endpoints")


def _load_json(data: str | dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    if isinstance(data, (dict, list)):
        return data
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ParseError("invalid sing-box JSON") from exc
    if not isinstance(payload, (dict, list)):
        raise ParseError("sing-box JSON must be an object or an array")
    return payload


def _coerce_outbounds(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect node entries from ``outbounds`` and ``endpoints`` in that order.

    When both arrays are present their entries are combined rather than one
    being preferred. A payload carrying neither is a single bare outbound.
    """
    present = [
        (key, payload[key])
        for key in SINGBOX_NODE_ARRAYS
        if payload.get(key) is not None
    ]
    if not present:
        return [payload]
    entries: list[dict[str, Any]] = []
    for key, value in present:
        if not isinstance(value, list):
            raise ParseError(f"sing-box {key} must be a list")
        entries.extend(entry for entry in value if isinstance(entry, dict))
    return entries


def _coerce_xray_array(payload: list[Any]) -> tuple[list[dict[str, Any]], int]:
    """Flatten a root-level Xray JSON array into outbound objects.

    Each element is read according to its own shape, so one array may mix them:
    an object carrying ``outbounds`` contributes the objects of that list, and
    an object carrying ``protocol`` is a single bare outbound. Element order and
    the order of derived outbounds are preserved. Elements that match neither
    shape, and non-object entries inside an element's ``outbounds`` list, are
    returned as a skipped count instead of being dropped silently.
    """
    entries: list[dict[str, Any]] = []
    skipped = 0
    for element in payload:
        if not isinstance(element, dict):
            skipped += 1
        elif element.get("outbounds") is not None:
            outbounds = element["outbounds"]
            if not isinstance(outbounds, list):
                raise ParseError("Xray JSON array element outbounds must be a list")
            for outbound in outbounds:
                if isinstance(outbound, dict):
                    entries.append(outbound)
                else:
                    skipped += 1
        elif "protocol" in element:
            entries.append(element)
        else:
            skipped += 1
    return entries, skipped


def _profile_name(outbound: dict[str, Any], protocol: ProtocolType) -> str:
    for key in ("tag", "name"):
        value = outbound.get(key)
        if value:
            return str(value)
    for key in ("server", "server_name", "server_port"):
        value = outbound.get(key)
        if value is not None:
            return str(value)
    return protocol.value


def _build_profile(outbound: dict[str, Any]) -> Profile | None:
    outbound_type = str(outbound.get("type", "")).lower()
    protocol = _TYPE_TO_PROTOCOL.get(outbound_type)
    if protocol is None:
        return None

    config = {key: value for key, value in outbound.items() if key != "type"}
    config.setdefault("raw", outbound)
    # Native sing-box configs keep TLS/reality settings nested under "tls".
    # The driver consumes them from top-level keys (pbk/sid/sni/fp), so flatten
    # them here without overriding explicit top-level values. This is additive
    # and does not change URI, v2ray, or any other import path.
    tls: dict[str, Any] = {}
    if isinstance(outbound.get("tls"), dict):
        tls = outbound["tls"]
    if tls:
        if not any(key in config for key in ("sni", "server_name")):
            server_name = tls.get("server_name")
            if server_name:
                config["sni"] = server_name
        utls: dict[str, Any] = {}
        if isinstance(tls.get("utls"), dict):
            utls = tls["utls"]
        if not any(key in config for key in ("fp", "fingerprint")):
            fingerprint = utls.get("fingerprint")
            if fingerprint:
                config["fp"] = fingerprint
        reality: dict[str, Any] = {}
        if isinstance(tls.get("reality"), dict):
            reality = tls["reality"]
        if reality:
            if not any(key in config for key in ("pbk", "public_key")):
                public_key = reality.get("public_key")
                if public_key:
                    config["pbk"] = public_key
            if not any(key in config for key in ("sid", "short_id")):
                short_id = reality.get("short_id")
                if short_id:
                    config["sid"] = short_id
    name = _profile_name(outbound, protocol)
    return Profile(
        id=name,
        name=name,
        protocol=protocol,
        config=config,
        source=ProfileSource.MANUAL,
    )


def _build_v2ray_profile(outbound: dict[str, Any]) -> Profile | None:
    protocol_name = str(outbound.get("protocol", "")).lower()
    protocol = _TYPE_TO_PROTOCOL.get(protocol_name)
    if protocol is None:
        return None

    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    servers = settings.get("servers") if isinstance(settings, dict) else None
    vnext = settings.get("vnext") if isinstance(settings, dict) else None
    server_list = vnext if protocol in {ProtocolType.VLESS, ProtocolType.VMESS} else servers
    server = (
        server_list[0]
        if isinstance(server_list, list) and server_list and isinstance(server_list[0], dict)
        else {}
    )
    users = server.get("users") if isinstance(server.get("users"), list) else []
    user = users[0] if users and isinstance(users[0], dict) else {}
    stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
    tls = stream.get("tlsSettings") if isinstance(stream.get("tlsSettings"), dict) else {}

    config: dict[str, Any] = {
        "raw": outbound,
        "server": server.get("address") or server.get("server"),
        "server_port": server.get("port"),
        "network": stream.get("network"),
    }
    if protocol is ProtocolType.TROJAN:
        config["password"] = server.get("password")
    elif protocol in {ProtocolType.VLESS, ProtocolType.VMESS}:
        config["uuid"] = user.get("id") or user.get("uuid")
        if protocol is ProtocolType.VMESS:
            config["alter_id"] = user.get("alterId") or user.get("alter_id")
            config["security"] = user.get("security")
    if tls:
        config["tls"] = True
        if tls.get("serverName"):
            config["sni"] = tls["serverName"]
        if tls.get("allowInsecure") is not None:
            config["allow_insecure"] = tls["allowInsecure"]

    name = str(outbound.get("tag") or server.get("email") or config.get("server") or protocol.value)
    return Profile(
        id=name,
        name=name,
        protocol=protocol,
        config=config,
        source=ProfileSource.MANUAL,
    )


def parse_singbox_json(data: str | dict[str, Any] | list[Any]) -> list[Profile]:
    profiles, _skipped_nodes = parse_singbox_json_detailed(data)
    return profiles


# Outbound types that describe sing-box's own control flow rather than a remote
# proxy node. They are expected in a complete configuration and are therefore
# never counted as an unimportable node. Every other outbound object that fails
# to produce an importable profile is counted as incompleteness: a structured
# candidate must not look clean after silently dropping an outbound object.
_SINGBOX_CONTROL_TYPES = frozenset({"direct", "block", "dns", "selector", "urltest"})


def _is_control_outbound(outbound: dict[str, Any]) -> bool:
    """True when an outbound is recognized as sing-box control flow."""
    outbound_type = str(outbound.get("type", "")).lower()
    return outbound_type in _SINGBOX_CONTROL_TYPES


def _count_malformed_outbounds(payload: dict[str, Any]) -> int:
    """Entries of the ``outbounds`` and ``endpoints`` lists that are not objects.

    ``_coerce_outbounds`` drops them, so they must be counted here: a response
    that mixes nodes with malformed entries is incomplete and must not be
    ranked as a complete, clean candidate.
    """
    malformed = 0
    for key in SINGBOX_NODE_ARRAYS:
        entries = payload.get(key)
        if isinstance(entries, list):
            malformed += sum(1 for entry in entries if not isinstance(entry, dict))
    return malformed


def parse_singbox_json_detailed(
    data: str | dict[str, Any] | list[Any],
) -> tuple[list[Profile], int]:
    """Parse sing-box or Xray JSON and report nodes that could not be imported.

    A recognized sing-box control-flow outbound is not a remote node and is
    excluded from incompleteness. Every other outbound object that does not
    yield an importable profile is counted so a structured candidate is never
    treated as a complete, clean response while entries were silently skipped.
    Malformed (non-object) ``outbounds`` and ``endpoints`` entries are counted
    too. A sing-box object may carry both arrays; ``endpoints`` entries go
    through exactly the same conversion and validation as ``outbounds`` entries.

    A root-level JSON array is the Xray array form. Its elements are read by
    ``_coerce_xray_array`` and converted with the Xray converter only: a root
    array of sing-box ``type`` objects is not a supported form and yields no
    profile.
    """
    payload = _load_json(data)
    if isinstance(payload, list):
        outbounds, skipped_nodes = _coerce_xray_array(payload)
        builders = (_build_v2ray_profile,)
        empty_message = "Xray JSON array contains no supported profiles"
    else:
        outbounds = _coerce_outbounds(payload)
        skipped_nodes = _count_malformed_outbounds(payload)
        builders = (_build_profile, _build_v2ray_profile)
        empty_message = "sing-box JSON contains no supported profiles"
    profiles: list[Profile] = []
    for outbound in outbounds:
        profile = next(
            (built for build in builders if (built := build(outbound)) is not None),
            None,
        )
        if profile is None:
            if not _is_control_outbound(outbound):
                skipped_nodes += 1
            continue
        try:
            validate_profile_endpoint(profile)
            validate_profile_semantics(profile)
        except (EndpointPolicyError, ProfileSemanticValidationError) as exc:
            raise ParseError(str(exc)) from exc
        profiles.append(profile)
    if not profiles:
        raise ParseError(empty_message)
    return profiles, skipped_nodes
