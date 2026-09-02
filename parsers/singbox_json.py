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


def _load_json(data: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ParseError("invalid sing-box JSON") from exc
    if not isinstance(payload, dict):
        raise ParseError("sing-box JSON must be an object")
    return payload


def _coerce_outbounds(payload: dict[str, Any]) -> list[dict[str, Any]]:
    outbounds = payload.get("outbounds")
    if outbounds is None:
        return [payload]
    if not isinstance(outbounds, list):
        raise ParseError("sing-box outbounds must be a list")
    return [outbound for outbound in outbounds if isinstance(outbound, dict)]


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


def parse_singbox_json(data: str | dict[str, Any]) -> list[Profile]:
    payload = _load_json(data)
    profiles: list[Profile] = []
    for outbound in _coerce_outbounds(payload):
        profile = _build_profile(outbound) or _build_v2ray_profile(outbound)
        if profile is not None:
            try:
                validate_profile_endpoint(profile)
                validate_profile_semantics(profile)
            except (EndpointPolicyError, ProfileSemanticValidationError) as exc:
                raise ParseError(str(exc)) from exc
            profiles.append(profile)
    if not profiles:
        raise ParseError("sing-box JSON contains no supported profiles")
    return profiles
