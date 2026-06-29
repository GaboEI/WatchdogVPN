from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import parse_qs, urlparse, unquote

from models.profile import Profile, ProfileSource, ProtocolType


class ParseError(ValueError):
    pass


SUPPORTED_SCHEMES = {
    "vless": ProtocolType.VLESS,
    "vmess": ProtocolType.VMESS,
    "trojan": ProtocolType.TROJAN,
    "hysteria2": ProtocolType.HYSTERIA2,
    "hy2": ProtocolType.HYSTERIA2,
    "ss": ProtocolType.SHADOWSOCKS,
    "tuic": ProtocolType.TUIC,
    "wg": ProtocolType.WIREGUARD,
}


def detect_scheme(uri: str) -> str:
    parsed = urlparse(uri or "")
    scheme = (parsed.scheme or "").lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ParseError(f"unsupported URI scheme: {scheme or 'missing'}")
    return scheme


def _decode_base64_text(value: str) -> str:
    raw = value.strip()
    padding = "=" * (-len(raw) % 4)
    for candidate in (raw, raw + padding):
        try:
            return base64.urlsafe_b64decode(candidate.encode("utf-8")).decode("utf-8")
        except Exception:
            continue
    raise ParseError("invalid base64 payload")


def _query_dict(parsed) -> dict[str, str]:
    result = {}
    for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
        result[key] = values[-1] if values else ""
    return result


def _build_profile(protocol: ProtocolType, parsed, config: dict[str, Any], name: str | None = None) -> Profile:
    host = parsed.hostname or ""
    port = parsed.port
    profile_id = name or parsed.fragment or host or protocol.value
    profile_name = name or parsed.fragment or host or protocol.value
    if port is not None:
        config.setdefault("port", port)
    if host:
        config.setdefault("host", host)
    if parsed.username:
        config.setdefault("username", parsed.username)
    if parsed.password:
        config.setdefault("password", parsed.password)
    if parsed.fragment:
        config.setdefault("fragment", parsed.fragment)
    config.setdefault("raw", parsed.geturl())
    return Profile(
        id=str(profile_id),
        name=str(profile_name),
        protocol=protocol,
        config=config,
        source=ProfileSource.MANUAL,
    )


def _parse_vless(uri: str):
    parsed = urlparse(uri)
    if not parsed.hostname or parsed.port is None:
        raise ParseError("VLESS URI requires host and port")
    config = _query_dict(parsed)
    if parsed.username:
        config["uuid"] = unquote(parsed.username)
    if parsed.password:
        config["password"] = unquote(parsed.password)
    return _build_profile(ProtocolType.VLESS, parsed, config)


def _parse_trojan(uri: str):
    parsed = urlparse(uri)
    if not parsed.hostname or parsed.port is None:
        raise ParseError("Trojan URI requires host and port")
    config = _query_dict(parsed)
    if parsed.username:
        config["password"] = unquote(parsed.username)
    if parsed.password:
        config["password"] = unquote(parsed.password)
    return _build_profile(ProtocolType.TROJAN, parsed, config)


def _parse_hysteria2(uri: str):
    parsed = urlparse(uri)
    if not parsed.hostname or parsed.port is None:
        raise ParseError("Hysteria2 URI requires host and port")
    config = _query_dict(parsed)
    if parsed.username and parsed.password:
        config["password"] = f"{unquote(parsed.username)}:{unquote(parsed.password)}"
    elif parsed.username:
        config["password"] = unquote(parsed.username)
    return _build_profile(ProtocolType.HYSTERIA2, parsed, config)


def _parse_tuic(uri: str):
    parsed = urlparse(uri)
    if not parsed.hostname or parsed.port is None:
        raise ParseError("TUIC URI requires host and port")
    config = _query_dict(parsed)
    if parsed.username:
        config["uuid"] = unquote(parsed.username)
    if parsed.password:
        config["password"] = unquote(parsed.password)
    return _build_profile(ProtocolType.TUIC, parsed, config)


def _parse_wireguard(uri: str):
    parsed = urlparse(uri)
    if not parsed.hostname:
        raise ParseError("WireGuard URI requires host")
    config = _query_dict(parsed)
    if parsed.port is not None:
        config["port"] = parsed.port
    if parsed.username:
        config["public_key"] = unquote(parsed.username)
    if parsed.password:
        config["private_key"] = unquote(parsed.password)
    if "public_key" not in config and parsed.fragment:
        config["public_key"] = parsed.fragment
    return _build_profile(ProtocolType.WIREGUARD, parsed, config)


def _parse_shadowsocks(uri: str):
    parsed = urlparse(uri)
    if not parsed.netloc:
        raise ParseError("Shadowsocks URI requires encoded payload")

    payload = parsed.netloc
    if "@" not in payload:
        decoded = _decode_base64_text(payload)
        if "@" not in decoded:
            raise ParseError("invalid Shadowsocks payload")
        payload = decoded

    method_password, host_port = payload.rsplit("@", 1)
    if ":" not in method_password or ":" not in host_port:
        raise ParseError("invalid Shadowsocks payload")

    method, password = method_password.split(":", 1)
    host, port = host_port.rsplit(":", 1)
    if not port.isdigit():
        raise ParseError("invalid Shadowsocks port")
    config = _query_dict(parsed)
    config.update(
        {
            "method": method,
            "password": password,
            "host": host,
            "port": int(port),
        }
    )
    return _build_profile(ProtocolType.SHADOWSOCKS, parsed, config)


def _parse_vmess(uri: str):
    parsed = urlparse(uri)
    payload = parsed.netloc or parsed.path.lstrip("/")
    if not payload:
        raise ParseError("VMess URI requires payload")
    decoded = _decode_base64_text(payload)
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ParseError("invalid VMess JSON payload") from exc
    if not isinstance(data, dict):
        raise ParseError("VMess payload must be a JSON object")
    host = data.get("add")
    port = data.get("port")
    if not host or port is None:
        raise ParseError("VMess payload requires add and port")
    config = {"raw_payload": data}
    config.update(_query_dict(parsed))
    config["host"] = host
    config["port"] = int(port)
    if "id" in data:
        config["uuid"] = data["id"]
    if "ps" in data:
        name = str(data["ps"])
    else:
        name = None
    return _build_profile(ProtocolType.VMESS, parsed, config, name=name)


def parse_uri(uri: str) -> Profile:
    scheme = detect_scheme(uri)
    if scheme == "vless":
        return _parse_vless(uri)
    if scheme == "vmess":
        return _parse_vmess(uri)
    if scheme == "trojan":
        return _parse_trojan(uri)
    if scheme in ("hysteria2", "hy2"):
        return _parse_hysteria2(uri)
    if scheme == "ss":
        return _parse_shadowsocks(uri)
    if scheme == "tuic":
        return _parse_tuic(uri)
    if scheme == "wg":
        return _parse_wireguard(uri)
    raise ParseError(f"unsupported URI scheme: {scheme}")
