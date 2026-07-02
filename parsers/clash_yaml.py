from __future__ import annotations

from typing import Any

from models.profile import Profile, ProfileSource, ProtocolType
from parsers.uri import ParseError


_TYPE_TO_PROTOCOL: dict[str, ProtocolType] = {
    "vless": ProtocolType.VLESS,
    "vmess": ProtocolType.VMESS,
    "trojan": ProtocolType.TROJAN,
    "hysteria2": ProtocolType.HYSTERIA2,
    "hy2": ProtocolType.HYSTERIA2,
    "tuic": ProtocolType.TUIC,
    "ss": ProtocolType.SHADOWSOCKS,
    "shadowsocks": ProtocolType.SHADOWSOCKS,
    "wireguard": ProtocolType.WIREGUARD,
    "wg": ProtocolType.WIREGUARD,
    "socks": ProtocolType.SOCKS,
    "http": ProtocolType.HTTP,
}


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_scalar(value: str) -> Any:
    value = _strip_quotes(value)
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value.isdigit():
        return int(value)
    return value


def _parse_mapping(lines: list[str], start: int, indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    i = start
    while i < len(lines):
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        current_indent = len(raw) - len(raw.lstrip(" "))
        if current_indent < indent:
            break
        if current_indent > indent:
            raise ParseError("invalid indentation in YAML mapping")
        stripped = raw.strip()
        if ":" not in stripped:
            raise ParseError("invalid YAML mapping entry")
        key, remainder = stripped.split(":", 1)
        key = key.strip()
        remainder = remainder.strip()
        if remainder:
            mapping[key] = _parse_scalar(remainder)
            i += 1
            continue
        next_index = i + 1
        while next_index < len(lines) and not lines[next_index].strip():
            next_index += 1
        if next_index < len(lines):
            next_indent = len(lines[next_index]) - len(lines[next_index].lstrip(" "))
            if lines[next_index].lstrip().startswith("- "):
                value, i = _parse_sequence(lines, next_index, next_indent)
            else:
                value, i = _parse_mapping(lines, next_index, next_indent)
        else:
            value = {}
            i = next_index
        mapping[key] = value
    return mapping, i


def _parse_sequence(lines: list[str], start: int, indent: int) -> tuple[list[dict[str, Any]], int]:
    items: list[dict[str, Any]] = []
    i = start
    while i < len(lines):
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        current_indent = len(raw) - len(raw.lstrip(" "))
        if current_indent < indent:
            break
        stripped = raw.strip()
        if not stripped.startswith("- "):
            break
        item_text = stripped[2:].strip()
        item: dict[str, Any] = {}
        if item_text:
            if ":" not in item_text:
                raise ParseError("invalid YAML sequence item")
            key, remainder = item_text.split(":", 1)
            item[key.strip()] = _parse_scalar(remainder.strip())
        i += 1
        while i < len(lines):
            lookahead = lines[i]
            if not lookahead.strip() or lookahead.lstrip().startswith("#"):
                i += 1
                continue
            lookahead_indent = len(lookahead) - len(lookahead.lstrip(" "))
            if lookahead_indent <= indent:
                break
            if ":" not in lookahead.strip():
                raise ParseError("invalid YAML sequence mapping entry")
            key, remainder = lookahead.strip().split(":", 1)
            item[key.strip()] = _parse_scalar(remainder.strip())
            i += 1
        items.append(item)
    return items, i


def _load_proxies(text: str) -> list[dict[str, Any]]:
    lines = (text or "").splitlines()
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("proxies:"):
            remainder = stripped.split(":", 1)[1].strip()
            if remainder:
                raise ParseError("inline proxies values are not supported")
            next_index = index + 1
            while next_index < len(lines) and not lines[next_index].strip():
                next_index += 1
            if next_index >= len(lines):
                return []
            next_indent = len(lines[next_index]) - len(lines[next_index].lstrip(" "))
            if not lines[next_index].lstrip().startswith("- "):
                raise ParseError("proxies section must be a YAML list")
            proxies, _ = _parse_sequence(lines, next_index, next_indent)
            return proxies
    raise ParseError("YAML missing proxies section")


def _profile_name(proxy: dict[str, Any], protocol: ProtocolType) -> str:
    for key in ("name", "tag", "server", "server_name"):
        value = proxy.get(key)
        if value:
            return str(value)
    return protocol.value


def parse_clash_yaml(text: str) -> list[Profile]:
    proxies = _load_proxies(text)
    profiles: list[Profile] = []
    for proxy in proxies:
        outbound_type = str(proxy.get("type", "")).lower()
        protocol = _TYPE_TO_PROTOCOL.get(outbound_type)
        if protocol is None:
            continue
        name = _profile_name(proxy, protocol)
        config = dict(proxy)
        config.setdefault("raw", proxy)
        profiles.append(
            Profile(
                id=name,
                name=name,
                protocol=protocol,
                config=config,
                source=ProfileSource.MANUAL,
            )
        )
    if not profiles:
        raise ParseError("Clash YAML contains no supported profiles")
    return profiles
