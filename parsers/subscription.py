from __future__ import annotations

import base64
import json
import os
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from models.profile import Profile
from parsers.clash_yaml import parse_clash_yaml
from parsers.singbox_json import parse_singbox_json
from parsers.uri import ParseError, parse_uri

DEFAULT_SUBSCRIPTION_USER_AGENT = (
    "WatchdogVPN/2.0 "
    "(compatible; sing-box; Clash; mihomo; v2ray-subscription)"
)


def _fetch_text(url: str) -> str:
    user_agent = os.environ.get("WATCHDOGVPN_SUBSCRIPTION_USER_AGENT", DEFAULT_SUBSCRIPTION_USER_AGENT)
    request = Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/plain, application/json, application/yaml, text/yaml, */*",
        },
    )
    try:
        with urlopen(request) as response:  # nosec - subscription URLs are user-provided inputs
            raw = response.read()
    except URLError as exc:
        raise ParseError(f"failed to fetch subscription: {exc}") from exc
    if not raw:
        raise ParseError("empty subscription response")
    return raw.decode("utf-8", errors="replace").strip()


def _looks_like_json(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _looks_like_yaml(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        return ":" in stripped or stripped.startswith("- ")
    return False


def _decode_base64_lines(text: str) -> list[str]:
    payload = text.replace("\n", "").replace("\r", "").strip()
    if not payload:
        raise ParseError("empty subscription response")
    padding = "=" * (-len(payload) % 4)
    for candidate in (payload, payload + padding):
        try:
            decoded = base64.b64decode(candidate.encode("utf-8"), validate=True).decode("utf-8")
            break
        except Exception:
            try:
                decoded = base64.urlsafe_b64decode(candidate.encode("utf-8")).decode("utf-8")
                break
            except Exception:
                decoded = ""
    if not decoded.strip():
        raise ParseError("invalid base64 subscription response")
    return [line.strip() for line in decoded.splitlines() if line.strip()]


def fetch_and_parse(url: str) -> list[Profile]:
    text = _fetch_text(url)
    if _looks_like_json(text):
        return parse_singbox_json(text)
    if _looks_like_yaml(text):
        return parse_clash_yaml(text)

    profiles: list[Profile] = []
    try:
        for line in _decode_base64_lines(text):
            profiles.append(parse_uri(line))
        return profiles
    except ParseError:
        pass

    if "outbounds" in text:
        try:
            return parse_singbox_json(text)
        except ParseError:
            pass
    if "proxies" in text:
        try:
            return parse_clash_yaml(text)
        except ParseError:
            pass
    raise ParseError("unsupported subscription format")
