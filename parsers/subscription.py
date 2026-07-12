from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from models.profile import Profile
from parsers.clash_yaml import parse_clash_yaml
from parsers.singbox_json import parse_singbox_json
from parsers.uri import ParseError, parse_uri

DEFAULT_SUBSCRIPTION_USER_AGENT = (
    "WatchdogVPN/2.0 "
    "(compatible; sing-box; Clash; mihomo; v2ray-subscription)"
)
SUBSCRIPTION_USERINFO_HEADER = "subscription-userinfo"


@dataclass(frozen=True, slots=True)
class SubscriptionFetchResult:
    profiles: list[Profile]
    metadata: dict[str, Any] = field(default_factory=dict)


def _fetch(url: str) -> tuple[str, dict[str, str]]:
    # Only https is accepted: plain http leaks the subscription token (often
    # embedded in the URL path) in cleartext, and urlopen would otherwise
    # also happily honor file://, ftp:// and other local/non-network
    # schemes - "add a provider" must never become "read an arbitrary local
    # file" or "fetch an internal-network URL an operator didn't intend".
    if urlparse(url).scheme != "https":
        raise ParseError(f"invalid subscription URL scheme (https required): {url}")
    user_agent = os.environ.get("WATCHDOGVPN_SUBSCRIPTION_USER_AGENT", DEFAULT_SUBSCRIPTION_USER_AGENT)
    try:
        request = Request(
            url,
            headers={
                "User-Agent": user_agent,
                "Accept": "text/plain, application/json, application/yaml, text/yaml, */*",
            },
        )
        with urlopen(request) as response:  # nosec - subscription URLs are user-provided inputs
            raw = response.read()
            headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
    except ValueError as exc:
        raise ParseError(f"invalid subscription URL: {url}") from exc
    except URLError as exc:
        raise ParseError(f"failed to fetch subscription: {exc}") from exc
    if not raw:
        raise ParseError("empty subscription response")
    return raw.decode("utf-8", errors="replace").strip(), headers


def _fetch_text(url: str) -> str:
    text, _headers = _fetch(url)
    return text


def _looks_like_json(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _looks_like_html(text: str) -> bool:
    stripped = text.lstrip().lower()
    return (
        stripped.startswith("<!doctype html")
        or stripped.startswith("<html")
        or "<body" in stripped[:500]
        or "</html>" in stripped[:1000]
    )


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


def _parse_profiles(text: str) -> list[Profile]:
    if _looks_like_html(text):
        raise ParseError("subscription response looks like HTML, not a VPN subscription")
    if _looks_like_json(text):
        return parse_singbox_json(text)
    if _looks_like_yaml(text):
        return parse_clash_yaml(text)

    try:
        decoded_lines = _decode_base64_lines(text)
    except ParseError:
        decoded_lines = []
    if decoded_lines:
        profiles: list[Profile] = []
        parse_errors: list[str] = []
        for line in decoded_lines:
            try:
                profiles.append(parse_uri(line))
            except ParseError as exc:
                parse_errors.append(str(exc))
        if not profiles:
            detail = f" ({'; '.join(parse_errors[:3])})" if parse_errors else ""
            raise ParseError(f"subscription contains no supported profiles{detail}")
        return profiles

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


def fetch_and_parse(url: str) -> list[Profile]:
    text = _fetch_text(url)
    return _parse_profiles(text)


def fetch_subscription(url: str) -> SubscriptionFetchResult:
    text, headers = _fetch(url)
    profiles = _parse_profiles(text)
    metadata = _parse_subscription_userinfo(headers.get(SUBSCRIPTION_USERINFO_HEADER))
    return SubscriptionFetchResult(profiles=profiles, metadata=metadata)


def _format_bytes(count: float) -> str:
    value = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"  # pragma: no cover - unreachable, loop always returns


def _parse_subscription_userinfo(header_value: str | None) -> dict[str, Any]:
    """Parse the de-facto `subscription-userinfo` response header
    (`upload=N; download=N; total=N; expire=unix_ts`, used by most VPN
    subscription panels: sing-box, Clash, mihomo, v2rayN) into the
    metadata keys cli/main.py's _traffic_label()/_provider_summary()
    already expect. Missing or unparseable input honestly yields {} -
    Traffic/Expires render as "-" rather than fabricating data."""
    if not header_value:
        return {}
    fields: dict[str, int] = {}
    for part in header_value.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, raw_value = part.partition("=")
        key = key.strip().lower()
        if key not in {"upload", "download", "total", "expire"}:
            continue
        try:
            fields[key] = int(raw_value.strip())
        except ValueError:
            continue
    if not fields:
        return {}
    metadata: dict[str, Any] = {}
    if "upload" in fields or "download" in fields:
        used = fields.get("upload", 0) + fields.get("download", 0)
        metadata["traffic_used"] = _format_bytes(used)
    if "total" in fields:
        metadata["traffic_limit"] = _format_bytes(fields["total"])
    if "expire" in fields:
        try:
            metadata["expires_at"] = (
                datetime.fromtimestamp(fields["expire"], tz=timezone.utc).date().isoformat()
            )
        except (OverflowError, OSError, ValueError):
            pass
    return metadata
