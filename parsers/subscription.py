from __future__ import annotations

import base64
import json
import os
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
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
SUBSCRIPTION_COMPATIBILITY_USER_AGENTS = (
    DEFAULT_SUBSCRIPTION_USER_AGENT,
    "Karing",
    "clash.meta",
    "mihomo",
    "ClashMeta",
)
SUBSCRIPTION_USERINFO_HEADER = "subscription-userinfo"
DEFAULT_SUBSCRIPTION_CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_SUBSCRIPTION_READ_TIMEOUT_SECONDS = 10.0
DEFAULT_SUBSCRIPTION_TOTAL_TIMEOUT_SECONDS = 20.0
DEFAULT_SUBSCRIPTION_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
SUBSCRIPTION_READ_CHUNK_BYTES = 64 * 1024
SUBSCRIPTION_RETRYABLE_HTTP_STATUSES = frozenset({403, 406, 415})


@dataclass(frozen=True, slots=True)
class SubscriptionFetchResult:
    profiles: list[Profile]
    metadata: dict[str, Any] = field(default_factory=dict)
    rejected_profiles: int = 0
    user_agent: str = ""


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if value <= 0:
        return default
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value <= 0:
        return default
    return value


def _subscription_fetch_limits() -> tuple[float, float, float, int]:
    connect_timeout = _env_float(
        "WATCHDOGVPN_SUBSCRIPTION_CONNECT_TIMEOUT_SECONDS",
        DEFAULT_SUBSCRIPTION_CONNECT_TIMEOUT_SECONDS,
    )
    read_timeout = _env_float(
        "WATCHDOGVPN_SUBSCRIPTION_READ_TIMEOUT_SECONDS",
        DEFAULT_SUBSCRIPTION_READ_TIMEOUT_SECONDS,
    )
    total_timeout = _env_float(
        "WATCHDOGVPN_SUBSCRIPTION_TOTAL_TIMEOUT_SECONDS",
        DEFAULT_SUBSCRIPTION_TOTAL_TIMEOUT_SECONDS,
    )
    max_response_bytes = _env_int(
        "WATCHDOGVPN_SUBSCRIPTION_MAX_RESPONSE_BYTES",
        DEFAULT_SUBSCRIPTION_MAX_RESPONSE_BYTES,
    )
    return connect_timeout, read_timeout, total_timeout, max_response_bytes


def _set_response_read_timeout(response: Any, timeout: float) -> None:
    sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    if sock is None:
        return
    settimeout = getattr(sock, "settimeout", None)
    if settimeout is None:
        return
    try:
        settimeout(timeout)
    except OSError:
        return


def _read_bounded_response(
    response: Any,
    *,
    started: float,
    total_timeout: float,
    max_bytes: int,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        if time.monotonic() - started > total_timeout:
            raise ParseError(f"subscription fetch timed out after {total_timeout:g} seconds")
        remaining = max_bytes - total
        try:
            chunk = response.read(min(SUBSCRIPTION_READ_CHUNK_BYTES, remaining + 1))
        except (socket.timeout, TimeoutError) as exc:
            raise ParseError("subscription fetch timed out while reading response") from exc
        if time.monotonic() - started > total_timeout:
            raise ParseError(f"subscription fetch timed out after {total_timeout:g} seconds")
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ParseError(
                f"subscription response exceeds maximum size ({max_bytes} bytes)"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _url_error_is_timeout(exc: URLError) -> bool:
    reason = getattr(exc, "reason", None)
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return True
    return "timed out" in str(exc).lower()


def validate_subscription_url(url: str) -> str:
    normalized = str(url or "").strip()
    if urlparse(normalized).scheme != "https":
        raise ParseError(f"invalid subscription URL scheme (https required): {normalized}")
    return normalized


def _subscription_user_agents() -> tuple[str, ...]:
    configured = os.environ.get("WATCHDOGVPN_SUBSCRIPTION_USER_AGENT", "").strip()
    if not configured:
        return SUBSCRIPTION_COMPATIBILITY_USER_AGENTS
    return (configured, *(item for item in SUBSCRIPTION_COMPATIBILITY_USER_AGENTS if item != configured))


def _fetch(url: str, *, user_agent: str) -> tuple[str, dict[str, str]]:
    # Only https is accepted: plain http leaks the subscription token (often
    # embedded in the URL path) in cleartext, and urlopen would otherwise
    # also happily honor file://, ftp:// and other local/non-network
    # schemes - "add a provider" must never become "read an arbitrary local
    # file" or "fetch an internal-network URL an operator didn't intend".
    url = validate_subscription_url(url)
    connect_timeout, read_timeout, total_timeout, max_response_bytes = _subscription_fetch_limits()
    started = time.monotonic()
    try:
        request = Request(
            url,
            headers={
                "User-Agent": user_agent,
                "Accept": "text/plain, application/json, application/yaml, text/yaml, */*",
            },
        )
        with urlopen(request, timeout=connect_timeout) as response:  # nosec - subscription URLs are user-provided inputs
            if time.monotonic() - started > total_timeout:
                raise ParseError(f"subscription fetch timed out after {total_timeout:g} seconds")
            _set_response_read_timeout(response, read_timeout)
            raw = _read_bounded_response(
                response,
                started=started,
                total_timeout=total_timeout,
                max_bytes=max_response_bytes,
            )
            headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
    except ParseError:
        raise
    except ValueError as exc:
        raise ParseError(f"invalid subscription URL: {url}") from exc
    except HTTPError as exc:
        if exc.code in SUBSCRIPTION_RETRYABLE_HTTP_STATUSES:
            raise ParseError(
                f"subscription request rejected with HTTP status {exc.code}"
            ) from exc
        raise ParseError(f"failed to fetch subscription: {exc}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise ParseError("subscription fetch timed out") from exc
    except URLError as exc:
        if _url_error_is_timeout(exc):
            raise ParseError("subscription fetch timed out") from exc
        raise ParseError(f"failed to fetch subscription: {exc}") from exc
    if not raw:
        raise ParseError("empty subscription response")
    return raw.decode("utf-8", errors="replace").strip(), headers


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


def _parse_profiles_detailed(text: str) -> tuple[list[Profile], int]:
    if _looks_like_html(text):
        raise ParseError("subscription response looks like HTML, not a VPN subscription")
    if _looks_like_json(text):
        return parse_singbox_json(text), 0
    if _looks_like_yaml(text):
        return parse_clash_yaml(text), 0

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
        return profiles, len(parse_errors)

    if "outbounds" in text:
        try:
            return parse_singbox_json(text), 0
        except ParseError:
            pass
    if "proxies" in text:
        try:
            return parse_clash_yaml(text), 0
        except ParseError:
            pass
    raise ParseError("unsupported subscription format")


def _parse_profiles(text: str) -> list[Profile]:
    profiles, _rejected_profiles = _parse_profiles_detailed(text)
    return profiles


def fetch_and_parse(url: str) -> list[Profile]:
    return fetch_subscription(url).profiles


def fetch_subscription(url: str) -> SubscriptionFetchResult:
    errors: list[str] = []
    candidates: list[SubscriptionFetchResult] = []
    for user_agent in _subscription_user_agents():
        try:
            text, headers = _fetch(url, user_agent=user_agent)
            profiles, rejected_profiles = _parse_profiles_detailed(text)
        except ParseError as exc:
            errors.append(str(exc))
            if not any(
                marker in str(exc)
                for marker in (
                    "no supported profiles",
                    "not a VPN subscription",
                    "unsupported subscription format",
                    "subscription request rejected with HTTP status",
                )
            ):
                raise
            continue
        metadata = _parse_subscription_userinfo(headers.get(SUBSCRIPTION_USERINFO_HEADER))
        candidates.append(
            SubscriptionFetchResult(
                profiles=profiles,
                metadata=metadata,
                rejected_profiles=rejected_profiles,
                user_agent=user_agent,
            )
        )
    if candidates:
        best = candidates[0]
        for candidate in candidates[1:]:
            if len(candidate.profiles) > len(best.profiles):
                best = candidate
        return best
    detail = f": {errors[-1]}" if errors else ""
    raise ParseError(f"subscription negotiation failed{detail}")


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
