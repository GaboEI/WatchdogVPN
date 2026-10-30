from __future__ import annotations

import base64
import json
import os
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from models.profile import Profile
from parsers.clash_yaml import parse_clash_yaml, parse_clash_yaml_detailed
from parsers.singbox_json import parse_singbox_json, parse_singbox_json_detailed
from parsers.uri import SUPPORTED_SCHEMES, ParseError, parse_uri

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
# Exact URI prefixes that positively identify a plain-text link list. The strict
# contract requires the literal ``scheme://`` prefix (not a parsed scheme), so
# these are intentionally explicit rather than derived from SUPPORTED_SCHEMES.
PLAINTEXT_URI_PREFIXES = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "wg://",
)


@dataclass(frozen=True, slots=True)
class SubscriptionFetchResult:
    profiles: list[Profile]
    metadata: dict[str, Any] = field(default_factory=dict)
    rejected_profiles: int = 0
    user_agent: str = ""


class SubscriptionFormat(str, Enum):
    """Subscription formats this build can positively identify and extract."""

    PLAINTEXT_LINK_LIST = "plaintext_link_list"
    BASE64_LINK_LIST = "base64_link_list"
    CLASH_YAML = "clash_yaml"
    SINGBOX_JSON = "singbox_json"
    XRAY_JSON = "xray_json"


@dataclass(frozen=True, slots=True)
class FormatMatch:
    """A format positively identified by its own structural signature."""

    format: SubscriptionFormat
    signature: str
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class FormatCheck:
    """A format that was examined and did not match its signature."""

    format: SubscriptionFormat
    reason: str


@dataclass(frozen=True, slots=True)
class IdentifiedFormat:
    """Exactly one format matched; extraction may run for it."""

    match: FormatMatch


@dataclass(frozen=True, slots=True)
class AmbiguousFormat:
    """More than one positive signature matched; nothing is extracted."""

    matches: tuple[FormatMatch, ...]
    checked: tuple[FormatCheck, ...] = ()


@dataclass(frozen=True, slots=True)
class UnrecognizedFormat:
    """No positive signature matched; every checked format is reported."""

    checked: tuple[FormatCheck, ...]
    html_response: bool = False


SubscriptionClassification = IdentifiedFormat | AmbiguousFormat | UnrecognizedFormat


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


def _looks_like_html(text: str) -> bool:
    stripped = text.lstrip().lower()
    return (
        stripped.startswith("<!doctype html")
        or stripped.startswith("<html")
        or "<body" in stripped[:500]
        or "</html>" in stripped[:1000]
    )


def _probe_json(text: str) -> tuple[Any | None, str | None]:
    """Parse candidate JSON for signature checking without raising.

    Returns the decoded payload and ``None``, or ``None`` and the reason the
    body is not usable JSON. Classification must report that reason instead of
    turning it into an extractor failure for a format never actually matched.
    """
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return None, "payload is not a JSON object or array"
    try:
        return json.loads(text), None
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON ({exc.msg} at line {exc.lineno} column {exc.colno})"


def _decode_base64_text(text: str) -> str | None:
    """Decode a base64 body to text, or return ``None`` when it is not base64."""
    payload = text.replace("\n", "").replace("\r", "").strip()
    if not payload:
        return None
    padding = "=" * (-len(payload) % 4)
    for candidate in (payload, payload + padding):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                if decoder is base64.b64decode:
                    decoded = decoder(candidate.encode("utf-8"), validate=True).decode("utf-8")
                else:
                    decoded = decoder(candidate.encode("utf-8")).decode("utf-8")
            except ValueError:
                continue
            if decoded.strip():
                return decoded
    return None


def _decode_base64_lines(text: str) -> list[str]:
    decoded = _decode_base64_text(text)
    if decoded is None:
        raise ParseError("invalid base64 subscription response")
    return [line.strip() for line in decoded.splitlines() if line.strip()]


def _match_plaintext_link_list(text: str) -> FormatMatch | FormatCheck:
    """Positive signature for a plain-text URI list.

    Strict by contract: every non-empty line must start with an exact supported
    URI prefix. A single offending line rejects the whole body as plain text,
    and the reason names only its line number so provider credentials carried by
    the line never reach an error message.
    """
    line_count = 0
    schemes: set[str] = set()
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not line.strip():
            continue
        prefix = next(
            (item for item in PLAINTEXT_URI_PREFIXES if line.startswith(item)),
            None,
        )
        if prefix is None:
            return FormatCheck(
                SubscriptionFormat.PLAINTEXT_LINK_LIST,
                f"line {index} does not start with a supported URI scheme",
            )
        schemes.add(prefix[: -len("://")])
        line_count += 1
    if line_count == 0:
        return FormatCheck(
            SubscriptionFormat.PLAINTEXT_LINK_LIST,
            "payload contains no non-empty lines",
        )
    return FormatMatch(
        SubscriptionFormat.PLAINTEXT_LINK_LIST,
        "every non-empty line starts with a supported URI scheme",
        {
            "lines": line_count,
            "schemes": sorted(schemes),
        },
    )


def _match_base64_link_list(text: str) -> FormatMatch | FormatCheck:
    decoded = _decode_base64_text(text)
    if decoded is None:
        return FormatCheck(
            SubscriptionFormat.BASE64_LINK_LIST,
            "body does not decode as base64 text",
        )
    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    if not lines:
        return FormatCheck(
            SubscriptionFormat.BASE64_LINK_LIST,
            "decoded payload contains no supported profiles",
        )
    schemes = sorted(
        {(urlparse(line).scheme or "").lower() for line in lines} & set(SUPPORTED_SCHEMES)
    )
    if not schemes:
        return FormatCheck(
            SubscriptionFormat.BASE64_LINK_LIST,
            "decoded payload contains no supported profiles",
        )
    return FormatMatch(
        SubscriptionFormat.BASE64_LINK_LIST,
        "base64 body decoding to at least one supported URI line",
        {
            "encoding": "base64",
            "decoded_lines": len(lines),
            "supported_schemes": schemes,
        },
    )


def _match_clash_yaml(text: str) -> FormatMatch | FormatCheck:
    for index, raw in enumerate(text.splitlines()):
        if raw != raw.lstrip():
            # An indented line can never be the document-level proxies section,
            # even when the extractor would tolerate it.
            continue
        if raw.rstrip() != "proxies:":
            # Reject look-alike keys (proxies:evil) and any inline value or
            # comment (proxies: [], proxies: # nodes): only the bare section
            # key is the positive Clash signature.
            continue
        return FormatMatch(
            SubscriptionFormat.CLASH_YAML,
            "root-level proxies: section key",
            {"key": "proxies", "line": index, "indent": 0},
        )
    return FormatCheck(
        SubscriptionFormat.CLASH_YAML,
        "no root-level proxies: section key",
    )


def _match_singbox_json(
    payload: Any | None, json_error: str | None
) -> FormatMatch | FormatCheck:
    if json_error is not None:
        return FormatCheck(SubscriptionFormat.SINGBOX_JSON, json_error)
    if not isinstance(payload, dict):
        return FormatCheck(SubscriptionFormat.SINGBOX_JSON, "root is not a JSON object")
    outbounds = payload.get("outbounds")
    if not isinstance(outbounds, list):
        return FormatCheck(
            SubscriptionFormat.SINGBOX_JSON,
            "no outbounds array at the document root",
        )
    typed_entries = [
        entry for entry in outbounds if isinstance(entry, dict) and "type" in entry
    ]
    if not typed_entries:
        return FormatCheck(
            SubscriptionFormat.SINGBOX_JSON,
            "outbounds entries do not carry a type key",
        )
    return FormatMatch(
        SubscriptionFormat.SINGBOX_JSON,
        "outbounds array whose entries carry a type key",
        {
            "root": "object",
            "array": "outbounds",
            "entry_key": "type",
            "matching_entries": len(typed_entries),
            "total_entries": len(outbounds),
        },
    )


def _match_xray_json(
    payload: Any | None, json_error: str | None
) -> FormatMatch | FormatCheck:
    if json_error is not None:
        return FormatCheck(SubscriptionFormat.XRAY_JSON, json_error)
    if not isinstance(payload, dict):
        return FormatCheck(SubscriptionFormat.XRAY_JSON, "root is not a JSON object")
    if "protocol" in payload:
        return FormatMatch(
            SubscriptionFormat.XRAY_JSON,
            "root object carrying a protocol key",
            {"form": "root_outbound", "key": "protocol"},
        )
    outbounds = payload.get("outbounds")
    if not isinstance(outbounds, list):
        return FormatCheck(
            SubscriptionFormat.XRAY_JSON,
            "no protocol key at the document root and no outbounds array",
        )
    protocol_entries = [
        entry for entry in outbounds if isinstance(entry, dict) and "protocol" in entry
    ]
    if not protocol_entries:
        return FormatCheck(
            SubscriptionFormat.XRAY_JSON,
            "outbounds entries do not carry a protocol key",
        )
    return FormatMatch(
        SubscriptionFormat.XRAY_JSON,
        "outbounds array whose entries carry a protocol key",
        {
            "form": "outbounds_object",
            "entry_key": "protocol",
            "matching_entries": len(protocol_entries),
            "total_entries": len(outbounds),
        },
    )


_HTML_REJECTION_REASON = "not evaluated: the payload is an HTML document"


def classify_subscription_text(text: str) -> SubscriptionClassification:
    """Positively classify a subscription payload without extracting profiles.

    Pure by contract: no network access, no state, and never a ``Profile``.
    A format is identified only by its own structural signature; it is never
    selected merely because every other format failed.
    """
    if _looks_like_html(text):
        return UnrecognizedFormat(
            checked=tuple(
                FormatCheck(fmt, _HTML_REJECTION_REASON) for fmt in SubscriptionFormat
            ),
            html_response=True,
        )
    payload, json_error = _probe_json(text)
    results: list[FormatMatch | FormatCheck] = [
        _match_plaintext_link_list(text),
        _match_base64_link_list(text),
        _match_clash_yaml(text),
        _match_singbox_json(payload, json_error),
        _match_xray_json(payload, json_error),
    ]
    matches = tuple(result for result in results if isinstance(result, FormatMatch))
    if len(matches) == 1:
        return IdentifiedFormat(matches[0])
    if matches:
        checked = tuple(result for result in results if isinstance(result, FormatCheck))
        return AmbiguousFormat(matches, checked)
    return UnrecognizedFormat(
        tuple(result for result in results if isinstance(result, FormatCheck))
    )


def _unrecognized_message(result: UnrecognizedFormat) -> str:
    if result.html_response:
        return "subscription response looks like HTML, not a VPN subscription"
    reasons = "; ".join(
        f"{check.format.value}: {check.reason}" for check in result.checked
    )
    return f"unrecognized subscription format ({reasons})"


def _extract_plaintext_link_list(text: str) -> tuple[list[Profile], int]:
    """Extract a strictly validated plain-text link list.

    Each non-empty line is parsed by the shared ``parse_uri``. A line whose
    prefix matched the signature but whose URI fails semantic or endpoint
    validation rejects the whole response, so no partial profile set is ever
    returned to the caller.
    """
    profiles: list[Profile] = []
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not line.strip():
            continue
        try:
            profiles.append(parse_uri(line))
        except ParseError as exc:
            raise ParseError(
                f"invalid plain-text subscription URI on line {index}"
            ) from exc
    if not profiles:
        raise ParseError("plain-text subscription contains no supported profiles")
    return profiles, 0


def _extract_base64_link_list(text: str) -> tuple[list[Profile], int]:
    decoded_lines = _decode_base64_lines(text)
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


def _extract_profiles(
    format: SubscriptionFormat, text: str
) -> tuple[list[Profile], int]:
    """Run the extractor for an already positively identified format."""
    if format is SubscriptionFormat.PLAINTEXT_LINK_LIST:
        return _extract_plaintext_link_list(text)
    if format is SubscriptionFormat.BASE64_LINK_LIST:
        return _extract_base64_link_list(text)
    if format is SubscriptionFormat.CLASH_YAML:
        return parse_clash_yaml_detailed(text)
    if format in {SubscriptionFormat.SINGBOX_JSON, SubscriptionFormat.XRAY_JSON}:
        # Both structured dialects are converted by the existing sing-box/Xray
        # converter; this task does not change its behavior.
        return parse_singbox_json_detailed(text)
    raise ParseError(f"no extractor for subscription format: {format.value}")


def _parse_profiles_detailed(text: str) -> tuple[list[Profile], int]:
    classification = classify_subscription_text(text)
    if isinstance(classification, IdentifiedFormat):
        return _extract_profiles(classification.match.format, text)
    if isinstance(classification, AmbiguousFormat):
        formats = ", ".join(match.format.value for match in classification.matches)
        raise ParseError(
            f"ambiguous subscription format: positive signatures for {formats}"
        )
    raise ParseError(_unrecognized_message(classification))


def _parse_profiles(text: str) -> list[Profile]:
    profiles, _rejected_profiles = _parse_profiles_detailed(text)
    return profiles


def fetch_and_parse(url: str) -> list[Profile]:
    return fetch_subscription(url).profiles


_SUBSCRIPTION_URL_TOKEN_RE = re.compile(r"(?:https?|ftp|file)://\S+")


def _redact_subscription_error(message: str, url: str) -> str:
    """Strip the subscription URL/token from a negotiation error message.

    Negotiation failures are surfaced to the user and may be logged. They must
    stay useful without echoing the subscription URL, whose path is often a
    bearer token. Both the exact input URL and any recognizable URL scheme are
    replaced (T-PR23-01)."""
    redacted = message
    for secret in {url, url.strip()}:
        if secret:
            redacted = redacted.replace(secret, "<redacted>")
    return _SUBSCRIPTION_URL_TOKEN_RE.sub("<redacted>", redacted)


def _candidate_rank(candidate: SubscriptionFetchResult) -> tuple[int, int]:
    """Rank a retrieved candidate for selection.

    More accepted profiles always wins. When accepted counts tie, fewer
    rejected profiles wins, because a cleaner complete candidate is the one
    that can safely replace the provider's last known-good state (T-PR23-04).
    The caller only replaces the current best on a strictly greater rank, so an
    exact tie preserves the established first-seen candidate order.
    """
    return (len(candidate.profiles), -candidate.rejected_profiles)


def fetch_subscription(url: str) -> SubscriptionFetchResult:
    errors: list[str] = []
    candidates: list[SubscriptionFetchResult] = []
    for user_agent in _subscription_user_agents():
        try:
            text, headers = _fetch(url, user_agent=user_agent)
        except ParseError as exc:
            # One User-Agent attempt must not discard a candidate another
            # User-Agent already produced (T-PR23-01). Every fetch failure -
            # HTTP rejection, timeout, URL error or any other ParseError - is
            # recorded and negotiation continues; a valid candidate wins.
            errors.append(_redact_subscription_error(str(exc), url))
            continue
        try:
            profiles, rejected_profiles = _parse_profiles_detailed(text)
        except ParseError as exc:
            # Providers can return different formats per User-Agent. A bad
            # format must not discard a valid candidate from another UA.
            errors.append(_redact_subscription_error(str(exc), url))
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
            if _candidate_rank(candidate) > _candidate_rank(best):
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
