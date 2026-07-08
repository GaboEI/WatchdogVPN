from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .unified import UnifiedDiagnostics


SUPPORT_EXPORT_SCHEMA_VERSION = 1
SUPPORT_EXPORT_GENERATOR = "watchdogvpn-redacted-support-export"


class SupportExportReviewRequired(ValueError):
    """Raised when a support export is requested without explicit review."""


@dataclass(frozen=True, slots=True)
class RedactedSupportExport:
    schema_version: int
    generated_by: str
    generated_at: str
    user_reviewed: bool
    redaction_mode: str
    payload: dict[str, Any]
    redaction_guards: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_by": self.generated_by,
            "generated_at": self.generated_at,
            "user_reviewed": self.user_reviewed,
            "redaction_mode": self.redaction_mode,
            "payload": copy.deepcopy(self.payload),
            "redaction_guards": dict(self.redaction_guards),
        }


_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_CANDIDATE_RE = re.compile(r"\b[0-9a-fA-F:]{2,}:[0-9a-fA-F:]{2,}\b")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|apikey|api_key|private_key|credential)"
    r"\s*[:=]\s*[^,\s;]+"
)
_BEARER_SECRET_RE = re.compile(r"(?i)\b(bearer|basic)\s+[a-z0-9._~+/\-=]{8,}")
_HIGH_ENTROPY_RE = re.compile(r"\b[a-zA-Z0-9._~+/\-=]{32,}\b")
_SENSITIVE_WORD_RE = re.compile(
    r"(?i)\b(?!redacted-)[\w.-]*(password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"credential)[\w.-]*\b"
)

_SENSITIVE_EXACT_KEYS = {
    "bssid",
    "bind_address",
    "client_cidr",
    "credential",
    "credentials",
    "gateway_identifier",
    "host",
    "interface_name",
    "password",
    "passwd",
    "private_key",
    "public_ip",
    "public_key",
    "secret",
    "server",
    "ssid",
    "subscription_url",
    "token",
    "tunnel_interface",
    "uri",
    "url",
}
_SENSITIVE_LIST_KEYS = {
    "default_route_interfaces",
    "nameservers",
    "search_domains",
}
_SENSITIVE_KEY_PARTS = {
    "api_key",
    "ip",
    "private_key",
    "public_key",
    "secret",
    "token",
}


def build_redacted_support_export(
    diagnostics: UnifiedDiagnostics,
    *,
    user_reviewed: bool = False,
) -> RedactedSupportExport:
    if not user_reviewed:
        raise SupportExportReviewRequired(
            "support export requires explicit user review before creation"
        )
    payload = redact_support_payload(diagnostics.to_dict())
    payload["support_export_ready"] = True
    return RedactedSupportExport(
        schema_version=SUPPORT_EXPORT_SCHEMA_VERSION,
        generated_by=SUPPORT_EXPORT_GENERATOR,
        generated_at=datetime.now(timezone.utc).isoformat(),
        user_reviewed=True,
        redaction_mode="strict",
        payload=payload,
        redaction_guards={
            "provider_urls_included": False,
            "raw_network_identifiers_included": False,
            "secret_value_scanner": "enabled",
            "user_review_required": True,
        },
    )


def redact_support_payload(value: Any) -> Any:
    return _redact_recursive(copy.deepcopy(value), ())


def _redact_recursive(value: Any, path: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            next_path = (*path, key_text)
            if next_path[-4:] == ("providers", "items", "[]", "name"):
                redacted[key_text] = "<redacted-provider-name>"
                continue
            if next_path[-4:] == ("providers", "items", "[]", "id"):
                redacted[key_text] = "<redacted-provider-id>"
                continue
            if _is_sensitive_key(key_text, item, next_path):
                redacted[key_text] = _marker_for_key(key_text)
                continue
            redacted[key_text] = _redact_recursive(item, next_path)
        return redacted
    if isinstance(value, list):
        return [_redact_recursive(item, (*path, "[]")) for item in value]
    if isinstance(value, tuple):
        return [_redact_recursive(item, (*path, "[]")) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


def _is_sensitive_key(key: str, value: Any, path: tuple[str, ...]) -> bool:
    normalized = key.lower()
    if normalized in {"last_updated", "last_health_check", "last_health_check_status"}:
        return False
    if normalized in _SENSITIVE_EXACT_KEYS or normalized in _SENSITIVE_LIST_KEYS:
        return True
    if normalized.endswith("_url") and not isinstance(value, bool):
        return True
    if normalized.endswith("_interface") and not isinstance(value, bool):
        return True
    if normalized.endswith("_address") and not isinstance(value, bool):
        return True
    return not isinstance(value, bool) and any(
        part in normalized for part in _SENSITIVE_KEY_PARTS
    )


def _marker_for_key(key: str) -> str:
    normalized = key.lower().replace("_", "-")
    if "url" in normalized:
        return "<redacted-url>"
    if "password" in normalized or "credential" in normalized or "auth" in normalized:
        return "<redacted-credential>"
    if "private-key" in normalized:
        return "<redacted-private-key>"
    if "token" in normalized or "secret" in normalized or "key" in normalized:
        return "<redacted-secret>"
    if "ssid" in normalized:
        return f"<redacted-{normalized}>"
    if "interface" in normalized:
        return "<redacted-interface>"
    if "gateway" in normalized:
        return "<redacted-gateway>"
    if "cidr" in normalized:
        return "<redacted-cidr>"
    if "ip" in normalized:
        return "<redacted-ip>"
    if "host" in normalized or "server" in normalized:
        return "<redacted-endpoint>"
    return "<redacted-sensitive-value>"


def _redact_string(value: str) -> str:
    if value.startswith("<redacted-") or value.startswith("<not-observed-"):
        return value
    lowered = value.lower()
    if any(term in lowered for term in ("ssid", "bssid", "gateway fingerprint")):
        return "<redacted-network-context>"
    redacted = _PRIVATE_KEY_RE.sub("<redacted-private-key>", value)
    redacted = _URL_RE.sub("<redacted-url>", redacted)
    redacted = _EMAIL_RE.sub("<redacted-email>", redacted)
    redacted = _CIDR_RE.sub("<redacted-cidr>", redacted)
    redacted = _IPV4_RE.sub("<redacted-ip>", redacted)
    redacted = _redact_ipv6_literals(redacted)
    redacted = _ASSIGNMENT_SECRET_RE.sub(
        lambda match: f"{match.group(1)}=<redacted-secret>",
        redacted,
    )
    redacted = _BEARER_SECRET_RE.sub("<redacted-authorization>", redacted)
    redacted = _HIGH_ENTROPY_RE.sub("<redacted-secret>", redacted)
    redacted = _SENSITIVE_WORD_RE.sub("<redacted-secret>", redacted)
    return redacted


def _redact_ipv6_literals(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if "::" not in candidate and not any(char.isalpha() for char in candidate):
            return candidate
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        if parsed.version != 6:
            return candidate
        return "<redacted-ipv6>"

    return _IPV6_CANDIDATE_RE.sub(replace, value)
