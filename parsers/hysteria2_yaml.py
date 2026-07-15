from __future__ import annotations

import re
import textwrap
from typing import Any

from models.profile import Profile, ProfileSource, ProtocolType
from parsers.uri import ParseError
from parsers.endpoint_policy import EndpointPolicyError, validate_profile_endpoint
from parsers.profile_schema import ProfileSemanticValidationError, validate_profile_semantics


_KEYVAL_RE = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z0-9_-]+)\s*:\s*(?P<value>.*?)\s*$")


def _coerce_scalar(value: str) -> Any:
    stripped = value.strip().strip("'\"")
    lowered = stripped.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if stripped.isdigit():
        return int(stripped)
    return stripped


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    current_parent: str | None = None
    current_child: str | None = None
    for raw_line in textwrap.dedent(text or "").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        match = _KEYVAL_RE.match(line)
        if not match:
            continue
        indent = len(match.group("indent"))
        key = match.group("key").strip()
        value = match.group("value").strip()
        if indent == 0:
            current_parent = key
            current_child = None
            if value:
                root[key] = _coerce_scalar(value)
            else:
                root.setdefault(key, {})
            continue
        if current_parent is None:
            continue
        parent = root.setdefault(current_parent, {})
        if not isinstance(parent, dict):
            continue
        if indent <= 2:
            current_child = key
            if value:
                parent[key] = _coerce_scalar(value)
            else:
                parent.setdefault(key, {})
            continue
        if current_child is None:
            continue
        child = parent.setdefault(current_child, {})
        if isinstance(child, dict):
            child[key] = _coerce_scalar(value)
    return root


def _split_server(value: Any) -> tuple[str, int | None]:
    server = str(value or "").strip()
    if not server:
        raise ParseError("Hysteria2 YAML requires server")
    if server.startswith("[") and "]:" in server:
        host, port = server[1:].split("]:", 1)
        return host, int(port) if port.isdigit() else None
    if ":" not in server:
        return server, None
    host, port = server.rsplit(":", 1)
    return host, int(port) if port.isdigit() else None


def _bandwidth_mbps(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    match = re.search(r"\d+", text)
    if not match:
        return None
    return int(match.group(0))


def _validated_profile(profile: Profile) -> Profile:
    try:
        validate_profile_endpoint(profile)
        validate_profile_semantics(profile)
    except (EndpointPolicyError, ProfileSemanticValidationError) as exc:
        raise ParseError(str(exc)) from exc
    return profile


def parse_hysteria2_yaml(text: str) -> Profile:
    data = _parse_simple_yaml(text)
    if "server" not in data or "auth" not in data:
        raise ParseError("Hysteria2 YAML requires server and auth")
    host, port = _split_server(data.get("server"))
    tls = data.get("tls") if isinstance(data.get("tls"), dict) else {}
    obfs = data.get("obfs") if isinstance(data.get("obfs"), dict) else {}
    salamander = obfs.get("salamander") if isinstance(obfs.get("salamander"), dict) else {}
    bandwidth = data.get("bandwidth") if isinstance(data.get("bandwidth"), dict) else {}

    config: dict[str, Any] = {
        "host": host,
        "server": host,
        "password": data["auth"],
        "raw": (text or "").strip(),
    }
    if port is not None:
        config["port"] = port
        config["server_port"] = port
    if tls.get("sni"):
        config["sni"] = tls["sni"]
        config["server_name"] = tls["sni"]
    if tls.get("insecure") is not None:
        config["insecure"] = tls["insecure"]
    if salamander.get("password"):
        config["obfs_password"] = salamander["password"]
    up_mbps = _bandwidth_mbps(bandwidth.get("up"))
    down_mbps = _bandwidth_mbps(bandwidth.get("down"))
    if up_mbps is not None:
        config["up_mbps"] = up_mbps
    if down_mbps is not None:
        config["down_mbps"] = down_mbps

    name = str(data.get("name") or host or "hysteria2")
    return _validated_profile(Profile(
        id=name,
        name=name,
        protocol=ProtocolType.HYSTERIA2,
        config=config,
        source=ProfileSource.MANUAL,
    ))
