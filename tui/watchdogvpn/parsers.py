"""Pure parsers for traceable WatchdogVPN logs and events."""

import re


def parse_event_detail(detail: str) -> dict:
    values = {}
    for key in ("title", "urgency", "body"):
        match = re.search(rf"{key}='((?:\\'|[^'])*)'", detail or "")
        if match:
            values[key] = match.group(1).replace("\\'", "'").replace("\\\\", "\\")
    return values


def parse_event_line(line: str):
    line = (line or "").strip()
    if not line:
        return None

    parts = [p.strip() for p in line.split("|")]

    if len(parts) >= 5 and parts[1] == "notify":
        detail = parse_event_detail("|".join(parts[4:]).strip())
        title = detail.get("title") or parts[3] or "VPN"
        urgency = detail.get("urgency") or ("critical" if parts[2].upper() == "ERROR" else "normal")
        body = detail.get("body") or "sin detalle"
        return {
            "title": title,
            "urgency": urgency.lower(),
            "body": body,
            "raw": line,
            "format": "trace",
        }

    if len(parts) >= 3:
        title = re.sub(r"^\[[^]]+\]\s*", "", parts[0]).strip() or "VPN"
        return {
            "title": title,
            "urgency": (parts[1] or "low").lower(),
            "body": parts[2] or "sin detalle",
            "raw": line,
            "format": "legacy",
        }

    return {
        "title": "VPN",
        "urgency": "low",
        "body": line[:80],
        "raw": line,
        "format": "raw",
    }


def parse_trace_line(line: str):
    parts = [part.strip() for part in (line or "").split("|", 4)]
    if len(parts) != 5:
        return None
    timestamp, component, level, event, detail = parts
    level = level.upper()
    if level not in ("INFO", "WARN", "ERROR"):
        return None
    if not component or not event:
        return None
    return {
        "timestamp": timestamp,
        "component": component,
        "level": level,
        "event": event,
        "detail": detail,
    }
