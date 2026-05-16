"""State collection for the WatchdogVPN TUI."""

import os
import re
import shlex

from watchdogvpn.commands import (
    run,
    service_age,
    service_state,
    timer_countdown,
    timer_enabled,
    timer_interval,
    timer_trigger,
)
from watchdogvpn.constants import (
    AG,
    AUTH_BIN,
    DNSCTL,
    LOGROTATE_CONF,
    LOGROTATE_TIMER,
    ROTATE_TIMER,
    TRACE_LOG_PATHS,
    TRUTH_BIN,
    VPN_LOG_PATHS,
    WATCHDOGVPN_CONFIG,
    WATCHDOG_TIMER,
)
from watchdogvpn.formatting import display_auth_status, display_vpn_status
from watchdogvpn.parsers import parse_event_line, parse_trace_line

COUNTRY_CACHE = {}


def config_path() -> str:
    return os.environ.get("WATCHDOGVPN_CONFIG_FILE", WATCHDOGVPN_CONFIG)


def parse_simple_toml(path: str) -> dict:
    values = {}
    section = ""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].strip()
                    continue
                if "=" not in line or not section:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"')
                if key:
                    values[f"{section}.{key}"] = value
    except FileNotFoundError:
        values["_status"] = "missing"
    except PermissionError:
        values["_status"] = "locked"
    except OSError:
        values["_status"] = "unavailable"
    else:
        values["_status"] = "readable"
    return values


def settings_snapshot():
    path = config_path()
    values = parse_simple_toml(path)
    status = values.get("_status", "unavailable")
    return [
        ("Archivo", path),
        ("Estado", status),
        ("Idioma", values.get("language.current", "unknown")),
        ("Auto idioma", values.get("language.auto_detect", "unknown")),
        ("Tema", values.get("tui.theme", "unknown")),
        ("Color", values.get("tui.color", "unknown")),
        ("Unicode", values.get("tui.unicode", "unknown")),
        ("Sanitize IPv4", values.get("reporting.sanitize_ipv4", "unknown")),
        ("Sanitize IPv6", values.get("reporting.sanitize_ipv6", "unknown")),
        ("Sanitize email", values.get("reporting.sanitize_email", "unknown")),
        ("Sanitize home", values.get("reporting.sanitize_home", "unknown")),
    ]


def truth_data():
    raw = run(f"{shlex.quote(TRUTH_BIN)} 2>/dev/null || true", 6)
    data = {
        "STATUS": "DOWN",
        "TUN": "DOWN",
        "ROUTE": "UNKNOWN",
        "IP": "FAIL",
        "IP_ADDR": "none",
    }
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().upper()
        if key in data:
            data[key] = value.strip()
    return data


def auth_data():
    raw = run(f"{shlex.quote(AUTH_BIN)} 2>/dev/null || true", 2)
    data = {
        "AUTH": "UNKNOWN",
        "REASON": "helper_unavailable",
        "CLI_RC": "",
        "DETAIL": "",
    }
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().upper()
        if key in data:
            data[key] = value.strip()
    return data


def country_code(ip: str) -> str:
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return "UNK"
    if ip in COUNTRY_CACHE:
        return COUNTRY_CACHE[ip]
    cmd = (
        f"curl -4 -s --max-time 4 https://ipwho.is/{shlex.quote(ip)} 2>/dev/null "
        r"""| sed -n 's/.*"country_code":"\([A-Za-z][A-Za-z]\)".*/\1/p' | head -n1 | tr '[:lower:]' '[:upper:]'"""
    )
    out = run(cmd, 8)
    code = out if re.match(r"^[A-Z]{2}$", out) else "UNK"
    COUNTRY_CACHE[ip] = code
    return code


def current_location(fallback_country: str = "") -> str:
    env_loc = run(r"""sudo -n sed -n 's/^LOCATION="\?\([^"]*\)"\?/\1/p' /etc/adguardvpn.env 2>/dev/null | head -n1 || true""", 4).strip()
    if env_loc:
        return env_loc
    rotate_loc = run(r"""sudo -n awk -F'|' 'NF>=2 {print $2; exit}' /var/lib/vpn-rotate/state.txt 2>/dev/null || true""", 4).strip()
    if rotate_loc:
        return rotate_loc.upper()
    if re.match(r"^[A-Z]{2}$", (fallback_country or "").strip().upper()):
        return fallback_country.strip().upper()
    return "sin valor"


def cli_status() -> str:
    return run(f"sudo -n -u adgvpn -H {shlex.quote(AG)} status 2>/dev/null | sed -n '1p' || true", 6) or "sin respuesta"


def bypass_count() -> str:
    return run(r"""awk '!/^[[:space:]]*(#|$)/ {n++} END{print n+0}' /etc/vpn-domain-bypass.conf 2>/dev/null || true""", 4) or "0"


def bypass_domains():
    raw = run(
        r"""awk '!/^[[:space:]]*(#|$)/ {d=tolower($1); if (d ~ /^\*\./) d=substr(d,3); print d}' /etc/vpn-domain-bypass.conf 2>/dev/null | sort -u""",
        5,
    )
    domains = []
    for line in raw.splitlines():
        domain = line.strip().lower()
        if domain and re.match(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", domain):
            domains.append(domain)
    return domains


def last_event():
    raw = run(r"""sudo -n tail -n 1 /var/log/myvpn/vpn-events.log 2>/dev/null || true""", 4)
    if not raw or raw.startswith("ERROR"):
        return ("VPN", "low", "sin eventos")
    event = parse_event_line(raw)
    if event:
        return (event["title"], event["urgency"], event["body"])
    return ("VPN", "low", raw[:60])


def rotate_setting(name: str) -> str:
    cmd = (
        "sudo -n awk -F= "
        + shlex.quote(f'/^[[:space:]]*{name}=/' + r'{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}')
        + " /usr/local/sbin/vpn_rotate.sh 2>/dev/null || true"
    )
    value = run(cmd, 4).strip()
    if value:
        return value
    defaults = {
        "RECENT_KEEP": "5",
    }
    return defaults.get(name, "?")


def dns_profile() -> str:
    raw = run(f"sudo -n {shlex.quote(DNSCTL)} current 2>/dev/null | awk -F= '/^profile_guess=/{{print $2; exit}}'", 4).strip()
    return raw or "locked"


def dashboard_data():
    truth = truth_data()
    auth = auth_data()
    ip = truth.get("IP_ADDR", "none")
    status = truth.get("STATUS", "DOWN")
    tun = truth.get("TUN", "DOWN")
    route = truth.get("ROUTE", "UNKNOWN")
    event_title, event_urgency, event_body = last_event()
    country = country_code(ip)
    vpn_age = service_age("adguardvpn.service")
    rotate_state = service_state(ROTATE_TIMER)
    rotate_interval = timer_interval(ROTATE_TIMER)
    rotate_eta = timer_countdown(ROTATE_TIMER)
    watchdog_state = service_state(WATCHDOG_TIMER)
    watchdog_interval = timer_interval(WATCHDOG_TIMER)
    watchdog_eta = timer_countdown(WATCHDOG_TIMER)
    route_label = {
        "TUN": "tun0",
        "DEFAULT": "default",
        "UNKNOWN": "unknown",
    }.get(route, route)
    return [
        ("VPN", f"{display_vpn_status(status)} · {vpn_age}" if vpn_age and status == "UP" else display_vpn_status(status)),
        ("Auth", display_auth_status(auth.get("AUTH", "UNKNOWN"), auth.get("REASON", ""))),
        ("Tun", tun),
        ("Route", route_label),
        ("IP", ip if ip != "none" else "no disponible"),
        ("Country", country),
        ("Location", current_location(country)),
        ("DNS", dns_profile()),
        ("Rotate", f"{rotate_state} · {rotate_interval}" + (f" · {rotate_eta}" if rotate_eta else "")),
        ("Watchdog", f"{watchdog_state} · {watchdog_interval}" + (f" · {watchdog_eta}" if watchdog_eta else "")),
        ("Event", f"{event_urgency} · {event_title}: {event_body}"),
        ("Bypass", f"{bypass_count()} dominios"),
    ]


def human_size(size: int) -> str:
    units = ["B", "K", "M", "G", "T"]
    value = float(max(0, size))
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)}B"
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{int(size)}B"


def log_size(path: str) -> str:
    try:
        return human_size(os.path.getsize(path))
    except FileNotFoundError:
        return "missing"
    except Exception:
        return "locked"


def rotated_log_count(path: str) -> int:
    directory = os.path.dirname(path) or "."
    base = os.path.basename(path) + "-"
    try:
        return sum(1 for name in os.listdir(directory) if name.startswith(base))
    except Exception:
        return 0


def logrotate_policy() -> dict:
    policy = {
        "interval": "hourly",
        "rotate": "?",
        "minsize": "?",
        "maxsize": "?",
        "compress": "off",
        "delaycompress": "off",
        "config": LOGROTATE_CONF,
    }
    try:
        with open(LOGROTATE_CONF, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                key = parts[0]
                if key in ("hourly", "daily", "weekly", "monthly"):
                    policy["interval"] = key
                elif key in ("rotate", "minsize", "maxsize") and len(parts) >= 2:
                    policy[key] = parts[1]
                elif key in ("compress", "delaycompress"):
                    policy[key] = "on"
    except Exception:
        policy["config"] = f"{LOGROTATE_CONF} no disponible"
    return policy


def housekeeping_snapshot():
    policy = logrotate_policy()
    logs = []
    for path in VPN_LOG_PATHS:
        logs.append(
            {
                "name": os.path.basename(path),
                "path": path,
                "size": log_size(path),
                "rotated": rotated_log_count(path),
            }
        )
    return {
        "timer_state": service_state(LOGROTATE_TIMER),
        "timer_enabled": timer_enabled(LOGROTATE_TIMER),
        "next": timer_trigger(LOGROTATE_TIMER),
        "eta": timer_countdown(LOGROTATE_TIMER),
        "policy": policy,
        "logs": logs,
    }


def tail_plain_lines(path: str, limit: int = 300):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        return lines[-limit:]
    except Exception:
        return []


def trace_snapshot():
    entries = []
    legacy = 0
    for path in TRACE_LOG_PATHS:
        for line in tail_plain_lines(path, 300):
            parsed = parse_trace_line(line)
            if parsed:
                parsed["source"] = os.path.basename(path)
                entries.append(parsed)
            elif line.strip():
                legacy += 1
    entries.sort(key=lambda item: item["timestamp"])
    counts = {"INFO": 0, "WARN": 0, "ERROR": 0}
    by_component = {}
    for item in entries:
        counts[item["level"]] = counts.get(item["level"], 0) + 1
        by_component[item["component"]] = item
    important = [
        item for item in entries
        if item["level"] in ("WARN", "ERROR") or item["event"] not in ("ok", "snapshot", "state", "truth")
    ]
    return {
        "entries": entries,
        "counts": counts,
        "legacy": legacy,
        "by_component": by_component,
        "important": important[-10:],
    }
