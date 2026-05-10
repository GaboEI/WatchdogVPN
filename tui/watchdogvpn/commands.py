"""Command execution helpers for the WatchdogVPN TUI.

This module centralizes shell execution used by the TUI. Most commands here are
existing shell pipelines around systemd, sudo, awk and sed; keeping them behind
one module makes later hardening measurable without changing the renderer.
"""

import re
import shlex
import subprocess

from watchdogvpn.formatting import format_span


def run(cmd: str, timeout: int = 8) -> str:
    try:
        out = subprocess.run(
            cmd,
            shell=True,
            text=True,
            capture_output=True,
            timeout=timeout,
            executable="/bin/bash",
        )
        text = ((out.stdout or "") + (out.stderr or "")).strip()
        return text
    except Exception as exc:
        return f"ERROR: {exc}"


def run_process(cmd: str, timeout: int = 8):
    try:
        return subprocess.run(
            cmd,
            shell=True,
            text=True,
            capture_output=True,
            timeout=timeout,
            executable="/bin/bash",
        )
    except Exception:
        return None


def run_with_input(cmd: str, data: str, timeout: int = 8):
    try:
        return subprocess.run(
            cmd,
            shell=True,
            text=True,
            input=data,
            capture_output=True,
            timeout=timeout,
            executable="/bin/bash",
        )
    except Exception:
        return None


def run_command(cmd: str, timeout: int = 8):
    del timeout
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            executable="/bin/bash",
        )
        return proc
    except Exception:
        return None


def service_state(unit: str) -> str:
    return run(f"systemctl is-active {shlex.quote(unit)} 2>/dev/null || true", 4) or "unknown"


def timer_enabled(unit: str) -> str:
    return run(f"systemctl is-enabled {shlex.quote(unit)} 2>/dev/null || true", 4) or "unknown"


def timer_interval(unit: str) -> str:
    cmd = (
        "awk -F= "
        + shlex.quote(
            r'/^[[:space:]]*OnUnitInactiveSec=/{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; found=1; exit}'
            r' /^[[:space:]]*OnUnitActiveSec=/{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); active=$2}'
            r' END{if (!found && active != "") print active}'
        )
        + f" /etc/systemd/system/{shlex.quote(unit)} 2>/dev/null || true"
    )
    return run(cmd, 4) or "?"


def monotonic_usec() -> int:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            first = fh.read().strip().split()[0]
        return int(float(first) * 1_000_000)
    except Exception:
        return 0


def systemctl_prop(unit: str, prop: str) -> str:
    return run(
        f"systemctl show {shlex.quote(unit)} -p {shlex.quote(prop)} --value 2>/dev/null || true",
        4,
    ).strip()


def service_age(unit: str) -> str:
    active_state = systemctl_prop(unit, "ActiveState")
    entered = systemctl_prop(unit, "ActiveEnterTimestampMonotonic")
    now = monotonic_usec()
    if active_state != "active" or not entered.isdigit() or now <= 0:
        return ""
    delta = max(0, (now - int(entered)) // 1_000_000)
    return format_span(delta)


def timer_countdown(unit: str) -> str:
    raw = run(
        f"systemctl status {shlex.quote(unit)} --no-pager -n 0 2>/dev/null "
        + r"""| sed -n 's/.*;[[:space:]]*\(.*\)[[:space:]]left/\1/p' | head -n1""",
        6,
    ).strip()
    return re.sub(r"\s+", " ", raw) if raw else ""


def timer_trigger(unit: str) -> str:
    raw = run(
        f"systemctl status {shlex.quote(unit)} --no-pager -n 0 2>/dev/null "
        + r"""| sed -n 's/^[[:space:]]*Trigger:[[:space:]]*//p' | head -n1""",
        6,
    ).strip()
    return re.sub(r"\s+", " ", raw) if raw else "sin dato"


def sudo_probe(timeout: int = 5) -> bool:
    probe = run_process("sudo -n -v", timeout)
    return bool(probe and probe.returncode == 0)
