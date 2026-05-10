"""Action command builders for the WatchdogVPN TUI.

The TUI owns interaction, confirmations and screen rendering.  This module owns
the shell commands that perform product actions, so they can be reviewed and
tested without walking through the interactive interface.
"""

import re
import shlex

from watchdogvpn.commands import run
from watchdogvpn.constants import (
    DNSCTL,
    NO_VPN,
    ROTATE_FIRSTBOOT_TIMER,
    ROTATE_TIMER,
    TRUTH_BIN,
    VPN_SET,
    VPNCTL,
    WATCHDOG_TIMER,
)
from watchdogvpn.validators import valid_location_hint


def restart_vpn_command(loc_hint: str) -> str:
    if valid_location_hint(loc_hint):
        return f"sudo {shlex.quote(VPN_SET)} {shlex.quote(loc_hint)}; {TRUTH_BIN}"
    return f"sudo systemctl restart adguardvpn.service; {TRUTH_BIN}"


def disconnect_vpn_command() -> str:
    return (
        "sudo systemctl stop adguardvpn.service; "
        "/usr/local/bin/vpn_notify 'VPN desconectada' "
        "'La conexion VPN fue detenida manualmente.' normal >/dev/null 2>&1 || true; "
        f"{TRUTH_BIN}"
    )


def rotate_now_command() -> str:
    return f"sudo env VPN_ROTATE_FORCE=1 {shlex.quote('/usr/local/sbin/vpn_rotate.sh')}; {TRUTH_BIN}"


def run_watchdog_command() -> str:
    return (
        f"sudo systemctl restart {WATCHDOG_TIMER}; "
        "sudo env VPN_WATCHDOG_FORCE=1 "
        f"{shlex.quote('/usr/local/sbin/vpn_watchdog.sh')}; {TRUTH_BIN}"
    )


def real_status_command() -> str:
    return f"{VPNCTL} status"


def start_rotate_timer_command() -> str:
    return (
        f"sudo systemctl start {ROTATE_TIMER} {ROTATE_FIRSTBOOT_TIMER} "
        f"&& systemctl status {ROTATE_TIMER} --no-pager -n 8"
    )


def stop_rotate_timer_command() -> str:
    return (
        f"sudo systemctl stop {ROTATE_TIMER} {ROTATE_FIRSTBOOT_TIMER} "
        f"&& systemctl status {ROTATE_TIMER} --no-pager -n 8"
    )


def start_watchdog_timer_command() -> str:
    return f"sudo systemctl start {WATCHDOG_TIMER} && systemctl status {WATCHDOG_TIMER} --no-pager -n 8"


def stop_watchdog_timer_command() -> str:
    return f"sudo systemctl stop {WATCHDOG_TIMER} && systemctl status {WATCHDOG_TIMER} --no-pager -n 8"


def list_bypass_domains_command() -> str:
    return f"sudo -n {shlex.quote(NO_VPN)} --list"


def add_bypass_domain_command(domain: str) -> str:
    return f"sudo -n {shlex.quote(NO_VPN)} {shlex.quote(domain)}"


def dns_current_command() -> str:
    return f"sudo -n {shlex.quote(DNSCTL)} current"


def dns_apply_command(profile: str) -> str:
    return f"sudo -n {shlex.quote(DNSCTL)} apply {shlex.quote(profile)}"


def dns_rollback_command() -> str:
    return f"sudo -n {shlex.quote(DNSCTL)} rollback"


def set_timer_interval_command(unit: str, value: str) -> str:
    return rf"""
tmp="$(mktemp)"
awk -F= -v val="{value}" '
BEGIN {{ done=0 }}
/^[[:space:]]*OnUnitInactiveSec=/ {{ print "OnUnitInactiveSec=" val; done=1; next }}
/^[[:space:]]*OnUnitActiveSec=/ {{ next }}
/^[[:space:]]*\[Install\]/ && !done {{ print "OnUnitInactiveSec=" val; done=1 }}
{{ print $0 }}
END {{ if (!done) print "OnUnitInactiveSec=" val }}
' /etc/systemd/system/{unit} > "$tmp"
sudo install -m 644 -o root -g root "$tmp" /etc/systemd/system/{unit}
rm -f "$tmp"
sudo systemctl daemon-reload
sudo systemctl restart {unit}
systemctl status {unit} --no-pager -n 8
"""


def set_timer_interval(unit: str, value: str) -> str:
    return run(set_timer_interval_command(unit, value), 20)


def set_rotate_top_n_command(value: str) -> str:
    value = (value or "").strip()
    if not re.match(r"^[0-9]+$", value):
        return "echo 'ERROR: TOP_N debe ser un numero.'"
    num = int(value)
    if num < 1 or num > 100:
        return "echo 'ERROR: TOP_N debe estar entre 1 y 100.'"
    return rf"""
tmp="$(mktemp)"
sudo awk -F= -v val="{value}" '
BEGIN {{ done=0 }}
/^[[:space:]]*TOP_N=/ {{ print "TOP_N=" val; done=1; next }}
{{ print $0 }}
END {{ if (!done) print "TOP_N=" val }}
' /usr/local/sbin/vpn_rotate.sh > "$tmp"
sudo install -m 700 -o root -g root "$tmp" /usr/local/sbin/vpn_rotate.sh
rm -f "$tmp"
sudo grep -E '^(TOP_N|RECENT_KEEP)=' /usr/local/sbin/vpn_rotate.sh
"""


def set_rotate_top_n(value: str) -> str:
    value = (value or "").strip()
    if not re.match(r"^[0-9]+$", value):
        return "ERROR: TOP_N debe ser un numero."
    num = int(value)
    if num < 1 or num > 100:
        return "ERROR: TOP_N debe estar entre 1 y 100."
    return run(set_rotate_top_n_command(value), 20)


def remove_bypass_domain_command(domain: str) -> str:
    domain = (domain or "").strip().lower()
    if not re.match(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", domain):
        return "echo 'ERROR: dominio invalido.'"
    return rf"""
tmp="$(mktemp)"
sudo awk -v d={shlex.quote(domain)} '
BEGIN {{ wd="*." d }}
{{
  line=tolower($0)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
  if (line == d || line == wd) next
  print $0
}}' /etc/vpn-domain-bypass.conf > "$tmp"
sudo install -m 0644 -o root -g root "$tmp" /etc/vpn-domain-bypass.conf
rm -f "$tmp"
sudo systemctl start vpn-domain-bypass.service
echo "Quitado: {domain}"
echo "Quitado: *.{domain}"
echo "Aplicado bypass con: vpn-domain-bypass.service"
"""


def remove_bypass_domain(domain: str) -> str:
    domain = (domain or "").strip().lower()
    if not re.match(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", domain):
        return "ERROR: dominio invalido."
    return run(remove_bypass_domain_command(domain), 30)
