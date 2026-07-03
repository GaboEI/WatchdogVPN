"""Action command builders for the WatchdogVPN TUI.

The TUI owns interaction, confirmations and screen rendering.  This module owns
the shell commands that perform product actions, so they can be reviewed and
tested without walking through the interactive interface.
"""

import re
import shlex

from watchdogvpn.commands import run
from watchdogvpn.constants import (
    NO_VPN,
    TRUTH_BIN,
    VPNCTL,
    WATCHDOGVPN_CLI,
)
from watchdogvpn.validators import valid_domain, valid_timer_interval


def restart_vpn_command(loc_hint: str) -> str:
    return f"{shlex.quote(VPNCTL)} restart"


def disconnect_vpn_command() -> str:
    return f"{shlex.quote(VPNCTL)} disconnect"


def rotate_now_command() -> str:
    return f"{shlex.quote(WATCHDOGVPN_CLI)} rotate --force; {TRUTH_BIN}"


def real_status_command() -> str:
    return f"{VPNCTL} status"


def list_bypass_domains_command() -> str:
    return f"sudo -n {shlex.quote(NO_VPN)} --list"


def add_bypass_domain_command(domain: str) -> str:
    ok, domain_or_error = valid_domain(domain)
    if not ok:
        return f"echo 'ERROR: {domain_or_error}'"
    domain = domain_or_error
    return f"sudo -n {shlex.quote(NO_VPN)} {shlex.quote(domain)}"


def set_timer_interval_command(unit: str, value: str) -> str:
    if unit != "myvpn-logrotate.timer":
        return "echo 'ERROR: timer no permitido.'"
    ok, value_or_error = valid_timer_interval(value)
    if not ok:
        return f"echo 'ERROR: {value_or_error}'"
    value = value_or_error
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
