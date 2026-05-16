"""Static TUI configuration.

These values are intentionally side-effect free so they can be imported by
tests without touching the host VPN or system services.
"""

AG = "/usr/local/bin/adguardvpn-cli"
VPNCTL = "/usr/local/bin/vpnctl"
TRUTH_BIN = "/usr/local/bin/vpn_truth_check"
AUTH_BIN = "/usr/local/bin/vpn_auth_check"
VPN_SET = "/usr/local/sbin/vpn_set"
NO_VPN = "/usr/local/bin/no_vpn"
DNSCTL = "/usr/local/bin/vpn_dnsctl"
WATCHDOGVPN_CLI = "/usr/local/bin/watchdogvpn"
WATCHDOGVPN_CONFIG = "/etc/watchdogvpn/config.toml"

ROTATE_TIMER = "vpn-rotate.timer"
ROTATE_FIRSTBOOT_TIMER = "vpn-rotate-firstboot.timer"
WATCHDOG_TIMER = "vpn-watchdog.timer"
ROTATE_SERVICE = "vpn-rotate.service"
WATCHDOG_SERVICE = "vpn-watchdog.service"
LOGROTATE_TIMER = "myvpn-logrotate.timer"
LOGROTATE_SERVICE = "myvpn-logrotate.service"
LOGROTATE_CONF = "/etc/logrotate.d/myvpn"

VPN_LOG_PATHS = [
    "/var/log/myvpn/vpn-events.log",
    "/var/log/myvpn/vpn-watchdog.log",
    "/var/log/myvpn/vpn-rotate.log",
    "/var/log/vpn-dispatcher.log",
    "/var/log/vpn-domain-bypass.log",
]

TRACE_LOG_PATHS = [
    "/var/log/myvpn/vpn-watchdog.log",
    "/var/log/myvpn/vpn-rotate.log",
    "/var/log/vpn-dispatcher.log",
    "/var/log/vpn-domain-bypass.log",
]

AUTO_REFRESH_SECONDS = 12
DASHBOARD_REFRESH_SECONDS = 1
SUDO_KEEPALIVE_SECONDS = 45

DNS_PROFILE_LABELS = {
    "quad9-doh": "Quad9",
    "cloudflare-doh": "Cloudflare",
    "google-doh": "Google",
    "adguard-unfiltered-doh": "AdGuard sin filtro",
    "adguard-doh": "AdGuard filtrado",
    "adguard-doq": "AdGuard DoQ",
    "opendns-doh": "OpenDNS",
}

MENU_ITEMS = [
    {"id": "dashboard", "label": "Dashboard", "section": "Dashboard", "group": "OPERACION"},
    {"id": "location", "label": "Ubicacion", "section": "Cambiar ubicacion", "group": "OPERACION"},
    {"id": "actions", "label": "Acciones", "section": "Acciones rapidas", "group": "OPERACION"},
    {"id": "dns", "label": "DNS", "section": "DNS / AdGuard", "group": "OPERACION"},
    {"id": "bypass", "label": "Exclusiones", "section": "Exclusiones", "group": "OPERACION"},
    {"id": "timers", "label": "Timers", "section": "Timers", "group": "AUTOMATIZACION"},
    {"id": "pool", "label": "Pool", "section": "Pool de rotacion", "group": "AUTOMATIZACION"},
    {"id": "logs", "label": "Logs", "section": "Ver logs", "group": "AUDITORIA"},
    {"id": "history", "label": "Historial", "section": "Historial", "group": "AUDITORIA"},
    {"id": "settings", "label": "Settings", "section": "Settings", "group": "SISTEMA"},
    {"id": "install", "label": "Instalacion", "section": "Instalacion", "group": "SISTEMA"},
    {"id": "exit", "label": "Salir", "section": "Salir", "group": "SISTEMA"},
]

MENU = [item["label"] for item in MENU_ITEMS]
