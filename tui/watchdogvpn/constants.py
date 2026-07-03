"""Static TUI configuration.

These values are intentionally side-effect free so they can be imported by
tests without touching the host VPN or system services.
"""

VPNCTL = "/usr/local/bin/vpnctl"
TRUTH_BIN = "/usr/local/bin/vpn_truth_check"
BACKEND_BIN = "/usr/local/bin/vpn_backend"
MANUAL_STATE_BIN = "/usr/local/bin/vpn_manual_state"
NO_VPN = "/usr/local/bin/no_vpn"
WATCHDOGVPN_CLI = "/usr/local/bin/watchdogvpn"
WATCHDOGVPN_CONFIG = "/etc/watchdogvpn/config.toml"

LOGROTATE_TIMER = "myvpn-logrotate.timer"
LOGROTATE_SERVICE = "myvpn-logrotate.service"
LOGROTATE_CONF = "/etc/logrotate.d/myvpn"

VPN_LOG_PATHS = [
    "/var/log/myvpn/vpn-events.log",
    "/var/log/vpn-dispatcher.log",
    "/var/log/vpn-domain-bypass.log",
]

TRACE_LOG_PATHS = [
    "/var/log/vpn-dispatcher.log",
    "/var/log/vpn-domain-bypass.log",
]

AUTO_REFRESH_SECONDS = 12
DASHBOARD_REFRESH_SECONDS = 1
SUDO_KEEPALIVE_SECONDS = 45

MENU_ITEMS = [
    {"id": "dashboard", "label": "Dashboard", "section": "Dashboard", "group": "OPERACION"},
    {"id": "backend", "label": "Backend", "section": "Backend", "group": "OPERACION"},
    {"id": "actions", "label": "Acciones", "section": "Acciones rapidas", "group": "OPERACION"},
    {"id": "bypass", "label": "Exclusiones", "section": "Exclusiones", "group": "OPERACION"},
    {"id": "dns", "label": "DNS", "section": "DNS", "group": "OPERACION"},
    {"id": "logs", "label": "Logs", "section": "Ver logs", "group": "AUDITORIA"},
    {"id": "history", "label": "Historial", "section": "Historial", "group": "AUDITORIA"},
    {"id": "settings", "label": "Settings", "section": "Settings", "group": "SISTEMA"},
    {"id": "update", "label": "Update", "section": "Update Center", "group": "SISTEMA"},
    {"id": "install", "label": "Instalacion", "section": "Instalacion", "group": "SISTEMA"},
    {"id": "exit", "label": "Salir", "section": "Salir", "group": "SISTEMA"},
]

MENU = [item["label"] for item in MENU_ITEMS]
