#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
VPN Control Center - Update

The update path is planned but not implemented yet.

It must preserve:
- /etc/adguardvpn.env
- /etc/vpn-domain-bypass.conf
- /var/lib/vpn-rotate/
- logs
- user AdGuard Home configuration
- user Conky configuration
EOF
