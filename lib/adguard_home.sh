#!/usr/bin/env bash
set -euo pipefail

adguard_home_install_supported() {
  return 1
}

adguard_home_message() {
  cat <<'EOF'
Advanced DNS with AdGuard Home is planned for the installer, but automatic
AdGuard Home provisioning is not enabled in this milestone.

The core VPN runtime can be installed now. DNS advanced mode can be added later
without reinstalling the product.
EOF
}
