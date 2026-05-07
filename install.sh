#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cat <<'EOF'
WatchdogVPN - Installer

The installer is not implemented yet in this packaging phase.

Next contract:
- run doctor checks
- ask only DNS advanced, desktop launcher and Conky
- preserve existing user configuration
- install common runtime on Ubuntu, Debian and Arch Linux

For now run:
  ./doctor.sh
EOF
