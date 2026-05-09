#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$ROOT_DIR/tests/unit/test_vpn_truth_check.sh"
"$ROOT_DIR/tests/unit/test_vpn_watchdog.sh"
"$ROOT_DIR/tests/unit/test_tui_install_layout.sh"
python3 "$ROOT_DIR/tests/unit/test_tui_modules.py"

echo "unit behavior checks passed"
