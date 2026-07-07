#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$ROOT_DIR/tests/unit/test_vpn_truth_check.sh"
"$ROOT_DIR/tests/unit/test_vpn_backend.sh"
"$ROOT_DIR/tests/unit/test_manual_off.sh"
"$ROOT_DIR/tests/unit/test_distro_detection.sh"
"$ROOT_DIR/tests/unit/test_watchdogvpn_cli.sh"
"$ROOT_DIR/tests/unit/test_install_backend_selection.sh"
"$ROOT_DIR/tests/unit/test_config_defaults.sh"
"$ROOT_DIR/tests/unit/test_config_helpers.sh"
"$ROOT_DIR/tests/unit/test_watchdogvpn_state_migration.sh"
"$ROOT_DIR/tests/unit/test_watchdogvpn_systemd_contract.sh"
"$ROOT_DIR/tests/unit/test_doctor_daemon_contract.sh"
"$ROOT_DIR/tests/unit/test_tui_install_layout.sh"
"$ROOT_DIR/tests/unit/test_install_security_contracts.sh"
"$ROOT_DIR/tests/unit/test_protocol_dependencies.sh"
"$ROOT_DIR/tests/unit/test_version_marker.sh"
"$ROOT_DIR/tests/unit/test_python_runtime_packages.sh"
python3 "$ROOT_DIR/tests/unit/test_tui_modules.py"

echo "unit behavior checks passed"
