#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

home_dir="$tmpdir/home"
install -d -m 0755 "$home_dir/.local/bin" "$home_dir/.local/share/watchdogvpn"
install -m 0755 "$ROOT_DIR/tui/VPN" "$home_dir/.local/bin/VPN"
cp -a "$ROOT_DIR/tui/watchdogvpn" "$home_dir/.local/share/watchdogvpn/watchdogvpn"

python3 -m py_compile "$home_dir/.local/bin/VPN" "$home_dir"/.local/share/watchdogvpn/watchdogvpn/*.py
HOME="$home_dir" python3 - "$home_dir/.local/bin/VPN" <<'PY'
import importlib.util
import importlib.machinery
import sys

loader = importlib.machinery.SourceFileLoader("watchdogvpn_tui_launcher", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)

for name in ("truth_data", "country_code", "current_location", "strip_ansi", "bypass_count", "settings_snapshot", "settings_set_command"):
    assert name in module.handle_menu.__globals__, f"missing handle_menu global: {name}"

cmd = module.settings_set_command("language.current", "es")
assert "/usr/local/bin/watchdogvpn config set language.current es" in cmd
assert "clave settings no permitida" in module.settings_set_command("timers.watchdog_interval", "1min")

for name in ("strip_ansi",):
    assert name in module.load_locations.__globals__, f"missing load_locations global: {name}"

for name in ("bypass_count",):
    assert name in module.section_meta.__globals__, f"missing section_meta global: {name}"
PY
launcher_output="$(HOME="$home_dir" "$home_dir/.local/bin/VPN")"
[[ "$launcher_output" == "VPN requiere una terminal interactiva." ]]

repo_output="$(HOME="$home_dir" "$ROOT_DIR/tui/VPN")"
[[ "$repo_output" == "VPN requiere una terminal interactiva." ]]

echo "tui install layout check passed"
