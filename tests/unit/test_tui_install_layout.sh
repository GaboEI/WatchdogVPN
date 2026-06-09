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

for name in ("truth_data", "country_code", "current_location", "strip_ansi", "bypass_count", "backend_snapshot", "build_backend_text", "settings_snapshot", "settings_set_command", "settings_reset_command", "update_center_repo_root", "update_center_snapshot", "update_center_recommendations", "update_center_fetch_command", "update_center_runtime_plan", "update_center_product_rows", "build_update_runtime_plan_text", "build_update_center_text", "build_update_technical_details_text", "confirm_update_fetch", "apply_tui_preferences"):
    assert name in module.handle_menu.__globals__, f"missing handle_menu global: {name}"

cmd = module.settings_set_command("language.current", "es")
assert "/usr/local/bin/watchdogvpn config set language.current es" in cmd
assert "clave settings no permitida" in module.settings_set_command("timers.watchdog_interval", "1min")
reset_cmd = module.settings_reset_command()
assert "config reset language --yes" in reset_cmd
assert "config reset tui --yes" in reset_cmd
update_text = module.build_update_center_text()
assert "Product update status." in update_text
assert "Runtime update" in update_text
assert "Show technical details" in update_text
assert "git fetch origin --tags" not in update_text
assert "./update.sh --skip-doctor" not in update_text
technical_text = module.build_update_technical_details_text()
assert "Technical Update Details" in technical_text
assert "git fetch origin --tags" in technical_text
fetch_cmd = module.update_center_fetch_command()
assert "git fetch origin --tags" in fetch_cmd
assert "git pull" not in fetch_cmd
assert "sudo" not in fetch_cmd
assert any("git pull --ff-only origin main" in line for line in module.update_center_recommendations([("Estado remoto", "behind"), ("Cambios locales", "clean")]))
assert any("git push origin main" in line for line in module.update_center_recommendations([("Estado remoto", "ahead"), ("Cambios locales", "clean")]))
assert any("git status --short" in line for line in module.update_center_recommendations([("Estado remoto", "up to date"), ("Cambios locales", "dirty")]))
assert any("git pull --ff-only origin main" in line for line in module.update_center_runtime_plan([("Estado remoto", "behind"), ("Cambios locales", "clean")]))
assert any("./update.sh --skip-doctor" in line for line in module.update_center_runtime_plan([("Estado remoto", "up to date"), ("Cambios locales", "clean")]))
assert not any("./update.sh --skip-doctor" in line for line in module.update_center_runtime_plan([("Estado remoto", "diverged"), ("Cambios locales", "clean")]))
runtime_text = module.build_update_runtime_plan_text()
assert "Contextual guide. No commands are executed." in runtime_text
assert module.update_center_repo_root().endswith("WatchdogVPN")
backend_text = module.build_backend_text()
assert "Custom VPS guarda solo metadatos no secretos" in backend_text
assert "watchdogvpn backend status" in backend_text

original_cyan = module.FG["cyan"]
module.settings_snapshot = lambda: [("Tema", "no_color"), ("Color", "false")]
module.apply_tui_preferences()
assert module.FG["cyan"] == ""
module.settings_snapshot = lambda: [("Tema", "default"), ("Color", "true")]
module.apply_tui_preferences()
assert module.FG["cyan"] == original_cyan

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
