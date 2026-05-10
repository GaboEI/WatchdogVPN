#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

install -m 0755 "$ROOT_DIR/tui/VPN" "$tmpdir/VPN"
cp -a "$ROOT_DIR/tui/watchdogvpn" "$tmpdir/watchdogvpn"

python3 -m py_compile "$tmpdir/VPN" "$tmpdir"/watchdogvpn/*.py
PYTHONPATH="$tmpdir" python3 - "$tmpdir/VPN" <<'PY'
import importlib.util
import importlib.machinery
import sys

loader = importlib.machinery.SourceFileLoader("watchdogvpn_tui_launcher", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)

for name in ("truth_data", "country_code", "current_location", "strip_ansi", "bypass_count"):
    assert name in module.handle_menu.__globals__, f"missing handle_menu global: {name}"

for name in ("strip_ansi",):
    assert name in module.load_locations.__globals__, f"missing load_locations global: {name}"

for name in ("bypass_count",):
    assert name in module.section_meta.__globals__, f"missing section_meta global: {name}"
PY
launcher_output="$("$tmpdir/VPN")"
[[ "$launcher_output" == "VPN requiere una terminal interactiva." ]]

echo "tui install layout check passed"
