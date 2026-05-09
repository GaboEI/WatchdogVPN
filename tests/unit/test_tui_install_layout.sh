#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

install -m 0755 "$ROOT_DIR/tui/VPN" "$tmpdir/VPN"
cp -a "$ROOT_DIR/tui/watchdogvpn" "$tmpdir/watchdogvpn"

python3 -m py_compile "$tmpdir/VPN" "$tmpdir"/watchdogvpn/*.py

echo "tui install layout check passed"
