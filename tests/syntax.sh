#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 -m py_compile "$ROOT_DIR/tui/VPN"

while IFS= read -r file; do
  bash -n "$file"
done < <(
  find "$ROOT_DIR" \
    -path "$ROOT_DIR/.git" -prune -o \
    -type f \( -name '*.sh' -o -path "$ROOT_DIR/bin/*" -o -path "$ROOT_DIR/sbin/*" -o -path "$ROOT_DIR/networkmanager/dispatcher.d/*" \) \
    -print
)

printf 'syntax checks passed\n'
