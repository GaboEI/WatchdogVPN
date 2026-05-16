#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_EXAMPLE="$ROOT_DIR/examples/watchdogvpn-config.toml.example"
CONFIG_DOC="$ROOT_DIR/docs/configuration.md"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  grep -Fq "$pattern" "$file" || fail "$message"
}

[[ -f "$CONFIG_EXAMPLE" ]] || fail "missing config example: $CONFIG_EXAMPLE"

for section in language timers dns tui reporting; do
  assert_contains "$CONFIG_EXAMPLE" "[$section]" "missing [$section] section"
  assert_contains "$CONFIG_DOC" "[$section]" "configuration docs must mention [$section]"
done

assert_contains "$CONFIG_EXAMPLE" 'current = "en"' "default language must be English"
assert_contains "$CONFIG_EXAMPLE" 'auto_detect = true' "language auto-detect default must be explicit"
assert_contains "$CONFIG_EXAMPLE" 'watchdog_interval = "5min"' "watchdog interval default missing"
assert_contains "$CONFIG_EXAMPLE" 'rotation_interval = "12h"' "rotation interval default missing"
assert_contains "$CONFIG_EXAMPLE" 'advanced_mode = false' "advanced DNS must default off"
assert_contains "$CONFIG_EXAMPLE" 'profile = "quad9-doh"' "DNS profile default missing"
assert_contains "$CONFIG_EXAMPLE" 'theme = "default"' "TUI theme default missing"
assert_contains "$CONFIG_EXAMPLE" 'color = true' "TUI color default missing"
assert_contains "$CONFIG_EXAMPLE" 'unicode = true' "TUI unicode default missing"
assert_contains "$CONFIG_EXAMPLE" 'sanitize_ipv4 = true' "IPv4 sanitization must default on"
assert_contains "$CONFIG_EXAMPLE" 'sanitize_ipv6 = true' "IPv6 sanitization must default on"
assert_contains "$CONFIG_EXAMPLE" 'sanitize_email = true' "email sanitization must default on"
assert_contains "$CONFIG_EXAMPLE" 'sanitize_home = true' "home path sanitization must default on"

if grep -Eiq '(password|passwd|token|secret|private[_-]?key|api[_-]?key)[[:space:]]*=' "$CONFIG_EXAMPLE"; then
  fail "config example must not define secrets"
fi

assert_contains "$CONFIG_DOC" '/etc/watchdogvpn/config.toml' "configuration docs must define target config path"
assert_contains "$CONFIG_DOC" 'examples/watchdogvpn-config.toml.example' "configuration docs must reference repo example source"

printf 'config defaults checks passed\n'
