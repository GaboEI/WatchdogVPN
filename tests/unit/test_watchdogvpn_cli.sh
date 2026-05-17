#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/bin/watchdogvpn"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
LOG_DIR="$TMP_DIR/logs"
mkdir -p "$LOG_DIR"

make_cmd() {
  local path="$1"
  shift
  {
    printf '#!/usr/bin/env bash\n'
    printf '%s\n' "$@"
  } >"$path"
  chmod +x "$path"
}

make_cmd "$TMP_DIR/truth" \
  'printf "STATUS=UP\nTUN=UP\nROUTE=TUN\nIP=OK\nIP_ADDR=198.51.100.10\n"'
make_cmd "$TMP_DIR/auth" \
  'printf "AUTH=OK\nREASON=license_valid\nDETAIL=user@example.com 203.0.113.4\n"'
make_cmd "$TMP_DIR/vpnctl" \
  'printf "VPN STATUS: UP\npublic ip: 198.51.100.10\n"'
make_cmd "$TMP_DIR/dnsctl" \
  'case "${1:-}" in current) printf "profile_guess=quad9-doh\n";; local-test) printf "OK example.com 198.51.100.20\n";; esac'

cat >"$TMP_DIR/config.toml" <<'EOF'
[language]
current = "es"
auto_detect = true

[reporting]
sanitize_ipv4 = true
sanitize_ipv6 = true
sanitize_email = true
sanitize_home = true
support_email = "user@example.com"

[tui]
theme = "default"
color = true
unicode = true
EOF

printf '%s\n' \
  '2026-05-16T00:00:00Z | vpn_notify | info | sample | user@example.com 198.51.100.11 /home/tester' \
  '2026-05-16T00:01:00Z | vpn_watchdog | warn | sample | 203.0.113.22' \
  >"$LOG_DIR/vpn-events.log"

output="$(
  WATCHDOGVPN_REPORT_DIR="$TMP_DIR" \
  WATCHDOGVPN_TRUTH_BIN="$TMP_DIR/truth" \
  WATCHDOGVPN_AUTH_BIN="$TMP_DIR/auth" \
  WATCHDOGVPN_VPNCTL_BIN="$TMP_DIR/vpnctl" \
  WATCHDOGVPN_DNSCTL_BIN="$TMP_DIR/dnsctl" \
  "$SCRIPT" report
)"

report="$(printf '%s\n' "$output" | sed -n 's/^Report written: //p')"
[[ -f "$report" ]]

grep -Fq "WatchdogVPN diagnostic report" "$report"
grep -Fq "== VPN truth ==" "$report"
grep -Fq "== DNS local test ==" "$report"
grep -Fq "<redacted-email>" "$report"
grep -Fq "<redacted-ip>" "$report"
if grep -Eq '198\.51\.100|203\.0\.113|user@example\.com' "$report"; then
  printf 'FAIL: report contains unsanitized sensitive sample data\n' >&2
  exit 1
fi

help_output="$("$SCRIPT" help)"
printf '%s\n' "$help_output" | grep -Fq 'Read-only commands:'
printf '%s\n' "$help_output" | grep -Fq 'logs          Read recent WatchdogVPN logs without sudo.'
printf '%s\n' "$help_output" | grep -Fq 'Configuration commands:'
printf '%s\n' "$help_output" | grep -Fq 'Interactive commands:'
printf '%s\n' "$help_output" | grep -Fq 'config set    Update a validated safe configuration key.'
printf '%s\n' "$help_output" | grep -Fq 'update, connect, disconnect and rotate are intentionally not product CLI'
dash_help_output="$("$SCRIPT" --help)"
[[ "$dash_help_output" == "$help_output" ]]
logs_output="$(WATCHDOGVPN_LOG_DIR="$LOG_DIR" "$SCRIPT" logs events 2)"
printf '%s\n' "$logs_output" | grep -Fq 'WatchdogVPN logs: events'
printf '%s\n' "$logs_output" | grep -Fq '<redacted-email>'
printf '%s\n' "$logs_output" | grep -Fq '<redacted-ip>'
if printf '%s\n' "$logs_output" | grep -Eq '198\.51\.100|203\.0\.113|user@example\.com'; then
  printf 'FAIL: logs output contains unsanitized sensitive sample data\n' >&2
  exit 1
fi
if WATCHDOGVPN_LOG_DIR="$LOG_DIR" "$SCRIPT" logs unknown >/dev/null 2>&1; then
  printf 'FAIL: unknown log target should fail\n' >&2
  exit 1
fi
if WATCHDOGVPN_LOG_DIR="$LOG_DIR" "$SCRIPT" logs events 0 >/dev/null 2>&1; then
  printf 'FAIL: invalid log line count should fail\n' >&2
  exit 1
fi
WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get | grep -Fq '[language]'
WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get | grep -Fq '<redacted-email>'
config_value="$(WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get language.current)"
[[ "$config_value" == "es" ]]
if WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get language.missing >/dev/null 2>&1; then
  printf 'FAIL: missing config key should fail\n' >&2
  exit 1
fi
WATCHDOGVPN_CONFIG_BACKUP_DIR="$TMP_DIR/backups" WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config set language.current fr >/dev/null 2>&1
[[ "$(WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get language.current)" == "fr" ]]
WATCHDOGVPN_CONFIG_BACKUP_DIR="$TMP_DIR/backups" WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config set language.current es >/dev/null 2>&1
[[ "$(find "$TMP_DIR/backups" -type f -name 'config.toml.*.bak' | wc -l)" -ge 2 ]]
WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config set tui.color false >/dev/null 2>&1
grep -Fq 'color = false' "$TMP_DIR/config.toml"
if WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config set timers.watchdog_interval 1min >/dev/null 2>&1; then
  printf 'FAIL: unsafe config key should not be writable yet\n' >&2
  exit 1
fi
if WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config set language.current klingon >/dev/null 2>&1; then
  printf 'FAIL: invalid language should fail validation\n' >&2
  exit 1
fi
if WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" WATCHDOGVPN_CONFIG_DEFAULTS="$ROOT_DIR/examples/watchdogvpn-config.toml.example" "$SCRIPT" config reset language >/dev/null 2>&1; then
  printf 'FAIL: config reset without --yes should fail\n' >&2
  exit 1
fi
WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" WATCHDOGVPN_CONFIG_DEFAULTS="$ROOT_DIR/examples/watchdogvpn-config.toml.example" "$SCRIPT" config reset language --yes >/dev/null 2>&1
[[ "$(WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get language.current)" == "en" ]]
WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config set tui.theme high_contrast >/dev/null 2>&1
WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" WATCHDOGVPN_CONFIG_DEFAULTS="$ROOT_DIR/examples/watchdogvpn-config.toml.example" "$SCRIPT" config reset tui --yes >/dev/null 2>&1
[[ "$(WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get tui.theme)" == "default" ]]
if WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" WATCHDOGVPN_CONFIG_DEFAULTS="$ROOT_DIR/examples/watchdogvpn-config.toml.example" "$SCRIPT" config reset timers --yes >/dev/null 2>&1; then
  printf 'FAIL: unsafe reset target should fail\n' >&2
  exit 1
fi
version_output="$("$SCRIPT" version)"
printf '%s\n' "$version_output" | grep -Fq "WatchdogVPN v0.2.0"
if printf '%s\n' "$version_output" | grep -Fq -- "-dev"; then
  printf 'FAIL: published CLI version must not use a -dev suffix\n' >&2
  exit 1
fi

printf 'watchdogvpn CLI checks passed\n'
