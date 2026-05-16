#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/bin/watchdogvpn"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

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
sanitize_email = true
support_email = "user@example.com"
EOF

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

"$SCRIPT" help >/dev/null
WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get | grep -Fq '[language]'
WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get | grep -Fq '<redacted-email>'
config_value="$(WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get language.current)"
[[ "$config_value" == "es" ]]
if WATCHDOGVPN_CONFIG_FILE="$TMP_DIR/config.toml" "$SCRIPT" config get language.missing >/dev/null 2>&1; then
  printf 'FAIL: missing config key should fail\n' >&2
  exit 1
fi
version_output="$("$SCRIPT" version)"
printf '%s\n' "$version_output" | grep -Fq "WatchdogVPN v0.1.1"
if printf '%s\n' "$version_output" | grep -Fq -- "-dev"; then
  printf 'FAIL: published CLI version must not use a -dev suffix\n' >&2
  exit 1
fi

printf 'watchdogvpn CLI checks passed\n'
