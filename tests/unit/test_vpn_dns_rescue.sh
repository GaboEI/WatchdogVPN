#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fake_bin="$TMP_DIR/fake-bin"
mkdir -p "$fake_bin"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'if [[ "${1:-}" == "hosts" && "${VPN_DNS_RESCUE_HEALTHY:-1}" == "1" ]]; then exit 0; fi' \
  'exit 2' \
  >"$fake_bin/getent"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\\n" "$*" >>"$VPN_DNS_RESCUE_SUDO_LOG"' \
  'exit 0' \
  >"$fake_bin/sudo"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'if [[ "${1:-}" == "is-active" ]]; then echo active; fi' \
  'exit 0' \
  >"$fake_bin/systemctl"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'if [[ "$*" == "-t -f NAME con show --active" ]]; then printf "wired\\nlo\\n"; exit 0; fi' \
  'if [[ "$*" == "-g connection.interface-name con show wired" ]]; then echo enp0s8; exit 0; fi' \
  'if [[ "$*" == "-g connection.interface-name con show lo" ]]; then echo lo; exit 0; fi' \
  'exit 0' \
  >"$fake_bin/nmcli"
chmod 755 "$fake_bin/getent" "$fake_bin/sudo" "$fake_bin/systemctl" "$fake_bin/nmcli"

sudo_log="$TMP_DIR/sudo.log"
output="$TMP_DIR/output"
if ! PATH="$fake_bin:$PATH" VPN_DNS_RESCUE_SUDO_LOG="$sudo_log" \
  "$ROOT_DIR/bin/vpn_dns_rescue" auto --no-reconnect --strict --preserve-working \
  >"$output" 2>"$TMP_DIR/stderr"; then
  echo "FAIL: preserve-working DNS rescue rejected a healthy resolver" >&2
  exit 1
fi
grep -Fq 'preserving the current resolver configuration' "$output" || {
  echo "FAIL: preserve-working DNS rescue did not report the no-mutation path" >&2
  exit 1
}
if [[ -s "$sudo_log" ]]; then
  echo "FAIL: preserve-working DNS rescue mutated an already-healthy resolver" >&2
  cat "$sudo_log" >&2
  exit 1
fi
if [[ -s "$TMP_DIR/stderr" ]]; then
  echo "FAIL: preserve-working DNS rescue emitted an unexpected error" >&2
  cat "$TMP_DIR/stderr" >&2
  exit 1
fi

mutation_sudo_log="$TMP_DIR/mutation-sudo.log"
if ! PATH="$fake_bin:$PATH" VPN_DNS_RESCUE_HEALTHY=0 \
  VPN_DNS_RESCUE_SUDO_LOG="$mutation_sudo_log" \
  "$ROOT_DIR/bin/vpn_dns_rescue" auto --no-reconnect --strict \
  >"$TMP_DIR/mutation-output" 2>"$TMP_DIR/mutation-stderr"; then
  echo "FAIL: DNS rescue mutation path failed with deterministic command stubs" >&2
  exit 1
fi
grep -Fq 'nmcli con mod wired' "$mutation_sudo_log" || {
  echo "FAIL: DNS rescue did not reset the active physical connection" >&2
  exit 1
}
if grep -Fq 'nmcli con mod lo' "$mutation_sudo_log"; then
  echo "FAIL: DNS rescue must exclude the loopback NetworkManager connection" >&2
  exit 1
fi

printf 'vpn DNS rescue checks passed\n'
