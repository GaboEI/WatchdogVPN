#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/distro.sh
. "$ROOT_DIR/lib/distro.sh"
# shellcheck source=lib/packages.sh
. "$ROOT_DIR/lib/packages.sh"

FAIL_COUNT=0
WARN_COUNT=0
OK_COUNT=0

section() {
  printf '\n== %s ==\n' "$*"
}

mark_ok() {
  ok "$*"
  OK_COUNT=$((OK_COUNT + 1))
}

mark_fail() {
  fail "$*"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

mark_warn() {
  warn "$*"
  WARN_COUNT=$((WARN_COUNT + 1))
}

check_command() {
  local cmd="$1"
  if have_cmd "$cmd"; then
    mark_ok "command: $cmd"
  else
    mark_fail "missing command: $cmd"
  fi
}

check_optional_command() {
  local cmd="$1"
  if have_cmd "$cmd"; then
    mark_ok "optional command: $cmd"
  else
    mark_warn "optional command missing: $cmd"
  fi
}

systemd_unit_known() {
  local unit="$1"
  systemctl list-unit-files "$unit" >/dev/null 2>&1
}

systemd_active_state() {
  local unit="$1"
  systemctl is-active "$unit" 2>/dev/null || true
}

systemd_enabled_state() {
  local unit="$1"
  systemctl is-enabled "$unit" 2>/dev/null || true
}

read_key_value() {
  local key="$1"
  awk -F= -v wanted="$key" '$1 == wanted {sub(/^[[:space:]]+/, "", $2); sub(/[[:space:]]+$/, "", $2); print $2; exit}'
}

adguard_cli_path() {
  if have_cmd adguardvpn-cli; then
    command -v adguardvpn-cli
  elif [[ -x /usr/local/bin/adguardvpn-cli ]]; then
    printf '%s\n' /usr/local/bin/adguardvpn-cli
  else
    return 1
  fi
}

print_package_hint() {
  local packages=("$@")
  ((${#packages[@]} > 0)) || return 0
  printf '      hint: '
  package_hint_header
  printf '%s\n' "${packages[*]}"
}

check_repo_file() {
  local path="$1" mode="${2:-file}"
  case "$mode" in
    exec)
      [[ -x "$ROOT_DIR/$path" ]] && mark_ok "repo executable: $path" || mark_fail "repo executable missing: $path"
      ;;
    file)
      [[ -f "$ROOT_DIR/$path" ]] && mark_ok "repo file: $path" || mark_fail "repo file missing: $path"
      ;;
  esac
}

printf '%s - Doctor\n' "$PROJECT_NAME"
printf 'Read-only preflight. No system changes will be made.\n'

section "Distro"
detect_distro
info "distro: $DISTRO_NAME ($DISTRO_ID)"

if [[ "${DISTRO_SUPPORTED:-0}" == "1" ]]; then
  mark_ok "distro supported"
  adapter="$(distro_adapter_path "$ROOT_DIR")"
  if [[ -r "$adapter" ]]; then
    # shellcheck disable=SC1090
    . "$adapter"
    mark_ok "distro adapter: distros/${DISTRO_ADAPTER_ID:-$DISTRO_ID}.sh"
    info "package manager: ${DISTRO_PACKAGE_MANAGER:-unknown}"
  else
    mark_fail "missing distro adapter: $adapter"
  fi
elif [[ "${DISTRO_FUTURE:-0}" == "1" ]]; then
  mark_fail "Fedora support is planned for a future release"
else
  mark_fail "unsupported distro for this release"
fi

section "System"
if [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]; then
  mark_ok "init: systemd"
else
  mark_fail "systemd is required"
fi

for cmd in $(required_commands); do
  check_command "$cmd"
done

missing_packages=()
if declare -p DISTRO_BASE_PACKAGES >/dev/null 2>&1; then
  for cmd in $(required_commands); do
    have_cmd "$cmd" || missing_packages+=("$cmd")
  done
  if ((${#missing_packages[@]} > 0)); then
    print_package_hint "${DISTRO_BASE_PACKAGES[@]}"
  fi
fi

if systemd_unit_known NetworkManager.service; then
  mark_ok "NetworkManager service known"
  nm_state="$(systemd_active_state NetworkManager.service)"
  [[ "$nm_state" == "active" ]] && mark_ok "NetworkManager active" || mark_warn "NetworkManager state: ${nm_state:-unknown}"
else
  mark_fail "NetworkManager service not found"
fi

section "AdGuard VPN"
if cli="$(adguard_cli_path)"; then
  mark_ok "adguardvpn-cli detected: $cli"
  version="$("$cli" --version 2>/dev/null | head -n1 || true)"
  [[ -n "$version" ]] && info "version: $version" || mark_warn "could not read adguardvpn-cli version"
else
  mark_fail "adguardvpn-cli not detected"
fi

if getent passwd adgvpn >/dev/null 2>&1; then
  mark_ok "service user: adgvpn"
else
  mark_warn "service user missing: adgvpn"
fi

if [[ -x "$ROOT_DIR/bin/vpn_auth_check" ]]; then
  auth_raw="$(ADGUARDVPN_CLI="${cli:-/usr/local/bin/adguardvpn-cli}" "$ROOT_DIR/bin/vpn_auth_check" 2>/dev/null || true)"
  auth_state="$(printf '%s\n' "$auth_raw" | read_key_value AUTH)"
  auth_reason="$(printf '%s\n' "$auth_raw" | read_key_value REASON)"
  case "$auth_state" in
    OK)
      mark_ok "auth: OK"
      ;;
    EXPIRED)
      mark_fail "auth expired: ${auth_reason:-unknown}"
      ;;
    *)
      mark_warn "auth unknown: ${auth_reason:-unknown}"
      ;;
  esac
else
  mark_fail "repo helper missing: bin/vpn_auth_check"
fi

section "Repository Runtime"
check_repo_file "tui/VPN" exec
check_repo_file "tui/watchdogvpn/__init__.py"
check_repo_file "tui/watchdogvpn/actions.py"
check_repo_file "tui/watchdogvpn/commands.py"
check_repo_file "tui/watchdogvpn/constants.py"
check_repo_file "tui/watchdogvpn/formatting.py"
check_repo_file "tui/watchdogvpn/parsers.py"
check_repo_file "tui/watchdogvpn/render.py"
check_repo_file "tui/watchdogvpn/state.py"
check_repo_file "tui/watchdogvpn/styles.py"
check_repo_file "tui/watchdogvpn/validators.py"
check_repo_file "bin/vpn_truth_check" exec
check_repo_file "bin/vpn_backend" exec
check_repo_file "bin/vpn_auth_check" exec
check_repo_file "bin/vpn_dns_rescue" exec
check_repo_file "bin/vpn_manual_state" exec
check_repo_file "bin/vpn_notify" exec
check_repo_file "bin/vpnctl" exec
check_repo_file "bin/watchdogvpn" exec
check_repo_file "sbin/vpn_set" exec
check_repo_file "sbin/vpn_rotate.sh" exec
check_repo_file "sbin/vpn_watchdog.sh" exec
check_repo_file "systemd/vpn-watchdog.timer"
check_repo_file "systemd/vpn-rotate.timer"
check_repo_file "etc/logrotate.d/myvpn"

section "Current Installation"
installed_any=0
for path in \
  /usr/local/bin/vpn_truth_check \
  /usr/local/bin/vpn_backend \
  /usr/local/bin/vpn_auth_check \
  /usr/local/bin/vpn_dns_rescue \
  /usr/local/bin/vpn_manual_state \
  /usr/local/bin/vpn_notify \
  /usr/local/bin/vpnctl \
  /usr/local/bin/watchdogvpn \
  /usr/local/sbin/vpn_set \
  /usr/local/sbin/vpn_rotate.sh \
  /usr/local/sbin/vpn_watchdog.sh \
  "$HOME/.local/bin/VPN" \
  "$HOME/.local/share/watchdogvpn/watchdogvpn"
do
  if [[ -e "$path" ]]; then
    installed_any=1
    mark_ok "installed: $path"
  fi
done
((installed_any == 1)) || mark_warn "no previous WatchdogVPN runtime detected"

if [[ -d "$HOME/.local/bin/watchdogvpn" ]]; then
  mark_warn "legacy TUI package path shadows CLI: $HOME/.local/bin/watchdogvpn"
fi

if [[ -d "$HOME/.local/share/watchdogvpn/watchdogvpn" ]]; then
  for module in \
    __init__.py \
    actions.py \
    commands.py \
    constants.py \
    formatting.py \
    parsers.py \
    render.py \
    state.py \
    styles.py \
    validators.py
  do
    if [[ -f "$HOME/.local/share/watchdogvpn/watchdogvpn/$module" ]]; then
      mark_ok "installed TUI module: $module"
    else
      mark_fail "missing installed TUI module: $module"
    fi
  done
fi

for unit in adguardvpn.service vpn-watchdog.timer vpn-rotate.timer vpn-domain-bypass.timer myvpn-logrotate.timer; do
  if systemd_unit_known "$unit"; then
    info "$unit: active=$(systemd_active_state "$unit") enabled=$(systemd_enabled_state "$unit")"
  else
    mark_warn "unit not found: $unit"
  fi
done

section "Network And DNS"
if [[ -x "$ROOT_DIR/bin/vpn_truth_check" ]]; then
  truth_raw="$("$ROOT_DIR/bin/vpn_truth_check" 2>/dev/null || true)"
  truth_status="$(printf '%s\n' "$truth_raw" | read_key_value STATUS)"
  case "$truth_status" in
    UP)
      mark_ok "truth state: UP"
      ;;
    DEGRADED)
      mark_warn "truth state: DEGRADED"
      ;;
    DOWN)
      mark_warn "truth state: DOWN"
      ;;
    *)
      mark_warn "truth state unknown"
      ;;
  esac
else
  mark_fail "repo helper missing: bin/vpn_truth_check"
fi

if curl -fsS --max-time 5 https://www.google.com/generate_204 >/dev/null 2>&1; then
  mark_ok "HTTPS connectivity"
else
  mark_warn "HTTPS connectivity check failed"
fi

section "Optional Integrations"
for cmd in $(optional_commands); do
  check_optional_command "$cmd"
done

if [[ -f "$HOME/.local/share/applications/watchdogvpn.desktop" || -f "$HOME/.local/share/applications/vpn-control-center.desktop" ]]; then
  mark_ok "desktop launcher detected"
else
  info "desktop launcher not detected"
fi

printf '\n== Result ==\n'
printf 'OK=%d WARN=%d FAIL=%d\n' "$OK_COUNT" "$WARN_COUNT" "$FAIL_COUNT"

if (( FAIL_COUNT > 0 )); then
  printf 'Result: FAIL\n'
  exit 1
fi

if (( WARN_COUNT > 0 )); then
  printf 'Result: WARN\n'
  exit 0
fi

printf 'Result: OK\n'
