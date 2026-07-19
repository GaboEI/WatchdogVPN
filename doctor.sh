#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=lib/distro.sh
. "$ROOT_DIR/lib/distro.sh"
# shellcheck source=lib/packages.sh
. "$ROOT_DIR/lib/packages.sh"
# shellcheck source=lib/singbox.sh
. "$ROOT_DIR/lib/singbox.sh"
# shellcheck source=lib/cloak.sh
. "$ROOT_DIR/lib/cloak.sh"
# shellcheck source=lib/amneziawg.sh
. "$ROOT_DIR/lib/amneziawg.sh"
# shellcheck source=lib/version_marker.sh
. "$ROOT_DIR/lib/version_marker.sh"
# shellcheck source=lib/systemd.sh
. "$ROOT_DIR/lib/systemd.sh"
# shellcheck source=lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"

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

systemd_show_value() {
  local unit="$1" property="$2"
  systemctl show "$unit" -p "$property" --value 2>/dev/null || true
}

read_key_value() {
  local key="$1"
  awk -F= -v wanted="$key" '$1 == wanted {sub(/^[[:space:]]+/, "", $2); sub(/[[:space:]]+$/, "", $2); print $2; exit}'
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

socket_reachable() {
  local socket_path="$1"
  python3 - "$socket_path" <<'PY'
import socket
import sys

path = sys.argv[1]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(1.0)
try:
    sock.connect(path)
except PermissionError:
    sys.exit(13)
except (FileNotFoundError, ConnectionRefusedError, TimeoutError, OSError):
    sys.exit(1)
finally:
    sock.close()
sys.exit(0)
PY
}

cap_eff_has_bind_service() {
  local pid="$1" cap_eff
  [[ -n "$pid" && "$pid" != "0" && -r "/proc/$pid/status" ]] || return 1
  cap_eff="$(awk '/^CapEff:/ {print $2; exit}' "/proc/$pid/status")"
  [[ -n "$cap_eff" ]] || return 1
  (( (16#$cap_eff & (1 << 10)) != 0 ))
}

cap_eff_has_process_attribution_caps() {
  local pid="$1" cap_eff
  [[ -n "$pid" && "$pid" != "0" && -r "/proc/$pid/status" ]] || return 1
  cap_eff="$(awk '/^CapEff:/ {print $2; exit}' "/proc/$pid/status")"
  [[ -n "$cap_eff" ]] || return 1
  (( (16#$cap_eff & (1 << 19)) != 0 && (16#$cap_eff & (1 << 2)) != 0 ))
}

capability_list_has() {
  local haystack="$1" needle="$2"
  [[ " $haystack " == *" $needle "* ]]
}

path_hits_for() {
  local name="$1" dir candidate seen=""
  local -a path_dirs=()
  IFS=: read -r -a path_dirs <<<"${PATH:-}"
  for dir in "${path_dirs[@]}"; do
    [[ -n "$dir" ]] || dir="."
    candidate="$dir/$name"
    [[ -x "$candidate" ]] || continue
    case ":$seen:" in
      *":$candidate:"*) continue ;;
    esac
    seen="${seen:+$seen:}$candidate"
    printf '%s\n' "$candidate"
  done
}

check_path_entrypoint() {
  local name="$1" expected="$2" hits first hit conflict=0
  hits="$(path_hits_for "$name")"
  first="$(printf '%s\n' "$hits" | sed -n '1p')"

  if [[ -z "$first" ]]; then
    mark_warn "PATH cannot resolve $name"
    info "expected: $expected"
    info "recovery: run ./install.sh or ./update.sh, then open a new shell"
    return 0
  fi

  if [[ "$first" == "$expected" ]]; then
    mark_ok "PATH resolves $name: $first"
  else
    mark_warn "PATH conflict for $name: first hit is $first"
    info "expected first hit: $expected"
    info "recovery: remove or rename the earlier wrapper, or adjust PATH precedence"
    conflict=1
  fi

  while IFS= read -r hit; do
    [[ -n "$hit" ]] || continue
    if [[ "$hit" != "$expected" ]]; then
      ((conflict == 1)) || mark_warn "PATH extra hit for $name: $hit"
      info "$name hit: $hit"
      conflict=1
    fi
  done <<<"$hits"
}

check_legacy_file_artifact() {
  local path="$1"
  if [[ -e "$path" ]]; then
    mark_warn "legacy product artifact present: $path"
    info "recovery: run ./update.sh to back up and remove known-dead legacy product files"
  else
    mark_ok "legacy product artifact absent: $path"
  fi
}

check_legacy_unit_artifact() {
  local unit="$1" unit_path="/etc/systemd/system/$unit"
  if [[ -e "$unit_path" ]] || systemd_unit_known "$unit"; then
    mark_warn "legacy systemd unit present: $unit"
    info "$unit: active=$(systemd_active_state "$unit") enabled=$(systemd_enabled_state "$unit")"
    info "recovery: run ./update.sh to back up and remove known-dead legacy units"
  else
    mark_ok "legacy systemd unit absent: $unit"
  fi
}

check_current_unit_status() {
  local unit="$1" unit_path="/etc/systemd/system/$unit" active enabled
  if systemd_unit_known "$unit"; then
    active="$(systemd_active_state "$unit")"
    enabled="$(systemd_enabled_state "$unit")"
    mark_ok "unit known: $unit"
    info "$unit: active=${active:-unknown} enabled=${enabled:-unknown}"
    if [[ -e "$unit_path" ]]; then
      mark_ok "unit file installed: $unit_path"
    else
      mark_warn "unit known but product unit file missing: $unit_path"
      info "recovery: run ./install.sh or ./update.sh to refresh systemd units"
    fi
  else
    mark_warn "unit not found: $unit"
    info "recovery: run ./install.sh or ./update.sh to install product units"
  fi
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

section "Time and NTP"
time_diag="$(PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m diagnostics.time_check 2>/dev/null || true)"
time_status="$(printf '%s\n' "$time_diag" | read_key_value STATUS)"
time_message="$(printf '%s\n' "$time_diag" | read_key_value MESSAGE)"
ntp_state="$(printf '%s\n' "$time_diag" | read_key_value NTP_STATE)"
skew_seconds="$(printf '%s\n' "$time_diag" | read_key_value SKEW_SECONDS)"
if [[ "$time_status" == "ok" ]]; then
  mark_ok "system time and NTP"
else
  mark_warn "system time/NTP risk: ${time_message:-unknown}"
fi
info "ntp_state=${ntp_state:-unknown} skew_seconds=${skew_seconds:-unknown}"
info "wrong system time can break TLS and VPN/proxy protocol handshakes; doctor does not change the clock"

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
check_repo_file "bin/vpn_dns_rescue" exec
check_repo_file "bin/vpn_domain_bypass_rescue" exec
check_repo_file "bin/vpn_manual_state" exec
check_repo_file "bin/vpn_notify" exec
check_repo_file "bin/vpnctl" exec
check_repo_file "bin/watchdog" exec
check_repo_file "bin/watchdog_panic" exec
check_repo_file "bin/watchdogvpn" exec
check_repo_file "bin/watchdogvpn-daemon" exec
check_repo_file "systemd/watchdogvpn.service"
check_repo_file "etc/logrotate.d/myvpn"
check_repo_file "etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules"

section "Current Installation"
installed_any=0
installed_product_paths=(
  /usr/local/bin/no_vpn
  /usr/local/bin/vpn_truth_check
  /usr/local/bin/vpn_backend
  /usr/local/bin/vpn_dns_rescue
  /usr/local/bin/vpn_domain_bypass_rescue
  /usr/local/bin/vpn_manual_state
  /usr/local/bin/vpn_notify
  /usr/local/bin/vpnctl
  /usr/local/bin/watchdog
  /usr/local/bin/watchdog_panic
  /usr/local/bin/watchdogvpn
  /usr/local/bin/watchdogvpn-daemon
  /usr/local/lib/watchdogvpn
  /etc/polkit-1/rules.d/49-watchdogvpn-resolved.rules
  "$HOME/.local/bin/VPN"
  "$HOME/.local/share/watchdogvpn/watchdogvpn"
)
for path in "${installed_product_paths[@]}"; do
  if [[ -e "$path" ]]; then
    installed_any=1
  fi
done
if ((installed_any == 1)); then
  for path in "${installed_product_paths[@]}"; do
    if [[ -e "$path" ]]; then
      mark_ok "installed: $path"
    else
      mark_warn "installed product file missing: $path"
      info "recovery: run ./install.sh or ./update.sh to refresh the installed runtime"
    fi
  done
else
  mark_warn "no previous WatchdogVPN runtime detected"
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

section "Installed/Source Version Skew"
installed_commit="$(installed_version_commit 2>/dev/null || true)"
source_commit="$(source_checkout_commit 2>/dev/null || true)"
if [[ -z "$installed_commit" ]]; then
  info "no installed version marker yet; run ./install.sh or ./update.sh to create one"
elif [[ -z "$source_commit" ]]; then
  info "not running from a git checkout; cannot compare installed vs source version"
  info "installed: $installed_commit (installed_at=$(installed_version_timestamp 2>/dev/null || printf unknown))"
elif [[ "$installed_commit" == "$source_commit" ]]; then
  mark_ok "installed runtime matches source checkout: $installed_commit"
else
  mark_warn "installed runtime commit differs from this source checkout"
  info "installed: $installed_commit (installed_at=$(installed_version_timestamp 2>/dev/null || printf unknown))"
  info "checkout:  $source_commit"
  info "recovery: run ./update.sh to refresh the installed runtime to match this checkout"
fi

section "PATH Entrypoints"
check_path_entrypoint watchdog /usr/local/bin/watchdog
check_path_entrypoint watchdogvpn /usr/local/bin/watchdogvpn
check_path_entrypoint watchdogvpn-daemon /usr/local/bin/watchdogvpn-daemon
check_path_entrypoint vpnctl /usr/local/bin/vpnctl
check_path_entrypoint vpn_truth_check /usr/local/bin/vpn_truth_check

section "WatchdogVPN Daemon"
daemon_unit="${WATCHDOGVPN_DAEMON_UNIT:-watchdogvpn.service}"
daemon_socket="${WATCHDOGVPN_SOCKET_PATH:-/run/watchdogvpn/control.sock}"
hibernate_marker="${WATCHDOGVPN_HIBERNATE_MARKER:-/etc/watchdogvpn/.hibernating}"

if [[ -e "$hibernate_marker" ]]; then
  mark_warn "WatchdogVPN is asleep (watchdog_panic sleep was run); run 'watchdog_panic wake' to resume"
fi

if getent passwd watchdogvpn >/dev/null 2>&1; then
  mark_ok "service user: watchdogvpn"
else
  mark_warn "service user missing: watchdogvpn"
  info "recovery: run ./install.sh or ./update.sh to create the service user"
fi

if systemd_unit_known "$daemon_unit"; then
  mark_ok "daemon unit known: $daemon_unit"
  daemon_state="$(systemd_active_state "$daemon_unit")"
  if [[ "$daemon_state" == "active" ]]; then
    mark_ok "daemon active: $daemon_unit"
  elif [[ -e "$hibernate_marker" ]]; then
    info "daemon state: ${daemon_state:-unknown} (expected while asleep)"
  else
    mark_warn "daemon state: ${daemon_state:-unknown}"
    info "recovery: enable/start $daemon_unit, or run ./update.sh to refresh the service"
  fi
  info "$daemon_unit: enabled=$(systemd_enabled_state "$daemon_unit")"

  ambient_caps="$(systemd_show_value "$daemon_unit" AmbientCapabilities)"
  bounding_caps="$(systemd_show_value "$daemon_unit" CapabilityBoundingSet)"
  if capability_list_has "$ambient_caps" cap_net_bind_service && capability_list_has "$bounding_caps" cap_net_bind_service; then
    mark_ok "daemon port 53 capability configured"
  else
    mark_warn "daemon missing CAP_NET_BIND_SERVICE in systemd capability sets"
    info "recovery: run ./update.sh to reinstall the current systemd unit"
  fi
  if capability_list_has "$ambient_caps" cap_sys_ptrace && capability_list_has "$bounding_caps" cap_sys_ptrace \
    && capability_list_has "$ambient_caps" cap_dac_read_search && capability_list_has "$bounding_caps" cap_dac_read_search; then
    mark_ok "daemon process-attribution capabilities configured"
  else
    mark_warn "daemon missing CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH for process attribution"
    info "recovery: run ./update.sh to reinstall the current systemd unit"
  fi

  daemon_pid="$(systemd_show_value "$daemon_unit" MainPID)"
  if [[ "$daemon_state" == "active" ]]; then
    if cap_eff_has_bind_service "$daemon_pid"; then
      mark_ok "daemon process can inherit privileged-port bind capability"
    else
      mark_warn "daemon process effective capabilities do not include CAP_NET_BIND_SERVICE"
      info "recovery: restart $daemon_unit after refreshing the unit with ./update.sh"
    fi
    if cap_eff_has_process_attribution_caps "$daemon_pid"; then
      mark_ok "daemon process can inherit process-attribution capabilities"
    else
      mark_warn "daemon process effective capabilities do not include CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH"
      info "recovery: restart $daemon_unit after refreshing the unit with ./update.sh"
    fi
  else
    info "daemon process capability check skipped; service is not active"
  fi
else
  mark_warn "daemon unit not found: $daemon_unit"
  info "recovery: run ./install.sh or ./update.sh to install the daemon unit"
fi

if socket_reachable "$daemon_socket"; then
  mark_ok "daemon socket reachable: $daemon_socket"
else
  socket_rc=$?
  if ((socket_rc == 13)); then
    mark_warn "daemon socket permission denied: $daemon_socket"
    info "add your user to the watchdogvpn group, then log out and back in"
  elif [[ -S "$daemon_socket" ]]; then
    mark_warn "daemon socket not reachable: $daemon_socket"
    info "recovery: check $daemon_unit logs, then restart the daemon if needed"
  elif [[ "${daemon_state:-}" == "active" ]]; then
    mark_fail "daemon socket missing while service is active: $daemon_socket"
    info "recovery: check $daemon_unit logs and restart the daemon"
  elif [[ -e "$hibernate_marker" ]]; then
    info "daemon socket missing (expected while asleep): $daemon_socket"
  else
    mark_warn "daemon socket missing: $daemon_socket"
    info "recovery: start $daemon_unit or run watchdog_panic wake if WatchdogVPN was put asleep"
  fi
fi

section "Current Product Systemd Units"
for unit in "${SYSTEMD_UNITS[@]}"; do
  check_current_unit_status "$unit"
done

section "Legacy Product Artifacts"
for unit in "${SYSTEMD_LEGACY_UNITS[@]}"; do
  check_legacy_unit_artifact "$unit"
done
for path in \
  /usr/local/bin/vpn_auth_check \
  /usr/local/sbin/vpn_rotate.sh \
  /usr/local/sbin/vpn_set \
  /usr/local/sbin/vpn_watchdog.sh \
  /etc/NetworkManager/dispatcher.d/99-vpn-rotate
do
  check_legacy_file_artifact "$path"
done
if [[ -d "$HOME/.local/bin/watchdogvpn" ]]; then
  mark_warn "legacy user wrapper directory present: $HOME/.local/bin/watchdogvpn"
  info "recovery: run ./update.sh to remove the legacy user wrapper directory"
else
  mark_ok "legacy user wrapper directory absent: $HOME/.local/bin/watchdogvpn"
fi

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

section "Capture Mode"
capture_diag="$(PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m diagnostics.capture_mode_check 2>/dev/null || true)"
capture_status="$(printf '%s\n' "$capture_diag" | read_key_value STATUS)"
capture_message="$(printf '%s\n' "$capture_diag" | read_key_value MESSAGE)"
capture_modes_value="$(printf '%s\n' "$capture_diag" | read_key_value CAPTURE_MODES)"
if [[ "$capture_status" == "ok" ]]; then
  mark_ok "capture mode matches configured routing intent"
elif [[ -n "$capture_status" ]]; then
  mark_warn "capture mode risk: ${capture_message:-unknown}"
else
  mark_warn "capture mode check did not run"
fi
info "capture_modes=${capture_modes_value:-unknown}"

section "Protocol Runtime Dependencies"
if singbox_available; then
  mark_ok "sing-box detected: $(singbox_path)"
else
  mark_warn "sing-box not detected; most Custom VPS protocols will not run"
fi

if amneziawg_runtime_available; then
  mark_ok "AmneziaWG tooling detected"
else
  mark_warn "AmneziaWG tooling not fully detected; AmneziaWG profiles will not run"
fi

if cloak_available; then
  mark_ok "Cloak client detected: $(cloak_path)"
else
  info "Cloak client (ck-client) not detected; only needed for OpenVPN+Cloak profiles"
fi

if python_cryptography_available; then
  mark_ok "python cryptography module available"
else
  mark_warn "python cryptography module missing; encrypted backups will not work"
fi

section "Optional Integrations"
for cmd in $(optional_commands); do
  check_optional_command "$cmd"
done

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
