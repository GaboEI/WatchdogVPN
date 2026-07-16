#!/usr/bin/env bash
set -euo pipefail

PYTHON_PACKAGE_DIR="${PYTHON_PACKAGE_DIR:-/usr/local/lib/watchdogvpn}"
PYTHON_RUNTIME_PACKAGES=(
  app_policy
  cli
  config
  core
  daemon
  diagnostics
  dns
  drivers
  metrics
  models
  network_context
  node_groups
  parsers
  providers
  route_chains
  rotation
  rules
  terminal_safety
)
PYTHON_RUNTIME_SUPPORT_FILES=(
  doctor.sh
  uninstall.sh
)
PYTHON_RUNTIME_SUPPORT_DIRS=(
  lib
  bin
  sbin
  systemd
  etc
  examples
  distros
  tui
)
PYTHON_RUNTIME_SUPPORT_EXECUTABLES=(
  doctor.sh
  uninstall.sh
  tui/VPN
)

# Historical WatchdogVPN-owned files removed from the shipped set before this
# release (AdGuard-era rotation/watchdog automation, Task 2.6). Kept separate
# from remove_runtime_files()/install_runtime_files() purely so both install
# and update can clean up a machine that installed before their removal, not
# only a full uninstall. See INV-18.1-001 in
# docs/phase-18-task-18-1-legacy-contamination-inventory.md.
remove_legacy_runtime_files() {
  remove_root_path /usr/local/bin/vpn_auth_check
  remove_root_path /usr/local/sbin/vpn_rotate.sh
  remove_root_path /usr/local/sbin/vpn_set
  remove_root_path /usr/local/sbin/vpn_watchdog.sh
  remove_root_path /etc/NetworkManager/dispatcher.d/99-vpn-rotate
}

install_runtime_files() {
  local runtime_root="${WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT:-$ROOT_DIR}"
  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_prepare_candidate "$ROOT_DIR"
    runtime_root="$WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT"
  fi
  create_system_user_no_home watchdogvpn
  add_installing_user_to_watchdogvpn_group
  create_root_dir /var/log/myvpn 0755

  create_config_if_missing "$runtime_root/examples/vpn-domain-bypass.conf.example" /etc/vpn-domain-bypass.conf 0644
  install_config_defaults
  install_sysctl_defaults
  migrate_watchdogvpn_shared_state
  repair_watchdogvpn_shared_state_permissions
  install_python_package_tree

  # Clean up pre-Phase-2.6 (AdGuard-era) contamination on every install and
  # update, not only on a full uninstall - a machine that never gets
  # uninstalled should not carry orphaned legacy units/scripts forever.
  remove_legacy_systemd_units
  remove_legacy_runtime_files

  install_root_file "$runtime_root/bin/no_vpn" /usr/local/bin/no_vpn 0755
  install_root_file "$runtime_root/bin/vpn_dns_rescue" /usr/local/bin/vpn_dns_rescue 0755
  install_root_file "$runtime_root/bin/vpn_domain_bypass_rescue" /usr/local/bin/vpn_domain_bypass_rescue 0755
  install_root_file "$runtime_root/bin/watchdog_panic" /usr/local/bin/watchdog_panic 0755
  install_root_file "$runtime_root/bin/vpn_backend" /usr/local/bin/vpn_backend 0755
  install_root_file "$runtime_root/bin/vpn_manual_state" /usr/local/bin/vpn_manual_state 0755
  install_root_file "$runtime_root/bin/vpn_notify" /usr/local/bin/vpn_notify 0755
  install_root_file "$runtime_root/bin/vpn_truth_check" /usr/local/bin/vpn_truth_check 0755
  install_root_file "$runtime_root/bin/vpnctl" /usr/local/bin/vpnctl 0755
  install_python_module_wrapper /usr/local/bin/watchdog cli.main
  install_root_file "$runtime_root/bin/watchdogvpn" /usr/local/bin/watchdogvpn 0755
  install_python_module_wrapper /usr/local/bin/watchdogvpn-daemon daemon.main

  install_root_file "$runtime_root/sbin/vpn_domain_bypass_apply.sh" /usr/local/sbin/vpn_domain_bypass_apply.sh 0700

  install_user_file "$runtime_root/tui/VPN" "$HOME/.local/bin/VPN" 0755
  remove_user_path "$HOME/.local/bin/watchdogvpn"
  install_user_dir "$runtime_root/tui/watchdogvpn" "$HOME/.local/share/watchdogvpn/watchdogvpn"
  install_user_dir "$runtime_root/terminal_safety" "$HOME/.local/share/watchdogvpn/terminal_safety"
  install_root_file "$runtime_root/etc/logrotate.d/myvpn" /etc/logrotate.d/myvpn 0644
  install_systemd_units
}

# net.ipv4.conf.all.src_valid_mark must be 1 for AmneziaWG/WireGuard-style
# fwmark default-route policy routing to pass return traffic. The daemon
# runs under ProtectKernelTunables=true and cannot set this itself at
# connect time (see drivers/amneziawg_driver.py), so it is applied once
# here, at install/update time, as root, outside the daemon's sandbox.
install_sysctl_defaults() {
  local runtime_root="${WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT:-$ROOT_DIR}"
  install_root_file "$runtime_root/etc/sysctl.d/99-watchdogvpn.conf" /etc/sysctl.d/99-watchdogvpn.conf 0644
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] sudo sysctl -p /etc/sysctl.d/99-watchdogvpn.conf\n'
    return 0
  fi
  run_step sudo sysctl -q -p /etc/sysctl.d/99-watchdogvpn.conf
}

install_python_module_wrapper() {
  local dest="$1" module="$2" tmp quoted_root
  tmp="$(mktemp)"
  printf -v quoted_root '%q' "$PYTHON_PACKAGE_DIR"
  {
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n\n'
    printf 'ROOT_DIR=%s\n' "$quoted_root"
    printf 'export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"\n'
    printf 'exec python3 -m %s "$@"\n' "$module"
  } >"$tmp"
  install_root_file "$tmp" "$dest" 0755
  rm -f "$tmp"
}

install_python_package_tree() {
  local dest="${1:-$PYTHON_PACKAGE_DIR}" package item stage source_root="${WATCHDOGVPN_RUNTIME_CANDIDATE_ROOT:-$ROOT_DIR}"
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] install Python runtime packages to %s\n' "$dest"
    return 0
  fi
  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_checkpoint disk
    stage="$(sudo mktemp -d "$(dirname "$dest")/.${dest##*/}.candidate.XXXXXX")" || return 1
    runtime_transaction_register_cleanup_path "$stage"
    for package in "${PYTHON_RUNTIME_PACKAGES[@]}"; do
      runtime_transaction_checkpoint copy
      run_step sudo cp -a "$source_root/$package" "$stage/"
    done
    for item in "${PYTHON_RUNTIME_SUPPORT_FILES[@]}"; do
      runtime_transaction_checkpoint copy
      run_step sudo cp -a "$source_root/$item" "$stage/"
    done
    for item in "${PYTHON_RUNTIME_SUPPORT_DIRS[@]}"; do
      runtime_transaction_checkpoint copy
      run_step sudo cp -a "$source_root/$item" "$stage/"
    done
    runtime_transaction_checkpoint permission
    run_step sudo chown -R root:root "$stage"
    run_step sudo find "$stage" -type d -exec chmod 0755 {} +
    run_step sudo find "$stage" -type f -exec chmod 0644 {} +
    for item in "${PYTHON_RUNTIME_SUPPORT_EXECUTABLES[@]}"; do
      run_step sudo chmod 0755 "$stage/$item"
    done
    run_step sudo find "$stage/bin" "$stage/sbin" -type f -exec chmod 0755 {} +
    _validate_staged_python_runtime "$stage"
    runtime_transaction_replace_directory_from_stage "$stage" "$dest"
    return 0
  fi
  backup_path "$dest"
  run_step sudo rm -rf -- "$dest"
  run_step sudo install -d -m 0755 -o root -g root "$dest"
  for package in "${PYTHON_RUNTIME_PACKAGES[@]}"; do
    run_step sudo cp -a "$source_root/$package" "$dest/"
  done
  for item in "${PYTHON_RUNTIME_SUPPORT_FILES[@]}"; do
    run_step sudo cp -a "$source_root/$item" "$dest/"
  done
  for item in "${PYTHON_RUNTIME_SUPPORT_DIRS[@]}"; do
    run_step sudo cp -a "$source_root/$item" "$dest/"
  done
  run_step sudo chown -R root:root "$dest"
  run_step sudo find "$dest" -type d -exec chmod 0755 {} +
  run_step sudo find "$dest" -type f -exec chmod 0644 {} +
  for item in "${PYTHON_RUNTIME_SUPPORT_EXECUTABLES[@]}"; do
    run_step sudo chmod 0755 "$dest/$item"
  done
  run_step sudo find "$dest/bin" "$dest/sbin" -type f -exec chmod 0755 {} +
}

_validate_staged_python_runtime() {
  local stage="$1" package item
  for package in "${PYTHON_RUNTIME_PACKAGES[@]}"; do
    [[ -d "$stage/$package" ]] || {
      printf 'ERROR: staged Python runtime is missing package: %s\n' "$package" >&2
      return 1
    }
  done
  for item in "${PYTHON_RUNTIME_SUPPORT_FILES[@]}" "${PYTHON_RUNTIME_SUPPORT_DIRS[@]}"; do
    [[ -e "$stage/$item" ]] || {
      printf 'ERROR: staged Python runtime is missing support path: %s\n' "$item" >&2
      return 1
    }
  done
  python3 -m compileall -q "$stage"
}

migrate_watchdogvpn_shared_state() {
  local source_dir="${WATCHDOGVPN_LEGACY_CONFIG_DIR:-$HOME/.config/watchdogvpn}"
  local target_dir="${WATCHDOGVPN_SHARED_STATE_DIR:-/var/lib/watchdogvpn}"
  local marker="$target_dir/.migrated"
  local journal="$target_dir/.migration-in-progress"
  local stage_dir marker_tmp journal_tmp entry_name
  local has_legacy_data=0

  # NOTE: the marker means "the shared state directory is ready for the CLI
  # and daemon to use," not literally "a copy happened." A fresh install with
  # no legacy $HOME/.config/watchdogvpn data must still get the marker once
  # the target directory exists, otherwise config/paths.py::resolve_config_dir()
  # keeps routing the CLI to $HOME/.config/watchdogvpn forever (the daemon
  # always uses the shared dir), so the CLI and daemon silently never share
  # state on any install that never had legacy per-user config. Found during
  # the Phase 18 Task 18.4 shared-state permissions audit.
  if [[ -e "$marker" ]]; then
    # A crash after marker publication but before journal cleanup is already a
    # completed migration: marker publication only follows target validation.
    if [[ -e "$journal" ]]; then
      run_step sudo rm -f -- "$journal"
    fi
    printf '[KEEP] WatchdogVPN shared state already migrated: %s\n' "$target_dir"
    return 0
  fi
  if [[ -e "$journal" ]] \
    && { [[ ! -f "$journal" ]] || ! sudo grep -Fxq 'watchdogvpn-state-migration-v1' "$journal"; }; then
    printf 'ERROR: WatchdogVPN migration recovery journal is invalid: %s\n' "$journal" >&2
    return 1
  fi
  if [[ -e "$target_dir" && ! -d "$target_dir" ]]; then
    printf 'ERROR: WatchdogVPN shared state target is not a directory: %s\n' "$target_dir" >&2
    return 1
  fi
  if [[ -d "$source_dir" ]] \
    && [[ -n "$(find "$source_dir" -mindepth 1 ! -name .migrated -print -quit)" ]]; then
    has_legacy_data=1
  fi
  if [[ ! -d "$target_dir" ]]; then
    prepare_watchdogvpn_state_directory "$target_dir"
  fi
  if [[ ! -d "$target_dir" ]]; then
    printf '[SKIP] WatchdogVPN shared state target is not available yet: %s\n' "$target_dir"
    return 0
  fi
  if [[ -e "$marker" ]]; then
    printf '[KEEP] WatchdogVPN shared state already migrated: %s\n' "$target_dir"
    return 0
  fi
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    if ((has_legacy_data == 1)); then
      printf '[DRY-RUN] migrate WatchdogVPN state %s -> %s\n' "$source_dir" "$target_dir"
    else
      printf '[DRY-RUN] mark WatchdogVPN shared state ready (no legacy user state to migrate): %s\n' "$target_dir"
    fi
    return 0
  fi

  if ((has_legacy_data == 0)); then
    printf '[SKIP] no legacy WatchdogVPN user state to migrate; marking shared state ready: %s\n' "$target_dir"
    _publish_watchdogvpn_migration_marker "$marker" || return 1
    repair_watchdogvpn_shared_state_permissions "$target_dir"
    return 0
  fi

  stage_dir="$(sudo mktemp -d "$target_dir/.migration-stage.XXXXXX")" || {
    printf 'ERROR: unable to create WatchdogVPN migration staging directory in %s\n' "$target_dir" >&2
    return 1
  }
  if ! _stage_watchdogvpn_legacy_state "$source_dir" "$stage_dir"; then
    run_step sudo rm -rf -- "$stage_dir"
    return 1
  fi
  if ! _validate_watchdogvpn_migration_tree "$source_dir" "$stage_dir" stage-validate; then
    printf 'ERROR: staged WatchdogVPN legacy state failed content validation\n' >&2
    run_step sudo rm -rf -- "$stage_dir"
    return 1
  fi

  if [[ ! -e "$journal" ]] && ! _watchdogvpn_migration_target_is_publishable "$stage_dir" "$target_dir"; then
    printf 'ERROR: WatchdogVPN shared state has unmarked conflicting entries; refusing to certify migration\n' >&2
    run_step sudo rm -rf -- "$stage_dir"
    return 1
  fi
  if [[ ! -e "$journal" ]]; then
    journal_tmp="$(sudo mktemp "$target_dir/.migration-journal.XXXXXX")" || {
      run_step sudo rm -rf -- "$stage_dir"
      return 1
    }
    if ! printf 'watchdogvpn-state-migration-v1\n' | sudo tee "$journal_tmp" >/dev/null \
      || ! _watchdogvpn_migration_checkpoint journal-publish \
      || ! run_step sudo mv -f -- "$journal_tmp" "$journal"; then
      printf 'ERROR: unable to publish WatchdogVPN migration recovery journal\n' >&2
      run_step sudo rm -f -- "$journal_tmp"
      run_step sudo rm -rf -- "$stage_dir"
      return 1
    fi
  fi

  while IFS= read -r -d '' entry_name; do
    if ! _watchdogvpn_migration_checkpoint "publish:$entry_name"; then
      printf 'ERROR: WatchdogVPN migration interrupted before publishing %s\n' "$entry_name" >&2
      run_step sudo rm -rf -- "$stage_dir"
      return 1
    fi
    # Each staged top-level entry is published with one same-filesystem rename.
    # A recovery rerun leaves an already-published identical entry untouched;
    # any divergent entry is rejected rather than deleted and falsely repaired.
    if [[ -e "$target_dir/$entry_name" || -L "$target_dir/$entry_name" ]]; then
      if ! run_step sudo diff -r --no-dereference -- \
        "$stage_dir/$entry_name" "$target_dir/$entry_name" >/dev/null; then
        printf 'ERROR: journaled WatchdogVPN migration entry diverged: %s\n' "$entry_name" >&2
        run_step sudo rm -rf -- "$stage_dir"
        return 1
      fi
      continue
    fi
    if ! run_step sudo mv -- "$stage_dir/$entry_name" "$target_dir/$entry_name"; then
      printf 'ERROR: unable to atomically publish WatchdogVPN state entry: %s\n' "$entry_name" >&2
      run_step sudo rm -rf -- "$stage_dir"
      return 1
    fi
  done < <(_watchdogvpn_migration_entries "$stage_dir")
  run_step sudo rm -rf -- "$stage_dir"

  if ! _watchdogvpn_migration_checkpoint target-validate \
    || ! _validate_watchdogvpn_migration_tree "$source_dir" "$target_dir" target-content-validate; then
    printf 'ERROR: published WatchdogVPN legacy state failed content validation; recovery journal retained\n' >&2
    return 1
  fi
  if ! _watchdogvpn_migration_checkpoint marker-publish \
    || ! _publish_watchdogvpn_migration_marker "$marker"; then
    printf 'ERROR: WatchdogVPN shared state is complete but not certified; recovery journal retained\n' >&2
    return 1
  fi
  run_step sudo rm -f -- "$journal"
  printf '[MIGRATE] WatchdogVPN shared state: %s -> %s\n' "$source_dir" "$target_dir"
  repair_watchdogvpn_shared_state_permissions "$target_dir"
}


_watchdogvpn_migration_entries() {
  local directory="$1"
  # sudo is required here: this is also called against the staging directory,
  # which is created with `sudo mktemp -d` and is therefore root-owned and
  # unreadable to the invoking user. A plain `find` silently returns zero
  # entries instead of failing, which made both the publishability check and
  # the publish loop above no-op instead of erroring - the publish loop then
  # left the target directory empty, and target-content-validate correctly
  # caught the resulting divergence, but only after silently discarding the
  # staged legacy state.
  sudo find "$directory" -mindepth 1 -maxdepth 1 \
    ! -name .migrated \
    ! -name .migration-in-progress \
    -printf '%f\0' | sort -z
}


_stage_watchdogvpn_legacy_state() {
  local source_dir="$1" stage_dir="$2" entry_name
  while IFS= read -r -d '' entry_name; do
    if ! _watchdogvpn_migration_checkpoint "stage-copy:$entry_name" \
      || ! run_step sudo cp -a -- "$source_dir/$entry_name" "$stage_dir/$entry_name"; then
      printf 'ERROR: unable to stage WatchdogVPN legacy state entry: %s\n' "$entry_name" >&2
      return 1
    fi
  done < <(_watchdogvpn_migration_entries "$source_dir")
}


_validate_watchdogvpn_migration_tree() {
  local source_dir="$1" candidate_dir="$2" checkpoint="$3" entry_name
  if ! _watchdogvpn_migration_checkpoint "$checkpoint"; then
    return 1
  fi
  while IFS= read -r -d '' entry_name; do
    if ! run_step sudo diff -r --no-dereference -- \
      "$source_dir/$entry_name" "$candidate_dir/$entry_name" >/dev/null; then
      return 1
    fi
  done < <(_watchdogvpn_migration_entries "$source_dir")
}


_watchdogvpn_migration_target_is_publishable() {
  local stage_dir="$1" target_dir="$2" entry_name
  while IFS= read -r -d '' entry_name; do
    if [[ -e "$target_dir/$entry_name" || -L "$target_dir/$entry_name" ]]; then
      return 1
    fi
  done < <(_watchdogvpn_migration_entries "$stage_dir")
  return 0
}


_publish_watchdogvpn_migration_marker() {
  local marker="$1" marker_tmp
  marker_tmp="$(sudo mktemp "${marker}.tmp.XXXXXX")" || return 1
  if ! printf 'watchdogvpn-shared-state-ready-v2\n' | sudo tee "$marker_tmp" >/dev/null \
    || ! run_step sudo mv -f -- "$marker_tmp" "$marker"; then
    run_step sudo rm -f -- "$marker_tmp"
    return 1
  fi
}


_watchdogvpn_migration_checkpoint() {
  # Test seam: unit coverage replaces this function to inject interruptions at
  # every staging, validation, publication, and marker boundary.
  return 0
}

prepare_watchdogvpn_state_directory() {
  local target_dir="$1"
  if [[ "$target_dir" != "/var/lib/watchdogvpn" ]]; then
    printf '[SKIP] non-default WatchdogVPN shared state target is not managed by systemd: %s\n' "$target_dir"
    return 0
  fi
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] ask systemd to create StateDirectory=watchdogvpn\n'
    return 0
  fi
  if ! command -v systemd-run >/dev/null 2>&1; then
    printf 'ERROR: systemd-run is required to prepare StateDirectory=watchdogvpn\n' >&2
    return 1
  fi
  run_step sudo systemd-run \
    --wait \
    --collect \
    --quiet \
    --unit=watchdogvpn-state-directory \
    --property=User=watchdogvpn \
    --property=Group=watchdogvpn \
    --property=StateDirectory=watchdogvpn \
    --property=StateDirectoryMode=2770 \
    /bin/true
}

add_installing_user_to_watchdogvpn_group() {
  local target_user="${SUDO_USER:-${USER:-}}"
  if [[ -z "$target_user" || "$target_user" == "root" ]]; then
    printf '[SKIP] no non-root installing user to add to watchdogvpn group\n'
    return 0
  fi
  if id -nG "$target_user" 2>/dev/null | tr ' ' '\n' | grep -Fxq watchdogvpn; then
    printf '[KEEP] user already in watchdogvpn group: %s\n' "$target_user"
    return 0
  fi
  run_step sudo usermod -a -G watchdogvpn "$target_user"
  warn "added $target_user to watchdogvpn group; open a new login session before using the v2 CLI"
}

repair_watchdogvpn_shared_state_permissions() {
  local target_dir="${1:-${WATCHDOGVPN_SHARED_STATE_DIR:-/var/lib/watchdogvpn}}"
  if [[ "$target_dir" != "/var/lib/watchdogvpn" ]]; then
    printf '[SKIP] non-default WatchdogVPN shared state permissions are caller-managed: %s\n' "$target_dir"
    return 0
  fi
  if [[ ! -d "$target_dir" ]]; then
    printf '[SKIP] WatchdogVPN shared state directory not present: %s\n' "$target_dir"
    return 0
  fi
  run_step sudo chown -R watchdogvpn:watchdogvpn "$target_dir"
  run_step sudo find "$target_dir" -type d -exec chmod 2770 {} +
  run_step sudo find "$target_dir" -type f -exec chmod 0660 {} +
}

smoke_test_watchdogvpn_daemon() {
  local socket_path="${WATCHDOGVPN_SOCKET_PATH:-/run/watchdogvpn/control.sock}"
  local status_output status_rc

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] smoke test watchdogvpn.service and daemon IPC status\n'
    return 0
  fi

  if declare -F runtime_transaction_is_active >/dev/null && runtime_transaction_is_active; then
    runtime_transaction_checkpoint smoke
  fi

  if [[ "${ENABLE_VPN_AUTOMATION:-1}" != "1" ]]; then
    printf '[SKIP] daemon smoke test; VPN automation is disabled for this install\n'
    return 0
  fi

  if [[ -e "${WATCHDOGVPN_HIBERNATE_MARKER:-/etc/watchdogvpn/.hibernating}" ]]; then
    printf '[SKIP] daemon smoke test; WatchdogVPN is asleep (run: watchdog_panic wake)\n'
    return 0
  fi

  if ! systemctl is-active --quiet watchdogvpn.service; then
    fail "watchdogvpn.service is not active after install/update"
    printf 'Check: sudo journalctl -u watchdogvpn --no-pager -n 80\n'
    return 1
  fi

  if ! sudo test -S "$socket_path"; then
    fail "daemon IPC socket was not created: $socket_path"
    printf 'Check: sudo systemctl status watchdogvpn --no-pager\n'
    return 1
  fi

  set +e
  status_output="$(WATCHDOGVPN_SOCKET_PATH="$socket_path" /usr/local/bin/watchdog status --json 2>&1)"
  status_rc=$?
  set -e
  if ((status_rc == 0)); then
    ok "daemon IPC status smoke test passed"
    return 0
  fi

  if grep -Fqi "watchdogvpn' group" <<<"$status_output" \
    || grep -Fqi "permission denied" <<<"$status_output"; then
    warn "daemon is active, but this login session cannot access the IPC socket yet"
    printf 'Open a new login session after the watchdogvpn group change, then run: watchdog status --json\n'
    return 0
  fi

  fail "daemon IPC status smoke test failed"
  printf '%s\n' "$status_output"
  return 1
}

ensure_user_local_bin_path() {
  local path_line='export PATH="$HOME/.local/bin:$PATH"'
  local marker="# WatchdogVPN: user local commands"
  local shell_rc=""

  case "${SHELL:-}" in
    */zsh) shell_rc="$HOME/.zshrc" ;;
    */bash) shell_rc="$HOME/.bashrc" ;;
  esac

  case ":$PATH:" in
    *":$HOME/.local/bin:"*)
      ok "PATH includes ~/.local/bin"
      return 0
      ;;
  esac

  if [[ -z "$shell_rc" ]]; then
    warn "~/.local/bin is not in PATH; run: export PATH=\"\$HOME/.local/bin:\$PATH\""
    return 0
  fi

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] append ~/.local/bin PATH setup to %s\n' "$shell_rc"
    return 0
  fi

  touch "$shell_rc"
  if grep -Fq "$path_line" "$shell_rc"; then
    ok "PATH setup already present in $shell_rc"
    return 0
  fi

  {
    printf '\n%s\n' "$marker"
    printf '%s\n' "$path_line"
  } >> "$shell_rc"
  PATH_UPDATED=1
  warn "added ~/.local/bin to PATH in $shell_rc; open a new terminal or run: source $shell_rc"
}
