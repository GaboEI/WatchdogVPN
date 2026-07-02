#!/usr/bin/env bash
set -euo pipefail

PYTHON_PACKAGE_DIR="${PYTHON_PACKAGE_DIR:-/usr/local/lib/watchdogvpn}"
PYTHON_RUNTIME_PACKAGES=(
  cli
  config
  core
  daemon
  dns
  drivers
  models
  parsers
  providers
  rotation
  rules
)

install_runtime_files() {
  create_service_user adgvpn /var/lib/adguardvpn
  create_system_user_no_home watchdogvpn
  create_root_dir /var/log/myvpn 0755
  create_root_dir /var/lib/vpn-rotate 0700

  create_config_if_missing "$ROOT_DIR/examples/adguardvpn.env.example" /etc/adguardvpn.env 0644
  create_config_if_missing "$ROOT_DIR/examples/vpn-domain-bypass.conf.example" /etc/vpn-domain-bypass.conf 0644
  install_config_defaults
  migrate_watchdogvpn_shared_state
  install_python_package_tree

  install_root_file "$ROOT_DIR/bin/no_vpn" /usr/local/bin/no_vpn 0755
  install_root_file "$ROOT_DIR/bin/vpn_auth_check" /usr/local/bin/vpn_auth_check 0755
  install_root_file "$ROOT_DIR/bin/vpn_dns_rescue" /usr/local/bin/vpn_dns_rescue 0755
  install_root_file "$ROOT_DIR/bin/vpn_backend" /usr/local/bin/vpn_backend 0755
  install_root_file "$ROOT_DIR/bin/vpn_manual_state" /usr/local/bin/vpn_manual_state 0755
  install_root_file "$ROOT_DIR/bin/vpn_notify" /usr/local/bin/vpn_notify 0755
  install_root_file "$ROOT_DIR/bin/vpn_truth_check" /usr/local/bin/vpn_truth_check 0755
  install_root_file "$ROOT_DIR/bin/vpnctl" /usr/local/bin/vpnctl 0755
  install_python_module_wrapper /usr/local/bin/watchdog cli.main
  install_root_file "$ROOT_DIR/bin/watchdogvpn" /usr/local/bin/watchdogvpn 0755
  install_python_module_wrapper /usr/local/bin/watchdogvpn-daemon daemon.main

  install_root_file "$ROOT_DIR/sbin/vpn_domain_bypass_apply.sh" /usr/local/sbin/vpn_domain_bypass_apply.sh 0700
  install_root_file "$ROOT_DIR/sbin/vpn_rotate.sh" /usr/local/sbin/vpn_rotate.sh 0700
  install_root_file "$ROOT_DIR/sbin/vpn_set" /usr/local/sbin/vpn_set 0700
  install_root_file "$ROOT_DIR/sbin/vpn_watchdog.sh" /usr/local/sbin/vpn_watchdog.sh 0700

  install_user_file "$ROOT_DIR/tui/VPN" "$HOME/.local/bin/VPN" 0755
  remove_user_path "$HOME/.local/bin/watchdogvpn"
  install_user_dir "$ROOT_DIR/tui/watchdogvpn" "$HOME/.local/share/watchdogvpn/watchdogvpn"
  install_root_file "$ROOT_DIR/networkmanager/dispatcher.d/99-vpn-rotate" /etc/NetworkManager/dispatcher.d/99-vpn-rotate 0755
  install_root_file "$ROOT_DIR/etc/logrotate.d/myvpn" /etc/logrotate.d/myvpn 0644
  install_systemd_units
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
  local dest="${1:-$PYTHON_PACKAGE_DIR}" package
  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] install Python runtime packages to %s\n' "$dest"
    return 0
  fi
  backup_path "$dest"
  run_step sudo rm -rf -- "$dest"
  run_step sudo install -d -m 0755 -o root -g root "$dest"
  for package in "${PYTHON_RUNTIME_PACKAGES[@]}"; do
    run_step sudo cp -a "$ROOT_DIR/$package" "$dest/"
  done
  run_step sudo chown -R root:root "$dest"
  run_step sudo find "$dest" -type d -exec chmod 0755 {} +
  run_step sudo find "$dest" -type f -exec chmod 0644 {} +
}

migrate_watchdogvpn_shared_state() {
  local source_dir="${WATCHDOGVPN_LEGACY_CONFIG_DIR:-$HOME/.config/watchdogvpn}"
  local target_dir="${WATCHDOGVPN_SHARED_STATE_DIR:-/var/lib/watchdogvpn}"
  local marker="$target_dir/.migrated"

  if [[ -e "$marker" ]]; then
    printf '[KEEP] WatchdogVPN shared state already migrated: %s\n' "$target_dir"
    return 0
  fi
  if [[ ! -d "$source_dir" ]]; then
    printf '[SKIP] no legacy WatchdogVPN user state: %s\n' "$source_dir"
    return 0
  fi
  if [[ -z "$(find "$source_dir" -mindepth 1 ! -name .migrated -print -quit)" ]]; then
    printf '[SKIP] legacy WatchdogVPN user state is empty: %s\n' "$source_dir"
    return 0
  fi
  if [[ -e "$target_dir" && ! -d "$target_dir" ]]; then
    printf 'ERROR: WatchdogVPN shared state target is not a directory: %s\n' "$target_dir" >&2
    return 1
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
    printf '[DRY-RUN] migrate WatchdogVPN state %s -> %s\n' "$source_dir" "$target_dir"
    return 0
  fi

  run_step sudo cp -a --update=none "$source_dir/." "$target_dir/"
  run_step sudo touch "$marker"
  printf '[MIGRATE] WatchdogVPN shared state: %s -> %s\n' "$source_dir" "$target_dir"
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
    --property=StateDirectoryMode=0750 \
    /bin/true
}

refresh_installed_desktop_launcher() {
  if [[ -f "$HOME/.local/share/applications/watchdogvpn.desktop" ]]; then
    install_desktop_launcher
  fi
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
