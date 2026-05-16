#!/usr/bin/env bash
set -euo pipefail

install_runtime_files() {
  create_service_user adgvpn /var/lib/adguardvpn
  create_root_dir /var/log/myvpn 0755
  create_root_dir /var/lib/vpn-rotate 0700

  create_config_if_missing "$ROOT_DIR/examples/adguardvpn.env.example" /etc/adguardvpn.env 0644
  create_config_if_missing "$ROOT_DIR/examples/vpn-domain-bypass.conf.example" /etc/vpn-domain-bypass.conf 0644
  install_config_defaults

  install_root_file "$ROOT_DIR/bin/no_vpn" /usr/local/bin/no_vpn 0755
  install_root_file "$ROOT_DIR/bin/vpn_auth_check" /usr/local/bin/vpn_auth_check 0755
  install_root_file "$ROOT_DIR/bin/vpn_dns_rescue" /usr/local/bin/vpn_dns_rescue 0755
  install_root_file "$ROOT_DIR/bin/vpn_dnsctl" /usr/local/bin/vpn_dnsctl 0755
  install_root_file "$ROOT_DIR/bin/vpn_notify" /usr/local/bin/vpn_notify 0755
  install_root_file "$ROOT_DIR/bin/vpn_truth_check" /usr/local/bin/vpn_truth_check 0755
  install_root_file "$ROOT_DIR/bin/vpnctl" /usr/local/bin/vpnctl 0755
  install_root_file "$ROOT_DIR/bin/watchdogvpn" /usr/local/bin/watchdogvpn 0755

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
