#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE="$ROOT_DIR/systemd/watchdogvpn.service"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  if ! grep -Fq -- "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    printf 'missing pattern in %s: %s\n' "$file" "$pattern" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1" pattern="$2" message="$3"
  if grep -Fq "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    printf 'unexpected pattern in %s: %s\n' "$file" "$pattern" >&2
    exit 1
  fi
}

assert_contains "$SERVICE" "Type=notify" "daemon unit must use sd_notify readiness"
assert_contains "$SERVICE" "User=watchdogvpn" "daemon unit must run as dedicated watchdogvpn user"
assert_contains "$SERVICE" "Group=watchdogvpn" "daemon unit must run as dedicated watchdogvpn group"
assert_contains "$SERVICE" "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH" "daemon unit must grant confirmed ambient capabilities"
assert_contains "$SERVICE" "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH" "daemon unit must keep bounding set coherent with ambient capabilities"
assert_contains "$SERVICE" "DevicePolicy=closed" "daemon unit must deny device access by default"
assert_contains "$SERVICE" "DeviceAllow=/dev/net/tun rw" "daemon unit must allow TUN device access"
assert_contains "$SERVICE" "RuntimeDirectory=watchdogvpn" "daemon unit must let systemd manage /run/watchdogvpn"
assert_contains "$SERVICE" "RuntimeDirectory=watchdogvpn amneziawg" "daemon unit must also expose /run/amneziawg for amneziawg-go's UAPI socket under ProtectSystem=strict"
assert_contains "$SERVICE" "RuntimeDirectoryMode=0750" "daemon runtime directory must be group-traversable for IPC"
assert_contains "$SERVICE" "StateDirectory=watchdogvpn" "daemon unit must let systemd manage /var/lib/watchdogvpn"
assert_contains "$SERVICE" "StateDirectoryMode=2770" "daemon state directory must be writable through the watchdogvpn group with setgid inheritance"
assert_contains "$SERVICE" "ConfigurationDirectory=watchdogvpn" "daemon unit must declare managed configuration directory"
assert_contains "$SERVICE" "ConfigurationDirectoryMode=0750" "daemon configuration directory mode must match what the installer creates"
# Regression guard: lib/config.sh used to create /etc/watchdogvpn at 0755
# while this unit declared ConfigurationDirectoryMode=0750, so the daemon
# warned about a mode mismatch on every single start. Pin both literals here
# so the two files can never silently re-drift from each other again.
assert_contains "$ROOT_DIR/lib/config.sh" 'create_owned_dir "$WATCHDOGVPN_ETC_CONFIG_DIR" root watchdogvpn 0750' "installer must create /etc/watchdogvpn as the private watchdogvpn-group directory systemd expects"
assert_contains "$ROOT_DIR/lib/config.sh" '0640 watchdogvpn' "installer must make product config readable by the watchdogvpn group, not other users"
assert_contains "$SERVICE" "Environment=WATCHDOGVPN_RUNTIME_DIR=/run/watchdogvpn" "daemon unit must place driver scratch files in /run/watchdogvpn"
assert_contains "$SERVICE" "ExecStart=/usr/local/bin/watchdogvpn-daemon" "daemon unit must use the installed daemon wrapper"
assert_contains "$SERVICE" "NoNewPrivileges=true" "daemon unit must include hardening"
assert_contains "$SERVICE" "ProtectSystem=strict" "daemon unit must protect system paths"
assert_contains "$SERVICE" "ProtectHome=read-only" "daemon unit must read the raw checkout under /home without write access"
assert_contains "$SERVICE" "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" "daemon unit must keep required socket families explicit"
assert_not_contains "$SERVICE" "DynamicUser=true" "daemon unit must use the persistent dedicated service user"

assert_contains "$ROOT_DIR/bin/watchdogvpn-daemon" 'exec "$(watchdogvpn_python)" -m daemon.main' "daemon wrapper must execute daemon.main via the resolved Python"
assert_contains "$ROOT_DIR/lib/install_files.sh" "useradd --system --no-create-home --shell" "watchdogvpn user creation must not create a home directory"
assert_not_contains "$ROOT_DIR/lib/install_files.sh" "create_owned_dir /var/lib/watchdogvpn" "install helper must not own the daemon state directory"
assert_contains "$ROOT_DIR/lib/runtime.sh" "add_installing_user_to_watchdogvpn_group" "runtime install must authorize the installing user for shared daemon state and IPC"
assert_contains "$ROOT_DIR/lib/runtime.sh" 'usermod -a -G watchdogvpn "$target_user"' "installer must add the invoking user to the watchdogvpn group"
assert_contains "$ROOT_DIR/lib/runtime.sh" "repair_watchdogvpn_shared_state_permissions" "runtime install must repair shared state permissions after migration"
assert_contains "$ROOT_DIR/lib/runtime.sh" "StateDirectory=watchdogvpn" "install migration must ask systemd to prepare the daemon state directory"
assert_contains "$ROOT_DIR/lib/runtime.sh" "StateDirectoryMode=2770" "state directory preparation must use group-writable setgid permissions"
assert_not_contains "$ROOT_DIR/lib/runtime.sh" "create_root_dir /var/lib/watchdogvpn" "runtime install must not create daemon state manually"
assert_contains "$ROOT_DIR/lib/systemd.sh" "watchdogvpn.service" "new daemon unit must be registered for install and enable"
assert_contains "$ROOT_DIR/.github/workflows/ci.yml" "useradd --system --no-create-home --shell /usr/sbin/nologin watchdogvpn" "CI verify must stub the watchdogvpn user"
assert_contains "$ROOT_DIR/.github/workflows/ci.yml" "/usr/local/bin/watchdogvpn-daemon" "CI verify must stub the daemon wrapper"

# shellcheck source=../../lib/common.sh
. "$ROOT_DIR/lib/common.sh"
# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"
# shellcheck source=../../lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"

install_root_file() {
  local src="$1" dest="$2" mode="$3"
  cp "$src" "$TMP_DIR/$(basename "$dest")"
  chmod "$mode" "$TMP_DIR/$(basename "$dest")"
}

PYTHON_PACKAGE_DIR="$TMP_DIR/python-runtime"
install_python_module_wrapper /usr/local/bin/watchdogvpn-daemon daemon.main
assert_contains "$TMP_DIR/watchdogvpn-daemon" "ROOT_DIR=$TMP_DIR/python-runtime" "installed daemon wrapper must pin the installed Python runtime path"
assert_contains "$TMP_DIR/watchdogvpn-daemon" "exec $(watchdogvpn_python) -m tools.installed_provenance launch-daemon" "installed daemon wrapper must use the verified daemon launcher"
assert_contains "$TMP_DIR/watchdogvpn-daemon" "--deployment /usr/local/bin/watchdogvpn-daemon --deployment /etc/systemd/system/watchdogvpn.service" "daemon generation must include the active wrapper and unit"
[[ "$WATCHDOGVPN_EXPECTED_DAEMON_WRAPPER_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'FAIL: wrapper installation must retain its expected pre-install hash\n' >&2
  exit 1
}

echo "watchdogvpn systemd contract checks passed"
