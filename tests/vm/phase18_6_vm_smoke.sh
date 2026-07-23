#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-}"
STATE_DIR="${WATCHDOGVPN_SHARED_STATE_DIR:-/var/lib/watchdogvpn}"
CONFIG_DIR="${WATCHDOGVPN_ETC_CONFIG_DIR:-/etc/watchdogvpn}"
CONFIG_FILE="${WATCHDOGVPN_CONFIG_FILE:-$CONFIG_DIR/config.toml}"
VERSION_MARKER="${WATCHDOGVPN_VERSION_MARKER:-$CONFIG_DIR/installed-version}"
LOG_DIR="${WATCHDOGVPN_VM_SMOKE_LOG_DIR:-/tmp/watchdogvpn-phase18-6}"

usage() {
  cat <<'USAGE'
Phase 18.6 VM smoke helper

Usage:
  WATCHDOGVPN_VM_SMOKE=1 tests/vm/phase18_6_vm_smoke.sh install-baseline
  WATCHDOGVPN_VM_SMOKE=1 tests/vm/phase18_6_vm_smoke.sh update-preserve

Modes:
  install-baseline  Run a real install on a VM/snapshot and verify install
                    markers plus fresh shared-state convergence.
  update-preserve   Seed valid state/config plus known legacy artifacts, run a
                    real update, and verify state preservation, backups,
                    daemon, version marker, PATH and legacy cleanup.

This script intentionally mutates system install paths. Run it only inside a
disposable VM or snapshot dedicated to installer validation.
USAGE
}

require_vm_guard() {
  if [[ "${WATCHDOGVPN_VM_SMOKE:-0}" != "1" ]]; then
    printf 'ERROR: refusing to run without WATCHDOGVPN_VM_SMOKE=1\n' >&2
    usage >&2
    exit 64
  fi
}

section() {
  printf '\n== %s ==\n' "$1"
}

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

sudo_run() {
  run sudo "$@"
}

require_repo_synced() {
  section "Repository"
  run git status --short --branch
  run git rev-parse HEAD
}

write_supported_config() {
  section "Seed supported backend config"
  sudo_run install -d -m 0755 -o root -g root "$CONFIG_DIR"
  sudo tee "$CONFIG_FILE" >/dev/null <<'CFG'
# Phase 18.6 VM smoke config. Contains no secrets.

[backend]
mode = "custom-vps"
active = "custom-vps"

[custom_vps]
enabled = true
name = "phase18-smoke"
host = "127.0.0.1"
ssh_user = ""
ssh_port = 22
protocol = "http"
profile_path = ""
service_name = "watchdogvpn-phase18-smoke.service"
interface = ""

[language]
current = "en"
auto_detect = true

[dns]
advanced_mode = false
profile = "quad9-doh"

[tui]
theme = "default"
color = true
unicode = true

[reporting]
sanitize_ipv4 = true
sanitize_ipv6 = true
sanitize_email = true
sanitize_home = true
CFG
  sudo_run chmod 0644 "$CONFIG_FILE"
}

seed_runtime_state() {
  section "Seed runtime state"
  sudo_run install -d -m 2770 -o root -g root "$STATE_DIR"
  sudo env PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
    WATCHDOGVPN_CONFIG_DIR="$STATE_DIR" \
    python3 - <<'PY'
from datetime import datetime, timezone

from app_policy.models import AppPolicy, AppPolicyAction, AppPolicyMode, AppPolicyRule
from app_policy.store import AppPolicyStore
from config.dns_policy_store import DNSPolicyStore
from config.state_manager import StateManager
from dns.models import (
    DNSChannel,
    DNSChannelName,
    DNSMode,
    DNSPolicy,
    DNSRule,
    Resolver,
    StaticIPEntry,
)
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider
from config.profile_store import ProfileStore
from config.provider_store import ProviderStore
from node_groups.models import NodeGroup
from node_groups.store import NodeGroupStore
from rules.models import Rule, RuleGroup
from rules.rule_store import RuleStore

now = datetime(2026, 7, 7, 0, 0, 0, tzinfo=timezone.utc)
profile_id = "phase18-profile"

ProfileStore().add(
    Profile(
        id=profile_id,
        name="Phase 18 Smoke Profile",
        protocol=ProtocolType.HTTP,
        config={"server": "127.0.0.1", "port": 18080},
        source=ProfileSource.MANUAL,
        provider_id="phase18-provider",
        in_rotation_pool=True,
        enabled=True,
        created_at=now,
        health_status="unknown",
    )
)
ProviderStore().add(
    Provider(
        id="phase18-provider",
        name="Phase 18 Smoke Provider",
        url="file:///phase18-smoke",
        last_updated=now.replace(tzinfo=None),
        profiles=[profile_id],
        rotation_enabled=True,
        auto_update=False,
        metadata={"phase": "18.6"},
    )
)
RuleStore().add_group(
    RuleGroup(
        name="phase18-smoke",
        priority=42,
        rules=[
            Rule(
                id="phase18-direct",
                action="direct",
                conditions={"domain_suffix": ["phase18.example"]},
            )
        ],
    )
)
AppPolicyStore().save(
    AppPolicy(
        enabled=True,
        mode=AppPolicyMode.BLACKLIST,
        default_action=AppPolicyAction.CURRENT,
        rules=[
            AppPolicyRule(
                id="phase18-app",
                action=AppPolicyAction.DIRECT,
                match={"process_name": ["phase18-smoke"]},
            )
        ],
    )
)
NodeGroupStore().add(
    NodeGroup(
        name="phase18-smoke",
        member_profile_ids=[profile_id],
    )
)
DNSPolicyStore().save(
    DNSPolicy(
        mode=DNSMode.CUSTOM,
        channels={
            DNSChannelName.DIRECT: DNSChannel(
                name=DNSChannelName.DIRECT,
                resolvers=[Resolver(uri="udp://1.1.1.1", label="Phase 18 smoke")],
            )
        },
        static_ips=[StaticIPEntry(domain="phase18.example", ip="203.0.113.10")],
        rules=[
            DNSRule(
                id="phase18-dns",
                pattern="suffix:phase18.example",
                channel=DNSChannelName.DIRECT,
            )
        ],
        static_ip_enabled=True,
        rules_enabled=True,
        test_domain="phase18.example",
    )
)
StateManager().save(
    {
        "app_autostart_enabled": False,
        "vpn_autoconnect_enabled": False,
        "vpn_desired_state": "off",
        "active_profile_id": profile_id,
        "active_mode": "rules",
        "language_mode": "manual",
        "selected_language": "en",
    }
)
PY
  if getent passwd watchdogvpn >/dev/null 2>&1 && getent group watchdogvpn >/dev/null 2>&1; then
    sudo_run chown -R watchdogvpn:watchdogvpn "$STATE_DIR"
    sudo_run find "$STATE_DIR" -type d -exec chmod 2770 {} +
    sudo_run find "$STATE_DIR" -type f -exec chmod 0660 {} +
  fi
}

seed_legacy_artifacts() {
  section "Seed known legacy artifacts"
  sudo_run install -d -m 0755 -o root -g root /usr/local/bin /usr/local/sbin /etc/systemd/system
  sudo tee /usr/local/bin/vpn_auth_check >/dev/null <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  sudo tee /usr/local/sbin/vpn_rotate.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  sudo tee /usr/local/sbin/vpn_watchdog.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  sudo tee /usr/local/sbin/vpn_set >/dev/null <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  sudo_run chmod 0755 /usr/local/bin/vpn_auth_check /usr/local/sbin/vpn_rotate.sh /usr/local/sbin/vpn_watchdog.sh /usr/local/sbin/vpn_set
  sudo tee /etc/systemd/system/adguardvpn.service >/dev/null <<'EOF'
[Unit]
Description=Phase 18 legacy smoke placeholder

[Service]
Type=oneshot
ExecStart=/bin/true
EOF
}

state_manifest() {
  sudo python3 - "$STATE_DIR" <<'PY'
from hashlib import sha256
from pathlib import Path
import sys

root = Path(sys.argv[1])
relative_paths = [
    "profiles.json",
    "providers.json",
    "rules/phase18-smoke.json",
    "app-policy.json",
    "node_groups.json",
    "dns-policy.json",
    "state.toml",
]
for rel in relative_paths:
    path = root / rel
    if not path.exists():
        print(f"MISSING  {rel}")
        continue
    print(f"{sha256(path.read_bytes()).hexdigest()}  {rel}")
PY
}

file_hash() {
  local path="$1"
  sudo sha256sum "$path" | awk '{print $1}'
}

verify_installed_version_marker() {
  section "Installed/source version marker"
  local installed source
  installed="$(sudo awk -F= '$1 == "commit" {print $2; exit}' "$VERSION_MARKER")"
  source="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  printf 'installed=%s\nsource=%s\n' "$installed" "$source"
  [[ "$installed" == "$source" ]]
}

verify_path_resolution() {
  section "PATH resolution"
  hash -r
  command -v watchdog || true
  command -v watchdogvpn || true
  command -v watchdogvpn-daemon || true
  [[ "$(command -v watchdogvpn)" == "/usr/local/bin/watchdogvpn" ]]
  [[ "$(command -v watchdog)" == "/usr/local/bin/watchdog" ]]
  [[ "$(command -v watchdogvpn-daemon)" == "/usr/local/bin/watchdogvpn-daemon" ]]
}

verify_runtime_files() {
  section "Runtime files"
  cmp -s "$ROOT_DIR/bin/watchdogvpn" /usr/local/bin/watchdogvpn
  grep -Fq 'ROOT_DIR=/usr/local/lib/watchdogvpn' /usr/local/bin/watchdog
  grep -Fq -- '-m cli.main "$@"' /usr/local/bin/watchdog
  grep -Fq -- '-m daemon.main "$@"' /usr/local/bin/watchdogvpn-daemon
  systemctl show watchdogvpn.service -p ExecStart --value
  systemctl show watchdogvpn.service -p ExecStart --value | grep -Fq /usr/local/bin/watchdogvpn-daemon
}

verify_daemon() {
  section "Daemon"
  systemctl is-active watchdogvpn.service
  systemctl is-enabled watchdogvpn.service
  sudo test -S /run/watchdogvpn/control.sock
  sudo /usr/local/bin/watchdog status --json >/tmp/watchdogvpn-phase18-6-watchdog-status.json
  cat /tmp/watchdogvpn-phase18-6-watchdog-status.json
}

verify_legacy_removed() {
  section "Legacy cleanup"
  local path
  for path in \
    /usr/local/bin/vpn_auth_check \
    /usr/local/sbin/vpn_rotate.sh \
    /usr/local/sbin/vpn_watchdog.sh \
    /usr/local/sbin/vpn_set \
    /etc/systemd/system/adguardvpn.service
  do
    if [[ -e "$path" || -L "$path" ]]; then
      printf 'legacy artifact still exists: %s\n' "$path" >&2
      return 1
    fi
    printf 'removed: %s\n' "$path"
  done
}

verify_backups_available() {
  section "Backups"
  sudo find /var/backups/watchdogvpn -type f -path '*/usr/local/bin/watchdogvpn.*' -print -quit | grep -q .
  sudo find /var/backups/watchdogvpn -type f -path '*/usr/local/lib/watchdogvpn.*/*' -print -quit | grep -q .
  sudo find /var/backups/watchdogvpn -type f | tail -20
}

run_doctor_report() {
  section "Doctor"
  set +e
  "$ROOT_DIR/doctor.sh"
  local rc=$?
  set -e
  printf 'doctor_rc=%s\n' "$rc"
  return 0
}

install_baseline() {
  require_repo_synced
  write_supported_config
  section "Real install"
  mkdir -p "$LOG_DIR"
  run "$ROOT_DIR/install.sh" --yes --skip-doctor 2>&1 | tee "$LOG_DIR/install-baseline.log"

  section "Fresh shared-state convergence"
  sudo test -d "$STATE_DIR"
  sudo test -f "$STATE_DIR/.migrated"
  sudo -u watchdogvpn env PYTHONPATH="/usr/local/lib/watchdogvpn" \
    python3 - <<'PY'
from config.paths import resolve_config_dir
print(resolve_config_dir())
assert str(resolve_config_dir()) == "/var/lib/watchdogvpn"
PY
  verify_installed_version_marker
  verify_path_resolution
  run_doctor_report
}

update_preserve() {
  require_repo_synced
  write_supported_config
  seed_runtime_state
  seed_legacy_artifacts

  local before_state after_state before_config after_config
  before_state="$(state_manifest)"
  before_config="$(file_hash "$CONFIG_FILE")"
  section "State manifest before update"
  printf '%s\n' "$before_state"

  section "Preflight dry-run"
  run "$ROOT_DIR/update.sh" --dry-run --yes --skip-doctor

  section "Real update"
  mkdir -p "$LOG_DIR"
  run "$ROOT_DIR/update.sh" --yes --skip-doctor 2>&1 | tee "$LOG_DIR/update-preserve.log"

  after_state="$(state_manifest)"
  after_config="$(file_hash "$CONFIG_FILE")"
  section "State manifest after update"
  printf '%s\n' "$after_state"

  section "Preservation assertions"
  [[ "$before_state" == "$after_state" ]]
  [[ "$before_config" == "$after_config" ]]
  printf 'state_preserved=yes\nconfig_preserved=yes\n'

  verify_daemon
  verify_installed_version_marker
  verify_runtime_files
  verify_path_resolution
  verify_legacy_removed
  verify_backups_available
  run_doctor_report
}

require_vm_guard

case "$MODE" in
  install-baseline)
    install_baseline
    ;;
  update-preserve)
    update_preserve
    ;;
  --help|-h|"")
    usage
    [[ -n "$MODE" ]]
    ;;
  *)
    printf 'ERROR: unknown mode: %s\n' "$MODE" >&2
    usage >&2
    exit 64
    ;;
esac

section "Phase 18.6 VM smoke result"
printf 'mode=%s\nresult=PASS\n' "$MODE"
