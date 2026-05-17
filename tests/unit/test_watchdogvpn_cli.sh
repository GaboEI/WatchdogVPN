#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/bin/watchdogvpn"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
LOG_DIR="$TMP_DIR/logs"
UPDATE_REPO="$TMP_DIR/update-repo"
UPDATE_REMOTE="$TMP_DIR/update-remote.git"
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

init_runtime_update_repo() {
  local repo="$1" remote="$2" branch="${3:-main}"

  git init -q --bare "$remote"
  git init -q -b "$branch" "$repo"
  git -C "$repo" config user.email "test@example.com"
  git -C "$repo" config user.name "WatchdogVPN Test"
  mkdir -p "$repo/bin"
  printf 'initial\n' >"$repo/README.md"
  make_cmd "$repo/update.sh" 'printf "update mock\n"'
  make_cmd "$repo/doctor.sh" 'printf "doctor mock\n"'
  make_cmd "$repo/bin/watchdogvpn" 'printf "watchdogvpn mock\n"'
  git -C "$repo" add README.md update.sh doctor.sh bin/watchdogvpn
  git -C "$repo" commit -q -m initial
  git -C "$repo" remote add origin "$remote"
  git -C "$repo" push -q -u origin "$branch"
  git -C "$remote" symbolic-ref HEAD "refs/heads/$branch"
}

init_local_update_repo() {
  local repo="$1"

  git init -q -b main "$repo"
  git -C "$repo" config user.email "test@example.com"
  git -C "$repo" config user.name "WatchdogVPN Test"
  printf 'initial\n' >"$repo/README.md"
  make_cmd "$repo/update.sh" 'printf "update mock\n"'
  make_cmd "$repo/doctor.sh" 'printf "doctor mock\n"'
  git -C "$repo" add README.md update.sh doctor.sh
  git -C "$repo" commit -q -m initial
}

contains() {
  local haystack="$1" needle="$2"
  grep -Fq "$needle" <<<"$haystack"
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

init_runtime_update_repo "$UPDATE_REPO" "$UPDATE_REMOTE"

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
contains "$help_output" 'Read-only commands:'
contains "$help_output" 'logs          Read recent WatchdogVPN logs without sudo.'
contains "$help_output" 'update-check  Show local repository update status without network access.'
contains "$help_output" 'update-plan   Print safe manual update steps for the current checkout.'
contains "$help_output" 'Configuration commands:'
contains "$help_output" 'Interactive commands:'
contains "$help_output" 'config set    Update a validated safe configuration key.'
contains "$help_output" 'update, connect, disconnect and rotate are intentionally not product CLI'
dash_help_output="$("$SCRIPT" --help)"
[[ "$dash_help_output" == "$help_output" ]]
contains "$("$SCRIPT" help logs)" 'watchdogvpn logs [events|watchdog|rotate|dispatcher] [lines]'
contains "$("$SCRIPT" help update-check)" 'watchdogvpn update-check'
contains "$("$SCRIPT" help update-plan)" 'watchdogvpn update-plan'
contains "$("$SCRIPT" help runtime-update)" 'watchdogvpn runtime-update --preflight'
contains "$("$SCRIPT" help config)" 'Writable safe keys:'
contains "$("$SCRIPT" config help)" 'Reset targets:'
if "$SCRIPT" help missing-topic >/dev/null 2>&1; then
  printf 'FAIL: unknown help topic should fail\n' >&2
  exit 1
fi
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
update_output="$(WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" update-check)"
printf '%s\n' "$update_output" | grep -Fq 'WatchdogVPN update check'
printf '%s\n' "$update_output" | grep -Fq 'Mode: read-only. No fetch, pull, push, update.sh or sudo is executed.'
printf '%s\n' "$update_output" | grep -Fq 'Branch: main'
printf '%s\n' "$update_output" | grep -Fq 'Remote state: up to date'
printf '%s\n' "$update_output" | grep -Fq 'Local changes: clean'
plan_output="$(WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" update-plan)"
printf '%s\n' "$plan_output" | grep -Fq 'WatchdogVPN update plan'
printf '%s\n' "$plan_output" | grep -Fq 'Mode: read-only. This prints commands only; it does not execute them.'
printf '%s\n' "$plan_output" | grep -Fq 'Recommended source routine:'
printf '%s\n' "$plan_output" | grep -Fq 'Source checkout appears current against local upstream metadata.'
printf '%s\n' "$plan_output" | grep -Fq './update.sh --skip-doctor'
runtime_help="$("$SCRIPT" runtime-update --help)"
printf '%s\n' "$runtime_help" | grep -Fq 'watchdogvpn runtime-update --preflight'
printf '%s\n' "$runtime_help" | grep -Fq 'does not fetch, pull, run update.sh'
runtime_preflight="$(WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" runtime-update --preflight)"
printf '%s\n' "$runtime_preflight" | grep -Fq 'WatchdogVPN runtime update'
printf '%s\n' "$runtime_preflight" | grep -Fq 'Mode: preflight only.'
printf '%s\n' "$runtime_preflight" | grep -Fq 'Runtime update preflight: OK'
printf '%s\n' "$runtime_preflight" | grep -Fq 'Execution: not run in this version.'
if WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" runtime-update unexpected >/dev/null 2>&1; then
  printf 'FAIL: runtime-update unexpected argument should fail\n' >&2
  exit 1
fi
printf 'dirty\n' >"$UPDATE_REPO/dirty.txt"
dirty_update_output="$(WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" update-check)"
printf '%s\n' "$dirty_update_output" | grep -Fq 'Local changes: dirty'
printf '%s\n' "$dirty_update_output" | grep -Fq 'Review local changes before updating'
dirty_plan_output="$(WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" update-plan)"
printf '%s\n' "$dirty_plan_output" | grep -Fq 'Review, commit or stash local changes before pulling.'
if printf '%s\n' "$dirty_plan_output" | grep -Fq './update.sh --skip-doctor'; then
  printf 'FAIL: dirty update plan should not recommend runtime update yet\n' >&2
  exit 1
fi
if WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" runtime-update --preflight >/dev/null 2>&1; then
  printf 'FAIL: dirty runtime-update preflight should fail\n' >&2
  exit 1
fi
dirty_preflight="$(WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" runtime-update --preflight 2>&1 || true)"
printf '%s\n' "$dirty_preflight" | grep -Fq 'Reason: working tree is dirty'
not_repo_output="$(WATCHDOGVPN_REPO_DIR="$TMP_DIR/not-a-repo" "$SCRIPT" update-check)"
printf '%s\n' "$not_repo_output" | grep -Fq 'State: not a git checkout'
not_repo_plan="$(WATCHDOGVPN_REPO_DIR="$TMP_DIR/not-a-repo" "$SCRIPT" update-plan)"
printf '%s\n' "$not_repo_plan" | grep -Fq 'Current state: not a git checkout'
not_repo_preflight="$(WATCHDOGVPN_REPO_DIR="$TMP_DIR/not-a-repo" "$SCRIPT" runtime-update --preflight 2>&1 || true)"
printf '%s\n' "$not_repo_preflight" | grep -Fq 'Reason: not a git checkout'
if WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" update-check unexpected >/dev/null 2>&1; then
  printf 'FAIL: update-check unexpected argument should fail\n' >&2
  exit 1
fi
if WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" update-plan unexpected >/dev/null 2>&1; then
  printf 'FAIL: update-plan unexpected argument should fail\n' >&2
  exit 1
fi

NO_UPSTREAM_REPO="$TMP_DIR/no-upstream-repo"
init_local_update_repo "$NO_UPSTREAM_REPO"
no_upstream_preflight="$(WATCHDOGVPN_REPO_DIR="$NO_UPSTREAM_REPO" "$SCRIPT" runtime-update --preflight 2>&1 || true)"
printf '%s\n' "$no_upstream_preflight" | grep -Fq 'Reason: upstream is not configured'

WRONG_BRANCH_REPO="$TMP_DIR/wrong-branch-repo"
WRONG_BRANCH_REMOTE="$TMP_DIR/wrong-branch-remote.git"
init_runtime_update_repo "$WRONG_BRANCH_REPO" "$WRONG_BRANCH_REMOTE" feature
wrong_branch_preflight="$(WATCHDOGVPN_REPO_DIR="$WRONG_BRANCH_REPO" "$SCRIPT" runtime-update --preflight 2>&1 || true)"
printf '%s\n' "$wrong_branch_preflight" | grep -Fq 'Reason: current branch is not main'

AHEAD_REPO="$TMP_DIR/ahead-repo"
AHEAD_REMOTE="$TMP_DIR/ahead-remote.git"
init_runtime_update_repo "$AHEAD_REPO" "$AHEAD_REMOTE"
printf 'ahead\n' >>"$AHEAD_REPO/README.md"
git -C "$AHEAD_REPO" add README.md
git -C "$AHEAD_REPO" commit -q -m ahead
ahead_preflight="$(WATCHDOGVPN_REPO_DIR="$AHEAD_REPO" "$SCRIPT" runtime-update --preflight 2>&1 || true)"
printf '%s\n' "$ahead_preflight" | grep -Fq 'Reason: branch is ahead of upstream'

DIVERGED_REPO="$TMP_DIR/diverged-repo"
DIVERGED_REMOTE="$TMP_DIR/diverged-remote.git"
DIVERGED_OTHER="$TMP_DIR/diverged-other"
init_runtime_update_repo "$DIVERGED_REPO" "$DIVERGED_REMOTE"
git clone -q "$DIVERGED_REMOTE" "$DIVERGED_OTHER"
git -C "$DIVERGED_OTHER" config user.email "test@example.com"
git -C "$DIVERGED_OTHER" config user.name "WatchdogVPN Test"
printf 'remote\n' >>"$DIVERGED_OTHER/README.md"
git -C "$DIVERGED_OTHER" add README.md
git -C "$DIVERGED_OTHER" commit -q -m remote-change
git -C "$DIVERGED_OTHER" push -q origin main
git -C "$DIVERGED_REPO" fetch -q origin main
printf 'local\n' >>"$DIVERGED_REPO/README.md"
git -C "$DIVERGED_REPO" add README.md
git -C "$DIVERGED_REPO" commit -q -m local-change
diverged_preflight="$(WATCHDOGVPN_REPO_DIR="$DIVERGED_REPO" "$SCRIPT" runtime-update --preflight 2>&1 || true)"
printf '%s\n' "$diverged_preflight" | grep -Fq 'Reason: branch diverged from upstream'

MISSING_UPDATE_REPO="$TMP_DIR/missing-update-repo"
MISSING_UPDATE_REMOTE="$TMP_DIR/missing-update-remote.git"
init_runtime_update_repo "$MISSING_UPDATE_REPO" "$MISSING_UPDATE_REMOTE"
rm -f "$MISSING_UPDATE_REPO/update.sh"
git -C "$MISSING_UPDATE_REPO" add -u update.sh
git -C "$MISSING_UPDATE_REPO" commit -q -m missing-update
git -C "$MISSING_UPDATE_REPO" push -q origin main
missing_update_preflight="$(WATCHDOGVPN_REPO_DIR="$MISSING_UPDATE_REPO" "$SCRIPT" runtime-update --preflight 2>&1 || true)"
printf '%s\n' "$missing_update_preflight" | grep -Fq 'Reason: update.sh is missing or not executable'

MISSING_DOCTOR_REPO="$TMP_DIR/missing-doctor-repo"
MISSING_DOCTOR_REMOTE="$TMP_DIR/missing-doctor-remote.git"
init_runtime_update_repo "$MISSING_DOCTOR_REPO" "$MISSING_DOCTOR_REMOTE"
rm -f "$MISSING_DOCTOR_REPO/doctor.sh"
git -C "$MISSING_DOCTOR_REPO" add -u doctor.sh
git -C "$MISSING_DOCTOR_REPO" commit -q -m missing-doctor
git -C "$MISSING_DOCTOR_REPO" push -q origin main
missing_doctor_preflight="$(WATCHDOGVPN_REPO_DIR="$MISSING_DOCTOR_REPO" "$SCRIPT" runtime-update --preflight 2>&1 || true)"
printf '%s\n' "$missing_doctor_preflight" | grep -Fq 'Reason: doctor.sh is missing or not executable'
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
printf '%s\n' "$version_output" | grep -Fq "WatchdogVPN v0.3.0"
if printf '%s\n' "$version_output" | grep -Fq -- "-dev"; then
  printf 'FAIL: published CLI version must not use a -dev suffix\n' >&2
  exit 1
fi

printf 'watchdogvpn CLI checks passed\n'
