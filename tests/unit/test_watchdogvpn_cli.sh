#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/bin/watchdogvpn"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
LOG_DIR="$TMP_DIR/logs"
UPDATE_REPO="$TMP_DIR/update-repo"
UPDATE_REMOTE="$TMP_DIR/update-remote.git"
REAL_GIT="$(command -v git)"
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

run_confirmed_runtime_update() {
  local repo="$1" log="$2" git_wrapper_dir="$3"
  printf 'yes\n' | \
    PATH="$git_wrapper_dir:$PATH" \
    WATCHDOGVPN_REAL_GIT="$REAL_GIT" \
    WATCHDOGVPN_REPO_DIR="$repo" \
    WATCHDOGVPN_TEST_STEP_LOG="$log" \
    "$SCRIPT" runtime-update 2>&1
}

make_runtime_git_wrapper() {
  local path="$1" mode="${2:-success}"

  case "$mode" in
    success)
      make_cmd "$path" \
        'if [[ "${1:-}" == "-C" ]]; then' \
        '  repo="$2"' \
        '  shift 2' \
        '  if [[ "${1:-}" == "fetch" && "${2:-}" == "origin" && "${3:-}" == "--tags" ]]; then' \
        '    printf "git fetch origin --tags\n" >>"$WATCHDOGVPN_TEST_STEP_LOG"' \
        '  fi' \
        '  if [[ "${1:-}" == "pull" && "${2:-}" == "--ff-only" && "${3:-}" == "origin" && "${4:-}" == "main" ]]; then' \
        '    printf "git pull --ff-only origin main\n" >>"$WATCHDOGVPN_TEST_STEP_LOG"' \
        '  fi' \
        '  exec "$WATCHDOGVPN_REAL_GIT" -C "$repo" "$@"' \
        'fi' \
        'exec "$WATCHDOGVPN_REAL_GIT" "$@"'
      ;;
    fail-fetch)
      make_cmd "$path" \
        'if [[ "${1:-}" == "-C" ]]; then' \
        '  repo="$2"' \
        '  shift 2' \
        '  if [[ "${1:-}" == "fetch" && "${2:-}" == "origin" && "${3:-}" == "--tags" ]]; then' \
        '    printf "git fetch origin --tags\n" >>"$WATCHDOGVPN_TEST_STEP_LOG"' \
        '    exit 42' \
        '  fi' \
        '  if [[ "${1:-}" == "pull" && "${2:-}" == "--ff-only" && "${3:-}" == "origin" && "${4:-}" == "main" ]]; then' \
        '    printf "git pull --ff-only origin main\n" >>"$WATCHDOGVPN_TEST_STEP_LOG"' \
        '  fi' \
        '  exec "$WATCHDOGVPN_REAL_GIT" -C "$repo" "$@"' \
        'fi' \
        'exec "$WATCHDOGVPN_REAL_GIT" "$@"'
      ;;
    fail-pull)
      make_cmd "$path" \
        'if [[ "${1:-}" == "-C" ]]; then' \
        '  repo="$2"' \
        '  shift 2' \
        '  if [[ "${1:-}" == "fetch" && "${2:-}" == "origin" && "${3:-}" == "--tags" ]]; then' \
        '    printf "git fetch origin --tags\n" >>"$WATCHDOGVPN_TEST_STEP_LOG"' \
        '  fi' \
        '  if [[ "${1:-}" == "pull" && "${2:-}" == "--ff-only" && "${3:-}" == "origin" && "${4:-}" == "main" ]]; then' \
        '    printf "git pull --ff-only origin main\n" >>"$WATCHDOGVPN_TEST_STEP_LOG"' \
        '    exit 43' \
        '  fi' \
        '  exec "$WATCHDOGVPN_REAL_GIT" -C "$repo" "$@"' \
        'fi' \
        'exec "$WATCHDOGVPN_REAL_GIT" "$@"'
      ;;
    *)
      printf 'unknown git wrapper mode: %s\n' "$mode" >&2
      return 64
      ;;
  esac
}

force_remote_back_one_commit() {
  local repo="$1" remote="$2" previous
  previous="$(git -C "$repo" rev-parse HEAD~1)"
  git --git-dir="$remote" update-ref refs/heads/main "$previous"
}

make_cmd "$TMP_DIR/truth" \
  'printf "STATUS=UP\nTUN=UP\nROUTE=TUN\nIP=OK\nIP_ADDR=198.51.100.10\n"'
make_cmd "$TMP_DIR/vpnctl" \
  'printf "VPN STATUS: UP\npublic ip: 198.51.100.10\n"'
make_cmd "$TMP_DIR/backend" \
  'case "${1:-}" in status) printf "MODE=custom-vps\nBACKEND=custom-vps\nCUSTOM_VPS_ENABLED=true\nIMPLEMENTED=true\nSUPPORTS_ROTATION=false\nTRUTH_INTERFACE=wg0\n";; active) printf "custom-vps\n";; mode) printf "custom-vps\n";; validate) exit 0;; *) exit 64;; esac'

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
  '2026-05-16T00:00:00Z | vpn_notify | info | sample | user@example.com 198.51.100.11 2001:db8::11 /home/tester' \
  '2026-05-16T00:01:00Z | watchdogvpn | warn | sample | token=supersecret-token password=hunter2 api_key=api-key-secret private_key=private-key-secret' \
  '2026-05-16T00:02:00Z | watchdogvpn | warn | sample | Authorization: Bearer bearer-secret Cookie: sessionid=cookie-secret; Set-Cookie: refresh=set-cookie-secret;' \
  '2026-05-16T00:03:00Z | watchdogvpn | warn | sample | https://provider.example/sub?token=query-secret&password=query-password 203.0.113.22' \
  >"$LOG_DIR/vpn-events.log"

cat >"$TMP_DIR/metrics.json" <<'EOF'
{
  "schema_version": 1,
  "enabled": true,
  "retention_days": 7,
  "redaction_mode": "aggregate",
  "max_bytes": 1048576,
  "buckets": [
    {
      "bucket_start": "2026-07-06T10:00:00+00:00",
      "bucket_end": "2026-07-06T11:00:00+00:00",
      "counters": {
        "command.connect.success": 3,
        "recovery.status.recovered": 2,
        "node_group.auto_test.unavailable": 1,
        "profile.secret-profile.connect.success": 9,
        "rule_group.private-group": 8,
        "node_group.private-lan.auto_test.ok": 7,
        "route_action.group:private": 6,
        "dns_query.secret.example": 5
      }
    }
  ],
  "updated_at": "2026-07-06T10:05:00+00:00"
}
EOF

init_runtime_update_repo "$UPDATE_REPO" "$UPDATE_REMOTE"

output="$(
  WATCHDOGVPN_REPORT_DIR="$TMP_DIR" \
  WATCHDOGVPN_TRUTH_BIN="$TMP_DIR/truth" \
  WATCHDOGVPN_BACKEND_BIN="$TMP_DIR/backend" \
  WATCHDOGVPN_VPNCTL_BIN="$TMP_DIR/vpnctl" \
  WATCHDOGVPN_LOG_DIR="$LOG_DIR" \
  WATCHDOGVPN_METRICS_FILE="$TMP_DIR/metrics.json" \
  WATCHDOGVPN_REPO_DIR="$ROOT_DIR" \
  "$SCRIPT" report
)"

report="$(printf '%s\n' "$output" | sed -n 's/^Report written: //p')"
[[ -f "$report" ]]
[[ "$(stat -c '%a' "$report")" == "600" ]]

grep -Fq "WatchdogVPN diagnostic report" "$report"
grep -Fq "== VPN truth ==" "$report"
grep -Fq "== Backend status ==" "$report"
grep -Fq "== Observability metrics ==" "$report"
grep -Fq "metrics_status=available" "$report"
grep -Fq "counter.command.connect.success=3" "$report"
grep -Fq "counter.recovery.status.recovered=2" "$report"
grep -Fq "counter.node_group.auto_test.unavailable=1" "$report"
grep -Fq "<redacted-email>" "$report"
grep -Fq "<redacted-ip>" "$report"
grep -Fq "<redacted-ipv6>" "$report"
grep -Fq "token=<redacted>" "$report"
grep -Fq "password=<redacted>" "$report"
grep -Fq "Authorization: Bearer <redacted>" "$report"
grep -Fq "Cookie: <redacted>" "$report"
grep -Fq "Set-Cookie: <redacted>" "$report"
grep -Fq "token=<redacted>&password=<redacted>" "$report"
if grep -Eq '198\.51\.100|203\.0\.113|2001:db8|user@example\.com|supersecret-token|hunter2|api-key-secret|private-key-secret|bearer-secret|cookie-secret|set-cookie-secret|query-secret|query-password' "$report"; then
  printf 'FAIL: report contains unsanitized sensitive sample data\n' >&2
  exit 1
fi
if grep -Eq 'secret-profile|private-group|private-lan|route_action\.group:private|secret\.example|metrics\.json' "$report"; then
  printf 'FAIL: report contains raw metrics data or local identifiers\n' >&2
  exit 1
fi

help_output="$("$SCRIPT" help)"
contains "$help_output" 'Read-only commands:'
contains "$help_output" 'backend       Show active backend capability summary.'
contains "$help_output" 'logs          Read recent WatchdogVPN logs without sudo.'
contains "$help_output" 'update-check  Show local repository update status without network access.'
contains "$help_output" 'update-plan   Print safe manual update steps for the current checkout.'
contains "$help_output" 'Configuration commands:'
contains "$help_output" 'Interactive commands:'
contains "$help_output" 'config set    Update a validated safe configuration key.'
contains "$help_output" 'daemon-backed connect, disconnect, status and rotate live in the Python'
dash_help_output="$("$SCRIPT" --help)"
[[ "$dash_help_output" == "$help_output" ]]
contains "$("$SCRIPT" help logs)" 'watchdogvpn logs [events|dispatcher] [lines]'
contains "$("$SCRIPT" help update-check)" 'watchdogvpn update-check'
contains "$("$SCRIPT" help update-plan)" 'watchdogvpn update-plan'
contains "$("$SCRIPT" help runtime-update)" 'watchdogvpn runtime-update --preflight'
contains "$("$SCRIPT" help runtime-update)" 'requires explicit confirmation: yes'
contains "$("$SCRIPT" help config)" 'Writable safe keys:'
contains "$("$SCRIPT" help backend)" 'watchdogvpn backend status'
contains "$("$SCRIPT" config help)" 'Reset targets:'
if "$SCRIPT" help missing-topic >/dev/null 2>&1; then
  printf 'FAIL: unknown help topic should fail\n' >&2
  exit 1
fi
logs_output="$(WATCHDOGVPN_LOG_DIR="$LOG_DIR" "$SCRIPT" logs events 4)"
printf '%s\n' "$logs_output" | grep -Fq 'WatchdogVPN logs: events'
printf '%s\n' "$logs_output" | grep -Fq '<redacted-email>'
printf '%s\n' "$logs_output" | grep -Fq '<redacted-ip>'
printf '%s\n' "$logs_output" | grep -Fq '<redacted-ipv6>'
printf '%s\n' "$logs_output" | grep -Fq "token=<redacted>"
printf '%s\n' "$logs_output" | grep -Fq "password=<redacted>"
printf '%s\n' "$logs_output" | grep -Fq "Authorization: Bearer <redacted>"
printf '%s\n' "$logs_output" | grep -Fq "Cookie: <redacted>"
printf '%s\n' "$logs_output" | grep -Fq "Set-Cookie: <redacted>"
printf '%s\n' "$logs_output" | grep -Fq "token=<redacted>&password=<redacted>"
if printf '%s\n' "$logs_output" | grep -Eq '198\.51\.100|203\.0\.113|2001:db8|user@example\.com|supersecret-token|hunter2|api-key-secret|private-key-secret|bearer-secret|cookie-secret|set-cookie-secret|query-secret|query-password'; then
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
backend_output="$(WATCHDOGVPN_BACKEND_BIN="$TMP_DIR/backend" "$SCRIPT" backend status)"
printf '%s\n' "$backend_output" | grep -Fq 'WatchdogVPN backend status'
printf '%s\n' "$backend_output" | grep -Fq 'MODE=custom-vps'
printf '%s\n' "$backend_output" | grep -Fq 'BACKEND=custom-vps'
if "$SCRIPT" backend unknown >/dev/null 2>&1; then
  printf 'FAIL: unknown backend command should fail\n' >&2
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
printf '%s\n' "$runtime_help" | grep -Fq 'watchdogvpn runtime-update'
printf '%s\n' "$runtime_help" | grep -Fq 'watchdogvpn runtime-update --preflight'
printf '%s\n' "$runtime_help" | grep -Fq 'requires explicit confirmation: yes'
runtime_preflight="$(WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" runtime-update --preflight)"
printf '%s\n' "$runtime_preflight" | grep -Fq 'WatchdogVPN runtime update'
printf '%s\n' "$runtime_preflight" | grep -Fq 'Mode: preflight only.'
printf '%s\n' "$runtime_preflight" | grep -Fq 'Runtime update preflight: OK'
printf '%s\n' "$runtime_preflight" | grep -Fq 'Execution: not run in preflight mode.'
if WATCHDOGVPN_REPO_DIR="$UPDATE_REPO" "$SCRIPT" runtime-update unexpected >/dev/null 2>&1; then
  printf 'FAIL: runtime-update unexpected argument should fail\n' >&2
  exit 1
fi
RUNTIME_EXEC_REPO="$TMP_DIR/runtime-exec-repo"
RUNTIME_EXEC_REMOTE="$TMP_DIR/runtime-exec-remote.git"
RUNTIME_EXEC_LOG="$TMP_DIR/runtime-exec.log"
GIT_WRAPPER_DIR="$TMP_DIR/git-wrapper"
init_runtime_update_repo "$RUNTIME_EXEC_REPO" "$RUNTIME_EXEC_REMOTE"
make_cmd "$RUNTIME_EXEC_REPO/update.sh" \
  'printf "update:%s\n" "$*" >>"$WATCHDOGVPN_TEST_STEP_LOG"'
make_cmd "$RUNTIME_EXEC_REPO/doctor.sh" \
  'printf "doctor\n" >>"$WATCHDOGVPN_TEST_STEP_LOG"'
git -C "$RUNTIME_EXEC_REPO" add update.sh doctor.sh
git -C "$RUNTIME_EXEC_REPO" commit -q -m runtime-exec-mocks
git -C "$RUNTIME_EXEC_REPO" push -q origin main
mkdir -p "$GIT_WRAPPER_DIR"
make_runtime_git_wrapper "$GIT_WRAPPER_DIR/git" success
cancel_output="$(printf 'no\n' | WATCHDOGVPN_REPO_DIR="$RUNTIME_EXEC_REPO" WATCHDOGVPN_TEST_STEP_LOG="$RUNTIME_EXEC_LOG" "$SCRIPT" runtime-update || true)"
printf '%s\n' "$cancel_output" | grep -Fq 'Runtime update cancelled.'
[[ ! -e "$RUNTIME_EXEC_LOG" ]]
runtime_exec_output="$(run_confirmed_runtime_update "$RUNTIME_EXEC_REPO" "$RUNTIME_EXEC_LOG" "$GIT_WRAPPER_DIR")"
printf '%s\n' "$runtime_exec_output" | grep -Fq 'Mode: confirmed execution.'
printf '%s\n' "$runtime_exec_output" | grep -Fq 'Warning: ./update.sh --skip-doctor may prompt for sudo.'
printf '%s\n' "$runtime_exec_output" | grep -Fq 'Running: hash -r'
printf '%s\n' "$runtime_exec_output" | grep -Fq 'Runtime update completed.'
printf '%s\n' "$runtime_exec_output" | grep -Fq 'git pull --ff-only origin main'
printf '%s\n' "$runtime_exec_output" | grep -Fq './update.sh --skip-doctor'
printf '%s\n' "$runtime_exec_output" | grep -Fq './doctor.sh'
cat >"$TMP_DIR/expected-runtime-exec.log" <<'EOF'
git fetch origin --tags
git pull --ff-only origin main
update:--skip-doctor
doctor
EOF
diff -u "$TMP_DIR/expected-runtime-exec.log" "$RUNTIME_EXEC_LOG"
RUNTIME_FAIL_REPO="$TMP_DIR/runtime-fail-repo"
RUNTIME_FAIL_REMOTE="$TMP_DIR/runtime-fail-remote.git"
RUNTIME_FAIL_LOG="$TMP_DIR/runtime-fail.log"
init_runtime_update_repo "$RUNTIME_FAIL_REPO" "$RUNTIME_FAIL_REMOTE"
make_cmd "$RUNTIME_FAIL_REPO/update.sh" \
  'printf "update:%s\n" "$*" >>"$WATCHDOGVPN_TEST_STEP_LOG"' \
  'exit 23'
make_cmd "$RUNTIME_FAIL_REPO/doctor.sh" \
  'printf "doctor\n" >>"$WATCHDOGVPN_TEST_STEP_LOG"'
git -C "$RUNTIME_FAIL_REPO" add update.sh doctor.sh
git -C "$RUNTIME_FAIL_REPO" commit -q -m runtime-fail-mocks
git -C "$RUNTIME_FAIL_REPO" push -q origin main
runtime_fail_output="$(run_confirmed_runtime_update "$RUNTIME_FAIL_REPO" "$RUNTIME_FAIL_LOG" "$GIT_WRAPPER_DIR" || true)"
printf '%s\n' "$runtime_fail_output" | grep -Fq 'Runtime update failed.'
printf '%s\n' "$runtime_fail_output" | grep -Fq 'Failed step: ./update.sh --skip-doctor'
printf '%s\n' "$runtime_fail_output" | grep -Fq 'Last successful step: git pull --ff-only origin main'
if printf '%s\n' "$runtime_fail_output" | grep -Fq 'Runtime update completed.'; then
  printf 'FAIL: failed runtime update should not report completion\n' >&2
  exit 1
fi
cat >"$TMP_DIR/expected-runtime-fail.log" <<'EOF'
git fetch origin --tags
git pull --ff-only origin main
update:--skip-doctor
EOF
diff -u "$TMP_DIR/expected-runtime-fail.log" "$RUNTIME_FAIL_LOG"
RUNTIME_FETCH_FAIL_REPO="$TMP_DIR/runtime-fetch-fail-repo"
RUNTIME_FETCH_FAIL_REMOTE="$TMP_DIR/runtime-fetch-fail-remote.git"
RUNTIME_FETCH_FAIL_LOG="$TMP_DIR/runtime-fetch-fail.log"
RUNTIME_FETCH_FAIL_WRAPPER_DIR="$TMP_DIR/git-wrapper-fetch-fail"
init_runtime_update_repo "$RUNTIME_FETCH_FAIL_REPO" "$RUNTIME_FETCH_FAIL_REMOTE"
mkdir -p "$RUNTIME_FETCH_FAIL_WRAPPER_DIR"
make_runtime_git_wrapper "$RUNTIME_FETCH_FAIL_WRAPPER_DIR/git" fail-fetch
runtime_fetch_fail_output="$(run_confirmed_runtime_update "$RUNTIME_FETCH_FAIL_REPO" "$RUNTIME_FETCH_FAIL_LOG" "$RUNTIME_FETCH_FAIL_WRAPPER_DIR" || true)"
printf '%s\n' "$runtime_fetch_fail_output" | grep -Fq 'Runtime update failed.'
printf '%s\n' "$runtime_fetch_fail_output" | grep -Fq 'Failed step: git fetch origin --tags'
printf '%s\n' "$runtime_fetch_fail_output" | grep -Fq 'Last successful step: none'
cat >"$TMP_DIR/expected-runtime-fetch-fail.log" <<'EOF'
git fetch origin --tags
EOF
diff -u "$TMP_DIR/expected-runtime-fetch-fail.log" "$RUNTIME_FETCH_FAIL_LOG"

RUNTIME_POST_FETCH_FAIL_REPO="$TMP_DIR/runtime-post-fetch-fail-repo"
RUNTIME_POST_FETCH_FAIL_REMOTE="$TMP_DIR/runtime-post-fetch-fail-remote.git"
RUNTIME_POST_FETCH_FAIL_LOG="$TMP_DIR/runtime-post-fetch-fail.log"
init_runtime_update_repo "$RUNTIME_POST_FETCH_FAIL_REPO" "$RUNTIME_POST_FETCH_FAIL_REMOTE"
printf 'second\n' >>"$RUNTIME_POST_FETCH_FAIL_REPO/README.md"
git -C "$RUNTIME_POST_FETCH_FAIL_REPO" add README.md
git -C "$RUNTIME_POST_FETCH_FAIL_REPO" commit -q -m second
git -C "$RUNTIME_POST_FETCH_FAIL_REPO" push -q origin main
force_remote_back_one_commit "$RUNTIME_POST_FETCH_FAIL_REPO" "$RUNTIME_POST_FETCH_FAIL_REMOTE"
runtime_post_fetch_fail_output="$(run_confirmed_runtime_update "$RUNTIME_POST_FETCH_FAIL_REPO" "$RUNTIME_POST_FETCH_FAIL_LOG" "$GIT_WRAPPER_DIR" || true)"
printf '%s\n' "$runtime_post_fetch_fail_output" | grep -Fq 'Runtime update failed.'
printf '%s\n' "$runtime_post_fetch_fail_output" | grep -Fq 'Failed step: post-fetch preflight'
printf '%s\n' "$runtime_post_fetch_fail_output" | grep -Fq 'Last successful step: git fetch origin --tags'
printf '%s\n' "$runtime_post_fetch_fail_output" | grep -Fq 'Reason: branch is ahead of upstream'
cat >"$TMP_DIR/expected-runtime-post-fetch-fail.log" <<'EOF'
git fetch origin --tags
EOF
diff -u "$TMP_DIR/expected-runtime-post-fetch-fail.log" "$RUNTIME_POST_FETCH_FAIL_LOG"

RUNTIME_PULL_FAIL_REPO="$TMP_DIR/runtime-pull-fail-repo"
RUNTIME_PULL_FAIL_REMOTE="$TMP_DIR/runtime-pull-fail-remote.git"
RUNTIME_PULL_FAIL_LOG="$TMP_DIR/runtime-pull-fail.log"
RUNTIME_PULL_FAIL_WRAPPER_DIR="$TMP_DIR/git-wrapper-pull-fail"
init_runtime_update_repo "$RUNTIME_PULL_FAIL_REPO" "$RUNTIME_PULL_FAIL_REMOTE"
mkdir -p "$RUNTIME_PULL_FAIL_WRAPPER_DIR"
make_runtime_git_wrapper "$RUNTIME_PULL_FAIL_WRAPPER_DIR/git" fail-pull
runtime_pull_fail_output="$(run_confirmed_runtime_update "$RUNTIME_PULL_FAIL_REPO" "$RUNTIME_PULL_FAIL_LOG" "$RUNTIME_PULL_FAIL_WRAPPER_DIR" || true)"
printf '%s\n' "$runtime_pull_fail_output" | grep -Fq 'Runtime update failed.'
printf '%s\n' "$runtime_pull_fail_output" | grep -Fq 'Failed step: git pull --ff-only origin main'
printf '%s\n' "$runtime_pull_fail_output" | grep -Fq 'Last successful step: post-fetch preflight'
cat >"$TMP_DIR/expected-runtime-pull-fail.log" <<'EOF'
git fetch origin --tags
git pull --ff-only origin main
EOF
diff -u "$TMP_DIR/expected-runtime-pull-fail.log" "$RUNTIME_PULL_FAIL_LOG"

RUNTIME_DOCTOR_FAIL_REPO="$TMP_DIR/runtime-doctor-fail-repo"
RUNTIME_DOCTOR_FAIL_REMOTE="$TMP_DIR/runtime-doctor-fail-remote.git"
RUNTIME_DOCTOR_FAIL_LOG="$TMP_DIR/runtime-doctor-fail.log"
init_runtime_update_repo "$RUNTIME_DOCTOR_FAIL_REPO" "$RUNTIME_DOCTOR_FAIL_REMOTE"
make_cmd "$RUNTIME_DOCTOR_FAIL_REPO/update.sh" \
  'printf "update:%s\n" "$*" >>"$WATCHDOGVPN_TEST_STEP_LOG"'
make_cmd "$RUNTIME_DOCTOR_FAIL_REPO/doctor.sh" \
  'printf "doctor\n" >>"$WATCHDOGVPN_TEST_STEP_LOG"' \
  'exit 24'
git -C "$RUNTIME_DOCTOR_FAIL_REPO" add update.sh doctor.sh
git -C "$RUNTIME_DOCTOR_FAIL_REPO" commit -q -m runtime-doctor-fail-mocks
git -C "$RUNTIME_DOCTOR_FAIL_REPO" push -q origin main
runtime_doctor_fail_output="$(run_confirmed_runtime_update "$RUNTIME_DOCTOR_FAIL_REPO" "$RUNTIME_DOCTOR_FAIL_LOG" "$GIT_WRAPPER_DIR" || true)"
printf '%s\n' "$runtime_doctor_fail_output" | grep -Fq 'Runtime update failed.'
printf '%s\n' "$runtime_doctor_fail_output" | grep -Fq 'Failed step: ./doctor.sh'
printf '%s\n' "$runtime_doctor_fail_output" | grep -Fq 'Last successful step: hash -r'
cat >"$TMP_DIR/expected-runtime-doctor-fail.log" <<'EOF'
git fetch origin --tags
git pull --ff-only origin main
update:--skip-doctor
doctor
EOF
diff -u "$TMP_DIR/expected-runtime-doctor-fail.log" "$RUNTIME_DOCTOR_FAIL_LOG"
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
printf '%s\n' "$version_output" | grep -Fq "WatchdogVPN v0.3.1"
if printf '%s\n' "$version_output" | grep -Fq -- "-dev"; then
  printf 'FAIL: published CLI version must not use a -dev suffix\n' >&2
  exit 1
fi

printf 'watchdogvpn CLI checks passed\n'
