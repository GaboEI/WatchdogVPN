#!/usr/bin/env bash
# TDD regression for the AlmaLinux Bloque 1 finding: the installed runtime tree
# under /usr/local/lib/watchdogvpn kept admin_home_t (inherited from the
# checkout via cp -a) instead of the policy-expected lib_t on SELinux-enforcing
# RPM hosts. The installer must relabel the published destination with
# restorecon when SELinux is active, and stay a no-op otherwise.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FAKE_BIN="$(mktemp -d)"
trap 'rm -rf "${FAKE_BIN}"' EXIT

RESTORECON_LOG="$(mktemp)"

cat > "${FAKE_BIN}/restorecon" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> '${RESTORECON_LOG}'
exit 0
EOF
chmod 0755 "${FAKE_BIN}/restorecon"

cat > "${FAKE_BIN}/getenforce" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${MOCK_GETENFORCE:-Enforcing}"
exit 0
EOF
chmod 0755 "${FAKE_BIN}/getenforce"

# Minimal sudo stub: run the command directly without privilege separation.
cat > "${FAKE_BIN}/sudo" <<'EOF'
#!/usr/bin/env bash
exec "$@"
EOF
chmod 0755 "${FAKE_BIN}/sudo"

run_step() {
  # Runtime.sh wraps privileged work in run_step; keep the same contract here.
  "$@"
}

# shellcheck source=lib/runtime.sh
source "${ROOT_DIR}/lib/runtime.sh"

fail_count=0

# ---------------------------------------------------------------- CASE 1 ----
# Semantics of selinux_relabel_runtime_path under Enforcing: must invoke
# restorecon -R -- <path> exactly once through the privileged wrapper.
: > "${RESTORECON_LOG}"
export MOCK_GETENFORCE="Enforcing"
PATH="${FAKE_BIN}:${PATH}" selinux_relabel_runtime_path "/tmp/fake-runtime-dest"
if grep -qx -- "-R -- /tmp/fake-runtime-dest" "${RESTORECON_LOG}"; then
  printf 'CASE1_OK: Enforcing triggers restorecon -R -- <path>\n'
else
  printf 'FAIL: Enforcing must trigger restorecon -R -- <path>; log:\n' >&2
  cat "${RESTORECON_LOG}" >&2
  fail_count=$((fail_count + 1))
fi

# ---------------------------------------------------------------- CASE 2 ----
# Disabled SELinux: must be an explicit no-op (no restorecon call).
: > "${RESTORECON_LOG}"
export MOCK_GETENFORCE="Disabled"
PATH="${FAKE_BIN}:${PATH}" selinux_relabel_runtime_path "/tmp/fake-runtime-dest"
if [[ -s "${RESTORECON_LOG}" ]]; then
  printf 'FAIL: Disabled SELinux must not invoke restorecon; log:\n' >&2
  cat "${RESTORECON_LOG}" >&2
  fail_count=$((fail_count + 1))
else
  printf 'CASE2_OK: Disabled SELinux is a no-op\n'
fi

# ---------------------------------------------------------------- CASE 3 ----
# Missing restorecon binary: no-op that still succeeds (non-SELinux distros).
: > "${RESTORECON_LOG}"
export MOCK_GETENFORCE="Enforcing"
if PATH="/usr/bin:/bin" selinux_relabel_runtime_path "/tmp/fake-runtime-dest"; then
  if [[ -s "${RESTORECON_LOG}" ]]; then
    printf 'FAIL: missing restorecon must not be invoked\n' >&2
    fail_count=$((fail_count + 1))
  else
    printf 'CASE3_OK: missing restorecon is a safe no-op\n'
  fi
else
  printf 'FAIL: missing restorecon must not fail the publication flow\n' >&2
  fail_count=$((fail_count + 1))
fi

# ---------------------------------------------------------------- CASE 4 ----
# Structural: install_python_package_tree must relabel the FINAL destination
# (not only the stage) in both the transactional and direct branches.
if grep -q 'selinux_relabel_runtime_path "$dest"' "${ROOT_DIR}/lib/runtime.sh"; then
  calls=$(grep -c 'selinux_relabel_runtime_path "\$dest"' "${ROOT_DIR}/lib/runtime.sh")
  if [[ "$calls" -ge 2 ]]; then
    printf 'CASE4_OK: destination relabel wired in both publication branches (%s calls)\n' "$calls"
  else
    printf 'FAIL: destination relabel present but only in one branch (%s calls)\n' "$calls" >&2
    fail_count=$((fail_count + 1))
  fi
else
  printf 'FAIL: install_python_package_tree never relabels the published destination\n' >&2
  fail_count=$((fail_count + 1))
fi

if [[ "$fail_count" -ne 0 ]]; then
  printf 'FAILED: %s case(s)\n' "$fail_count" >&2
  exit 1
fi

printf 'OK: test_runtime_selinux_contexts\n'
