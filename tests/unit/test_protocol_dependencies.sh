#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assert_contains() {
  local file="$1" pattern="$2" message="$3"
  if ! grep -Fq "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    printf 'missing pattern in %s: %s\n' "$file" "$pattern" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1" pattern="$2" message="$3"
  if grep -Fq "$pattern" "$file"; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

assert_order() {
  local file="$1" first="$2" second="$3" message="$4" first_line second_line
  first_line="$(grep -nF "$first" "$file" | head -n1 | cut -d: -f1 || true)"
  second_line="$(grep -nF "$second" "$file" | head -n1 | cut -d: -f1 || true)"
  if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

assert_sha256_shape() {
  local value="$1" message="$2"
  if [[ ! "$value" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'FAIL: %s\n' "$message" >&2
    exit 1
  fi
}

# --- checksum pinning: sing-box and Cloak client (Task 18.3 / INV pin) ---

assert_contains "$ROOT_DIR/lib/singbox.sh" 'SINGBOX_SHA256_LINUX_AMD64' "sing-box lib must pin an amd64 checksum"
assert_contains "$ROOT_DIR/lib/singbox.sh" 'SINGBOX_SHA256_LINUX_ARM64' "sing-box lib must pin an arm64 checksum"
assert_contains "$ROOT_DIR/lib/singbox.sh" 'verify_sha256' "sing-box install must verify the download checksum"
assert_not_contains "$ROOT_DIR/lib/singbox.sh" 'does not currently pin the archive by checksum' "sing-box notice must not claim checksums are unpinned anymore"

assert_contains "$ROOT_DIR/lib/cloak.sh" 'CLOAK_SHA256_LINUX_AMD64' "Cloak lib must pin an amd64 checksum"
assert_contains "$ROOT_DIR/lib/cloak.sh" 'CLOAK_SHA256_LINUX_ARM64' "Cloak lib must pin an arm64 checksum"
assert_contains "$ROOT_DIR/lib/cloak.sh" 'verify_sha256' "Cloak install must verify the download checksum"
assert_contains "$ROOT_DIR/lib/cloak.sh" '"${INSTALL_DRY_RUN:-0}" == "1"' "Cloak install must skip prompting under --dry-run"

# --- shared verify_sha256 utility actually works ---

# shellcheck source=lib/common.sh
. "$ROOT_DIR/lib/common.sh"
tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT
printf 'watchdogvpn test payload\n' >"$tmp_file"
expected_hash="$(sha256sum "$tmp_file" | awk '{print $1}')"
if ! verify_sha256 "$tmp_file" "$expected_hash"; then
  printf 'FAIL: verify_sha256 must accept a matching checksum\n' >&2
  exit 1
fi
if verify_sha256 "$tmp_file" "0000000000000000000000000000000000000000000000000000000000000000"; then
  printf 'FAIL: verify_sha256 must reject a mismatched checksum\n' >&2
  exit 1
fi

# --- pinned hash values are well-formed 64-char hex strings ---

# shellcheck source=lib/singbox.sh
. "$ROOT_DIR/lib/singbox.sh"
assert_sha256_shape "$SINGBOX_SHA256_LINUX_AMD64" "SINGBOX_SHA256_LINUX_AMD64 must be a 64-char hex sha256"
assert_sha256_shape "$SINGBOX_SHA256_LINUX_ARM64" "SINGBOX_SHA256_LINUX_ARM64 must be a 64-char hex sha256"

# shellcheck source=lib/cloak.sh
. "$ROOT_DIR/lib/cloak.sh"
assert_sha256_shape "$CLOAK_SHA256_LINUX_AMD64" "CLOAK_SHA256_LINUX_AMD64 must be a 64-char hex sha256"
assert_sha256_shape "$CLOAK_SHA256_LINUX_ARM64" "CLOAK_SHA256_LINUX_ARM64 must be a 64-char hex sha256"

# --- AmneziaWG: guided manual install, never executed by WatchdogVPN itself ---

assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_userspace_available' "amneziawg lib must define a userspace tooling check"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_kernel_module_available' "amneziawg lib must define a kernel module check"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_userspace_fallback_available' "amneziawg lib must define a userspace fallback check"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_runtime_available' "amneziawg lib must combine native module and userspace fallback checks"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'guide_amneziawg_setup()' "amneziawg lib must define a guided setup wizard"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_setup_commands_ubuntu' "amneziawg lib must provide exact Ubuntu setup commands"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_setup_commands_debian' "amneziawg lib must provide exact Debian setup commands"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_setup_commands_arch' "amneziawg lib must provide exact Arch setup commands"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'read -r -p' "guided setup must wait for the user to run the printed commands themselves"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" '"${INSTALL_DRY_RUN:-0}" == "1"' "guided setup must skip prompting under --dry-run"
# The setup command blocks are only ever printed (via `cat <<'EOF' ... EOF`
# heredocs), never executed by the library itself - WatchdogVPN must not
# silently add a third-party repository or build an AUR package on its own.
assert_not_contains "$ROOT_DIR/lib/amneziawg.sh" 'run_step sudo apt' "amneziawg lib must not execute apt commands itself, only print them"
assert_not_contains "$ROOT_DIR/lib/amneziawg.sh" 'run_step sudo pacman' "amneziawg lib must not execute pacman commands itself, only print them"
assert_not_contains "$ROOT_DIR/lib/amneziawg.sh" 'run_step git clone' "amneziawg lib must not clone/build AUR packages itself, only print the commands"
assert_not_contains "$ROOT_DIR/lib/amneziawg.sh" 'run_step makepkg' "amneziawg lib must not run makepkg itself, only print the command"

# --- guided setup actually behaves correctly end to end (stubbed detection) ---

guided_setup_test_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
source lib/common.sh
source lib/distro.sh
detect_distro
source lib/amneziawg.sh
amneziawg_userspace_available() { return 1; }
amneziawg_kernel_module_available() { return 1; }
prompt_yes_no() { return 0; }
INSTALL_DRY_RUN=0
printf "skip\n" | guide_amneziawg_setup
' 2>&1)"
grep -Fq "Run the following commands" <<<"$guided_setup_test_output" || {
  printf 'FAIL: guided setup must print copy-pasteable commands, not just a link\n' >&2
  exit 1
}
grep -Fq "AmneziaWG guided setup stopped" <<<"$guided_setup_test_output" || {
  printf 'FAIL: guided setup must honor a skip answer without looping forever\n' >&2
  exit 1
}

dry_run_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
source lib/common.sh
source lib/distro.sh
detect_distro
source lib/amneziawg.sh
amneziawg_userspace_available() { return 1; }
amneziawg_kernel_module_available() { return 1; }
INSTALL_DRY_RUN=1
guide_amneziawg_setup
' 2>&1)"
grep -Fq "[DRY-RUN] skip interactive AmneziaWG setup guide" <<<"$dry_run_output" || {
  printf 'FAIL: guided setup must skip without prompting under --dry-run\n' >&2
  exit 1
}

# --- Python cryptography dependency (encrypted backups, Phase 17) ---

assert_contains "$ROOT_DIR/lib/packages.sh" 'python_cryptography_available' "packages lib must define a cryptography availability check"
assert_contains "$ROOT_DIR/lib/packages.sh" 'validate_python_runtime_dependencies' "packages lib must define a python runtime dependency validator"
assert_contains "$ROOT_DIR/distros/ubuntu.sh" 'DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"' "Ubuntu adapter must map the cryptography package name"
assert_contains "$ROOT_DIR/distros/debian.sh" 'DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"' "Debian adapter must map the cryptography package name"
assert_contains "$ROOT_DIR/distros/arch.sh" 'DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python-cryptography"' "Arch adapter must map the cryptography package name"

# --- install.sh wiring ---

assert_contains "$ROOT_DIR/install.sh" 'validate_protocol_runtime_dependencies' "installer must validate protocol runtime dependencies"
assert_contains "$ROOT_DIR/install.sh" 'install_official_cloak' "installer must offer the Cloak client for Custom VPS"
assert_order "$ROOT_DIR/install.sh" "validate_required_commands" "validate_protocol_runtime_dependencies" "installer must check protocol dependencies after required commands"
assert_order "$ROOT_DIR/install.sh" "install_official_singbox" "install_official_cloak" "installer must offer sing-box before the optional Cloak client"

# --- update.sh wiring: full parity with install.sh, not a weaker subset ---
# (feedback from the maintainer: update.sh must not leave a returning user
# with a worse experience than a fresh install just because it is "only" an
# update)

assert_contains "$ROOT_DIR/update.sh" 'validate_python_runtime_dependencies' "updater must backfill missing python runtime dependencies"
assert_contains "$ROOT_DIR/update.sh" 'install_official_singbox' "updater must ensure sing-box is present, not only a fresh install"
assert_contains "$ROOT_DIR/update.sh" 'install_official_cloak' "updater must offer the Cloak client, not only a fresh install"
assert_contains "$ROOT_DIR/update.sh" 'guide_amneziawg_setup' "updater must offer the AmneziaWG guided setup, not only a fresh install"
assert_contains "$ROOT_DIR/update.sh" 'prompt_yes_no()' "updater must define the prompt helper required by optional dependency installers"
assert_contains "$ROOT_DIR/update.sh" '. "$ROOT_DIR/lib/singbox.sh"' "updater must source lib/singbox.sh to use install_official_singbox"
assert_contains "$ROOT_DIR/update.sh" '. "$ROOT_DIR/lib/cloak.sh"' "updater must source lib/cloak.sh to use install_official_cloak"
assert_contains "$ROOT_DIR/update.sh" '. "$ROOT_DIR/lib/amneziawg.sh"' "updater must source lib/amneziawg.sh to use guide_amneziawg_setup"

# --- uninstall.sh also sources lib/runtime.sh now that legacy file cleanup
#     moved there to be shared with install/update ---

assert_contains "$ROOT_DIR/uninstall.sh" '. "$ROOT_DIR/lib/runtime.sh"' "uninstall must source lib/runtime.sh for the shared legacy cleanup function"

# --- doctor.sh reports dependency state without installing anything ---

assert_contains "$ROOT_DIR/doctor.sh" 'Protocol Runtime Dependencies' "doctor must report protocol runtime dependency state"
assert_contains "$ROOT_DIR/doctor.sh" 'singbox_available' "doctor must check sing-box availability"
assert_contains "$ROOT_DIR/doctor.sh" 'amneziawg_runtime_available' "doctor must check AmneziaWG availability the same way the driver does (userspace tool plus kernel module OR amneziawg-go fallback), not require both unconditionally"
assert_not_contains "$ROOT_DIR/doctor.sh" 'amneziawg_userspace_available && amneziawg_kernel_module_available' "doctor must not require the kernel module unconditionally; the userspace amneziawg-go fallback is a real working runtime path"
assert_contains "$ROOT_DIR/doctor.sh" 'cloak_available' "doctor must check Cloak client availability"
assert_contains "$ROOT_DIR/doctor.sh" 'python_cryptography_available' "doctor must check the cryptography module"
assert_not_contains "$ROOT_DIR/doctor.sh" 'install_official_singbox' "doctor must never call an installer function"
assert_not_contains "$ROOT_DIR/doctor.sh" 'install_official_cloak' "doctor must never call an installer function"

echo "protocol dependency checks passed"
