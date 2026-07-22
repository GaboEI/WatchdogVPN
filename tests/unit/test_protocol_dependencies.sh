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
  # Wiring assertions care about the executable call sites, which appear
  # after any helper definitions containing the same function names.
  first_line="$(grep -nF "$first" "$file" | tail -n1 | cut -d: -f1 || true)"
  second_line="$(grep -nF "$second" "$file" | tail -n1 | cut -d: -f1 || true)"
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
assert_contains "$ROOT_DIR/lib/singbox.sh" 'download_release_asset' "sing-box install must use the shared resilient downloader"
assert_not_contains "$ROOT_DIR/lib/singbox.sh" 'does not currently pin the archive by checksum' "sing-box notice must not claim checksums are unpinned anymore"

assert_contains "$ROOT_DIR/lib/cloak.sh" 'CLOAK_SHA256_LINUX_AMD64' "Cloak lib must pin an amd64 checksum"
assert_contains "$ROOT_DIR/lib/cloak.sh" 'CLOAK_SHA256_LINUX_ARM64' "Cloak lib must pin an arm64 checksum"
assert_contains "$ROOT_DIR/lib/cloak.sh" 'verify_sha256' "Cloak install must verify the download checksum"
assert_contains "$ROOT_DIR/lib/cloak.sh" 'download_release_asset' "Cloak install must use the shared resilient downloader"
assert_contains "$ROOT_DIR/lib/cloak.sh" '"${INSTALL_DRY_RUN:-0}" == "1"' "Cloak install must skip prompting under --dry-run"
assert_contains "$ROOT_DIR/lib/cloak.sh" 'Cloak client is required for the supported OpenVPN+Cloak protocol' "declining Cloak must fail instead of publishing a partial installation"

if (cd "$ROOT_DIR" && bash -c '
set -euo pipefail
source lib/common.sh
source lib/install_files.sh
source lib/cloak.sh
cloak_available() { return 1; }
prompt_yes_no() { return 1; }
install_official_cloak
' >/dev/null 2>&1); then
  printf 'FAIL: declining a missing Cloak runtime must abort install/update\n' >&2
  exit 1
fi

# --- release downloads: default path first, bounded IPv4 fallback ---

download_fallback_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
source lib/common.sh
source lib/install_files.sh
attempts=()
curl() {
  attempts+=("$*")
  [[ " $* " == *" --ipv4 "* ]]
}
download_release_asset "https://example.invalid/release" "/tmp/watchdogvpn-download-test" 120 "test asset"
printf "%s\n" "${#attempts[@]}" "${attempts[0]}" "${attempts[1]}"
' 2>&1)"
grep -Fqx '2' <<<"$download_fallback_output" || {
  printf 'FAIL: release download must retry exactly once after a default-path failure\n' >&2
  exit 1
}
grep -Fq -- '--ipv4' <<<"$download_fallback_output" || {
  printf 'FAIL: release download fallback must force IPv4\n' >&2
  exit 1
}
grep -Fq 'retrying once over IPv4' <<<"$download_fallback_output" || {
  printf 'FAIL: release download fallback must explain the retry\n' >&2
  exit 1
}

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

# --- AmneziaWG: doctor-only runtime detection; import guidance is Python ---

assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_userspace_available' "amneziawg lib must define a userspace tooling check"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_kernel_module_available' "amneziawg lib must define a kernel module check"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_userspace_fallback_available' "amneziawg lib must define a userspace fallback check"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'amneziawg_runtime_available' "amneziawg lib must combine native module and userspace fallback checks"
assert_contains "$ROOT_DIR/lib/amneziawg.sh" 'DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS' "amneziawg commands must come from a distro adapter"
assert_contains "$ROOT_DIR/diagnostics/amneziawg_guidance.py" 'distro_adapter_path' "CLI guidance must reuse the shared distro adapter resolver"
assert_contains "$ROOT_DIR/distros/arch.sh" 'DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS' "Arch adapter must own its AmneziaWG guidance"
assert_contains "$ROOT_DIR/distros/arch.sh" '/usr/lib/modules/$(uname -r)/pkgbase' "Arch AmneziaWG guidance must derive headers from the running kernel package"
assert_contains "$ROOT_DIR/distros/arch.sh" '${kernel_pkgbase}-headers' "Arch AmneziaWG guidance must install matching headers for default, LTS and alternate packaged kernels"
assert_not_contains "$ROOT_DIR/distros/arch.sh" 'base-devel git linux-headers' "Arch AmneziaWG guidance must not hardcode default-kernel headers"
assert_contains "$ROOT_DIR/distros/ubuntu.sh" 'DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS' "Ubuntu adapter must own its AmneziaWG guidance"
assert_contains "$ROOT_DIR/distros/debian.sh" 'DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS' "Debian adapter must own its AmneziaWG guidance"
assert_not_contains "$ROOT_DIR/distros/debian.sh" 'software-properties-common' "Debian AmneziaWG guidance must not require Ubuntu-only software-properties-common"
assert_not_contains "$ROOT_DIR/distros/debian.sh" 'apt-key' "Debian AmneziaWG guidance must not use removed apt-key tooling"
assert_contains "$ROOT_DIR/distros/debian.sh" 'signed-by=/usr/share/keyrings/amneziawg-archive-keyring.gpg' "Debian AmneziaWG guidance must use a signed-by keyring"
assert_contains "$ROOT_DIR/distros/debian.sh" 'sudo chmod 0644 /usr/share/keyrings/amneziawg-archive-keyring.gpg' "Debian AmneziaWG guidance must keep the keyring readable by apt"
assert_not_contains "$ROOT_DIR/install.sh" 'guide_amneziawg_setup' "blank installation must not show AmneziaWG instructions"
assert_not_contains "$ROOT_DIR/update.sh" 'guide_amneziawg_setup' "routine update must not show AmneziaWG instructions"
assert_not_contains "$ROOT_DIR/install.sh" 'lib/amneziawg.sh' "installer must not load unused AmneziaWG guidance"
assert_not_contains "$ROOT_DIR/update.sh" 'lib/amneziawg.sh' "updater must not load unused AmneziaWG guidance"

# --- Python cryptography dependency (encrypted backups, Phase 17) ---

assert_contains "$ROOT_DIR/lib/packages.sh" 'python_cryptography_available' "packages lib must define a cryptography availability check"
assert_contains "$ROOT_DIR/lib/packages.sh" 'validate_python_runtime_dependencies' "packages lib must define a python runtime dependency validator"
assert_contains "$ROOT_DIR/distros/ubuntu.sh" 'DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"' "Ubuntu adapter must map the cryptography package name"
assert_contains "$ROOT_DIR/distros/debian.sh" 'DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"' "Debian adapter must map the cryptography package name"
assert_contains "$ROOT_DIR/distros/arch.sh" 'DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python-cryptography"' "Arch adapter must map the cryptography package name"

# --- complete distro runtime package contract ---

for required_cmd in git ss systemd-run getent useradd usermod sysctl modinfo nmcli nft iptables ip6tables ping pgrep resolvectl; do
  assert_contains "$ROOT_DIR/lib/packages.sh" "$required_cmd" "required command inventory must include $required_cmd"
done
assert_contains "$ROOT_DIR/lib/common.sh" 'WATCHDOGVPN_COMMAND_PATHS:-/usr/local/sbin:/usr/sbin:/sbin' "command detection must search standard sbin paths outside user PATH"
assert_contains "$ROOT_DIR/lib/common.sh" 'IFS= read -r name </proc/1/comm' "systemd detection must not require procps before procps can be installed"
assert_not_contains "$ROOT_DIR/install.sh" 'ps -p 1' "installer bootstrap must not require ps before package reconciliation"
assert_contains "$ROOT_DIR/lib/packages.sh" '[[ ! -c /dev/net/tun ]]' "install/update dependency validation must fail closed without the running kernel TUN device"
for package in git coreutils findutils grep gawk sed glibc shadow systemd sudo kmod ca-certificates nftables iptables iputils procps-ng; do
  assert_contains "$ROOT_DIR/distros/arch.sh" "$package" "Arch adapter must install $package"
done
for adapter in ubuntu debian; do
  for package in git coreutils findutils grep gawk sed libc-bin passwd systemd sudo kmod ca-certificates nftables iptables iputils-ping procps systemd-resolved; do
    assert_contains "$ROOT_DIR/distros/$adapter.sh" "$package" "$adapter adapter must install $package"
  done
done
for package in git coreutils findutils grep gawk sed glibc-common shadow-utils systemd sudo kmod ca-certificates nftables iptables-nft iputils procps-ng openvpn NetworkManager polkit firewalld systemd-resolved; do
  assert_contains "$ROOT_DIR/distros/fedora.sh" "$package" "Fedora adapter must map $package"
done
assert_contains "$ROOT_DIR/distros/fedora.sh" 'DISTRO_PACKAGE_MANAGER="dnf"' "Fedora adapter must use dnf"
assert_contains "$ROOT_DIR/distros/fedora.sh" 'DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"' "Fedora adapter must map cryptography"
for package in git coreutils findutils grep gawk sed glibc shadow systemd sudo kmod ca-certificates nftables iptables iputils procps openvpn NetworkManager polkit firewalld systemd-resolved apparmor-utils; do
  assert_contains "$ROOT_DIR/distros/opensuse.sh" "$package" "openSUSE adapter must map $package"
done
assert_contains "$ROOT_DIR/distros/opensuse.sh" 'DISTRO_PACKAGE_MANAGER="zypper"' "openSUSE adapter must use zypper"
assert_contains "$ROOT_DIR/distros/opensuse.sh" 'DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"' "openSUSE adapter must map cryptography"
assert_contains "$ROOT_DIR/lib/packages.sh" 'sudo zypper --non-interactive install --no-recommends ' "openSUSE package hint must match zypper install behavior"

dnf_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
source lib/common.sh
source lib/packages.sh
run_step() { printf "%s\n" "$*"; }
DISTRO_PACKAGE_MANAGER=dnf
install_package_set nftables iputils
')"
grep -Fqx 'sudo dnf install -y nftables iputils' <<<"$dnf_output" || {
  printf 'FAIL: Fedora package adapter must use non-interactive dnf install\n' >&2
  exit 1
}

zypper_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
source lib/common.sh
source lib/packages.sh
run_step() { printf "%s\n" "$*"; }
DISTRO_PACKAGE_MANAGER=zypper
install_package_set nftables iputils
')"
grep -Fqx 'sudo zypper --non-interactive install --no-recommends nftables iputils' <<<"$zypper_output" || {
  printf 'FAIL: openSUSE package adapter must use non-interactive zypper install\n' >&2
  exit 1
}

dependency_reconcile_output="$(cd "$ROOT_DIR" && bash -c '
set -euo pipefail
source lib/common.sh
source lib/packages.sh
DISTRO_BASE_PACKAGES=(runtime-one nftables iputils procps)
reconciled=0
install_package_set() {
  printf "packages=%s\n" "$*"
  reconciled=1
}
have_cmd() {
  case "$1" in
    nft|ping|pgrep) ((reconciled == 1)) ;;
    *) return 0 ;;
  esac
}
validate_required_commands
' 2>&1)"
grep -Fq 'packages=runtime-one nftables iputils procps' <<<"$dependency_reconcile_output" || {
  printf 'FAIL: dependency validation must always reconcile the complete distro package set\n' >&2
  exit 1
}
grep -Fq 'required runtime packages, commands and kernel TUN device available' <<<"$dependency_reconcile_output" || {
  printf 'FAIL: dependency validation must re-check commands after package installation\n' >&2
  exit 1
}

sbin_lookup_output="$(cd "$ROOT_DIR" && tmp="$(mktemp -d)" && bash -c '
set -euo pipefail
source lib/common.sh
source lib/packages.sh
mkdir -p "$1/bin" "$1/sbin"
for cmd in $(required_commands); do
  printf "#!/usr/bin/env sh\nexit 0\n" >"$1/sbin/$cmd"
  chmod 0755 "$1/sbin/$cmd"
done
PATH="$1/bin" WATCHDOGVPN_COMMAND_PATHS="$1/sbin" have_cmd nft
PATH="$1/bin" WATCHDOGVPN_COMMAND_PATHS="$1/sbin" have_cmd useradd
PATH="$1/bin" WATCHDOGVPN_COMMAND_PATHS="$1/sbin" have_cmd openvpn
DISTRO_BASE_PACKAGES=(already-installed)
install_package_set() { return 0; }
PATH="$1/bin" WATCHDOGVPN_COMMAND_PATHS="$1/sbin" validate_required_commands
' bash "$tmp"; rc=$?; rm -rf "$tmp"; exit "$rc" 2>&1)"
grep -Fq 'required runtime packages, commands and kernel TUN device available' <<<"$sbin_lookup_output" || {
  printf 'FAIL: dependency validation must find required commands in sbin paths outside the user PATH\n' >&2
  printf '%s\n' "$sbin_lookup_output" >&2
  exit 1
}

if (cd "$ROOT_DIR" && bash -c '
set -euo pipefail
source lib/common.sh
source lib/packages.sh
DISTRO_BASE_PACKAGES=(nftables iputils procps)
install_package_set() { return 0; }
have_cmd() { [[ "$1" != nft ]]; }
validate_required_commands
' >/dev/null 2>&1); then
  printf 'FAIL: dependency validation must fail closed when a command remains missing\n' >&2
  exit 1
fi

if (cd "$ROOT_DIR" && bash -c '
set -euo pipefail
source lib/common.sh
source lib/packages.sh
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE=python-cryptography
python_cryptography_available() { return 1; }
install_package_set() { return 0; }
validate_python_runtime_dependencies
' >/dev/null 2>&1); then
  printf 'FAIL: cryptography must be mandatory after its package install attempt\n' >&2
  exit 1
fi

# --- install.sh wiring ---

assert_contains "$ROOT_DIR/install.sh" 'validate_protocol_runtime_dependencies' "installer must validate protocol runtime dependencies"
assert_contains "$ROOT_DIR/install.sh" 'install_official_cloak' "installer must offer the Cloak client for Custom VPS"
assert_not_contains "$ROOT_DIR/install.sh" 'if [[ "$CUSTOM_VPS_ENABLED" == "true" ]]; then' "supported sing-box/Cloak runtimes must not depend on the legacy custom_vps backend toggle"
assert_order "$ROOT_DIR/install.sh" "validate_required_commands" "validate_protocol_runtime_dependencies" "installer must check protocol dependencies after required commands"
assert_order "$ROOT_DIR/install.sh" "install_official_singbox" "install_official_cloak" "installer must ensure sing-box before the required Cloak client"

# Regression: confirmed live 2026-07-17 - this prompt defaulted to "no"
# while install_official_singbox's equivalent prompt (lib/singbox.sh)
# defaults to "yes". Under a non-interactive `install.sh --yes` (the
# documented ordinary way to run this installer, used throughout Phase
# 23.5's own VM validation), a "no" default means prompt_yes_no's own
# ASSUME_YES branch always declines - OpenVPN+Cloak (a resilient-tier
# protocol, same tier as AmneziaWG/VLESS/Trojan/Hysteria2, all of which
# install their own dependencies automatically) silently lost ck-client
# on every such install, while doctor.sh correctly reported it missing
# the whole time without that ever being treated as a real problem.
assert_contains "$ROOT_DIR/lib/cloak.sh" 'prompt_yes_no "Download and install the official Cloak client now?" yes' "Cloak client install prompt must default to yes, matching install_official_singbox"

# --- update.sh wiring: required dependencies have parity with install.sh ---
# (feedback from the maintainer: update.sh must not leave a returning user
# with a worse experience than a fresh install just because it is "only" an
# update)

assert_contains "$ROOT_DIR/update.sh" 'validate_python_runtime_dependencies' "updater must backfill missing python runtime dependencies"
assert_contains "$ROOT_DIR/update.sh" 'validate_required_commands' "updater must reconcile the same complete distro runtime package set as install"
assert_order "$ROOT_DIR/update.sh" 'validate_required_commands' 'validate_python_runtime_dependencies' "updater must reconcile system packages before Python/runtime dependencies"
assert_contains "$ROOT_DIR/update.sh" 'install_official_singbox' "updater must ensure sing-box is present, not only a fresh install"
assert_contains "$ROOT_DIR/update.sh" 'install_official_cloak' "updater must offer the Cloak client, not only a fresh install"
assert_contains "$ROOT_DIR/update.sh" 'prompt_yes_no()' "updater must define the prompt helper required by reviewed external dependency installers"
assert_contains "$ROOT_DIR/update.sh" '. "$ROOT_DIR/lib/singbox.sh"' "updater must source lib/singbox.sh to use install_official_singbox"
assert_contains "$ROOT_DIR/update.sh" '. "$ROOT_DIR/lib/cloak.sh"' "updater must source lib/cloak.sh to use install_official_cloak"

# --- uninstall.sh also sources lib/runtime.sh now that legacy file cleanup
#     moved there to be shared with install/update ---

assert_contains "$ROOT_DIR/uninstall.sh" '. "$ROOT_DIR/lib/runtime.sh"' "uninstall must source lib/runtime.sh for the shared legacy cleanup function"

# --- doctor.sh reports dependency state without installing anything ---

assert_contains "$ROOT_DIR/doctor.sh" 'Protocol Runtime Dependencies' "doctor must report protocol runtime dependency state"
assert_contains "$ROOT_DIR/doctor.sh" '[[ -c /dev/net/tun ]]' "doctor must fail closed when the running kernel does not expose the TUN device"
assert_contains "$ROOT_DIR/doctor.sh" 'singbox_available' "doctor must check sing-box availability"
assert_contains "$ROOT_DIR/doctor.sh" 'amneziawg_runtime_available' "doctor must check AmneziaWG availability the same way the driver does (userspace tool plus kernel module OR amneziawg-go fallback), not require both unconditionally"
assert_not_contains "$ROOT_DIR/doctor.sh" 'amneziawg_userspace_available && amneziawg_kernel_module_available' "doctor must not require the kernel module unconditionally; the userspace amneziawg-go fallback is a real working runtime path"
assert_not_contains "$ROOT_DIR/doctor.sh" 'compatible WireGuard' "doctor must not claim plain WireGuard tooling satisfies the AmneziaWG runtime"
assert_contains "$ROOT_DIR/doctor.sh" 'cloak_available' "doctor must check Cloak client availability"
assert_contains "$ROOT_DIR/doctor.sh" 'python_cryptography_available' "doctor must check the cryptography module"
assert_contains "$ROOT_DIR/doctor.sh" 'mark_fail "nftables missing;' "doctor must fail closed without the atomic firewall dependency"
assert_contains "$ROOT_DIR/doctor.sh" 'mark_fail "Cloak client (ck-client) missing;' "doctor must fail closed without the resilient Cloak dependency"
assert_contains "$ROOT_DIR/doctor.sh" 'mark_fail "python cryptography module missing;' "doctor must fail closed without encrypted-backup support"
assert_not_contains "$ROOT_DIR/doctor.sh" 'install_official_singbox' "doctor must never call an installer function"
assert_not_contains "$ROOT_DIR/doctor.sh" 'install_official_cloak' "doctor must never call an installer function"

echo "protocol dependency checks passed"
