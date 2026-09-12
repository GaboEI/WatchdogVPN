#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../lib/packages.sh
. "$ROOT_DIR/lib/packages.sh"

assert_not_contains() {
  local needle="$1" haystack="$2" label="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'FAIL %s: %s must not be present\n' "$label" "$needle" >&2
    exit 1
  fi
}

assert_contains() {
  local needle="$1" haystack="$2" label="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'FAIL %s: %s must be present\n' "$label" "$needle" >&2
    exit 1
  fi
}

# openSUSE uses netconfig/Wicked as its DNS backend, not systemd-resolved:
# Leap 15.6 has no `systemd-resolved` package and ships no resolvectl command.
# The SUSE family must therefore not require resolvectl, and the openSUSE
# adapter must not request the non-existent systemd-resolved package.
DISTRO_ID="opensuse-leap"
DISTRO_FAMILY="suse"
suse_required="$(required_commands)"
assert_not_contains "resolvectl" "$suse_required" "suse resolvectl excluded"

# shellcheck source=../../distros/opensuse.sh
. "$ROOT_DIR/distros/opensuse.sh"
suse_base="${DISTRO_BASE_PACKAGES[*]}"
assert_not_contains "systemd-resolved" "$suse_base" "suse adapter has no systemd-resolved package"
assert_contains "systemd" "$suse_base" "suse adapter keeps systemd"
# Leap 15.6 pins the python3.11 interpreter pair: python3 = 3.6 is below the
# runtime floor, so the adapter must keep python311 in the base set and select
# python3.11 + python311-cryptography for the stable release.
assert_contains "python311" "$suse_base" "leap base keeps python311"
if [[ "${DISTRO_PYTHON:-}" != "python3.11" ]]; then
  printf 'FAIL leap DISTRO_PYTHON must be python3.11, got %s\n' "${DISTRO_PYTHON:-}" >&2
  exit 1
fi
if [[ "${DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE:-}" != "python311-cryptography" ]]; then
  printf 'FAIL leap cryptography must be python311-cryptography, got %s\n' "${DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE:-}" >&2
  exit 1
fi
bootstrap_leap="$(distro_python_bootstrap_package)"
if [[ "$bootstrap_leap" != "python311" ]]; then
  printf 'FAIL leap bootstrap package must be python311, got %s\n' "$bootstrap_leap" >&2
  exit 1
fi

# Tumbleweed rolling must NOT silently reuse the Leap stable python pair:
# python311-cryptography does not exist in the Tumbleweed repository (modules
# build against python313), so the adapter switches the interpreter pair to
# python3.13/python313/python313-cryptography for the rolling release.
DISTRO_ID="opensuse-tumbleweed"
DISTRO_FAMILY="suse"
# shellcheck source=../../distros/opensuse.sh
. "$ROOT_DIR/distros/opensuse.sh"
tumbleweed_base="${DISTRO_BASE_PACKAGES[*]}"
assert_contains "python313" "$tumbleweed_base" "tumbleweed base keeps python313"
assert_not_contains "python311" "$tumbleweed_base" "tumbleweed base must not carry python311"
if [[ "${DISTRO_PYTHON:-}" != "python3.13" ]]; then
  printf 'FAIL tumbleweed DISTRO_PYTHON must be python3.13, got %s\n' "${DISTRO_PYTHON:-}" >&2
  exit 1
fi
if [[ "${DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE:-}" != "python313-cryptography" ]]; then
  printf 'FAIL tumbleweed cryptography must be python313-cryptography, got %s\n' "${DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE:-}" >&2
  exit 1
fi
bootstrap_tw="$(distro_python_bootstrap_package)"
if [[ "$bootstrap_tw" != "python313" ]]; then
  printf 'FAIL tumbleweed bootstrap package must be python313, got %s\n' "$bootstrap_tw" >&2
  exit 1
fi

# Ubuntu keeps resolvectl (systemd-resolved is its DNS backend).
DISTRO_ID="ubuntu"
DISTRO_FAMILY="ubuntu"
ubuntu_required="$(required_commands)"
assert_contains "resolvectl" "$ubuntu_required" "ubuntu resolvectl kept"

# Kali keeps its existing resolvectl exclusion.
DISTRO_ID="kali"
DISTRO_FAMILY="debian"
kali_required="$(required_commands)"
assert_not_contains "resolvectl" "$kali_required" "kali resolvectl excluded"

printf 'opensuse adapter packages checks passed\n'