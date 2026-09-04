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