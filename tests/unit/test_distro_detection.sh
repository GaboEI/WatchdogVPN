#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../lib/distro.sh
. "$ROOT_DIR/lib/distro.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

write_os_release() {
  local name="$1"
  shift
  OS_RELEASE_FILE="$TMP_DIR/$name"
  printf '%s\n' "$@" >"$OS_RELEASE_FILE"
}

assert_eq() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  if [[ "$expected" != "$actual" ]]; then
    printf 'FAIL %s: expected %s, got %s\n' "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

write_os_release ubuntu \
  'ID=ubuntu' \
  'PRETTY_NAME="Ubuntu 24.04 LTS"'
detect_distro
assert_eq "ubuntu" "$DISTRO_ID" "ubuntu id"
assert_eq "ubuntu" "$DISTRO_ADAPTER_ID" "ubuntu adapter"
assert_eq "1" "$DISTRO_SUPPORTED" "ubuntu supported"

write_os_release debian \
  'ID=debian' \
  'PRETTY_NAME="Debian GNU/Linux 12"'
detect_distro
assert_eq "debian" "$DISTRO_ID" "debian id"
assert_eq "debian" "$DISTRO_ADAPTER_ID" "debian adapter"
assert_eq "1" "$DISTRO_SUPPORTED" "debian supported"

write_os_release arch \
  'ID=arch' \
  'PRETTY_NAME="Arch Linux"'
detect_distro
assert_eq "arch" "$DISTRO_ID" "arch id"
assert_eq "arch" "$DISTRO_ADAPTER_ID" "arch adapter"
assert_eq "1" "$DISTRO_SUPPORTED" "arch supported"

write_os_release cachyos \
  'ID=cachyos' \
  'ID_LIKE="arch"' \
  'PRETTY_NAME="CachyOS"'
detect_distro
assert_eq "cachyos" "$DISTRO_ID" "cachyos id"
assert_eq "arch" "$DISTRO_ADAPTER_ID" "cachyos adapter"
assert_eq "arch" "$DISTRO_FAMILY" "cachyos family"
assert_eq "1" "$DISTRO_SUPPORTED" "cachyos supported"
assert_eq "$ROOT_DIR/distros/arch.sh" "$(distro_adapter_path "$ROOT_DIR")" "cachyos adapter path"

write_os_release fedora \
  'ID=fedora' \
  'PRETTY_NAME="Fedora Linux"'
detect_distro
assert_eq "1" "$DISTRO_SUPPORTED" "fedora supported"
assert_eq "0" "$DISTRO_FUTURE" "fedora not future scope"
assert_eq "fedora" "$DISTRO_ADAPTER_ID" "fedora adapter"
assert_eq "redhat" "$DISTRO_FAMILY" "fedora family"
assert_eq "$ROOT_DIR/distros/fedora.sh" "$(distro_adapter_path "$ROOT_DIR")" "fedora adapter path"

write_os_release rhel \
  'ID=rhel' \
  'PRETTY_NAME="Red Hat Enterprise Linux"'
detect_distro
assert_eq "1" "$DISTRO_SUPPORTED" "rhel supported"
assert_eq "0" "$DISTRO_FUTURE" "rhel not future scope"
assert_eq "fedora" "$DISTRO_ADAPTER_ID" "rhel adapter"
assert_eq "redhat" "$DISTRO_FAMILY" "rhel family"

for redhat_id in centos rocky almalinux; do
  write_os_release "$redhat_id" \
    "ID=$redhat_id" \
    'ID_LIKE="rhel centos fedora"' \
    "PRETTY_NAME=\"$redhat_id\""
  detect_distro
  assert_eq "1" "$DISTRO_SUPPORTED" "$redhat_id supported"
  assert_eq "0" "$DISTRO_FUTURE" "$redhat_id not future scope"
  assert_eq "fedora" "$DISTRO_ADAPTER_ID" "$redhat_id adapter"
  assert_eq "redhat" "$DISTRO_FAMILY" "$redhat_id family"
done

for suse_id in opensuse opensuse-leap opensuse-tumbleweed; do
  write_os_release "$suse_id" \
    "ID=$suse_id" \
    'ID_LIKE="suse opensuse"' \
    "PRETTY_NAME=\"$suse_id\""
  detect_distro
  assert_eq "1" "$DISTRO_SUPPORTED" "$suse_id supported"
  assert_eq "0" "$DISTRO_FUTURE" "$suse_id not future scope"
  assert_eq "opensuse" "$DISTRO_ADAPTER_ID" "$suse_id adapter"
  assert_eq "suse" "$DISTRO_FAMILY" "$suse_id family"
  assert_eq "$ROOT_DIR/distros/opensuse.sh" "$(distro_adapter_path "$ROOT_DIR")" "$suse_id adapter path"
done

write_os_release suse_like_unknown \
  'ID=example-suse' \
  'ID_LIKE="suse opensuse"' \
  'PRETTY_NAME="Example SUSE-like"'
detect_distro
assert_eq "0" "$DISTRO_SUPPORTED" "unknown suse-like unsupported"
assert_eq "example-suse" "$DISTRO_ADAPTER_ID" "unknown suse-like adapter remains explicit id"

write_os_release unknown \
  'ID=exampleos' \
  'PRETTY_NAME="ExampleOS"'
detect_distro
assert_eq "exampleos" "$DISTRO_ID" "unknown id"
assert_eq "0" "$DISTRO_SUPPORTED" "unknown unsupported"

# Debian/Ubuntu-derivative ID_LIKE fallback (Task 23.6.4). Only families with a
# shipped adapter are accepted; Ubuntu is matched before Debian so a derivative
# reporting both resolves to the Ubuntu adapter.
write_os_release linuxmint \
  'ID=linuxmint' \
  'ID_LIKE="ubuntu debian"' \
  'PRETTY_NAME="Linux Mint 22"'
detect_distro
assert_eq "linuxmint" "$DISTRO_ID" "mint id"
assert_eq "1" "$DISTRO_SUPPORTED" "mint supported"
assert_eq "0" "$DISTRO_FUTURE" "mint not future scope"
assert_eq "ubuntu" "$DISTRO_ADAPTER_ID" "mint adapter (ubuntu wins over debian)"
assert_eq "ubuntu" "$DISTRO_FAMILY" "mint family"
assert_eq "$ROOT_DIR/distros/ubuntu.sh" "$(distro_adapter_path "$ROOT_DIR")" "mint adapter path"

write_os_release elementary \
  'ID=elementary' \
  'ID_LIKE="ubuntu"' \
  'PRETTY_NAME="elementary OS 8"'
detect_distro
assert_eq "1" "$DISTRO_SUPPORTED" "elementary supported"
assert_eq "ubuntu" "$DISTRO_ADAPTER_ID" "elementary adapter"
assert_eq "ubuntu" "$DISTRO_FAMILY" "elementary family"

write_os_release debian_derivative \
  'ID=exampledeb' \
  'ID_LIKE="debian"' \
  'PRETTY_NAME="Example Debian Derivative"'
detect_distro
assert_eq "exampledeb" "$DISTRO_ID" "debian-derivative id"
assert_eq "1" "$DISTRO_SUPPORTED" "debian-derivative supported"
assert_eq "debian" "$DISTRO_ADAPTER_ID" "debian-derivative adapter"
assert_eq "debian" "$DISTRO_FAMILY" "debian-derivative family"
assert_eq "$ROOT_DIR/distros/debian.sh" "$(distro_adapter_path "$ROOT_DIR")" "debian-derivative adapter path"

# An unrelated ID_LIKE must never become supported through the fallback.
write_os_release unrelated_like \
  'ID=weirdos' \
  'ID_LIKE="gentoo"' \
  'PRETTY_NAME="WeirdOS"'
detect_distro
assert_eq "0" "$DISTRO_SUPPORTED" "unrelated id_like unsupported"
assert_eq "weirdos" "$DISTRO_ADAPTER_ID" "unrelated id_like adapter remains explicit id"

printf 'distro detection checks passed\n'
