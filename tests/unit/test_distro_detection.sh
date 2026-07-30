#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${WATCHDOGVPN_PYTHON:-python3}"

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

# Query the engine for expected support classification and identity fields.
# Emits: support_classification adapter_id family_id_short
engine_expectations() {
  local fixture="$1"
  "$PYTHON" "$ROOT_DIR/tools/compat_distro_classify.py" \
    --os-release "$fixture" classify 2>/dev/null | "$PYTHON" -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if d.get("status") != "ok":
    sys.exit(1)
family_short = {
    "arch_pacman": "arch",
    "debian_apt": "debian",
    "ubuntu_apt": "ubuntu",
    "redhat_dnf": "redhat",
    "suse_zypper": "suse",
}.get(d.get("family_id", ""), d.get("family_id", ""))
print(d.get("support_classification", ""))
print(d.get("adapter_id", ""))
print(family_short)
'
}

# Verify that lib/distro.sh agrees with the engine for a given fixture.
assert_engine_consistent() {
  local label="$1"
  local expected_support expected_adapter expected_family
  {
    IFS= read -r expected_support
    IFS= read -r expected_adapter
    IFS= read -r expected_family
  } <<<"$(engine_expectations "$OS_RELEASE_FILE")"

  case "$expected_support" in
    certified|supported|family_inferred)
      assert_eq "1" "$DISTRO_SUPPORTED" "$label supported"
      assert_eq "0" "$DISTRO_FUTURE" "$label not future"
      assert_eq "0" "$DISTRO_UNSUPPORTED" "$label not unsupported"
      ;;
    experimental)
      assert_eq "0" "$DISTRO_SUPPORTED" "$label not supported"
      assert_eq "1" "$DISTRO_FUTURE" "$label future"
      assert_eq "0" "$DISTRO_UNSUPPORTED" "$label not unsupported"
      ;;
    unsupported)
      assert_eq "0" "$DISTRO_SUPPORTED" "$label not supported"
      assert_eq "0" "$DISTRO_FUTURE" "$label not future"
      assert_eq "1" "$DISTRO_UNSUPPORTED" "$label unsupported"
      ;;
    *)
      printf 'FAIL %s: unexpected engine classification %s\n' "$label" "$expected_support" >&2
      exit 1
      ;;
  esac

  assert_eq "$expected_adapter" "$DISTRO_ADAPTER_ID" "$label adapter"
  assert_eq "$expected_family" "$DISTRO_FAMILY" "$label family"
}

write_os_release ubuntu \
  'ID=ubuntu' \
  'PRETTY_NAME="Ubuntu 24.04 LTS"' \
  'VERSION_ID="24.04"' \
  'VERSION_CODENAME=noble' \
  'UBUNTU_CODENAME=noble'
detect_distro
assert_eq "ubuntu" "$DISTRO_ID" "ubuntu id"
assert_engine_consistent "ubuntu"
assert_eq "$ROOT_DIR/distros/ubuntu.sh" "$(distro_adapter_path "$ROOT_DIR")" "ubuntu adapter path"

write_os_release debian \
  'ID=debian' \
  'PRETTY_NAME="Debian GNU/Linux 13"' \
  'VERSION_ID="13"' \
  'VERSION_CODENAME=trixie'
detect_distro
assert_eq "debian" "$DISTRO_ID" "debian id"
assert_engine_consistent "debian"

write_os_release arch \
  'ID=arch' \
  'PRETTY_NAME="Arch Linux"'
detect_distro
assert_eq "arch" "$DISTRO_ID" "arch id"
assert_engine_consistent "arch"

write_os_release cachyos \
  'ID=cachyos' \
  'ID_LIKE="arch"' \
  'PRETTY_NAME="CachyOS"'
detect_distro
assert_eq "cachyos" "$DISTRO_ID" "cachyos id"
assert_engine_consistent "cachyos"
assert_eq "$ROOT_DIR/distros/arch.sh" "$(distro_adapter_path "$ROOT_DIR")" "cachyos adapter path"

write_os_release fedora \
  'ID=fedora' \
  'PRETTY_NAME="Fedora Linux 44"' \
  'VERSION_ID="44"'
detect_distro
assert_engine_consistent "fedora"
assert_eq "$ROOT_DIR/distros/fedora.sh" "$(distro_adapter_path "$ROOT_DIR")" "fedora adapter path"

write_os_release rocky \
  'ID=rocky' \
  'ID_LIKE="rhel centos fedora"' \
  'PRETTY_NAME="Rocky Linux 9.6"' \
  'VERSION_ID="9.6"'
detect_distro
assert_engine_consistent "rocky"

write_os_release almalinux \
  'ID=almalinux' \
  'ID_LIKE="rhel centos fedora"' \
  'PRETTY_NAME="AlmaLinux 9.6"' \
  'VERSION_ID="9.6"'
detect_distro
assert_engine_consistent "almalinux"

write_os_release opensuse_leap \
  'ID=opensuse-leap' \
  'ID_LIKE="suse opensuse"' \
  'PRETTY_NAME="openSUSE Leap 15.6"' \
  'VERSION_ID="15.6"'
detect_distro
assert_engine_consistent "opensuse leap"

write_os_release kali \
  'ID=kali' \
  'ID_LIKE="debian"' \
  'PRETTY_NAME="Kali GNU/Linux Rolling"' \
  'VERSION_ID="2024.4"' \
  'VERSION_CODENAME=kali-rolling'
detect_distro
assert_eq "kali" "$DISTRO_ID" "kali id"
assert_engine_consistent "kali"

write_os_release ubuntu26 \
  'ID=ubuntu' \
  'PRETTY_NAME="Ubuntu 26.04 LTS"' \
  'VERSION_ID="26.04"' \
  'VERSION_CODENAME=resolute' \
  'UBUNTU_CODENAME=resolute'
detect_distro
assert_eq "ubuntu" "$DISTRO_ID" "ubuntu 26.04 id"
assert_engine_consistent "ubuntu 26.04"

write_os_release linuxmint \
  'ID=linuxmint' \
  'ID_LIKE="ubuntu debian"' \
  'PRETTY_NAME="Linux Mint 22.3"' \
  'VERSION_ID="22.3"' \
  'VERSION_CODENAME=zena' \
  'UBUNTU_CODENAME=noble'
detect_distro
assert_eq "linuxmint" "$DISTRO_ID" "mint id"
assert_engine_consistent "mint"
assert_eq "$ROOT_DIR/distros/ubuntu.sh" "$(distro_adapter_path "$ROOT_DIR")" "mint adapter path"

write_os_release unknown \
  'ID=exampleos' \
  'PRETTY_NAME="ExampleOS"'
detect_distro
assert_eq "exampleos" "$DISTRO_ID" "unknown id"
assert_engine_consistent "unknown"

# Fallback: when Python is unavailable, the shell layer must not classify support.
write_os_release fallback \
  'ID=ubuntu' \
  'PRETTY_NAME="Ubuntu 24.04 LTS"' \
  'VERSION_ID="24.04"' \
  'VERSION_CODENAME=noble' \
  'UBUNTU_CODENAME=noble'
mkdir -p "$TMP_DIR/empty"
(
  # Force the bootstrap fallback by removing every external command from PATH.
  # Bash builtins (command, printf, echo, test, [[ ]]) remain available.
  PATH="$TMP_DIR/empty"
  detect_distro
  assert_eq "ubuntu" "$DISTRO_ID" "fallback id"
  assert_eq "ubuntu" "$DISTRO_ADAPTER_ID" "fallback adapter"
  assert_eq "ubuntu" "$DISTRO_FAMILY" "fallback family"
  assert_eq "0" "$DISTRO_SUPPORTED" "fallback does not claim supported"
  assert_eq "0" "$DISTRO_FUTURE" "fallback does not claim future"
  assert_eq "0" "$DISTRO_UNSUPPORTED" "fallback does not claim unsupported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "fallback marks undetermined"
)

# Fallback multi-family: the pure-Bash fallback derives mechanical identity for
# every major family without claiming support.
write_os_release fallback_arch \
  'ID=arch' \
  'PRETTY_NAME="Arch Linux"'
(
  PATH="$TMP_DIR/empty"
  OS_RELEASE_FILE="$TMP_DIR/fallback_arch" detect_distro
  assert_eq "arch" "$DISTRO_ID" "fallback arch id"
  assert_eq "arch" "$DISTRO_ADAPTER_ID" "fallback arch adapter"
  assert_eq "arch" "$DISTRO_FAMILY" "fallback arch family"
  assert_eq "pacman" "$DISTRO_PACKAGE_MANAGER" "fallback arch package manager"
  assert_eq "0" "$DISTRO_SUPPORTED" "fallback arch does not claim supported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "fallback arch marks undetermined"
)

write_os_release fallback_redhat \
  'ID=fedora' \
  'PRETTY_NAME="Fedora Linux 44"' \
  'VERSION_ID="44"'
(
  PATH="$TMP_DIR/empty"
  OS_RELEASE_FILE="$TMP_DIR/fallback_redhat" detect_distro
  assert_eq "fedora" "$DISTRO_ID" "fallback redhat id"
  assert_eq "fedora" "$DISTRO_ADAPTER_ID" "fallback redhat adapter"
  assert_eq "redhat" "$DISTRO_FAMILY" "fallback redhat family"
  assert_eq "dnf" "$DISTRO_PACKAGE_MANAGER" "fallback redhat package manager"
  assert_eq "0" "$DISTRO_SUPPORTED" "fallback redhat does not claim supported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "fallback redhat marks undetermined"
)

write_os_release fallback_suse \
  'ID=opensuse-leap' \
  'ID_LIKE="suse opensuse"' \
  'PRETTY_NAME="openSUSE Leap 15.6"' \
  'VERSION_ID="15.6"'
(
  PATH="$TMP_DIR/empty"
  OS_RELEASE_FILE="$TMP_DIR/fallback_suse" detect_distro
  assert_eq "opensuse-leap" "$DISTRO_ID" "fallback suse id"
  assert_eq "opensuse" "$DISTRO_ADAPTER_ID" "fallback suse adapter"
  assert_eq "suse" "$DISTRO_FAMILY" "fallback suse family"
  assert_eq "zypper" "$DISTRO_PACKAGE_MANAGER" "fallback suse package manager"
  assert_eq "0" "$DISTRO_SUPPORTED" "fallback suse does not claim supported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "fallback suse marks undetermined"
)

# Engine failure modes: if the Python engine is present but returns garbage,
# exits non-zero, or hangs, lib/distro.sh must degrade to the pure-Bash fallback.
write_os_release engine_failure \
  'ID=debian' \
  'PRETTY_NAME="Debian GNU/Linux 13"' \
  'VERSION_ID="13"' \
  'VERSION_CODENAME=trixie'

_mk_fake_python() {
  printf '%s\n' "$1" > "$TMP_DIR/fake-python"
  chmod +x "$TMP_DIR/fake-python"
}

# 1. Engine returns invalid JSON.
_mk_fake_python '#!/usr/bin/env bash
printf "not json\n"
exit 0
'
(
  PATH="$TMP_DIR"
  WATCHDOGVPN_PYTHON="$TMP_DIR/fake-python"
  OS_RELEASE_FILE="$TMP_DIR/engine_failure" detect_distro
  assert_eq "debian" "$DISTRO_ID" "invalid-json fallback id"
  assert_eq "0" "$DISTRO_SUPPORTED" "invalid-json fallback does not claim supported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "invalid-json fallback marks undetermined"
)

# 2. Engine exits non-zero.
_mk_fake_python '#!/usr/bin/env bash
printf "engine crash\n" >&2
exit 2
'
(
  PATH="$TMP_DIR"
  WATCHDOGVPN_PYTHON="$TMP_DIR/fake-python"
  OS_RELEASE_FILE="$TMP_DIR/engine_failure" detect_distro
  assert_eq "debian" "$DISTRO_ID" "crash fallback id"
  assert_eq "0" "$DISTRO_SUPPORTED" "crash fallback does not claim supported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "crash fallback marks undetermined"
)

# 3. Engine hangs (timeout 1s via the wrapper used by lib/distro.sh).
_mk_fake_python '#!/usr/bin/env bash
sleep 60
'
(
  PATH="$TMP_DIR"
  WATCHDOGVPN_PYTHON="$TMP_DIR/fake-python"
  OS_RELEASE_FILE="$TMP_DIR/engine_failure" detect_distro
  assert_eq "debian" "$DISTRO_ID" "timeout fallback id"
  assert_eq "0" "$DISTRO_SUPPORTED" "timeout fallback does not claim supported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "timeout fallback marks undetermined"
)

printf 'distro detection checks passed\n'
