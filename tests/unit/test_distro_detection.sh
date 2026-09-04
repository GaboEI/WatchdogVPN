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
  local body="$1"
  {
    printf '#!/bin/bash\n'
    # Simulate an interpreter that satisfies the detection floor (3.7+), so
    # the version gate passes and the engine failure mode below is reached.
    printf 'if [[ "$1" == "-c" ]]; then\n'
    printf '  if [[ "$2" =~ \\(3,\\ ([0-9]+)\\) ]]; then\n'
    printf '    exit 0\n'
    printf '  fi\n'
    printf '  exit 0\n'
    printf 'fi\n'
    printf '%s\n' "$body"
  } > "$TMP_DIR/fake-python"
  chmod +x "$TMP_DIR/fake-python"
}

# 1. Engine returns invalid JSON.
_mk_fake_python 'printf "not json\n"
exit 0'
(
  PATH="$TMP_DIR"
  WATCHDOGVPN_PYTHON="$TMP_DIR/fake-python"
  OS_RELEASE_FILE="$TMP_DIR/engine_failure" detect_distro
  assert_eq "debian" "$DISTRO_ID" "invalid-json fallback id"
  assert_eq "0" "$DISTRO_SUPPORTED" "invalid-json fallback does not claim supported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "invalid-json fallback marks undetermined"
)

# 2. Engine exits non-zero.
_mk_fake_python 'printf "engine crash\n" >&2
exit 2'
(
  PATH="$TMP_DIR"
  WATCHDOGVPN_PYTHON="$TMP_DIR/fake-python"
  OS_RELEASE_FILE="$TMP_DIR/engine_failure" detect_distro
  assert_eq "debian" "$DISTRO_ID" "crash fallback id"
  assert_eq "0" "$DISTRO_SUPPORTED" "crash fallback does not claim supported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "crash fallback marks undetermined"
)

# 3. Engine hangs (timeout 1s via the wrapper used by lib/distro.sh).
_mk_fake_python 'sleep 60'
(
  PATH="$TMP_DIR"
  WATCHDOGVPN_PYTHON="$TMP_DIR/fake-python"
  OS_RELEASE_FILE="$TMP_DIR/engine_failure" detect_distro
  assert_eq "debian" "$DISTRO_ID" "timeout fallback id"
  assert_eq "0" "$DISTRO_SUPPORTED" "timeout fallback does not claim supported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "timeout fallback marks undetermined"
)

# Fallback: un os-release ilegible/inexistente NO es "unsupported"; es
# "undetermined" (no se pudo leer, no se demostró que sea no soportado). Un
# archivo inexistente nunca es legible (incluso bajo root), por lo que el
# test es determinístico.
(
  OS_RELEASE_FILE="$TMP_DIR/does-not-exist" detect_distro
  assert_eq "unknown" "$DISTRO_ID" "unreadable fallback id"
  assert_eq "0" "$DISTRO_SUPPORTED" "unreadable fallback does not claim supported"
  assert_eq "0" "$DISTRO_FUTURE" "unreadable fallback does not claim future"
  assert_eq "0" "$DISTRO_UNSUPPORTED" "unreadable fallback does not claim unsupported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "unreadable fallback marks undetermined"
)

# Misma garantía a nivel de la función de fallback directa.
_detect_distro_fallback "$TMP_DIR/does-not-exist"
assert_eq "0" "$DISTRO_UNSUPPORTED" "direct fallback does not claim unsupported"
assert_eq "1" "$DISTRO_UNDETERMINED" "direct fallback marks undetermined"

# Engine resolves python3.11 when available even if python3 also exists.
# Regression: _detect_distro_with_engine() used to default to python3 only,
# failing on distros where python3 < 3.7 (e.g. Leap 15.6 python3=3.6).
write_os_release engine_python_leap \
  'ID="opensuse-leap"' \
  'VERSION_ID="15.6"' \
  'PRETTY_NAME="openSUSE Leap 15.6"'
(
  OS_RELEASE_FILE="$TMP_DIR/engine_python_leap" detect_distro
  if command -v python3.11 >/dev/null 2>&1; then
    assert_eq "0" "$DISTRO_UNDETERMINED" "engine succeeds, not undetermined"
  fi
)

# Leap 15.6 ships python3=3.6 with no python3.11 preinstalled. The detection
# engine needs 3.7+ (stdlib dataclasses + `from __future__ import
# annotations`), so a 3.6 interpreter must never be handed to it. detect_distro
# must mark the engine blocked with reason interpreter_missing and fall back to
# the pure-Bash identity (opensuse/zypper) without ever claiming support.
_mk_python_36() {
  {
    printf '#!/bin/bash\n'
    printf 'if [[ "$1" == "-c" ]]; then\n'
    printf '  if [[ "$2" =~ \\(3,\\ ([0-9]+)\\) ]]; then\n'
    printf '    [[ 6 -ge "${BASH_REMATCH[1]}" ]] && exit 0 || exit 1\n'
    printf '  fi\n'
    printf '  exit 1\n'
    printf 'fi\n'
    printf 'exit 1\n'
  } > "$TMP_DIR/python3"
  chmod +x "$TMP_DIR/python3"
}

write_os_release leap_36 \
  'ID="opensuse-leap"' \
  'ID_LIKE="suse opensuse"' \
  'VERSION_ID="15.6"' \
  'PRETTY_NAME="openSUSE Leap 15.6"'
_mk_python_36
(
  PATH="$TMP_DIR"
  OS_RELEASE_FILE="$TMP_DIR/leap_36" detect_distro
  assert_eq "opensuse-leap" "$DISTRO_ID" "leap-36 id"
  assert_eq "opensuse" "$DISTRO_ADAPTER_ID" "leap-36 adapter"
  assert_eq "suse" "$DISTRO_FAMILY" "leap-36 family"
  assert_eq "zypper" "$DISTRO_PACKAGE_MANAGER" "leap-36 package manager"
  assert_eq "0" "$DISTRO_SUPPORTED" "leap-36 does not claim supported"
  assert_eq "1" "$DISTRO_UNDETERMINED" "leap-36 marks undetermined"
  assert_eq "1" "$DISTRO_ENGINE_BLOCKED" "leap-36 marks engine blocked"
  assert_eq "interpreter_missing" "$DISTRO_ENGINE_BLOCKED_REASON" "leap-36 engine blocked reason"
)

# Tumbleweed shares the opensuse adapter but ships a modern default python3, so
# the engine must classify it directly with no interpreter bootstrap. This is
# the non-regression guard for the sequencing fix: Tumbleweed must stay
# non-operative for the new bootstrap step.
write_os_release tumbleweed \
  'ID="opensuse-tumbleweed"' \
  'ID_LIKE="suse opensuse"' \
  'VERSION_ID="20260727"' \
  'PRETTY_NAME="openSUSE Tumbleweed"'
detect_distro
assert_engine_consistent "tumbleweed"
assert_eq "0" "$DISTRO_ENGINE_BLOCKED" "tumbleweed engine not blocked"

printf 'distro detection checks passed\n'
