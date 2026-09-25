#!/usr/bin/env bash
set -euo pipefail

# Distro detection for WatchdogVPN bootstrap.
#
# PRIMARY SOURCE OF TRUTH (preferred):
#   tools/compat_distro_classify.py reads compat/compatibility.json and the
#   compat.detection engine. It returns a stable JSON shape with
#   support_classification, adapter_id, family_id, etc.
#
# FALLBACK (bootstrap only, no support classification):
#   If Python or the engine is unavailable, this file falls back to a minimal
#   pure-Bash reader of /etc/os-release. The fallback resolves identity,
#   adapter/family and a package-manager seed, but it NEVER decides
#   support_classification, NEVER marks a distro as supported, and NEVER
#   produces DISTRO_FUTURE=1. When the fallback is active the distro is
#   considered undetermined/unsupported until the engine can be run.


# Reset all exported variables so repeated calls are idempotent.
detect_distro() {
  DISTRO_ID="unknown"
  DISTRO_ID_LIKE=""
  DISTRO_NAME="Unknown Linux"
  DISTRO_ADAPTER_ID="unknown"
  DISTRO_FAMILY="unknown"
  DISTRO_PACKAGE_MANAGER="unknown"
  DISTRO_SUPPORTED=0
  DISTRO_FUTURE=0
  DISTRO_UNSUPPORTED=0
  DISTRO_UNDETERMINED=0
  DISTRO_ENGINE_BLOCKED=0
  DISTRO_ENGINE_BLOCKED_REASON=""

  local os_release="${OS_RELEASE_FILE:-/etc/os-release}"

  if _detect_distro_with_engine "$os_release"; then
    return 0
  fi

  _detect_distro_fallback "$os_release"
}

# Certification runs may exercise a release before its manifest promotion, but
# only when both the caller and the field-validation harness opt in explicitly.
distro_certification_lab_enabled() {
  [[ "${WATCHDOGVPN_CERTIFICATION_LAB:-0}" == "1" ]] \
    && [[ "${WATCHDOGVPN_FIELD_VALIDATION:-0}" == "1" ]]
}

# Marker recording that a real end user - not the internal certification lab
# - explicitly accepted the risk of running WatchdogVPN on an experimental
# distro. This is intentionally separate from distro_certification_lab_enabled:
# that one is the internal field-validation gate and is never promoted or
# persisted; this one is the honest end-user informed-consent record, and it
# never changes support_classification in the manifest - it only lets the
# product run here because the user, not WatchdogVPN, decided to accept the
# risk.
WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER="${WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER:-${WATCHDOGVPN_ETC_CONFIG_DIR:-/etc/watchdogvpn}/.experimental-distro-override}"

# True only when a previously recorded acceptance exists AND matches the
# distro detected right now. A stale acceptance for a different distro never
# silently carries over - switching to another unproven distro re-prompts.
distro_experimental_override_accepted() {
  [[ -r "$WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER" ]] || return 1
  local recorded_distro=""
  recorded_distro="$(head -n 1 "$WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER" 2>/dev/null || true)"
  [[ -n "$recorded_distro" && "$recorded_distro" == "${DISTRO_ID:-}" ]]
}

# Persist that the user accepted the experimental-distro risk for the distro
# detected right now. Never called for the certification-lab path - that one
# stays unpromoted and unrecorded, exactly as before this function existed.
distro_record_experimental_override() {
  local marker_dir tmp_marker
  marker_dir="$(dirname "$WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER")"

  if [[ "${EUID:-$(id -u)}" -ne 0 && "$WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER" == /etc/* ]]; then
    tmp_marker="$(mktemp)"
    {
      printf '%s\n' "${DISTRO_ID:-unknown}"
      printf '%s\n' "${DISTRO_NAME:-Unknown Linux}"
      date -u '+%Y-%m-%dT%H:%M:%SZ'
    } >"$tmp_marker"
    sudo install -d -m 0700 -o root -g root "$marker_dir"
    sudo install -m 0600 -o root -g root "$tmp_marker" "$WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER"
    rm -f "$tmp_marker"
    return 0
  fi

  install -d -m 0700 "$marker_dir"
  {
    printf '%s\n' "${DISTRO_ID:-unknown}"
    printf '%s\n' "${DISTRO_NAME:-Unknown Linux}"
    date -u '+%Y-%m-%dT%H:%M:%SZ'
  } >"$WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER"
  chmod 600 "$WATCHDOGVPN_EXPERIMENTAL_OVERRIDE_MARKER"
}


# Minimum Python (3.MINOR) the detection engine itself requires. The engine
# (tools/compat_distro_classify.py + compat.detection / compat.support_model)
# needs only `from __future__ import annotations` and stdlib `dataclasses`,
# both Python 3.7+. It does NOT need dataclass(slots=True), so this floor is
# deliberately lower than the runtime floor WATCHDOGVPN_MIN_PYTHON_MINOR (3.10)
# in lib/common.sh. Keeping the two floors separate is what lets RHEL-family
# fresh hosts (platform python3 = 3.9) keep classifying through the engine as
# they do today: reusing the 3.10 runtime floor here would wrongly block them
# and force an unnecessary interpreter bootstrap on every certified distro.
WATCHDOGVPN_MIN_DETECT_PYTHON_MINOR="${WATCHDOGVPN_MIN_DETECT_PYTHON_MINOR:-7}"

# Try the engine first. Returns 0 on success, 1 on any failure. When the
# failure is specifically that no interpreter meets the detection floor, it
# sets DISTRO_ENGINE_BLOCKED=1 with reason interpreter_missing; detect_distro
# then degrades to the pure-Bash identity fallback, which never classifies
# support. The caller (install.sh) may bootstrap the adapter-declared
# interpreter and re-run detection to obtain the authoritative classification.
_detect_distro_with_engine() {
  local os_release="$1"
  local root_dir
  if [[ -n "${_WATCHDOGVPN_ROOT_DIR:-}" ]]; then
    root_dir="$_WATCHDOGVPN_ROOT_DIR"
  else
    # Use only bash builtins so this works even when PATH is empty.
    root_dir="$(cd "${BASH_SOURCE[0]%/*}/.." 2>/dev/null && pwd)"
  fi

  local python_cmd=""
  local candidate
  if [[ -n "${WATCHDOGVPN_PYTHON:-}" ]]; then
    candidate="$WATCHDOGVPN_PYTHON"
    # A forced interpreter that does not meet the detection floor must not be
    # handed to the engine; treat it as interpreter_missing so the caller can
    # bootstrap the adapter-declared one.
    if command -v "$candidate" >/dev/null 2>&1 \
      && "$candidate" -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3, ${WATCHDOGVPN_MIN_DETECT_PYTHON_MINOR}) else 1)" >/dev/null 2>&1; then
      python_cmd="$candidate"
    fi
  else
    # Select the first interpreter that actually meets the DETECTION floor.
    # This replaces the former unguarded local loop (python3.11 python3.10
    # python3) that silently handed a too-old python3 (e.g. Leap 15.6's 3.6)
    # to the classifier, which then died with a SyntaxError.
    for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 \
      python3.9 python3.8 python3.7 python3; do
      if command -v "$candidate" >/dev/null 2>&1 \
        && "$candidate" -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3, ${WATCHDOGVPN_MIN_DETECT_PYTHON_MINOR}) else 1)" >/dev/null 2>&1; then
        python_cmd="$candidate"
        break
      fi
    done
  fi
  if [[ -z "$python_cmd" ]]; then
    DISTRO_ENGINE_BLOCKED=1
    DISTRO_ENGINE_BLOCKED_REASON="interpreter_missing"
    return 1
  fi

  local classify_output classify_rc
  classify_rc=0
  classify_output="$(timeout 5 "$python_cmd" \
    "$root_dir/tools/compat_distro_classify.py" \
    --os-release "$os_release" \
    classify 2>/dev/null)" || classify_rc=$?

  if [[ "$classify_rc" != "0" || -z "$classify_output" ]]; then
    return 1
  fi

  # Parse the stable JSON output with Python (the engine already required it).
  local parsed
  parsed="$(printf '%s\n' "$classify_output" | "$python_cmd" -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if d.get("status") != "ok":
    sys.exit(1)
for key in (
    "distro_id", "distro_name", "adapter_id", "family_id",
    "package_manager", "support_classification", "resolution_status"
):
    print(d.get(key, ""))
' 2>/dev/null)" || return 1

  if [[ -z "$parsed" ]]; then
    return 1
  fi

  local distro_id distro_name adapter_id family_id package_manager support resolution
  {
    IFS= read -r distro_id
    IFS= read -r distro_name
    IFS= read -r adapter_id
    IFS= read -r family_id
    IFS= read -r package_manager
    IFS= read -r support
    IFS= read -r resolution
  } <<<"$parsed"

  if [[ -z "$distro_id" || -z "$support" ]]; then
    return 1
  fi

  DISTRO_ID="$distro_id"
  DISTRO_NAME="${distro_name:-Unknown Linux}"
  DISTRO_ADAPTER_ID="${adapter_id:-$distro_id}"
  DISTRO_FAMILY="$(_family_short_from_technical "${family_id:-$distro_id}")"
  DISTRO_PACKAGE_MANAGER="${package_manager:-unknown}"

  case "$support" in
    certified|supported|family_inferred)
      DISTRO_SUPPORTED=1
      ;;
    experimental)
      DISTRO_FUTURE=1
      ;;
    unsupported)
      DISTRO_UNSUPPORTED=1
      ;;
    *)
      return 1
      ;;
  esac

  return 0
}


# Minimal pure-Bash fallback for bootstrap identity only.
_detect_distro_fallback() {
  local os_release="$1"

  DISTRO_SUPPORTED=0
  DISTRO_FUTURE=0
  DISTRO_UNSUPPORTED=0
  DISTRO_UNDETERMINED=1

  if [[ ! -r "$os_release" ]]; then
    # No legible/inexistente: NO es un "unsupported" demostrado, es estado
    # indeterminado (no se pudo determinar la distro). UNDETERMINED ya está
    # marcado por defecto arriba; solo hay que no alterarlo.
    return 0
  fi

  unset ID ID_LIKE NAME PRETTY_NAME
  # shellcheck disable=SC1090,SC1091
  . "$os_release"

  DISTRO_ID="${ID:-unknown}"
  DISTRO_ID_LIKE="${ID_LIKE:-}"
  DISTRO_NAME="${PRETTY_NAME:-${NAME:-Unknown Linux}}"

  # Mechanical adapter/family derivation. This is NOT a support decision.
  case "$DISTRO_ID" in
    ubuntu)
      DISTRO_ADAPTER_ID="ubuntu"
      DISTRO_FAMILY="ubuntu"
      DISTRO_PACKAGE_MANAGER="apt"
      ;;
    debian)
      DISTRO_ADAPTER_ID="debian"
      DISTRO_FAMILY="debian"
      DISTRO_PACKAGE_MANAGER="apt"
      ;;
    arch)
      DISTRO_ADAPTER_ID="arch"
      DISTRO_FAMILY="arch"
      DISTRO_PACKAGE_MANAGER="pacman"
      ;;
    fedora|rhel|centos|rocky|almalinux)
      DISTRO_ADAPTER_ID="fedora"
      DISTRO_FAMILY="redhat"
      DISTRO_PACKAGE_MANAGER="dnf"
      ;;
    opensuse|opensuse-leap|opensuse-tumbleweed)
      DISTRO_ADAPTER_ID="opensuse"
      DISTRO_FAMILY="suse"
      DISTRO_PACKAGE_MANAGER="zypper"
      ;;
    *)
      case " $DISTRO_ID_LIKE " in
        *" arch "*)
          DISTRO_ADAPTER_ID="arch"
          DISTRO_FAMILY="arch"
          DISTRO_PACKAGE_MANAGER="pacman"
          ;;
        *" ubuntu "*)
          DISTRO_ADAPTER_ID="ubuntu"
          DISTRO_FAMILY="ubuntu"
          DISTRO_PACKAGE_MANAGER="apt"
          ;;
        *" debian "*)
          DISTRO_ADAPTER_ID="debian"
          DISTRO_FAMILY="debian"
          DISTRO_PACKAGE_MANAGER="apt"
          ;;
        *" rhel "*|*" centos "*|*" fedora "*)
          DISTRO_ADAPTER_ID="fedora"
          DISTRO_FAMILY="redhat"
          DISTRO_PACKAGE_MANAGER="dnf"
          ;;
        *" suse "*|*" opensuse "*)
          DISTRO_ADAPTER_ID="opensuse"
          DISTRO_FAMILY="suse"
          DISTRO_PACKAGE_MANAGER="zypper"
          ;;
        *)
          DISTRO_ADAPTER_ID="$DISTRO_ID"
          DISTRO_FAMILY="$DISTRO_ID"
          DISTRO_PACKAGE_MANAGER="unknown"
          ;;
      esac
      ;;
  esac

  return 0
}


# Map a technical family id (e.g. redhat_dnf) to the short legacy family
# identifier used by doctor.sh and other shell consumers. This is purely a
# compatibility shim; the engine remains the source of truth for support.
_family_short_from_technical() {
  case "$1" in
    arch_pacman) printf 'arch' ;;
    debian_apt)  printf 'debian' ;;
    ubuntu_apt)  printf 'ubuntu' ;;
    redhat_dnf)  printf 'redhat' ;;
    suse_zypper) printf 'suse' ;;
    *)           printf '%s' "$1" ;;
  esac
}


distro_adapter_path() {
  local root="$1"
  printf '%s/distros/%s.sh' "$root" "${DISTRO_ADAPTER_ID:-$DISTRO_ID}"
}

# Sequencing fix for the compatibility-engine bootstrap (Phase 23.7.5.11D).
#
# When the detection engine could not run because no interpreter meets the
# DETECTION floor (DISTRO_ENGINE_BLOCKED=1, reason interpreter_missing) but the
# pure-Bash identity fallback already resolved a known adapter and package
# manager, this provisions ONLY the interpreter package the adapter declares
# (e.g. python311 for openSUSE) through the normal package path, then re-runs
# authoritative detection through the Python engine - never through the Bash
# fallback. This keeps the engine (compat.detection) and the runtime floor
# (WATCHDOGVPN_MIN_PYTHON_MINOR=10) untouched, and never lets Bash grant
# support_classification.
#
# Return codes:
#   0  bootstrap not needed, dry-run simulated it, or bootstrap succeeded.
#   1  bootstrap not applicable (unknown identity, missing adapter, or the
#      adapter declares no bootstrap package) - leave undetermined handling to
#      the caller.
#   2  bootstrap was needed but failed - the caller must abort the install.
distro_bootstrap_interpreter_if_needed() {
  [[ "${DISTRO_ENGINE_BLOCKED:-0}" == "1" ]] || return 0
  [[ "${DISTRO_UNDETERMINED:-0}" == "1" ]] || return 0
  [[ "${DISTRO_ADAPTER_ID:-unknown}" != "unknown" ]] || return 1
  [[ "${DISTRO_PACKAGE_MANAGER:-unknown}" != "unknown" ]] || return 1

  local adapter
  adapter="$(distro_adapter_path "${_WATCHDOGVPN_ROOT_DIR:-$(cd "${BASH_SOURCE[0]%/*}/.." 2>/dev/null && pwd)}")"
  [[ -r "$adapter" ]] || return 1

  # shellcheck disable=SC1090
  . "$adapter"
  if ! declare -F distro_python_bootstrap_package >/dev/null 2>&1; then
    return 1
  fi
  local pkg
  pkg="$(distro_python_bootstrap_package)"
  [[ -n "$pkg" ]] || return 1

  info "compatibility engine needs a Python >=3.${WATCHDOGVPN_MIN_DETECT_PYTHON_MINOR}; bootstrapping adapter-declared interpreter package: ${pkg}"

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] install interpreter package %s via %s, then re-run detection\n' \
      "$pkg" "$DISTRO_PACKAGE_MANAGER"
    return 0
  fi

  if ! declare -F install_package_set >/dev/null 2>&1; then
    fail "cannot bootstrap interpreter package ${pkg}: package installer unavailable"
    return 2
  fi
  if ! install_package_set "$pkg"; then
    fail "failed to bootstrap interpreter package ${pkg} via ${DISTRO_PACKAGE_MANAGER}"
    return 2
  fi

  if [[ -n "${DISTRO_PYTHON:-}" ]] && ! command -v "${DISTRO_PYTHON}" >/dev/null 2>&1; then
    fail "interpreter bootstrap installed ${pkg} but ${DISTRO_PYTHON} is still unavailable"
    return 2
  fi

  info "re-running compatibility detection with the bootstrapped interpreter"
  detect_distro
  if [[ "${DISTRO_ENGINE_BLOCKED:-0}" == "1" ]]; then
    fail "compatibility engine still blocked after interpreter bootstrap"
    return 2
  fi
  return 0
}
