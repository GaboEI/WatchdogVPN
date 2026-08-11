#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT_DIR/lib/distro.sh"

WATCHDOGVPN_CERTIFICATION_LAB=1
WATCHDOGVPN_FIELD_VALIDATION=0
if distro_certification_lab_enabled; then
  printf 'FAIL: certification lab must require field validation\n' >&2
  exit 1
fi

WATCHDOGVPN_CERTIFICATION_LAB=0
WATCHDOGVPN_FIELD_VALIDATION=1
if distro_certification_lab_enabled; then
  printf 'FAIL: field validation alone must not enable certification lab\n' >&2
  exit 1
fi

WATCHDOGVPN_CERTIFICATION_LAB=1
WATCHDOGVPN_FIELD_VALIDATION=1
if ! distro_certification_lab_enabled; then
  printf 'FAIL: both explicit certification controls must enable the lab\n' >&2
  exit 1
fi

printf 'certification lab gate checks passed\n'
