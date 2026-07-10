#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${WATCHDOGVPN_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
MANIFEST="${WATCHDOGVPN_PHASE23_MANIFEST:-/tmp/watchdogvpn-phase23-field-manifest.json}"
RUNBOOK="${WATCHDOGVPN_PHASE23_RUNBOOK:-/tmp/watchdogvpn-phase23-cli-runbook.md}"
SECTION="${1:-}"
EXTERNAL_VPN_STATE="${WATCHDOGVPN_EXTERNAL_VPN_STATE:-absent}"
DRY_RUN=0

usage() {
  cat <<'USAGE'
Phase 23 CLI field validation section runner.

Usage:
  tests/vm/phase23_run_cli_field_section.sh --dry-run all
  WATCHDOGVPN_FIELD_VALIDATION=1 tests/vm/phase23_run_cli_field_section.sh preflight
  WATCHDOGVPN_FIELD_VALIDATION=1 WATCHDOGVPN_EXTERNAL_VPN_STATE=present tests/vm/phase23_run_cli_field_section.sh protocols

Sections:
  all
  preflight
  imports
  protocols
  provider
  app-policy
  dns
  kill-switch
  rotation
  manual-off
  cleanup

Environment:
  WATCHDOGVPN_PHASE23_MANIFEST       default: /tmp/watchdogvpn-phase23-field-manifest.json
  WATCHDOGVPN_PHASE23_RUNBOOK        default: /tmp/watchdogvpn-phase23-cli-runbook.md
  WATCHDOGVPN_EXTERNAL_VPN_STATE     absent|present, default: absent
  WATCHDOGVPN_FIELD_VALIDATION=1     required for non-dry-run execution

This wrapper delegates to tests/vm/phase23_cli_field_validation_runner.py.
It can mutate VPN, DNS, routes, firewall, daemon and system state when not in
--dry-run. Run it only in the approved VM/lab context.
USAGE
}

section() {
  printf '\n== %s ==\n' "$1"
}

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      SECTION="$1"
      shift
      ;;
  esac
done

case "$SECTION" in
  all|preflight|imports|protocols|provider|app-policy|dns|kill-switch|rotation|manual-off|cleanup)
    ;;
  "")
    usage >&2
    exit 64
    ;;
  *)
    printf 'ERROR: unsupported Phase 23 section: %s\n' "$SECTION" >&2
    usage >&2
    exit 64
    ;;
esac

case "$EXTERNAL_VPN_STATE" in
  absent|present)
    ;;
  *)
    printf 'ERROR: WATCHDOGVPN_EXTERNAL_VPN_STATE must be absent or present, got: %s\n' "$EXTERNAL_VPN_STATE" >&2
    exit 64
    ;;
esac

cd "$ROOT_DIR"

section "Repository state"
run git status --short --branch
run git rev-parse HEAD "origin/phase-23-cli-field-validation"

section "Manifest and runbook"
run python3 tests/vm/phase23_cli_field_validation_plan.py \
  --manifest "$MANIFEST" \
  --output "$RUNBOOK"
printf 'PHASE23_RUNBOOK=%s\n' "$RUNBOOK"

section "Runner"
args=(
  tests/vm/phase23_cli_field_validation_runner.py
  --manifest "$MANIFEST"
  --section "$SECTION"
  --external-vpn-state "$EXTERNAL_VPN_STATE"
)
if [[ "$DRY_RUN" == "1" ]]; then
  args+=(--dry-run)
else
  if [[ "${WATCHDOGVPN_FIELD_VALIDATION:-0}" != "1" ]]; then
    printf 'ERROR: refusing real validation without WATCHDOGVPN_FIELD_VALIDATION=1\n' >&2
    exit 64
  fi
fi

run python3 "${args[@]}"
