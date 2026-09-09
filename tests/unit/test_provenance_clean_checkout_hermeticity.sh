#!/usr/bin/env bash
# Hermeticity regression for the provenance clean-checkout gate: a developer's
# global git excludesFile (resolved via $HOME) must never decide whether the
# repository looks "clean" to require_clean_source_checkout. Local tool
# artifacts (e.g. .claude/) must be ignored by the versioned .gitignore so the
# gate sees the same tree on any machine and with any HOME.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_HOME="$(mktemp -d)"
trap 'rm -rf "${TMP_HOME}"' EXIT

fail_count=0

# CASE 1: the versioned .gitignore must cover local tool state directories
# that are known to appear inside developer checkouts.
for pattern in '.claude/'; do
  if grep -Fxq "${pattern}" "${ROOT_DIR}/.gitignore"; then
    printf 'CASE_OK: .gitignore covers %s\n' "${pattern}"
  else
    printf 'FAIL: .gitignore does not cover %s; provenance gate sees developer tool state as untracked\n' "${pattern}" >&2
    fail_count=$((fail_count + 1))
  fi
done

# CASE 2: with an empty HOME (no user excludesFile), a clean tree must report
# zero porcelain entries. This is exactly what install.sh/update.sh see when
# tests or users run them with a different HOME.
porcelain="$(HOME="${TMP_HOME}" git -C "${ROOT_DIR}" status --porcelain=v1 --untracked-files=all)"
if [[ -z "${porcelain}" ]]; then
  printf 'CASE_OK: clean tree is hermetic under a foreign HOME\n'
else
  printf 'FAIL: tree looks dirty under a foreign HOME; entries:\n%s\n' "${porcelain}" >&2
  fail_count=$((fail_count + 1))
fi

if [[ "$fail_count" -ne 0 ]]; then
  printf 'FAILED: %s case(s)\n' "$fail_count" >&2
  exit 1
fi

printf 'OK: test_provenance_clean_checkout_hermeticity\n'
