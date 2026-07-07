#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Regression coverage for a real bug found during Phase 18 Task 18.4 manual
# validation: lib/runtime.sh::PYTHON_RUNTIME_PACKAGES was missing `metrics`
# (added in Phase 16) and `diagnostics` (imported by cli/main.py), so any
# real (non-dry-run) install/update since Phase 16 shipped a daemon that
# crashed immediately with `ModuleNotFoundError: No module named 'metrics'`.
# This was never caught because no real (non-dry-run) install/update had
# been run since - only --dry-run, which never touches the installed
# package tree or restarts the daemon.
#
# Rather than just asserting the two specific missing names, this
# discovers every top-level Python package in the repo, finds every
# cross-package import among the packages that ARE listed as installed,
# and fails if any imported top-level package is missing from the list -
# so this class of bug cannot recur when a future phase adds a new
# top-level package and forgets to list it here.

# shellcheck source=../../lib/runtime.sh
. "$ROOT_DIR/lib/runtime.sh"

listed="$(printf '%s\n' "${PYTHON_RUNTIME_PACKAGES[@]}" | sort -u)"

missing="$(cd "$ROOT_DIR" && python3 - "$listed" <<'PY'
import ast
import sys
from pathlib import Path

root = Path(".")
listed = set(sys.argv[1].split())

all_packages = {
    p.name
    for p in root.iterdir()
    if p.is_dir() and (p / "__init__.py").exists()
}

imported_from = set()
for pkg in sorted(listed & all_packages):
    for py_file in (root / pkg).rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                top = node.module.split(".", 1)[0]
                if top in all_packages:
                    imported_from.add(top)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".", 1)[0]
                    if top in all_packages:
                        imported_from.add(top)

missing = sorted(imported_from - listed)
print("\n".join(missing))
PY
)"

if [[ -n "$missing" ]]; then
  printf 'FAIL: lib/runtime.sh PYTHON_RUNTIME_PACKAGES is missing packages actually imported by installed code:\n' >&2
  printf '  %s\n' $missing >&2
  printf 'A real install/update would ship a daemon/CLI that crashes with ModuleNotFoundError.\n' >&2
  exit 1
fi

printf 'python runtime packages checks passed\n'
