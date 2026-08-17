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
# shellcheck source=../../lib/install_files.sh
. "$ROOT_DIR/lib/install_files.sh"

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

runtime_items="$({
  printf '%s\n' "${PYTHON_RUNTIME_PACKAGES[@]}"
  printf '%s\n' "${PYTHON_RUNTIME_SUPPORT_FILES[@]}"
  printf '%s\n' "${PYTHON_RUNTIME_SUPPORT_DIRS[@]}"
} | sort -u)"
runtime_executables="$(printf '%s\n' "${PYTHON_RUNTIME_SUPPORT_EXECUTABLES[@]}" | sort -u)"

missing_doctor_runtime="$(python3 - "$ROOT_DIR/doctor.sh" "$runtime_items" "$runtime_executables" <<'PY'
import re
import sys
from pathlib import Path

doctor_path = Path(sys.argv[1])
declared_items = set(sys.argv[2].splitlines())
declared_executables = set(sys.argv[3].splitlines())
source = doctor_path.read_text(encoding="utf-8")

required_items = set()
required_executables = set()
for match in re.finditer(
    r'check_repo_file\s+"([^"]+)"(?:\s+(?:"exec"|exec))?',
    source,
):
    path = match.group(1)
    required_items.add(path.split("/", 1)[0])
    if match.group(0).endswith("exec"):
        required_executables.add(path)

for match in re.finditer(r'\$ROOT_DIR/([A-Za-z0-9_.-]+)(?:/|\")', source):
    required_items.add(match.group(1))
if 'distro_adapter_path "$ROOT_DIR"' in source:
    required_items.add("distros")

errors = [
    f"missing installed runtime item: {item}"
    for item in sorted(required_items - declared_items)
]
for path in sorted(required_executables):
    top_level = path.split("/", 1)[0]
    if top_level not in {"bin", "sbin"} and path not in declared_executables:
        errors.append(f"missing executable-mode preservation: {path}")
print("\n".join(errors))
PY
)"

if [[ -n "$missing_doctor_runtime" ]]; then
  printf 'FAIL: installed doctor runtime manifest is incomplete:\n%s\n' "$missing_doctor_runtime" >&2
  exit 1
fi

# Exercise the actual installed-tree layout. Static dependency checks above
# cannot see the engine paths that lib/distro.sh resolves at runtime.
runtime_tmp="$(mktemp -d)"
cleanup_runtime_tmp() {
  rm -rf -- "$runtime_tmp"
}
trap cleanup_runtime_tmp EXIT

sudo() {
  case "$1" in
    chown)
      return 0
      ;;
    install)
      shift
      local -a args=()
      while (($#)); do
        case "$1" in
          -o|-g)
            shift 2
            ;;
          *)
            args+=("$1")
            shift
            ;;
        esac
      done
      command install "${args[@]}"
      ;;
    *)
      command "$@"
      ;;
  esac
}

INSTALL_DRY_RUN=0
BACKUP_ROOT="$runtime_tmp/backups"
PYTHON_PACKAGE_DIR="$runtime_tmp/installed"
install_python_package_tree "$PYTHON_PACKAGE_DIR"

# The installed doctor may return non-zero when provenance is not published in
# this environment (e.g. a temp installed tree without a real
# /usr/local/lib/watchdogvpn/installed-version marker). That provenance FAIL is
# legitimate and out of scope for this test. We must still capture the output to
# verify the thing this test actually guards: that the installed doctor can load
# its compatibility engine. Guard against set -e aborting on the doctor's rc.
set +e
installed_doctor_output="$("$PYTHON_PACKAGE_DIR/doctor.sh" 2>&1)"
installed_doctor_rc=$?
set -e
if [[ "$installed_doctor_output" == *"could not load its compatibility engine"* ]]; then
  printf 'FAIL: installed doctor cannot load the compatibility engine\n' >&2
  exit 1
fi

if [[ ! -r "$PYTHON_PACKAGE_DIR/tools/compat_distro_classify.py" ]] \
  || [[ ! -r "$PYTHON_PACKAGE_DIR/compat/compatibility.json" ]]; then
  printf 'FAIL: installed runtime is missing compatibility classifier inputs\n' >&2
  exit 1
fi

printf 'python runtime packages checks passed\n'
