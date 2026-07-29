#!/usr/bin/env python3
"""VM validation harness for Task 23.7.5.6b AmneziaWG userspace provisioning.

This harness is intentionally standalone and internal. It drives
``tools/compat_runtime_prepare.py`` with argv-based subprocess calls, captures
before/after evidence, and never integrates profile activation, public CLI,
package-manager repository execution, DKMS, kernel modules, DNS, firewall or
VPN traffic.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "compat_runtime_prepare.py"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(argv: list[str]) -> dict:
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, shell=False)
    payload = None
    if result.stdout.strip():
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = result.stdout
    return {"argv": argv, "returncode": result.returncode, "stdout": payload, "stderr": result.stderr}


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _baseline() -> dict:
    return {
        "captured_at": _now(),
        "boot_id": _read("/proc/sys/kernel/random/boot_id"),
        "os_release": _read("/etc/os-release"),
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "outputs": {
            name: {
                "exists": Path("/usr/local/bin", name).exists(),
                "is_symlink": Path("/usr/local/bin", name).is_symlink(),
            }
            for name in ("awg", "awg-quick", "amneziawg-go")
        },
    }


def _tool_args(args) -> list[str]:
    base = [
        sys.executable,
        str(TOOL),
        "--state-root",
        args.state_root,
        "--global-lock-root",
        args.global_lock_root,
        "--install-root",
        args.install_root,
        "--workspace-root",
        args.workspace_root,
    ]
    if args.os_release:
        base.extend(["--os-release", args.os_release])
    if args.build_user:
        base.extend(["--build-user", args.build_user])
    if args.force_runtime_absent:
        base.append("--force-runtime-absent")
    return base


def cmd_run_all(args) -> int:
    evidence = {"schema": "watchdogvpn.phase23_7_5_6b.vm_evidence.v1", "before": _baseline(), "steps": []}
    evidence["steps"].append(_run(_tool_args(args) + ["plan"]))
    if args.apply:
        evidence["steps"].append(_run(_tool_args(args) + ["prepare", "--apply"]))
        evidence["steps"].append(_run(_tool_args(args) + ["status"]))
        evidence["steps"].append(_run(_tool_args(args) + ["recover"]))
        evidence["steps"].append(_run(_tool_args(args) + ["uninstall", "--apply"]))
        evidence["steps"].append(_run(_tool_args(args) + ["status"]))
    evidence["after"] = _baseline()
    path = Path(args.evidence)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    print(json.dumps({"evidence": str(path), "steps": len(evidence["steps"])}, sort_keys=True))
    return 0 if all(step["returncode"] == 0 for step in evidence["steps"]) else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", default="/var/lib/watchdogvpn/provisioning")
    parser.add_argument("--global-lock-root", default="/run/lock/watchdogvpn/provisioning")
    parser.add_argument("--install-root", default="/usr/local/bin")
    parser.add_argument("--workspace-root", default="/var/lib/watchdogvpn/provisioning/build/amneziawg")
    parser.add_argument("--os-release")
    parser.add_argument("--build-user")
    parser.add_argument("--force-runtime-absent", action="store_true")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--apply", action="store_true", help="mutate the VM by preparing and uninstalling AWG userspace outputs")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run-all").set_defaults(func=cmd_run_all)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
