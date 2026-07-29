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
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "compat_runtime_prepare.py"
MAX_CAPTURE_CHARS = 128 * 1024

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from compat.provisioning import engine, journal as journal_mod
from compat.provisioning.model import TransactionState
from tools import compat_runtime_prepare


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(argv: list[str]) -> dict:
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, shell=False)
    payload = None
    if result.stdout.strip():
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = _clip(result.stdout)
    return {"argv": argv, "returncode": result.returncode, "stdout": payload, "stderr": _clip(result.stderr)}


def _run_observation(argv: list[str], *, timeout: float = 20.0) -> dict:
    try:
        result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, shell=False, timeout=timeout)
        return {
            "argv": argv,
            "returncode": result.returncode,
            "stdout": _clip(result.stdout),
            "stderr": _clip(result.stderr),
        }
    except FileNotFoundError as exc:
        return {"argv": argv, "returncode": None, "stdout": "", "stderr": str(exc), "error_kind": "command_missing"}
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": argv,
            "returncode": None,
            "stdout": _clip(exc.stdout or ""),
            "stderr": _clip(exc.stderr or ""),
            "error_kind": "timeout",
        }


def _clip(value: str | bytes) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if len(value) <= MAX_CAPTURE_CHARS:
        return value
    return value[:MAX_CAPTURE_CHARS] + "\n[truncated]"


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _path_state(path: Path) -> dict:
    try:
        st = path.lstat()
    except OSError as exc:
        return {"path": str(path), "exists": False, "error": str(exc)}
    result = {
        "path": str(path),
        "exists": True,
        "mode": oct(st.st_mode & 0o7777),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size": st.st_size,
        "is_dir": path.is_dir(),
        "is_file": path.is_file(),
        "is_symlink": path.is_symlink(),
    }
    if path.is_file() and st.st_size <= 8 * 1024 * 1024:
        try:
            result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            result["sha256_error"] = str(exc)
    return result


def _tree_state(root: Path) -> dict:
    if not root.exists():
        return {"root": str(root), "exists": False, "entries": []}
    entries = []
    for current, dirs, files in os.walk(root):
        dirs.sort()
        files.sort()
        current_path = Path(current)
        for name in dirs + files:
            path = current_path / name
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                rel = str(path)
            state = _path_state(path)
            state["relative_path"] = rel
            entries.append(state)
    return {"root": str(root), "exists": True, "entries": entries}


def _write_evidence(path: Path, evidence: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)
    parent_fd = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _proc_matches() -> list[dict]:
    matches = []
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            raw = (item / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except OSError:
            continue
        lowered = raw.lower()
        if any(token in lowered for token in ("watchdogvpn", "amneziawg", " awg", "/awg")):
            matches.append({"pid": int(item.name), "cmdline": _clip(raw)})
    return sorted(matches, key=lambda row: row["pid"])


def _baseline(args, phase: str) -> dict:
    return {
        "phase": phase,
        "captured_at": _now(),
        "boot_id": (_read("/proc/sys/kernel/random/boot_id") or "").strip() or None,
        "os_release": _read("/etc/os-release"),
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "packages": {
            "dpkg": _run_observation(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]),
            "rpm": _run_observation(["rpm", "-qa"]),
            "pacman": _run_observation(["pacman", "-Q"]),
            "zypper": _run_observation(["zypper", "se", "-si"]),
        },
        "repositories": {
            "apt_policy": _run_observation(["apt-cache", "policy"]),
            "dnf_repolist": _run_observation(["dnf", "repolist", "--all"]),
            "zypper_lr": _run_observation(["zypper", "lr", "-u"]),
            "pacman_conf": _read("/etc/pacman.conf"),
            "apt_sources": _tree_state(Path("/etc/apt")),
            "yum_repos": _tree_state(Path("/etc/yum.repos.d")),
            "zypp_repos": _tree_state(Path("/etc/zypp/repos.d")),
        },
        "services": _run_observation(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain", "--no-legend"]),
        "network": {
            "address": _run_observation(["ip", "address", "show"]),
            "routes": _run_observation(["ip", "route", "show", "table", "all"]),
            "rules": _run_observation(["ip", "rule", "show"]),
        },
        "processes": _proc_matches(),
        "permissions": {
            "install_root": _path_state(Path(args.install_root)),
            "workspace_root": _path_state(Path(args.workspace_root)),
            "state_root": _path_state(Path(args.state_root)),
            "global_lock_root": _path_state(Path(args.global_lock_root)),
            "var_lib_watchdogvpn": _path_state(Path("/var/lib/watchdogvpn")),
        },
        "var_lib_watchdogvpn": _tree_state(Path("/var/lib/watchdogvpn")),
        "outputs": {
            name: {
                "exists": Path(args.install_root, name).exists(),
                "is_symlink": Path(args.install_root, name).is_symlink(),
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
    if getattr(args, "manifest", None):
        base.extend(["--manifest", args.manifest])
    if getattr(args, "dependency", None):
        base.extend(["--dependency", args.dependency])
    if args.os_release:
        base.extend(["--os-release", args.os_release])
    if getattr(args, "usr_os_release", None):
        base.extend(["--usr-os-release", args.usr_os_release])
    if args.build_user:
        base.extend(["--build-user", args.build_user])
    if args.force_runtime_absent:
        base.append("--force-runtime-absent")
    return base


def _seed_pending_prepare(args) -> dict:
    """Create a real durable prepare journal that recovery must resume.

    The VM reboot campaign needs evidence for recovery of pending state, not
    merely a post-reboot no-op. This harness-only helper uses the same internal
    plan builder as ``compat_runtime_prepare.py`` and persists the normal
    PLANNED -> AUTHORIZED -> APPLYING journal sequence without executing any
    build step. After a real reboot, ``recover`` must resume that journal
    through the production recovery path.
    """
    manifest, decision = compat_runtime_prepare._context(args)
    if decision.selected_method_id is None:
        return {"returncode": 2, "error_kind": "no_selected_method", "status": decision.resolution_status, "reason": decision.reason}
    Path(args.install_root).mkdir(parents=True, exist_ok=True)
    Path(args.workspace_root).mkdir(parents=True, exist_ok=True)
    env = compat_runtime_prepare._build_env(args, manifest, decision, mutating=True)
    plan, _executor = engine.build_plan(decision, registry=env.registry, expected_executor_version=env.expected_executor_version, context=env.context)
    transaction_id = "vm6b_reboot_%s" % os.urandom(8).hex()
    now = env.context.now
    journal = engine._initial_journal(plan, transaction_id=transaction_id, now_value=now())
    journal_mod.write_journal(env.state_root, journal)
    journal = journal.with_state(TransactionState.AUTHORIZED, now=now())
    journal_mod.write_journal(env.state_root, journal)
    journal = journal.with_state(TransactionState.APPLYING, now=now())
    journal_mod.write_journal(env.state_root, journal)
    loaded = journal_mod.read_journal(env.state_root, transaction_id)
    return {
        "returncode": 0,
        "transaction_id": transaction_id,
        "state": loaded.state.value,
        "step_states": [step.state.value for step in loaded.steps],
        "plan_digest": loaded.plan_digest,
    }


def cmd_run_all(args) -> int:
    evidence = {"schema": "watchdogvpn.phase23_7_5_6b.vm_evidence.v2", "mode": "single_boot_smoke", "before": _baseline(args, "before"), "steps": []}
    evidence["steps"].append(_run(_tool_args(args) + ["plan"]))
    if args.apply:
        evidence["steps"].append(_run(_tool_args(args) + ["prepare", "--apply"]))
        evidence["steps"].append(_run(_tool_args(args) + ["status"]))
        evidence["steps"].append(_run(_tool_args(args) + ["recover"]))
        evidence["steps"].append(_run(_tool_args(args) + ["uninstall", "--apply"]))
        evidence["steps"].append(_run(_tool_args(args) + ["status"]))
    evidence["after"] = _baseline(args, "after")
    path = Path(args.evidence)
    _write_evidence(path, evidence)
    print(json.dumps({"evidence": str(path), "steps": len(evidence["steps"])}, sort_keys=True))
    return 0 if all(step["returncode"] == 0 for step in evidence["steps"]) else 2


def cmd_prepare_reboot_campaign(args) -> int:
    evidence = {
        "schema": "watchdogvpn.phase23_7_5_6b.reboot_recovery.v1",
        "mode": "pre_reboot",
        "observations": {"before": _baseline(args, "pre_reboot_before")},
        "steps": [],
        "operator_next_step": "perform a real VM/host reboot, then run recover-after-reboot with --pre-evidence pointing to this file",
    }
    evidence["steps"].append({"phase": "plan", "result": _run(_tool_args(args) + ["plan"])})
    if args.apply:
        seeded = _seed_pending_prepare(args)
        evidence["pending_prepare"] = seeded
        evidence["steps"].append({"phase": "seed_pending_prepare", "result": seeded})
    else:
        evidence["steps"].append({"phase": "prepare_dry_run", "result": _run(_tool_args(args) + ["prepare"])})
    evidence["steps"].append({"phase": "status_after_prepare", "result": _run(_tool_args(args) + ["status"])})
    evidence["observations"]["after_prepare"] = _baseline(args, "pre_reboot_after_prepare")
    path = Path(args.evidence)
    _write_evidence(path, evidence)
    ok = all(step["result"]["returncode"] == 0 for step in evidence["steps"])
    print(json.dumps({"evidence": str(path), "phase": "pre_reboot", "boot_id": evidence["observations"]["before"]["boot_id"], "steps": len(evidence["steps"])}, sort_keys=True))
    return 0 if ok else 2


def cmd_recover_after_reboot(args) -> int:
    pre = json.loads(Path(args.pre_evidence).read_text(encoding="utf-8"))
    before_boot_id = pre.get("observations", {}).get("before", {}).get("boot_id")
    after = _baseline(args, "post_reboot_before_recovery")
    after_boot_id = after.get("boot_id")
    evidence = {
        "schema": "watchdogvpn.phase23_7_5_6b.reboot_recovery.v1",
        "mode": "post_reboot_recovery",
        "pre_evidence": str(Path(args.pre_evidence)),
        "boot_id_before_reboot": before_boot_id,
        "boot_id_after_reboot": after_boot_id,
        "boot_id_changed": bool(before_boot_id and after_boot_id and before_boot_id != after_boot_id),
        "observations": {"pre_reboot": pre.get("observations", {}), "post_reboot_before_recovery": after},
        "recovery": {},
        "cleanup": {},
    }
    recovery = _run(_tool_args(args) + ["recover"])
    status_after_recovery = _run(_tool_args(args) + ["status"])
    pending_transaction_id = pre.get("pending_prepare", {}).get("transaction_id")
    recovery_stdout = recovery.get("stdout")
    status_stdout = status_after_recovery.get("stdout")
    pending_recovered = True
    pending_committed = True
    if pending_transaction_id:
        pending_recovered = any(
            item.get("transaction_id") == pending_transaction_id and item.get("action") == "resume"
            for item in recovery_stdout
            if isinstance(item, dict)
        ) if isinstance(recovery_stdout, list) else False
        pending_committed = any(
            item.get("transaction_id") == pending_transaction_id and item.get("state") == "committed"
            for item in status_stdout
            if isinstance(item, dict)
        ) if isinstance(status_stdout, list) else False
    evidence["recovery"] = {
        "recover": recovery,
        "status_after_recovery": status_after_recovery,
        "pending_prepare_transaction_id": pending_transaction_id,
        "pending_prepare_recovered": pending_recovered,
        "pending_prepare_committed": pending_committed,
    }
    if args.cleanup:
        evidence["cleanup"]["uninstall"] = _run(_tool_args(args) + ["uninstall", "--apply"])
        evidence["cleanup"]["status_after_uninstall"] = _run(_tool_args(args) + ["status"])
    evidence["observations"]["post_recovery"] = _baseline(args, "post_reboot_after_recovery")
    path = Path(args.evidence)
    _write_evidence(path, evidence)
    step_results = [recovery, status_after_recovery] + [item for item in evidence["cleanup"].values()]
    ok = (
        evidence["boot_id_changed"]
        and pending_recovered
        and pending_committed
        and all(item["returncode"] == 0 for item in step_results)
    )
    print(json.dumps({"evidence": str(path), "phase": "post_reboot_recovery", "boot_id_changed": evidence["boot_id_changed"], "recovery_rc": recovery["returncode"]}, sort_keys=True))
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", default="/var/lib/watchdogvpn/provisioning")
    parser.add_argument("--global-lock-root", default="/run/lock/watchdogvpn/provisioning")
    parser.add_argument("--install-root", default="/usr/local/bin")
    parser.add_argument("--workspace-root", default="/var/lib/watchdogvpn/provisioning/build/amneziawg")
    parser.add_argument("--manifest")
    parser.add_argument("--dependency", default=compat_runtime_prepare.DEPENDENCY_ID, choices=(compat_runtime_prepare.DEPENDENCY_ID,))
    parser.add_argument("--os-release")
    parser.add_argument("--usr-os-release")
    parser.add_argument("--build-user")
    parser.add_argument("--force-runtime-absent", action="store_true")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--apply", action="store_true", help="mutate the VM by preparing and uninstalling AWG userspace outputs")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run-all").set_defaults(func=cmd_run_all)
    pre = sub.add_parser("prepare-reboot-campaign", help="capture pre-reboot baseline and run plan/prepare before a real VM reboot")
    pre.set_defaults(func=cmd_prepare_reboot_campaign)
    post = sub.add_parser("recover-after-reboot", help="verify boot_id changed, capture post-reboot baseline and run recovery")
    post.add_argument("--pre-evidence", required=True)
    post.add_argument("--cleanup", action="store_true", help="after recovery, uninstall owned AWG outputs through the provisioner")
    post.set_defaults(func=cmd_recover_after_reboot)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
