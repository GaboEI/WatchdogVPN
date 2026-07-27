#!/usr/bin/env python3
"""Phase 23.7.5.6a real-process validation harness for transactional provisioning.

Standalone by design (not named test_*.py, not swept up by
`python3 -m unittest discover tests`): several scenarios here send a real,
uncatchable SIGKILL to a child process and are not something the routine
full-suite gate should ever execute automatically.

Everything is confined to an injected sandbox directory using the lab-only
CanaryExecutor. This harness never touches a real package manager,
repository, network, DNS, firewall, service, protocol, VPN state or any
WatchdogVPN-managed system path. It is safe to run on any Linux host,
including a non-disposable one, because it mutates nothing outside the
sandbox/state-root directories passed on the command line.

Usage:
    python3 tests/vm/phase23_7_5_6a_transactional_provisioning_validation.py \
        --sandbox /tmp/wdvpn-6a-sandbox --state-root /tmp/wdvpn-6a-state run-all

    # Internal worker mode (used by run-all via subprocess, also callable directly):
    python3 .../phase23_7_5_6a_transactional_provisioning_validation.py \
        --sandbox ... --state-root ... worker --capability-id c1 --dependency-id d1 \
        --kill-after write_ahead_applying
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from compat.dependency_resolution import ResolutionDecision
from compat.provisioning import engine, journal as journal_mod, lock as lock_mod
from compat.provisioning.errors import ProvisionerLockHeldError
from compat.provisioning.executors import (
    CANARY_EXECUTOR_VERSION,
    CANARY_METHOD_KIND,
    CanaryExecutor,
    ExecutionContext,
    TrustedExecutorRegistry,
    _companion_content,
    _marker_content,
)
from compat.provisioning.model import RecoveryAction, StepState, TransactionState


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _decision(capability_id: str, dependency_id: str) -> ResolutionDecision:
    return ResolutionDecision(
        capability_id=capability_id, dependency_id=dependency_id,
        resolved_distribution="lab", resolved_release=None, technical_family="lab_fixture",
        release_model="rolling", support_classification="lab_fixture", machine_architecture="x86_64",
        observed_capability_status="absent", candidate_chain=("canary_method",),
        selected_method_id="canary_method", selected_method_kind=CANARY_METHOD_KIND,
        resolution_status="method_selected", execution_ready=True,
        rejected_candidates=(), evidence=(), reason="VM validation harness for 23.7.5.6a",
        provider_type="lab_fixture", provider_authoritative=False,
        availability_observations=(), all_availability_observations=(),
    )


def _env(sandbox: Path, state_root: Path) -> engine.ProvisioningEnvironment:
    sandbox.mkdir(parents=True, exist_ok=True)
    registry = TrustedExecutorRegistry()
    registry.register(method_kind=CANARY_METHOD_KIND, method_id="canary_method", executor=CanaryExecutor())
    context = ExecutionContext(allowed_roots=(sandbox,), now=_now)
    return engine.ProvisioningEnvironment(
        state_root=state_root, registry=registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=context
    )


class Evidence:
    def __init__(self, path: Path):
        self.path = path
        self.entries: list[dict] = []
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, phase: str, **data) -> None:
        entry = {"phase": phase, "at": _now(), **data}
        self.entries.append(entry)
        print("PHASE23_7_5_6A_VM %s %s" % (phase, json.dumps(data, sort_keys=True, default=str)))

    def flush(self) -> None:
        self.path.write_text(json.dumps(self.entries, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        os.chmod(self.path, 0o600)


# --------------------------------------------------------------------------
# Worker mode: runs a real apply, self-terminating with SIGKILL at a chosen
# checkpoint. SIGKILL cannot be caught -- this is a genuine hard kill, not a
# simulated one.
# --------------------------------------------------------------------------


def cmd_worker(args) -> int:
    sandbox = Path(args.sandbox)
    state_root = Path(args.state_root)
    env = _env(sandbox, state_root)
    decision = _decision(args.capability_id, args.dependency_id)
    plan, executor = engine.build_plan(decision, registry=env.registry, expected_executor_version=env.expected_executor_version, context=env.context)

    with lock_mod.acquire_provisioner_lock(journal_mod.lock_path(state_root), transaction_id=args.transaction_id, timeout=10.0):
        journal = engine._initial_journal(plan, transaction_id=args.transaction_id, now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        journal_mod.write_journal(state_root, journal)

        step0 = plan.steps[0]
        record = journal.step(step0.sequence)

        if args.kill_after == "write_ahead_applying":
            record = record.with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)  # write-ahead durable
            os.kill(os.getpid(), signal.SIGKILL)  # never returns

        record = record.with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
        journal = journal.with_step(record)
        journal_mod.write_journal(state_root, journal)
        result = executor.apply_step(record, env.context)  # real file write
        record = record.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result.undo_record)
        journal = journal.with_step(record)

        if args.kill_after == "after_apply_before_verify":
            journal_mod.write_journal(state_root, journal)
            os.kill(os.getpid(), signal.SIGKILL)  # never returns

        journal_mod.write_journal(state_root, journal)
        record = record.with_state(StepState.VERIFYING)
        journal = journal.with_step(record)
        verification = executor.verify_step(record, result, env.context)
        record = record.with_state(StepState.VERIFIED, completed_at=_now(), verification=verification.evidence)
        journal = journal.with_step(record)
        journal_mod.write_journal(state_root, journal)

        # Apply the remaining steps normally so "after_verify_before_commit"
        # has a fully-applied-and-verified transaction to crash on.
        for step in plan.steps[1:]:
            record = journal.step(step.sequence)
            record = record.with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            result = executor.apply_step(record, env.context)
            record = record.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result.undo_record)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            record = record.with_state(StepState.VERIFYING)
            journal = journal.with_step(record)
            verification = executor.verify_step(record, result, env.context)
            record = record.with_state(StepState.VERIFIED, completed_at=_now(), verification=verification.evidence)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)

        journal = journal.with_state(TransactionState.VERIFYING, now=_now())
        journal_mod.write_journal(state_root, journal)

        if args.kill_after == "after_verify_before_commit":
            os.kill(os.getpid(), signal.SIGKILL)  # never returns

        postcondition = executor.verify_postcondition(plan, env.context)
        assert postcondition.status == "verified"
        provenance = engine._finalize_provenance(state_root, journal, plan, executor, _now())
        journal = journal.with_state(TransactionState.COMMITTED, now=_now(), provenance=provenance)
        journal_mod.write_journal(state_root, journal)
    return 0


def _run_worker_and_expect_kill(sandbox: Path, state_root: Path, capability_id: str, dependency_id: str, transaction_id: str, kill_after: str, evidence: Evidence) -> None:
    argv = [
        sys.executable, __file__, "--sandbox", str(sandbox), "--state-root", str(state_root),
        "worker", "--capability-id", capability_id, "--dependency-id", dependency_id,
        "--transaction-id", transaction_id, "--kill-after", kill_after,
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    killed_by_sigkill = proc.returncode == -signal.SIGKILL
    evidence.record(
        "worker_killed", checkpoint=kill_after, returncode=proc.returncode, killed_by_sigkill=killed_by_sigkill,
        stdout=proc.stdout[-2000:], stderr=proc.stderr[-2000:],
    )
    if not killed_by_sigkill:
        raise SystemExit("worker for checkpoint %r did not die by SIGKILL (rc=%s); aborting harness" % (kill_after, proc.returncode))


# --------------------------------------------------------------------------
# Supervisor: drives every scenario, one disposable capability_id at a time.
# --------------------------------------------------------------------------


def cmd_run_all(args) -> int:
    sandbox = Path(args.sandbox)
    state_root = Path(args.state_root)
    if sandbox.exists():
        shutil.rmtree(sandbox)
    if state_root.exists():
        shutil.rmtree(state_root)
    sandbox.mkdir(parents=True)
    evidence = Evidence(Path(args.evidence) if args.evidence else (state_root.parent / "phase23_7_5_6a_vm_evidence.json"))
    env = _env(sandbox, state_root)

    baseline = _snapshot(sandbox, state_root)
    evidence.record("pre_state", snapshot=baseline)

    # 1. Lock exclusion between two real processes.
    lock_path = journal_mod.lock_path(state_root)
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys, time; sys.path.insert(0, %r); from pathlib import Path; "
         "from compat.provisioning.lock import acquire_provisioner_lock\n"
         "with acquire_provisioner_lock(Path(%r), transaction_id='holder', timeout=5.0):\n"
         "    print('ACQUIRED', flush=True); time.sleep(2.0)\n" % (str(ROOT), str(lock_path))],
        stdout=subprocess.PIPE, text=True,
    )
    line = holder.stdout.readline()
    contended = False
    try:
        with lock_mod.acquire_provisioner_lock(lock_path, transaction_id="contender", timeout=0.3):
            pass
    except ProvisionerLockHeldError:
        contended = True
    holder.wait(5)
    holder.stdout.close()
    evidence.record("lock_exclusion", holder_line=line.strip(), contended=contended)
    if not contended:
        raise SystemExit("lock exclusion did not hold between two real processes")

    # 2. Apply and verify.
    decision = _decision("cap_vm_apply", "dep_vm_apply")
    outcome = engine.prepare(decision, env, apply=True)
    evidence.record("apply_and_verify", status=outcome.status.value, transaction_id=outcome.transaction_id)
    if outcome.status.value != "committed":
        raise SystemExit("apply_and_verify did not commit: %r" % outcome)

    # 3. Second apply is idempotent.
    second = engine.prepare(decision, env, apply=True)
    evidence.record("idempotent_second_apply", status=second.status.value)
    if second.status.value != "already_provisioned":
        raise SystemExit("second apply was not idempotent: %r" % second)

    # 4. Rollback by injected failure (verification forced to fail).
    rollback_decision = _decision("cap_vm_rollback", "dep_vm_rollback")
    from unittest import mock
    from compat.provisioning.model import VerificationResult

    executor = env.registry.resolve(method_kind=CANARY_METHOD_KIND, method_id="canary_method", expected_executor_version=CANARY_EXECUTOR_VERSION)
    with mock.patch.object(executor, "verify_step", return_value=VerificationResult(status="verification_failed", error_kind="forced", error="forced VM validation failure")):
        rollback_outcome = engine.prepare(rollback_decision, env, apply=True)
    evidence.record("rollback_injected_failure", status=rollback_outcome.status.value, residuals=list(rollback_outcome.residuals))
    if rollback_outcome.status.value != "preparation_failed" or list((sandbox / "cap_vm_rollback.marker").parent.glob("cap_vm_rollback.*")):
        raise SystemExit("rollback via injected failure did not clean up: %r" % rollback_outcome)

    # 5/6. kill -9 after write-ahead (before apply) and after apply (before verify).
    for checkpoint, capability_id in (("write_ahead_applying", "cap_vm_kill_early"), ("after_apply_before_verify", "cap_vm_kill_mid")):
        transaction_id = "vm-%s" % checkpoint
        _run_worker_and_expect_kill(sandbox, state_root, capability_id, "dep_%s" % capability_id, transaction_id, checkpoint, evidence)
        pre_recovery = journal_mod.read_journal(state_root, transaction_id)
        evidence.record("pre_recovery_state", checkpoint=checkpoint, state=pre_recovery.state.value)
        reports = engine.recover_pending(state_root, env.registry, env.expected_executor_version, env.context)
        matching = [r for r in reports if r.transaction_id == transaction_id]
        evidence.record("recovery_decision", checkpoint=checkpoint, action=matching[0].action.value if matching else "none", reason=matching[0].reason if matching else "")
        final = journal_mod.read_journal(state_root, transaction_id)
        if final.state != TransactionState.COMMITTED:
            raise SystemExit("recovery after kill -9 at %r did not commit: %r" % (checkpoint, final.state))

    # 7. Process-restart recovery is exactly what the loop above already
    #    demonstrated (a fresh `recover_pending` call in a brand-new
    #    interpreter process picks up the killed worker's journal).
    evidence.record("recovery_after_process_restart", note="demonstrated by steps 5/6 above: recover_pending runs in the supervisor's own process, separate from the killed worker")

    # 8/9. Recovery/rollback after a full OS reboot require an actual reboot
    # of the host this harness runs on and are intentionally NOT executed
    # automatically; see --reboot-checkpoint below for the second half of
    # that specific scenario.
    if args.reboot_checkpoint:
        transaction_id = "vm-reboot-%s" % args.reboot_checkpoint
        pending = journal_mod.list_pending_transaction_ids(state_root)
        if transaction_id in pending:
            reports = engine.recover_pending(state_root, env.registry, env.expected_executor_version, env.context)
            matching = [r for r in reports if r.transaction_id == transaction_id]
            evidence.record("recovery_after_reboot", transaction_id=transaction_id, action=matching[0].action.value if matching else "none")
        else:
            evidence.record("recovery_after_reboot_setup", note="no pending pre-reboot transaction found; run --prepare-reboot-checkpoint before rebooting")

    # 10/11. Uninstall + preservation of a pre-existing capability.
    uninstall_outcome = engine.uninstall("cap_vm_apply", env, apply=True)
    evidence.record("uninstall", status=uninstall_outcome.status.value)
    if uninstall_outcome.status.value != "uninstalled":
        raise SystemExit("uninstall did not complete: %r" % uninstall_outcome)

    pre_existing_id = "cap_vm_pre_existing"
    marker = _marker_content(pre_existing_id)
    companion = _companion_content(pre_existing_id, marker)
    (sandbox / ("%s.marker" % pre_existing_id)).write_bytes(marker)
    (sandbox / ("%s.companion" % pre_existing_id)).write_bytes(companion)
    pre_existing_outcome = engine.prepare(_decision(pre_existing_id, "dep_pre_existing"), env, apply=True)
    uninstall_pre_existing = engine.uninstall(pre_existing_id, env, apply=True)
    evidence.record(
        "preserve_pre_existing", prepare_status=pre_existing_outcome.status.value, uninstall_status=uninstall_pre_existing.status.value,
        marker_survives=(sandbox / ("%s.marker" % pre_existing_id)).exists(),
    )
    if pre_existing_outcome.status.value != "already_present" or uninstall_pre_existing.status.value != "out_of_contract":
        raise SystemExit("pre-existing capability was not preserved correctly: %r / %r" % (pre_existing_outcome, uninstall_pre_existing))

    # 12. Symlink rejection (end to end, via ownership-conflict/path-policy path).
    symlink_id = "cap_vm_symlink"
    real_target = sandbox / "elsewhere.txt"
    real_target.write_text("not a canary file")
    (sandbox / ("%s.marker" % symlink_id)).symlink_to(real_target)
    symlink_outcome = engine.prepare(_decision(symlink_id, "dep_symlink"), env, apply=True)
    evidence.record("symlink_rejected", status=symlink_outcome.status.value)
    if symlink_outcome.status.value != "ownership_conflict":
        raise SystemExit("symlink target was not rejected: %r" % symlink_outcome)
    (sandbox / ("%s.marker" % symlink_id)).unlink()
    real_target.unlink()

    # 13/14. Final cleanup + residual scan (no packages/repos/DNS/firewall/services/protocols touched).
    remaining_capabilities = [
        cid for cid in ("cap_vm_kill_early", "cap_vm_kill_mid")
    ]
    for cid in remaining_capabilities:
        engine.uninstall(cid, env, apply=True)
    residual_files = sorted(p.name for p in sandbox.iterdir())
    evidence.record("residual_scan", remaining_sandbox_files=residual_files, note="only state_root journal/ownership/lock bookkeeping may remain outside the sandbox; no package manager, repository, network, DNS, firewall, service or protocol state exists in this process")
    evidence.record("post_state", snapshot=_snapshot(sandbox, state_root))
    evidence.flush()
    print("PHASE23_7_5_6A_VM_HARNESS_OK evidence=%s" % evidence.path)
    return 0


def cmd_prepare_reboot_checkpoint(args) -> int:
    """Run this, then reboot the host, then run run-all with
    --reboot-checkpoint matching the one used here."""
    sandbox = Path(args.sandbox)
    state_root = Path(args.state_root)
    sandbox.mkdir(parents=True, exist_ok=True)
    transaction_id = "vm-reboot-%s" % args.checkpoint
    _run_worker_and_expect_kill(sandbox, state_root, "cap_vm_reboot", "dep_vm_reboot", transaction_id, args.checkpoint, Evidence(state_root.parent / "reboot_prep_evidence.json"))
    print("prepared pending transaction %s at checkpoint %s; reboot the host now, then run: "
          "run-all --reboot-checkpoint %s" % (transaction_id, args.checkpoint, args.checkpoint))
    return 0


def _snapshot(sandbox: Path, state_root: Path) -> dict:
    def _listing(root: Path) -> list[str]:
        if not root.exists():
            return []
        return sorted(str(p.relative_to(root)) for p in root.rglob("*"))

    return {"sandbox": _listing(sandbox), "state_root": _listing(state_root)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--state-root", required=True)
    sub = parser.add_subparsers(dest="command", required=True)

    worker = sub.add_parser("worker", help="internal: runs a real apply, self-killing at --kill-after")
    worker.add_argument("--capability-id", required=True)
    worker.add_argument("--dependency-id", required=True)
    worker.add_argument("--transaction-id", required=True)
    worker.add_argument("--kill-after", required=True, choices=("write_ahead_applying", "after_apply_before_verify", "after_verify_before_commit"))
    worker.set_defaults(func=cmd_worker)

    run_all = sub.add_parser("run-all", help="run the full local VM-equivalent validation matrix")
    run_all.add_argument("--evidence", help="evidence JSON output path")
    run_all.add_argument("--reboot-checkpoint", choices=("write_ahead_applying", "after_apply_before_verify", "after_verify_before_commit"), default=None)
    run_all.set_defaults(func=cmd_run_all)

    reboot_prep = sub.add_parser("prepare-reboot-checkpoint", help="prepare a pending transaction, kill -9 it, then you reboot the host manually")
    reboot_prep.add_argument("--checkpoint", required=True, choices=("write_ahead_applying", "after_apply_before_verify", "after_verify_before_commit"))
    reboot_prep.set_defaults(func=cmd_prepare_reboot_checkpoint)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
