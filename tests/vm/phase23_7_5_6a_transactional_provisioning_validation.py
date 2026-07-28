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
from compat.provisioning.paths import remove_file_if_owned


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

        if args.kill_after in (
            "rolling_back_pending", "undoing_before_unlink", "undoing_after_unlink_before_undone",
        ):
            # Step 0 applies and verifies for real (its resource stays on
            # disk); step 1 is forced to fail so the transaction must move
            # to rolling_back with step 0's undo still pending when killed.
            step0 = plan.steps[0]
            record0 = journal.step(step0.sequence)
            record0 = record0.with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
            journal = journal.with_step(record0)
            journal_mod.write_journal(state_root, journal)
            result0 = executor.apply_step(record0, env.context)
            record0 = record0.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result0.undo_record)
            journal = journal.with_step(record0)
            journal_mod.write_journal(state_root, journal)
            record0 = record0.with_state(StepState.VERIFYING)
            journal = journal.with_step(record0)
            verification0 = executor.verify_step(record0, result0, env.context)
            record0 = record0.with_state(StepState.VERIFIED, completed_at=_now(), verification=verification0.evidence)
            journal = journal.with_step(record0)
            journal_mod.write_journal(state_root, journal)

            step1 = plan.steps[1]
            record1 = journal.step(step1.sequence)
            record1 = record1.with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
            journal = journal.with_step(record1)
            journal_mod.write_journal(state_root, journal)
            record1 = record1.with_state(
                StepState.APPLY_FAILED, completed_at=_now(),
                error_kind="forced_for_reboot_rollback_test", error="forced failure to reach rolling_back before reboot",
            )
            journal = journal.with_step(record1)
            journal_mod.write_journal(state_root, journal)

            journal = journal.with_state(TransactionState.ROLLING_BACK, now=_now())
            journal_mod.write_journal(state_root, journal)  # durable: step 0's resource still present, undo pending

            if args.kill_after == "rolling_back_pending":
                os.kill(os.getpid(), signal.SIGKILL)  # never returns

            # Both remaining checkpoints resume from step 0 already durably
            # in UNDOING -- the exact "UNDOING" recovery boundary (point 3).
            record0 = record0.with_state(StepState.UNDOING)
            journal = journal.with_step(record0)
            journal_mod.write_journal(state_root, journal)  # durable: UNDOING written, real unlink not yet attempted

            if args.kill_after == "undoing_before_unlink":
                os.kill(os.getpid(), signal.SIGKILL)  # never returns

            # undoing_after_unlink_before_undone: perform the REAL unlink
            # (bypassing undo_step's own journal write for UNDONE), then
            # crash before that durable transition ever lands.
            marker_path = Path(record0.undo_record["path"])
            remove_file_if_owned(marker_path, expected_sha256=record0.undo_record.get("expected_sha256"))
            os.kill(os.getpid(), signal.SIGKILL)  # never returns

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
    # of the host this harness runs on. They are not part of this local,
    # state-wiping matrix; use `prepare-reboot-checkpoint` then a real host
    # reboot then `recover-after-reboot` instead (see module docstring).
    evidence.record(
        "reboot_scenarios_note",
        note="recovery/rollback after a literal OS reboot use the dedicated "
        "prepare-reboot-checkpoint / recover-after-reboot subcommands on a real host, not run-all",
    )

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


def _read_boot_id() -> str | None:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return None


def cmd_prepare_reboot_checkpoint(args) -> int:
    """Run this, then reboot the host for real (not just restart this
    process), then run recover-after-reboot with the same --checkpoint."""
    sandbox = Path(args.sandbox)
    state_root = Path(args.state_root)
    sandbox.mkdir(parents=True, exist_ok=True)
    transaction_id = "vm-reboot-%s" % args.checkpoint
    evidence_path = Path(args.evidence) if args.evidence else (state_root.parent / "reboot_prep_evidence.json")
    evidence = Evidence(evidence_path)
    evidence.record("boot_id_before_reboot", boot_id=_read_boot_id())
    _run_worker_and_expect_kill(sandbox, state_root, "cap_vm_reboot", "dep_vm_reboot", transaction_id, args.checkpoint, evidence)
    pending = journal_mod.read_journal(state_root, transaction_id)
    evidence.record("pre_reboot_journal_state", transaction_id=transaction_id, state=pending.state.value, plan_digest=pending.plan_digest)
    evidence.record("pre_reboot_sandbox", files=sorted(p.name for p in sandbox.iterdir()) if sandbox.exists() else [])
    evidence.flush()
    print("prepared pending transaction %s at checkpoint %s (state=%s); now reboot the HOST OS for real "
          "(e.g. `sudo reboot`), log back in, then run: recover-after-reboot --checkpoint %s"
          % (transaction_id, args.checkpoint, pending.state.value, args.checkpoint))
    return 0


def cmd_recover_after_reboot(args) -> int:
    """Does NOT wipe sandbox/state-root: recovers the exact pending
    transaction prepare-reboot-checkpoint left behind before a real reboot."""
    sandbox = Path(args.sandbox)
    state_root = Path(args.state_root)
    checkpoint = args.checkpoint
    transaction_id = "vm-reboot-%s" % checkpoint
    evidence = Evidence(Path(args.evidence) if args.evidence else (state_root.parent / "recovery-after-reboot.json"))
    evidence.record("boot_id_after_reboot", boot_id=_read_boot_id())

    pending_before = journal_mod.list_pending_transaction_ids(state_root)
    if transaction_id not in pending_before:
        raise SystemExit(
            "expected pending transaction %r not found after reboot (pending: %r); did "
            "prepare-reboot-checkpoint --checkpoint %s run before the reboot?" % (transaction_id, pending_before, checkpoint)
        )
    pre_recovery = journal_mod.read_journal(state_root, transaction_id)
    evidence.record("pre_recovery_state", transaction_id=transaction_id, state=pre_recovery.state.value, plan_digest=pre_recovery.plan_digest)
    evidence.record("pre_recovery_sandbox", files=sorted(p.name for p in sandbox.iterdir()) if sandbox.exists() else [])

    env = _env(sandbox, state_root)
    reports = engine.recover_pending(state_root, env.registry, env.expected_executor_version, env.context)
    matching = [r for r in reports if r.transaction_id == transaction_id]
    if not matching:
        raise SystemExit("recover_pending produced no decision for %r (reports: %r)" % (transaction_id, reports))
    decision = matching[0]
    evidence.record("recovery_decision", transaction_id=transaction_id, action=decision.action.value, reason=decision.reason)

    final = journal_mod.read_journal(state_root, transaction_id)
    post_recovery_sandbox = sorted(p.name for p in sandbox.iterdir()) if sandbox.exists() else []
    evidence.record("post_recovery_state", state=final.state.value)
    evidence.record("post_recovery_sandbox", files=post_recovery_sandbox)

    remaining_for_capability = [f for f in post_recovery_sandbox if f.startswith("cap_vm_reboot.")]
    if checkpoint in ("rolling_back_pending", "undoing_before_unlink", "undoing_after_unlink_before_undone"):
        expected_action, expected_state = "rollback", TransactionState.PREPARATION_FAILED
        ok = decision.action.value == expected_action and final.state == expected_state and not remaining_for_capability
    else:
        expected_action, expected_state = "resume", TransactionState.COMMITTED
        ok = decision.action.value == expected_action and final.state == expected_state and len(remaining_for_capability) == 2
    evidence.record(
        "result", ok=ok, expected_action=expected_action, expected_state=expected_state.value,
        actual_action=decision.action.value, actual_state=final.state.value, remaining_for_capability=remaining_for_capability,
    )
    evidence.flush()
    if not ok:
        raise SystemExit("recovery-after-reboot did not match expectations; see %s" % evidence.path)
    print("PHASE23_7_5_6A_VM_REBOOT_RECOVERY_OK checkpoint=%s evidence=%s" % (checkpoint, evidence.path))
    return 0


UNINSTALL_CHECKPOINTS = ("after_unlink_before_applied", "after_verify_before_revoke", "after_revoke_before_uninstalled")


def _find_pending_uninstall_transaction_id(state_root: Path, capability_id: str) -> str:
    """The uninstall journal's own transaction_id is a freshly minted random
    id (see engine._build_uninstall_plan), never derived from the checkpoint
    name -- find it by scanning for the one pending "uninstall" journal that
    targets this exact capability_id."""
    for transaction_id in journal_mod.list_pending_transaction_ids(state_root):
        journal = journal_mod.read_journal(state_root, transaction_id)
        if journal.operation == "uninstall" and journal.capability_id == capability_id:
            return transaction_id
    raise SystemExit("no pending uninstall transaction found for capability_id=%r" % capability_id)


def cmd_uninstall_worker(args) -> int:
    """Internal: starts a real uninstall of an already-committed capability
    and self-kills with SIGKILL at one of three real boundaries:

    after_unlink_before_applied  -- the REAL unlink of the marker resource
                                     happens, then crash before the journal
                                     ever records that step as APPLIED.
    after_verify_before_revoke   -- both resources are REALLY removed and
                                     verified (all steps VERIFIED), the
                                     journal is durably moved to
                                     REVOKING_OWNERSHIP, then crash before
                                     ownership is ever actually revoked.
    after_revoke_before_uninstalled -- same, but ownership IS actually
                                     revoked for real, then crash before the
                                     journal ever records UNINSTALLED.
    """
    sandbox = Path(args.sandbox)
    state_root = Path(args.state_root)
    capability_id = args.capability_id
    checkpoint = args.checkpoint
    env = _env(sandbox, state_root)
    transaction_id = "vm-uninstall-reboot-%s" % checkpoint
    with lock_mod.acquire_provisioner_lock(journal_mod.lock_path(state_root), transaction_id=transaction_id, timeout=10.0):
        owned = [r for r in journal_mod.read_ownership_records(state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal_mod.write_journal(state_root, journal)
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        journal_mod.write_journal(state_root, journal)

        if checkpoint == "after_unlink_before_applied":
            marker_index = next(i for i, s in enumerate(plan.steps) if s.intent["resource_identity"].endswith(".marker"))
            record = journal.step(marker_index)
            record = record.with_state(StepState.APPLYING, started_at=_now())
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)  # write-ahead: durable before the real unlink
            path = Path(record.intent["resource_identity"])
            remove_file_if_owned(path, expected_sha256=record.intent.get("expected_sha256"))  # the REAL unlink happens here
            os.kill(os.getpid(), signal.SIGKILL)  # never returns: crash before APPLIED is ever journaled

        # after_verify_before_revoke / after_revoke_before_uninstalled: run
        # the real removal loop to completion (both resources genuinely
        # gone, both steps VERIFIED) before reaching the ownership-revocation
        # boundary itself.
        journal, ok, residuals = engine._run_uninstall_loop(
            state_root, journal, env.context, registry=env.registry, expected_executor_version=env.expected_executor_version
        )
        if not ok:
            raise SystemExit("uninstall-worker's real removal loop did not complete: %r" % residuals)
        journal = journal.with_state(TransactionState.REVOKING_OWNERSHIP, now=_now())
        journal_mod.write_journal(state_root, journal)  # durable: all resources gone, ownership not yet revoked

        if checkpoint == "after_verify_before_revoke":
            os.kill(os.getpid(), signal.SIGKILL)  # never returns

        # after_revoke_before_uninstalled: perform the REAL revocation, then
        # crash before the journal ever records UNINSTALLED.
        revoked, revoke_error = engine._revoke_ownership_and_verify(state_root, capability_id)
        if not revoked:
            raise SystemExit("uninstall-worker's real ownership revocation did not complete: %s" % revoke_error)
        os.kill(os.getpid(), signal.SIGKILL)  # never returns
    return 0


def cmd_prepare_uninstall_reboot_checkpoint(args) -> int:
    """Commits a real prepare transaction, then runs a real subprocess that
    starts uninstalling it and SIGKILLs itself at the requested checkpoint
    (see cmd_uninstall_worker). Reboot the host for real afterward, then run
    recover-uninstall-after-reboot with the same --checkpoint. Each
    checkpoint uses its own dedicated capability_id, so several checkpoints
    can be prepared independently before a single shared reboot."""
    sandbox = Path(args.sandbox)
    state_root = Path(args.state_root)
    sandbox.mkdir(parents=True, exist_ok=True)
    checkpoint = args.checkpoint
    capability_id = "cap_vm_uninstall_reboot_%s" % checkpoint
    evidence_path = Path(args.evidence) if args.evidence else (state_root.parent / ("uninstall_reboot_prep_evidence_%s.json" % checkpoint))
    evidence = Evidence(evidence_path)
    evidence.record("boot_id_before_reboot", boot_id=_read_boot_id())

    env = _env(sandbox, state_root)
    prepare_outcome = engine.prepare(_decision(capability_id, "dep_vm_uninstall_reboot_%s" % checkpoint), env, apply=True)
    evidence.record("prepare_committed", status=prepare_outcome.status.value, transaction_id=prepare_outcome.transaction_id)
    if prepare_outcome.status.value != "committed":
        raise SystemExit("prepare for uninstall-reboot scenario did not commit: %r" % prepare_outcome)

    argv = [
        sys.executable, __file__, "--sandbox", str(sandbox), "--state-root", str(state_root),
        "uninstall-worker", "--capability-id", capability_id, "--checkpoint", checkpoint,
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    killed_by_sigkill = proc.returncode == -signal.SIGKILL
    evidence.record(
        "uninstall_worker_killed", checkpoint=checkpoint, returncode=proc.returncode, killed_by_sigkill=killed_by_sigkill,
        stdout=proc.stdout[-2000:], stderr=proc.stderr[-2000:],
    )
    if not killed_by_sigkill:
        raise SystemExit("uninstall worker did not die by SIGKILL (rc=%s); aborting harness" % proc.returncode)

    transaction_id = _find_pending_uninstall_transaction_id(state_root, capability_id)
    pending = journal_mod.read_journal(state_root, transaction_id)
    evidence.record("pre_reboot_journal_state", transaction_id=transaction_id, state=pending.state.value, plan_digest=pending.plan_digest)
    evidence.record("pre_reboot_sandbox", files=sorted(p.name for p in sandbox.iterdir()) if sandbox.exists() else [])
    evidence.flush()
    print(
        "prepared pending uninstall transaction %s at checkpoint %s (state=%s); now reboot the HOST OS for real "
        "(e.g. `sudo reboot`), log back in, then run: recover-uninstall-after-reboot --checkpoint %s"
        % (transaction_id, checkpoint, pending.state.value, checkpoint)
    )
    return 0


def cmd_recover_uninstall_after_reboot(args) -> int:
    """Does NOT wipe sandbox/state-root: recovers the exact pending uninstall
    transaction prepare-uninstall-reboot-checkpoint left behind before a
    real reboot, for the given --checkpoint."""
    sandbox = Path(args.sandbox)
    state_root = Path(args.state_root)
    checkpoint = args.checkpoint
    capability_id = "cap_vm_uninstall_reboot_%s" % checkpoint
    evidence = Evidence(Path(args.evidence) if args.evidence else (state_root.parent / ("uninstall-recovery-after-reboot-%s.json" % checkpoint)))
    evidence.record("boot_id_after_reboot", boot_id=_read_boot_id())

    transaction_id = _find_pending_uninstall_transaction_id(state_root, capability_id)
    pre_recovery = journal_mod.read_journal(state_root, transaction_id)
    evidence.record("pre_recovery_state", transaction_id=transaction_id, state=pre_recovery.state.value, plan_digest=pre_recovery.plan_digest)
    evidence.record("pre_recovery_sandbox", files=sorted(p.name for p in sandbox.iterdir()) if sandbox.exists() else [])

    env = _env(sandbox, state_root)
    reports = engine.recover_pending(state_root, env.registry, env.expected_executor_version, env.context)
    matching = [r for r in reports if r.transaction_id == transaction_id]
    if not matching:
        raise SystemExit("recover_pending produced no decision for %r (reports: %r)" % (transaction_id, reports))
    decision = matching[0]
    evidence.record("recovery_decision", transaction_id=transaction_id, action=decision.action.value, reason=decision.reason)

    final = journal_mod.read_journal(state_root, transaction_id)
    post_recovery_sandbox = sorted(p.name for p in sandbox.iterdir()) if sandbox.exists() else []
    remaining_ownership = journal_mod.read_ownership_records(state_root, capability_id)
    evidence.record("post_recovery_state", state=final.state.value, remaining_ownership_records=len(remaining_ownership))
    evidence.record("post_recovery_sandbox", files=post_recovery_sandbox)

    remaining_for_capability = [f for f in post_recovery_sandbox if f.startswith("%s." % capability_id)]
    ok = (
        decision.action.value == "resume"
        and final.state == TransactionState.UNINSTALLED
        and not remaining_for_capability
        and not remaining_ownership
    )
    evidence.record(
        "result", ok=ok, actual_action=decision.action.value, actual_state=final.state.value,
        remaining_for_capability=remaining_for_capability, remaining_ownership_records=len(remaining_ownership),
    )
    evidence.flush()
    if not ok:
        raise SystemExit("uninstall recovery-after-reboot did not match expectations; see %s" % evidence.path)
    print("PHASE23_7_5_6A_VM_UNINSTALL_REBOOT_RECOVERY_OK evidence=%s" % evidence.path)
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

    checkpoints = (
        "write_ahead_applying", "after_apply_before_verify", "after_verify_before_commit", "rolling_back_pending",
        "undoing_before_unlink", "undoing_after_unlink_before_undone",
    )

    worker = sub.add_parser("worker", help="internal: runs a real apply, self-killing at --kill-after")
    worker.add_argument("--capability-id", required=True)
    worker.add_argument("--dependency-id", required=True)
    worker.add_argument("--transaction-id", required=True)
    worker.add_argument("--kill-after", required=True, choices=checkpoints)
    worker.set_defaults(func=cmd_worker)

    run_all = sub.add_parser("run-all", help="run the full local VM-equivalent validation matrix (wipes sandbox/state-root first)")
    run_all.add_argument("--evidence", help="evidence JSON output path")
    run_all.set_defaults(func=cmd_run_all)

    reboot_prep = sub.add_parser("prepare-reboot-checkpoint", help="prepare a pending transaction, kill -9 it; then reboot the host for real")
    reboot_prep.add_argument("--checkpoint", required=True, choices=checkpoints)
    reboot_prep.add_argument("--evidence", help="evidence JSON output path")
    reboot_prep.set_defaults(func=cmd_prepare_reboot_checkpoint)

    recover_after_reboot = sub.add_parser("recover-after-reboot", help="does NOT wipe state; recovers the pending transaction left by prepare-reboot-checkpoint after a real reboot")
    recover_after_reboot.add_argument("--checkpoint", required=True, choices=checkpoints)
    recover_after_reboot.add_argument("--evidence", help="evidence JSON output path")
    recover_after_reboot.set_defaults(func=cmd_recover_after_reboot)

    uninstall_worker = sub.add_parser("uninstall-worker", help="internal: starts a real uninstall, self-kills at --checkpoint")
    uninstall_worker.add_argument("--capability-id", required=True)
    uninstall_worker.add_argument("--checkpoint", required=True, choices=UNINSTALL_CHECKPOINTS)
    uninstall_worker.set_defaults(func=cmd_uninstall_worker)

    prepare_uninstall_reboot = sub.add_parser(
        "prepare-uninstall-reboot-checkpoint",
        help="commit a real prepare, then kill -9 a real uninstall at --checkpoint; then reboot the host for real",
    )
    prepare_uninstall_reboot.add_argument("--checkpoint", required=True, choices=UNINSTALL_CHECKPOINTS)
    prepare_uninstall_reboot.add_argument("--evidence", help="evidence JSON output path")
    prepare_uninstall_reboot.set_defaults(func=cmd_prepare_uninstall_reboot_checkpoint)

    recover_uninstall_after_reboot = sub.add_parser(
        "recover-uninstall-after-reboot",
        help="does NOT wipe state; recovers the pending uninstall left by prepare-uninstall-reboot-checkpoint after a real reboot",
    )
    recover_uninstall_after_reboot.add_argument("--checkpoint", required=True, choices=UNINSTALL_CHECKPOINTS)
    recover_uninstall_after_reboot.add_argument("--evidence", help="evidence JSON output path")
    recover_uninstall_after_reboot.set_defaults(func=cmd_recover_uninstall_after_reboot)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
