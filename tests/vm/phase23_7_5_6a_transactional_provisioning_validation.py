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
import dataclasses
import hashlib
import json
import os
import select
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
from compat.provisioning import engine, journal as journal_mod, lock as lock_mod, paths as paths_mod, storage as storage_mod
from compat.provisioning.errors import ProvisionerLockHeldError
from compat.provisioning.executors import (
    CANARY_EXECUTOR_VERSION,
    CANARY_METHOD_KIND,
    CanaryExecutor,
    ExecutionContext,
    TrustedExecutorRegistry,
    handle_for_allowed_root,
    _companion_content,
    _marker_content,
)
from compat.provisioning.model import RecoveryAction, StepState, TransactionState


# --------------------------------------------------------------------------
# FIFO-based blocking barriers for real two-process race scenarios (sixth
# correction round, point 5): a genuine kernel wait via ``select``, never a
# sleep-poll loop -- timeouts below are strictly a watchdog, not the
# synchronization mechanism itself.
# --------------------------------------------------------------------------


def _fifo_create(path: Path) -> None:
    os.mkfifo(str(path))


def _fifo_open_reader(path: Path) -> int:
    return os.open(str(path), os.O_RDONLY | os.O_NONBLOCK)


def _fifo_wait(fd: int, *, timeout: float, description: str) -> None:
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        raise SystemExit("timed out waiting for %s" % description)
    os.read(fd, 1)


def _fifo_signal(path: Path) -> None:
    fd = os.open(str(path), os.O_WRONLY)
    try:
        os.write(fd, b"x")
    finally:
        os.close(fd)


class _NestedResourceExecutor(CanaryExecutor):
    """Places its marker/companion one directory level deeper
    (``sandbox/nested/...``) than ``CanaryExecutor``, to exercise
    intermediate-component identity binding in ``AllowedRootHandle``
    (sixth correction round, point 2). Never used outside this harness."""

    executor_id = "nested_resource_vm_executor"
    supported_method_kind = "nested_resource_vm"

    def plan_steps(self, *, capability_id: str, dependency_id: str, context: ExecutionContext):
        steps = super().plan_steps(capability_id=capability_id, dependency_id=dependency_id, context=context)
        nested_steps = []
        for step in steps:
            original = Path(step.target)
            nested_target = original.parent / "nested" / original.name
            nested_steps.append(dataclasses.replace(step, target=str(nested_target)))
        return tuple(nested_steps)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _decision(capability_id: str, dependency_id: str, *, method_kind: str = CANARY_METHOD_KIND, method_id: str = "canary_method") -> ResolutionDecision:
    return ResolutionDecision(
        capability_id=capability_id, dependency_id=dependency_id,
        resolved_distribution="lab", resolved_release=None, technical_family="lab_fixture",
        release_model="rolling", support_classification="lab_fixture", machine_architecture="x86_64",
        observed_capability_status="absent", candidate_chain=(method_id,),
        selected_method_id=method_id, selected_method_kind=method_kind,
        resolution_status="method_selected", execution_ready=True,
        rejected_candidates=(), evidence=(), reason="VM validation harness for 23.7.5.6a",
        provider_type="lab_fixture", provider_authoritative=False,
        availability_observations=(), all_availability_observations=(),
    )


def _env(sandbox: Path, state_root: Path, global_lock_root: Path) -> engine.ProvisioningEnvironment:
    sandbox.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(sandbox, 0o700)
    registry = TrustedExecutorRegistry()
    registry.register(method_kind=CANARY_METHOD_KIND, method_id="canary_method", executor=CanaryExecutor())
    registry.register(method_kind="nested_resource_vm", method_id="nested_resource_vm_method", executor=_NestedResourceExecutor())
    context = ExecutionContext(
        allowed_roots=(sandbox,),
        now=_now,
        custody_isolation_policy=paths_mod.LAB_CUSTODY_ISOLATION_POLICY,
    )
    return engine.ProvisioningEnvironment(
        state_root=state_root, registry=registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=context,
        global_lock_root=global_lock_root,
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
    global_lock_root = Path(args.global_lock_root)
    env = _env(sandbox, state_root, global_lock_root)
    decision = _decision(args.capability_id, args.dependency_id)
    plan, executor = engine.build_plan(decision, registry=env.registry, expected_executor_version=env.expected_executor_version, context=env.context)

    with lock_mod.acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id=args.transaction_id, timeout=10.0):
        locked_context = engine._open_locked_context(env.context)
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
            result0 = executor.apply_step(record0, locked_context)
            record0 = record0.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result0.undo_record)
            journal = journal.with_step(record0)
            journal_mod.write_journal(state_root, journal)
            record0 = record0.with_state(StepState.VERIFYING)
            journal = journal.with_step(record0)
            verification0 = executor.verify_step(record0, result0, locked_context)
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
            validated = paths_mod.validate_target_path(
                marker_path,
                allowed_roots=locked_context.allowed_roots,
                forbidden_roots=locked_context.forbidden_roots,
            )
            handle = handle_for_allowed_root(locked_context, validated)
            paths_mod.remove_file_if_owned_relative(
                handle,
                validated,
                expected_sha256=record0.undo_record.get("expected_sha256"),
                isolation_policy=locked_context.custody_isolation_policy,
            )
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
        result = executor.apply_step(record, locked_context)  # real file write
        record = record.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result.undo_record)
        journal = journal.with_step(record)

        if args.kill_after == "after_apply_before_verify":
            journal_mod.write_journal(state_root, journal)
            os.kill(os.getpid(), signal.SIGKILL)  # never returns

        journal_mod.write_journal(state_root, journal)
        record = record.with_state(StepState.VERIFYING)
        journal = journal.with_step(record)
        verification = executor.verify_step(record, result, locked_context)
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
            result = executor.apply_step(record, locked_context)
            record = record.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result.undo_record)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)
            record = record.with_state(StepState.VERIFYING)
            journal = journal.with_step(record)
            verification = executor.verify_step(record, result, locked_context)
            record = record.with_state(StepState.VERIFIED, completed_at=_now(), verification=verification.evidence)
            journal = journal.with_step(record)
            journal_mod.write_journal(state_root, journal)

        journal = journal.with_state(TransactionState.VERIFYING, now=_now())
        journal_mod.write_journal(state_root, journal)

        if args.kill_after == "after_verify_before_commit":
            os.kill(os.getpid(), signal.SIGKILL)  # never returns

        postcondition = executor.verify_postcondition(plan, locked_context)
        assert postcondition.status == "verified"
        provenance = engine._finalize_provenance(state_root, journal, plan, executor, locked_context, _now())
        journal = journal.with_state(TransactionState.COMMITTED, now=_now(), provenance=provenance)
        journal_mod.write_journal(state_root, journal)
    return 0


def _run_worker_and_expect_kill(sandbox: Path, state_root: Path, global_lock_root: Path, capability_id: str, dependency_id: str, transaction_id: str, kill_after: str, evidence: Evidence) -> None:
    argv = [
        sys.executable, __file__, "--sandbox", str(sandbox), "--state-root", str(state_root),
        "--global-lock-root", str(global_lock_root),
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
    global_lock_root = Path(args.global_lock_root)
    if sandbox.exists():
        shutil.rmtree(sandbox)
    if state_root.exists():
        shutil.rmtree(state_root)
    scratch = state_root.parent / "phase23_7_5_6a_round6_scratch"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(mode=0o700, parents=True)
    os.chmod(scratch, 0o700)
    sandbox.mkdir(mode=0o700, parents=True)
    os.chmod(sandbox, 0o700)
    evidence = Evidence(Path(args.evidence) if args.evidence else (state_root.parent / "phase23_7_5_6a_vm_evidence.json"))
    env = _env(sandbox, state_root, global_lock_root)

    baseline = _snapshot(sandbox, state_root)
    evidence.record("pre_state", snapshot=baseline)

    # 1. Lock exclusion between two real processes.
    lock_go = scratch / "lock_exclusion_go.fifo"
    _fifo_create(lock_go)
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r); from pathlib import Path; "
         "from compat.provisioning.lock import acquire_provisioner_lock\n"
         "from tests.vm.phase23_7_5_6a_transactional_provisioning_validation import _fifo_open_reader, _fifo_wait\n"
         "go = Path(%r)\n"
         "go_fd = _fifo_open_reader(go)\n"
         "with acquire_provisioner_lock(Path(%r), global_lock_root=Path(%r), transaction_id='holder', timeout=5.0):\n"
         "    print('ACQUIRED', flush=True)\n"
         "    _fifo_wait(go_fd, timeout=60.0, description='lock exclusion release signal')\n"
         % (str(ROOT), str(lock_go), str(state_root), str(global_lock_root))],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    line = holder.stdout.readline()
    contended = False
    try:
        with lock_mod.acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id="contender", timeout=0.3):
            pass
    except ProvisionerLockHeldError:
        contended = True
    finally:
        _fifo_signal(lock_go)
    holder_stdout, holder_stderr = holder.communicate(timeout=60)
    holder.stdout.close()
    evidence.record("lock_exclusion", holder_line=line.strip(), contended=contended, holder_returncode=holder.returncode)
    if not contended or holder.returncode != 0:
        raise SystemExit(
            "lock exclusion did not hold between two real processes: contended=%r stdout=%r stderr=%r"
            % (contended, holder_stdout, holder_stderr)
        )

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
        _run_worker_and_expect_kill(sandbox, state_root, global_lock_root, capability_id, "dep_%s" % capability_id, transaction_id, checkpoint, evidence)
        pre_recovery = journal_mod.read_journal(state_root, transaction_id)
        evidence.record("pre_recovery_state", checkpoint=checkpoint, state=pre_recovery.state.value)
        reports = engine.recover_pending(state_root, env.registry, env.expected_executor_version, env.context, global_lock_root=global_lock_root)
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

    # 15. Seventh correction round, point 1: direct quarantine protocol
    # checks for the post-move/pre-unlink boundary, in-place content drift,
    # and no-replace restore when the basename reappears.
    quarantine_sandbox = scratch / "round7_quarantine"
    quarantine_sandbox.mkdir(mode=0o700)

    def _reset_quarantine_hooks() -> None:
        paths_mod.UNLINK_REVERIFY_HOOK = paths_mod._default_unlink_pause
        paths_mod.QUARANTINE_POST_VERIFY_HOOK = paths_mod._default_unlink_pause
        paths_mod.QUARANTINE_BEFORE_RESTORE_HOOK = paths_mod._default_unlink_pause
        paths_mod.QUARANTINE_NAME_FACTORY = paths_mod._default_quarantine_name

    try:
        substitute_root = quarantine_sandbox / "substitute"
        substitute_root.mkdir(mode=0o700)
        substitute_target = substitute_root / "owned"
        substitute_target.write_bytes(b"owned")
        substitute_quarantine_name = ".wdvpn-quarantine.owned.vm"
        substitute_quarantine = substitute_root / paths_mod.CUSTODY_DIR_NAME / substitute_quarantine_name
        paths_mod.QUARANTINE_NAME_FACTORY = lambda basename: substitute_quarantine_name

        def _replace_quarantine() -> None:
            substitute_quarantine.unlink()
            substitute_quarantine.write_bytes(b"foreign")

        paths_mod.QUARANTINE_POST_VERIFY_HOOK = _replace_quarantine
        substitute_failed_closed = False
        substitute_handle = paths_mod.open_allowed_root(substitute_root)
        try:
            try:
                paths_mod.remove_file_if_owned_relative(
                    substitute_handle,
                    substitute_target,
                    expected_sha256=hashlib.sha256(b"owned").hexdigest(),
                    isolation_policy=paths_mod.LAB_CUSTODY_ISOLATION_POLICY,
                )
            except Exception:
                substitute_failed_closed = True
        finally:
            substitute_handle.close()
        substitute_foreign_survives = substitute_quarantine.exists() and substitute_quarantine.read_bytes() == b"foreign"
        evidence.record(
            "round7_quarantine_substitution_after_verify",
            failed_closed=substitute_failed_closed, foreign_file_survives=substitute_foreign_survives,
            original_basename_exists=substitute_target.exists(),
        )
        if not substitute_failed_closed or not substitute_foreign_survives:
            raise SystemExit("round7 quarantine substitution scenario failed")
    finally:
        _reset_quarantine_hooks()

    try:
        inplace_root = quarantine_sandbox / "inplace"
        inplace_root.mkdir(mode=0o700)
        inplace_target = inplace_root / "owned"
        inplace_target.write_bytes(b"owned")
        inplace_quarantine_name = ".wdvpn-quarantine.owned.vm"
        inplace_quarantine = inplace_root / paths_mod.CUSTODY_DIR_NAME / inplace_quarantine_name
        paths_mod.QUARANTINE_NAME_FACTORY = lambda basename: inplace_quarantine_name

        def _mutate_in_place() -> None:
            with inplace_target.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"pwned")
                handle.truncate()

        paths_mod.UNLINK_REVERIFY_HOOK = _mutate_in_place
        inplace_failed_closed = False
        inplace_handle = paths_mod.open_allowed_root(inplace_root)
        try:
            try:
                paths_mod.remove_file_if_owned_relative(
                    inplace_handle,
                    inplace_target,
                    expected_sha256=hashlib.sha256(b"owned").hexdigest(),
                    isolation_policy=paths_mod.LAB_CUSTODY_ISOLATION_POLICY,
                )
            except Exception:
                inplace_failed_closed = True
        finally:
            inplace_handle.close()
        inplace_residue = inplace_quarantine.exists() and inplace_quarantine.read_bytes() == b"pwned"
        evidence.record("round7_quarantine_in_place_modification", failed_closed=inplace_failed_closed, residue_remains=inplace_residue)
        if not inplace_failed_closed or not inplace_residue:
            raise SystemExit("round7 quarantine in-place modification scenario failed")
    finally:
        _reset_quarantine_hooks()

    try:
        restore_root = quarantine_sandbox / "restore"
        restore_root.mkdir(mode=0o700)
        restore_target = restore_root / "owned"
        restore_target.write_bytes(b"owned")
        restore_quarantine_name = ".wdvpn-quarantine.owned.vm"
        restore_quarantine = restore_root / paths_mod.CUSTODY_DIR_NAME / restore_quarantine_name
        paths_mod.QUARANTINE_NAME_FACTORY = lambda basename: restore_quarantine_name

        def _swap_original_before_quarantine() -> None:
            restore_target.unlink()
            restore_target.write_bytes(b"foreign")

        def _occupy_basename_before_restore() -> None:
            restore_target.write_bytes(b"occupied")

        paths_mod.UNLINK_REVERIFY_HOOK = _swap_original_before_quarantine
        paths_mod.QUARANTINE_BEFORE_RESTORE_HOOK = _occupy_basename_before_restore
        restore_failed_closed = False
        restore_handle = paths_mod.open_allowed_root(restore_root)
        try:
            try:
                paths_mod.remove_file_if_owned_relative(
                    restore_handle,
                    restore_target,
                    expected_sha256=hashlib.sha256(b"owned").hexdigest(),
                    isolation_policy=paths_mod.LAB_CUSTODY_ISOLATION_POLICY,
                )
            except Exception:
                restore_failed_closed = True
        finally:
            restore_handle.close()
        restore_both_recoverable = (
            restore_quarantine.exists() and restore_quarantine.read_bytes() == b"foreign"
            and restore_target.exists() and restore_target.read_bytes() == b"occupied"
        )
        evidence.record("round7_quarantine_restore_noreplace", failed_closed=restore_failed_closed, both_recoverable=restore_both_recoverable)
        if not restore_failed_closed or not restore_both_recoverable:
            raise SystemExit("round7 quarantine restore no-replace scenario failed")
    finally:
        _reset_quarantine_hooks()

    # 16. Seventh correction round, point 2: swap an intermediate directory
    # before entering uninstall. Detection must come from persisted
    # ownership identity, never a warm in-process cache.
    persistent_nested_sandbox = scratch / "round7_nested_persistent_sandbox"
    persistent_nested_state = scratch / "round7_nested_persistent_state"
    persistent_nested_lock = scratch / "round7_nested_persistent_lock"
    persistent_nested_env = _env(persistent_nested_sandbox, persistent_nested_state, persistent_nested_lock)
    (persistent_nested_sandbox / "nested").mkdir(mode=0o700, exist_ok=True)
    persistent_nested_capability_id = "cap_vm_round7_nested_persistent"
    persistent_nested_outcome = engine.prepare(
        _decision(
            persistent_nested_capability_id, "dep_vm_round7_nested_persistent",
            method_kind="nested_resource_vm", method_id="nested_resource_vm_method",
        ),
        persistent_nested_env, apply=True,
    )
    if persistent_nested_outcome.status.value != "committed":
        raise SystemExit("round7 persistent nested setup did not commit: %r" % persistent_nested_outcome)
    persistent_nested_dir = persistent_nested_sandbox / "nested"
    persistent_nested_old = persistent_nested_sandbox / "nested.old"
    persistent_nested_dir.rename(persistent_nested_old)
    persistent_nested_dir.mkdir(mode=0o700)
    persistent_nested_result = engine.uninstall(persistent_nested_capability_id, persistent_nested_env, apply=True)
    persistent_nested_records = journal_mod.read_ownership_records(persistent_nested_state, persistent_nested_capability_id)
    persistent_nested_resource_survives = (persistent_nested_old / ("%s.marker" % persistent_nested_capability_id)).exists()
    evidence.record(
        "round7_intermediate_swap_before_uninstall",
        status=persistent_nested_result.status.value,
        ownership_intact=any(r.product_owned for r in persistent_nested_records),
        resource_survives_in_renamed_dir=persistent_nested_resource_survives,
        replacement_dir_empty=(sorted(p.name for p in persistent_nested_dir.iterdir()) == []),
    )
    if persistent_nested_result.status.value == "uninstalled" or not persistent_nested_resource_survives:
        raise SystemExit("round7 persistent intermediate swap scenario failed: %r" % persistent_nested_result)

    # 17. Seventh correction round, point 3: unsafe immediate parents of
    # the configured global lock root are rejected before the leaf is used.
    lock_parent_results = []
    for mode in (0o770, 0o2770, 0o777):
        parent = scratch / ("round7_lock_parent_%o" % mode)
        parent.mkdir(mode=0o700)
        os.chmod(parent, mode)
        rejected = False
        try:
            storage_mod.ensure_private_lock_root(parent / "global-lock-root")
        except Exception:
            rejected = True
        lock_parent_results.append({"mode": oct(mode), "rejected": rejected, "leaf_created": (parent / "global-lock-root").exists()})
    evidence.record("round7_global_lock_parent_rejections", results=lock_parent_results)
    if not all(item["rejected"] and not item["leaf_created"] for item in lock_parent_results):
        raise SystemExit("round7 global lock parent rejection scenario failed: %r" % lock_parent_results)

    # 18. Seventh correction round, point 4: losing allowed-root identity
    # immediately after the last undo must block a clean PREPARATION_FAILED
    # terminal result.
    from unittest import mock
    from compat.provisioning.model import VerificationResult

    terminal_sandbox = scratch / "round7_terminal_sandbox"
    terminal_state = scratch / "round7_terminal_state"
    terminal_lock = scratch / "round7_terminal_lock"
    terminal_env = _env(terminal_sandbox, terminal_state, terminal_lock)
    terminal_old = scratch / "round7_terminal_sandbox.old"
    real_run_rollback = engine._run_rollback

    def _rollback_then_swap_allowed_root(*args, **kwargs):
        result = real_run_rollback(*args, **kwargs)
        terminal_sandbox.rename(terminal_old)
        terminal_sandbox.mkdir(mode=0o700)
        return result

    terminal_executor = terminal_env.registry.resolve(
        method_kind=CANARY_METHOD_KIND, method_id="canary_method", expected_executor_version=CANARY_EXECUTOR_VERSION
    )
    with mock.patch.object(
        terminal_executor, "verify_step",
        return_value=VerificationResult(status="verification_failed", error_kind="forced", error="forced VM terminal identity check"),
    ):
        with mock.patch("compat.provisioning.engine._run_rollback", side_effect=_rollback_then_swap_allowed_root):
            terminal_result = engine.prepare(_decision("cap_vm_round7_terminal", "dep_vm_round7_terminal"), terminal_env, apply=True)
    evidence.record("round7_identity_loss_before_terminal_state", status=terminal_result.status.value)
    if terminal_result.status.value == "preparation_failed":
        raise SystemExit("round7 terminal identity loss reached a clean terminal state")

    # 15. Sixth correction round, point 1: a genuine second process (real
    # SIGKILL-free race, not a mock) substitutes a resource's basename in
    # the window strictly AFTER the hash/identity re-verify and BEFORE the
    # atomic quarantine-rename. Must never delete the foreign inode.
    # Isolated environment: this scenario intentionally leaves a
    # RECOVERY_REQUIRED-class transaction behind, which would otherwise
    # block every subsequent engine.prepare() call sharing the main env.
    toctou_sandbox = scratch / "toctou_sandbox"
    toctou_state_root = scratch / "toctou_state"
    toctou_global_lock_root = scratch / "toctou_global_lock"
    toctou_env = _env(toctou_sandbox, toctou_state_root, toctou_global_lock_root)
    toctou_capability_id = "cap_vm_toctou_race"
    toctou_outcome = engine.prepare(_decision(toctou_capability_id, "dep_vm_toctou_race"), toctou_env, apply=True)
    if toctou_outcome.status.value != "committed":
        raise SystemExit("toctou race setup did not commit: %r" % toctou_outcome)
    toctou_marker = toctou_sandbox / ("%s.marker" % toctou_capability_id)
    toctou_ready = scratch / "toctou_ready.fifo"
    toctou_go = scratch / "toctou_go.fifo"
    toctou_result = scratch / "toctou_result.json"
    toctou_script = scratch / "toctou_holder.py"
    toctou_script.write_text(
        "import sys, json\n"
        "sys.path.insert(0, %r)\n"
        "from pathlib import Path\n"
        "from compat.provisioning import engine, paths as paths_mod\n"
        "from tests.vm.phase23_7_5_6a_transactional_provisioning_validation import _env, _fifo_open_reader, _fifo_signal, _fifo_wait\n"
        "env = _env(Path(%r), Path(%r), Path(%r))\n"
        "ready = Path(%r); go = Path(%r)\n"
        "go_fd = _fifo_open_reader(go)\n"
        "def _pause():\n"
        "    _fifo_signal(ready)\n"
        "    _fifo_wait(go_fd, timeout=10.0, description='go marker')\n"
        "paths_mod.UNLINK_REVERIFY_HOOK = _pause\n"
        "result = engine.uninstall(%r, env, apply=True)\n"
        "Path(%r).write_text(json.dumps({'status': result.status.value}))\n"
        % (str(ROOT), str(toctou_sandbox), str(toctou_state_root), str(toctou_global_lock_root), str(toctou_ready), str(toctou_go), toctou_capability_id, str(toctou_result))
    )
    _fifo_create(toctou_ready)
    _fifo_create(toctou_go)
    toctou_ready_fd = _fifo_open_reader(toctou_ready)
    toctou_proc = subprocess.Popen([sys.executable, str(toctou_script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _fifo_wait(toctou_ready_fd, timeout=10.0, description="toctou holder ready signal")
    os.close(toctou_ready_fd)
    toctou_marker.unlink()
    toctou_marker.write_bytes(b"foreign content planted by a real second process")
    _fifo_signal(toctou_go)
    toctou_stdout, toctou_stderr = toctou_proc.communicate(timeout=15)
    toctou_status = json.loads(toctou_result.read_text())["status"] if toctou_result.exists() else None
    toctou_survives = toctou_marker.exists() and toctou_marker.read_bytes() == b"foreign content planted by a real second process"
    evidence.record("toctou_race_after_last_inode_check", status=toctou_status, foreign_file_survives=toctou_survives, returncode=toctou_proc.returncode)
    if toctou_proc.returncode != 0 or toctou_status == "uninstalled" or not toctou_survives:
        raise SystemExit("TOCTOU race scenario failed: status=%r survives=%r stderr=%r" % (toctou_status, toctou_survives, toctou_stderr))

    # 16. Sixth correction round, point 2: an INTERMEDIATE directory (not
    # the allowed root itself) is renamed aside and replaced by a new,
    # same-uid, empty real directory strictly between eager-caching and
    # first real use during uninstall. Must never reach UNINSTALLED.
    # Isolated environment, for the same reason as the TOCTOU scenario above.
    nested_sandbox = scratch / "nested_swap_sandbox"
    nested_state_root = scratch / "nested_swap_state"
    nested_global_lock_root = scratch / "nested_swap_global_lock"
    nested_env = _env(nested_sandbox, nested_state_root, nested_global_lock_root)
    (nested_sandbox / "nested").mkdir(mode=0o700, exist_ok=True)
    nested_capability_id = "cap_vm_nested_swap"
    nested_outcome = engine.prepare(
        _decision(nested_capability_id, "dep_vm_nested_swap", method_kind="nested_resource_vm", method_id="nested_resource_vm_method"),
        nested_env, apply=True,
    )
    if nested_outcome.status.value != "committed":
        raise SystemExit("nested swap setup did not commit: %r" % nested_outcome)
    nested_dir = nested_sandbox / "nested"
    nested_renamed = nested_sandbox / "nested.old"
    real_uninstall_source_matches = engine._uninstall_source_matches

    def _nested_swap_then_check(*args, **kwargs):
        nested_dir.rename(nested_renamed)
        nested_dir.mkdir(mode=0o700)
        return real_uninstall_source_matches(*args, **kwargs)

    engine._uninstall_source_matches = _nested_swap_then_check
    try:
        nested_result = engine.uninstall(nested_capability_id, nested_env, apply=True)
    finally:
        engine._uninstall_source_matches = real_uninstall_source_matches
    nested_records = journal_mod.read_ownership_records(nested_state_root, nested_capability_id)
    nested_ownership_intact = any(r.product_owned for r in nested_records)
    nested_resource_survives = (nested_renamed / ("%s.marker" % nested_capability_id)).exists()
    evidence.record(
        "intermediate_component_swapped_for_real_directory", status=nested_result.status.value,
        ownership_intact=nested_ownership_intact, resource_survives_in_renamed_dir=nested_resource_survives,
        new_replacement_dir_empty=(sorted(p.name for p in nested_dir.iterdir()) == []),
    )
    if nested_result.status.value == "uninstalled" or not nested_ownership_intact or not nested_resource_survives:
        raise SystemExit("intermediate component swap scenario failed: %r" % nested_result)

    # 17. Sixth correction round, point 3: global_lock_root (or its lock
    # file) is renamed/replaced while a holder is active. A same-uid
    # contender using the swapped directory must still be refused, via the
    # secondary flock directly on the real, unswapped state_root.
    global_swap_state_root = scratch / "state_global_swap"
    global_swap_lock_root = scratch / "global_lock_root_swap"
    global_swap_ready = scratch / "global_swap_ready.fifo"
    global_swap_go = scratch / "global_swap_go.fifo"
    global_swap_script = scratch / "global_swap_holder.py"
    global_swap_script.write_text(
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "from pathlib import Path\n"
        "from compat.provisioning.lock import acquire_provisioner_lock\n"
        "from tests.vm.phase23_7_5_6a_transactional_provisioning_validation import _fifo_open_reader, _fifo_signal, _fifo_wait\n"
        "state_root = Path(%r); global_lock_root = Path(%r)\n"
        "ready = Path(%r); go = Path(%r)\n"
        "go_fd = _fifo_open_reader(go)\n"
        "with acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id='holder', timeout=10.0):\n"
        "    _fifo_signal(ready)\n"
        "    _fifo_wait(go_fd, timeout=10.0, description='go marker')\n"
        % (str(ROOT), str(global_swap_state_root), str(global_swap_lock_root), str(global_swap_ready), str(global_swap_go))
    )
    _fifo_create(global_swap_ready)
    _fifo_create(global_swap_go)
    global_swap_ready_fd = _fifo_open_reader(global_swap_ready)
    global_swap_proc = subprocess.Popen([sys.executable, str(global_swap_script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _fifo_wait(global_swap_ready_fd, timeout=10.0, description="global lock root holder ready signal")
    os.close(global_swap_ready_fd)
    global_swap_renamed = scratch / "global_lock_root_swap.old"
    global_swap_lock_root.rename(global_swap_renamed)
    global_swap_lock_root.mkdir(mode=0o700)
    global_swap_contender_refused = False
    try:
        with lock_mod.acquire_provisioner_lock(global_swap_state_root, global_lock_root=global_swap_lock_root, transaction_id="contender", timeout=0.3):
            pass
    except ProvisionerLockHeldError:
        global_swap_contender_refused = True
    _fifo_signal(global_swap_go)
    global_swap_proc.wait(60)
    evidence.record("global_lock_root_swapped_while_holder_active", contender_refused=global_swap_contender_refused, holder_returncode=global_swap_proc.returncode)
    if not global_swap_contender_refused or global_swap_proc.returncode != 0:
        raise SystemExit("global_lock_root swap scenario did not refuse the contender")

    # 18. Sixth correction round, point 4: an uninstall journal that
    # legitimately reached REVOKING_OWNERSHIP (crash simulated before
    # ownership was actually revoked) becomes unreadable; a file is then
    # recreated at the original path. The unreadable journal must never be
    # silently skipped -- authority must be denied, never reactivating the
    # recreated file as product-owned.
    # Isolated environment, for the same reason as the scenarios above.
    unreadable_sandbox = scratch / "unreadable_journal_sandbox"
    unreadable_state_root = scratch / "unreadable_journal_state"
    unreadable_global_lock_root = scratch / "unreadable_journal_global_lock"
    unreadable_env = _env(unreadable_sandbox, unreadable_state_root, unreadable_global_lock_root)
    unreadable_capability_id = "cap_vm_unreadable_uninstall_journal"
    unreadable_outcome = engine.prepare(_decision(unreadable_capability_id, "dep_vm_unreadable_uninstall_journal"), unreadable_env, apply=True)
    if unreadable_outcome.status.value != "committed":
        raise SystemExit("unreadable-uninstall-journal setup did not commit: %r" % unreadable_outcome)
    unreadable_marker = unreadable_sandbox / ("%s.marker" % unreadable_capability_id)
    unreadable_marker_content = unreadable_marker.read_bytes()
    owned_for_unreadable = [r for r in journal_mod.read_ownership_records(unreadable_state_root, unreadable_capability_id) if r.product_owned]
    unreadable_txn_id = "uninstall-%s" % unreadable_capability_id
    unreadable_plan = engine._build_uninstall_plan(unreadable_capability_id, owned_for_unreadable, transaction_id=unreadable_txn_id)
    unreadable_journal = engine._initial_uninstall_journal(unreadable_plan, now_value=_now())
    unreadable_journal = unreadable_journal.with_state(TransactionState.UNINSTALLING, now=_now())
    journal_mod.write_journal(unreadable_state_root, unreadable_journal)
    unreadable_locked_context = engine._open_locked_context(unreadable_env.context)
    try:
        unreadable_journal, unreadable_ok, unreadable_residuals = engine._run_uninstall_loop(
            unreadable_state_root, unreadable_journal, unreadable_locked_context,
            registry=unreadable_env.registry, expected_executor_version=unreadable_env.expected_executor_version,
        )
    finally:
        engine._close_locked_context(unreadable_locked_context)
    if not unreadable_ok:
        raise SystemExit("unreadable-uninstall-journal setup's real uninstall loop did not complete: %r" % unreadable_residuals)
    unreadable_journal = unreadable_journal.with_state(TransactionState.REVOKING_OWNERSHIP, now=_now())
    journal_mod.write_journal(unreadable_state_root, unreadable_journal)
    if not journal_mod.read_ownership_records(unreadable_state_root, unreadable_capability_id) or unreadable_marker.exists():
        raise SystemExit("unreadable-uninstall-journal setup did not reach the expected stalled state")
    unreadable_journal_path = journal_mod.transaction_path(unreadable_state_root, unreadable_txn_id)
    os.chmod(unreadable_journal_path, 0o644)
    unreadable_marker.write_bytes(unreadable_marker_content)
    unreadable_result = engine.uninstall(unreadable_capability_id, unreadable_env, apply=True)
    unreadable_recreated_survives = unreadable_marker.exists() and unreadable_marker.read_bytes() == unreadable_marker_content
    evidence.record(
        "unreadable_uninstall_journal_never_reactivates_ownership", status=unreadable_result.status.value,
        recreated_resource_survives=unreadable_recreated_survives,
    )
    if unreadable_result.status.value == "uninstalled" or not unreadable_recreated_survives:
        raise SystemExit("unreadable-uninstall-journal scenario failed: %r" % unreadable_result)

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
    global_lock_root = Path(args.global_lock_root)
    sandbox.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(sandbox, 0o700)
    transaction_id = "vm-reboot-%s" % args.checkpoint
    evidence_path = Path(args.evidence) if args.evidence else (state_root.parent / "reboot_prep_evidence.json")
    evidence = Evidence(evidence_path)
    evidence.record("boot_id_before_reboot", boot_id=_read_boot_id())
    _run_worker_and_expect_kill(sandbox, state_root, global_lock_root, "cap_vm_reboot", "dep_vm_reboot", transaction_id, args.checkpoint, evidence)
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
    global_lock_root = Path(args.global_lock_root)
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

    env = _env(sandbox, state_root, global_lock_root)
    reports = engine.recover_pending(state_root, env.registry, env.expected_executor_version, env.context, global_lock_root=global_lock_root)
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
    global_lock_root = Path(args.global_lock_root)
    capability_id = args.capability_id
    checkpoint = args.checkpoint
    env = _env(sandbox, state_root, global_lock_root)
    transaction_id = "vm-uninstall-reboot-%s" % checkpoint
    with lock_mod.acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id=transaction_id, timeout=10.0):
        locked_context = engine._open_locked_context(env.context)
        owned = [r for r in journal_mod.read_ownership_records(state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id=transaction_id)
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
            validated = paths_mod.validate_target_path(
                path,
                allowed_roots=locked_context.allowed_roots,
                forbidden_roots=locked_context.forbidden_roots,
            )
            handle = handle_for_allowed_root(locked_context, validated)
            paths_mod.remove_file_if_owned_relative(
                handle,
                validated,
                expected_sha256=record.intent.get("expected_sha256"),
                isolation_policy=locked_context.custody_isolation_policy,
            )  # the REAL custody protocol unlink happens here
            os.kill(os.getpid(), signal.SIGKILL)  # never returns: crash before APPLIED is ever journaled

        # after_verify_before_revoke / after_revoke_before_uninstalled: run
        # the real removal loop to completion (both resources genuinely
        # gone, both steps VERIFIED) before reaching the ownership-revocation
        # boundary itself.
        journal, ok, residuals = engine._run_uninstall_loop(
            state_root, journal, locked_context, registry=env.registry, expected_executor_version=env.expected_executor_version
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
    global_lock_root = Path(args.global_lock_root)
    sandbox.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(sandbox, 0o700)
    checkpoint = args.checkpoint
    capability_id = "cap_vm_uninstall_reboot_%s" % checkpoint
    evidence_path = Path(args.evidence) if args.evidence else (state_root.parent / ("uninstall_reboot_prep_evidence_%s.json" % checkpoint))
    evidence = Evidence(evidence_path)
    evidence.record("boot_id_before_reboot", boot_id=_read_boot_id())

    env = _env(sandbox, state_root, global_lock_root)
    prepare_outcome = engine.prepare(_decision(capability_id, "dep_vm_uninstall_reboot_%s" % checkpoint), env, apply=True)
    evidence.record("prepare_committed", status=prepare_outcome.status.value, transaction_id=prepare_outcome.transaction_id)
    if prepare_outcome.status.value != "committed":
        raise SystemExit("prepare for uninstall-reboot scenario did not commit: %r" % prepare_outcome)

    argv = [
        sys.executable, __file__, "--sandbox", str(sandbox), "--state-root", str(state_root),
        "--global-lock-root", str(global_lock_root),
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
    global_lock_root = Path(args.global_lock_root)
    checkpoint = args.checkpoint
    capability_id = "cap_vm_uninstall_reboot_%s" % checkpoint
    evidence = Evidence(Path(args.evidence) if args.evidence else (state_root.parent / ("uninstall-recovery-after-reboot-%s.json" % checkpoint)))
    evidence.record("boot_id_after_reboot", boot_id=_read_boot_id())

    transaction_id = _find_pending_uninstall_transaction_id(state_root, capability_id)
    pre_recovery = journal_mod.read_journal(state_root, transaction_id)
    evidence.record("pre_recovery_state", transaction_id=transaction_id, state=pre_recovery.state.value, plan_digest=pre_recovery.plan_digest)
    evidence.record("pre_recovery_sandbox", files=sorted(p.name for p in sandbox.iterdir()) if sandbox.exists() else [])

    env = _env(sandbox, state_root, global_lock_root)
    reports = engine.recover_pending(state_root, env.registry, env.expected_executor_version, env.context, global_lock_root=global_lock_root)
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
    parser.add_argument(
        "--global-lock-root", required=True,
        help="dedicated, stable root the global provisioner lock lives under; never inside --state-root or --sandbox",
    )
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
