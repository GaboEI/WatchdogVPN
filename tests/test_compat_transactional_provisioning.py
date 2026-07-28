"""L1 tests for transactional provisioning infrastructure (Phase 23.7.5.6a).

Covers the maintainer's 35-item L1 checklist: deterministic planning, strict
rejection gates, lock exclusion, write-ahead journaling, the state machines,
path protection, idempotency/ownership, apply/verify/rollback, interruption
handling, recovery, uninstall and defensive scans. Everything here runs
against the lab-only CanaryExecutor inside temporary directories -- no real
package, repository, network, DNS, firewall or service is ever touched.
"""

from __future__ import annotations

import dataclasses
import errno
import fcntl
import hashlib
import json
import os
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from compat.dependency_resolution import ResolutionDecision, SelectedArtifact
from compat.provisioning import engine, journal as journal_mod, lock as lock_mod, storage as storage_mod
from compat.provisioning.engine import PrepareStatus, ProvisioningEnvironment
from compat.provisioning.errors import (
    DurabilityError,
    IdentifierError,
    InvalidTransitionError,
    JournalError,
    PathPolicyError,
    ProvisionerLockHeldError,
)
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
from compat.provisioning.digest import compute_plan_digest, compute_uninstall_plan_digest
from compat.provisioning.model import (
    OwnershipCandidate,
    OwnershipRecord,
    ProvisioningPlan,
    ProvisioningStep,
    RecoveryAction,
    StepState,
    TransactionState,
    UninstallPlan,
    VerificationResult,
    transition_step,
    transition_transaction,
)
from compat.provisioning import paths as paths_mod
from compat.provisioning.paths import AllowedRootHandle, canary_forbidden_roots, confirm_absent_descriptor_safe, open_allowed_root, validate_target_path

ROOT = Path(__file__).resolve().parents[1]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fifo_create(path: Path) -> None:
    """Creates a FIFO special file at ``path``. Must be called (by
    whichever side owns the filesystem namespace, typically the parent
    process before spawning a child) before either side attempts to open
    it."""
    os.mkfifo(str(path))


def _fifo_open_reader(path: Path) -> int:
    """Opens an already-created FIFO's read end in non-blocking mode.
    POSIX guarantees an ``O_NONBLOCK`` read-only open of a FIFO never
    blocks, regardless of whether a writer exists yet -- so this is
    always safe to call before starting whatever process will later
    signal on the FIFO, closing the race that a sleep-poll loop on
    ``Path.exists()`` cannot close (the reader is genuinely listening
    before the signaler can possibly write)."""
    return os.open(str(path), os.O_RDONLY | os.O_NONBLOCK)


def _fifo_wait(fd: int, *, timeout: float, description: str) -> None:
    """Blocks via a real kernel wait (``select``) until a byte is
    available on ``fd``, or raises after ``timeout`` seconds. The timeout
    is strictly a watchdog: the wakeup itself is immediate once the
    signaler writes, never delayed by a polling interval."""
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        raise AssertionError("timed out waiting for %s" % description)
    os.read(fd, 1)


def _fifo_signal(path: Path) -> None:
    """Opens a FIFO's write end and writes a single marker byte. The
    blocking open here returns immediately in practice: the reader is
    expected to have already opened its end (via ``_fifo_open_reader``)
    before this is ever called."""
    fd = os.open(str(path), os.O_WRONLY)
    try:
        os.write(fd, b"x")
    finally:
        os.close(fd)


def _fail_directory_fsync_side_effect(exc: Exception | None = None, *, only_within: Path | None = None):
    """A ``os.fsync`` side_effect that fails only for a DIRECTORY fd,
    letting a regular file's own fsync succeed normally. The relative,
    descriptor-bound write primitives (point 2, fifth correction round --
    ``create_file_exclusive_relative``/``atomic_write_private_relative``)
    call ``os.fsync`` directly on the held directory fd instead of the
    legacy path-based ``fsync_parent_directory`` seam, so a durability
    failure must be injected here to still exercise the same real code
    path end to end through ``engine.prepare()``.

    ``mock.patch("compat.provisioning.paths.os.fsync", ...)`` patches the
    ``os`` module's own attribute -- a single shared module object -- so it
    is process-wide, not scoped to the ``paths`` module. ``only_within``
    (typically the test's own sandbox) keeps the fault confined to THAT
    directory's fd, via ``/proc/self/fd``, so unrelated directory fsyncs
    (the global lock root, the state root, its subdirectories) are never
    affected."""
    real_fsync = os.fsync

    def _side_effect(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            if only_within is None:
                raise exc if exc is not None else OSError("boom")
            try:
                resolved = Path(os.readlink("/proc/self/fd/%d" % fd))
            except OSError:
                resolved = None
            if resolved is not None and (resolved == only_within or only_within in resolved.parents):
                raise exc if exc is not None else OSError("boom")
        return real_fsync(fd)

    return _side_effect


def _decision(capability_id: str, *, execution_ready: bool = True, method_kind: str = CANARY_METHOD_KIND, resolution_status: str = "method_selected", method_id: str = "canary_method") -> ResolutionDecision:
    return ResolutionDecision(
        capability_id=capability_id,
        dependency_id="dep_%s" % capability_id,
        resolved_distribution="arch",
        resolved_release=None,
        technical_family="arch_pacman",
        release_model="rolling",
        support_classification="certified",
        machine_architecture="x86_64",
        observed_capability_status="absent",
        candidate_chain=(method_id,),
        selected_method_id=method_id,
        selected_method_kind=method_kind,
        resolution_status=resolution_status,
        execution_ready=execution_ready,
        rejected_candidates=(),
        evidence=(),
        reason="lab-only synthetic decision for 23.7.5.6a L1 tests",
        provider_type="lab_fixture",
        provider_authoritative=False,
        availability_observations=(),
        all_availability_observations=(),
    )


class _Harness:
    """Builds a fresh sandbox + state_root + registry + environment per test."""

    def __init__(self, tmp: Path, *, requires_network: bool = False, forbidden_roots=()):
        self.sandbox = tmp / "sandbox"
        self.sandbox.mkdir(mode=0o700)
        os.chmod(self.sandbox, 0o700)
        self.state_root = tmp / "state"
        # Deliberately a SIBLING of state_root, never a descendant of it --
        # the whole point of the global lock root (point 1, fifth
        # correction round) is that it is never inside the same renamable
        # tree as state_root itself.
        self.global_lock_root = tmp / "global-lock-root"
        self.executor = CanaryExecutor(requires_network=requires_network)
        self.registry = TrustedExecutorRegistry()
        self.registry.register(method_kind=CANARY_METHOD_KIND, method_id="canary_method", executor=self.executor)
        self.context = ExecutionContext(allowed_roots=(self.sandbox,), now=_now, forbidden_roots=forbidden_roots)
        self.env = ProvisioningEnvironment(
            state_root=self.state_root, registry=self.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.context,
            global_lock_root=self.global_lock_root,
        )

    def decision(self, capability_id: str = "cap_test", **kwargs) -> ResolutionDecision:
        return _decision(capability_id, **kwargs)

    def locked_context(self) -> ExecutionContext:
        """A context with ``allowed_root_handles`` populated (point 2, fifth
        correction round), exactly like ``engine._open_locked_context``
        builds internally inside a real lock-protected transaction --
        needed by tests that call an ``Executor`` method (``apply_step``/
        ``verify_step``/...) DIRECTLY, outside of ``engine.prepare()``/
        ``engine.uninstall()``, typically to simulate a step already
        applied before a crash. The caller owns the returned handles and
        should let the process exit / not worry about closing them in a
        short-lived test process; storage_mod's fd cleanup is handled by
        process exit like the rest of this test file's raw fd usage."""
        from compat.provisioning.paths import open_allowed_root

        handles = tuple(open_allowed_root(root) for root in self.context.allowed_roots)
        return dataclasses.replace(self.context, allowed_root_handles=handles)


class TransactionalProvisioningTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    # 1. Plan determinista y digest estable.
    def test_01_plan_digest_is_stable_and_deterministic(self) -> None:
        decision = self.harness.decision()
        plan1, _ = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        plan2, _ = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        self.assertEqual(compute_plan_digest(plan1), compute_plan_digest(plan2))
        different = self.harness.decision(capability_id="cap_other")
        plan3, _ = engine.build_plan(different, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        self.assertNotEqual(compute_plan_digest(plan1), compute_plan_digest(plan3))

    # 2. Rechazo de decisión execution_ready=false.
    def test_02_rejects_execution_ready_false(self) -> None:
        decision = self.harness.decision(execution_ready=False, resolution_status="availability_unknown")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.OUT_OF_CONTRACT)
        self.assertEqual(outcome.error_kind, "execution_not_ready")
        self.assertEqual(list(self.harness.sandbox.iterdir()), [])

    # 3. Rechazo de ejecutor no registrado.
    def test_03_rejects_unregistered_executor(self) -> None:
        decision = self.harness.decision(method_id="no_such_method")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.RECIPE_NOT_IMPLEMENTED)
        self.assertEqual(list(self.harness.sandbox.iterdir()), [])

    # 4. Rechazo de kind divergente.
    def test_04_rejects_mismatched_executor_kind(self) -> None:
        decision = self.harness.decision(method_kind="not_canary_lab")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.RECIPE_NOT_IMPLEMENTED)

    # 5. Dry-run con cero cambios.
    def test_05_dry_run_causes_zero_filesystem_mutation(self) -> None:
        before = sorted(str(p) for p in self.tmp.rglob("*"))
        outcome = engine.prepare(self.harness.decision(), self.harness.env, apply=False)
        after = sorted(str(p) for p in self.tmp.rglob("*"))
        self.assertEqual(before, after)
        self.assertEqual(outcome.status, PrepareStatus.DRY_RUN)
        description = engine.describe_plan(outcome.plan)
        self.assertIn("plan_digest", description)
        self.assertIn("planned_rollback", description)

    # 6. Lock entre dos procesos.
    def test_06_lock_contention_between_two_processes(self) -> None:
        state_root = self.harness.state_root
        global_lock_root = self.harness.global_lock_root
        holder_script = self.tmp / "holder.py"
        holder_script.write_text(
            "import sys, time\n"
            "sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from compat.provisioning.lock import acquire_provisioner_lock\n"
            "with acquire_provisioner_lock(Path(%r), global_lock_root=Path(%r), transaction_id='holder', timeout=2.0):\n"
            "    print('ACQUIRED', flush=True)\n"
            "    time.sleep(1.5)\n" % (str(ROOT), str(state_root), str(global_lock_root))
        )
        proc = subprocess.Popen([sys.executable, str(holder_script)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.stdout.close)
        line = proc.stdout.readline()
        self.assertEqual(line.strip(), "ACQUIRED")
        with self.assertRaises(ProvisionerLockHeldError) as ctx:
            with lock_mod.acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id="contender", timeout=0.3):
                pass
        self.assertIsNotNone(ctx.exception.holder_pid)
        # A generous bound for the holder's own teardown (sleep + interpreter
        # shutdown) under load -- not a correctness-relevant wait, so no
        # need for a barrier: the lock-exclusion assertions above already
        # ran, this only confirms the process eventually exits.
        proc.wait(60)

    # 7. Journal durable antes y después de cada paso.
    def test_07_journal_is_durable_before_and_after_each_step(self) -> None:
        decision = self.harness.decision()
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        journal = journal_mod.read_journal(self.harness.state_root, outcome.transaction_id)
        for step in journal.steps:
            self.assertEqual(step.state, StepState.VERIFIED)
            self.assertIsNotNone(step.started_at)
            self.assertIsNotNone(step.completed_at)
            self.assertIsNotNone(step.undo_record)
            self.assertIsNotNone(step.verification)

    # 8. Transiciones inválidas.
    def test_08_invalid_transitions_are_rejected(self) -> None:
        with self.assertRaises(InvalidTransitionError):
            transition_transaction(TransactionState.PLANNED, TransactionState.COMMITTED)
        with self.assertRaises(InvalidTransitionError):
            transition_transaction(TransactionState.COMMITTED, TransactionState.APPLYING)
        with self.assertRaises(InvalidTransitionError):
            transition_transaction(TransactionState.ROLLED_BACK, TransactionState.VERIFYING)
        with self.assertRaises(InvalidTransitionError):
            transition_transaction(TransactionState.UNINSTALLED, TransactionState.APPLYING)
        with self.assertRaises(InvalidTransitionError):
            transition_step(StepState.PLANNED, StepState.VERIFIED)
        with self.assertRaises(InvalidTransitionError):
            transition_step(StepState.UNDONE, StepState.APPLYING)

    # 9. Journal corrupto.
    def test_09_corrupt_journal_blocks_the_provisioner_without_deleting_it(self) -> None:
        bad_path = journal_mod.transaction_path(self.harness.state_root, "corrupt-txn")
        bad_path.parent.mkdir(parents=True, exist_ok=True)
        bad_path.write_text("{not valid json", encoding="utf-8")
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        self.assertTrue(bad_path.exists())

    # 10. Schema desconocido.
    def test_10_unknown_schema_version_is_rejected(self) -> None:
        path = journal_mod.transaction_path(self.harness.state_root, "schema-txn")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"schema_version": 999}', encoding="utf-8")
        with self.assertRaises(Exception):
            journal_mod.read_journal(self.harness.state_root, "schema-txn")

    # 11. Digest divergente.
    def test_11_digest_mismatch_blocks_recovery_and_leaves_evidence(self) -> None:
        decision = self.harness.decision(capability_id="cap_digest")
        plan, _ = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="digest-txn", now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        journal = dataclasses.replace(journal, plan_digest="0" * 64)
        journal_mod.write_journal(self.harness.state_root, journal)
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        self.assertIn("digest", reports[0].reason)
        final = journal_mod.read_journal(self.harness.state_root, "digest-txn")
        self.assertEqual(final.state, TransactionState.RECOVERY_REQUIRED)
        self.assertEqual(list(self.harness.sandbox.iterdir()), [])

    # 12. Ruta fuera de allowlist.
    def test_12_path_outside_allowlist_is_rejected(self) -> None:
        outside = self.tmp / "outside"
        outside.mkdir()
        with self.assertRaises(PathPolicyError):
            validate_target_path(outside / "x", allowed_roots=[self.harness.sandbox])

    # 13. "..".
    def test_13_path_traversal_is_rejected(self) -> None:
        with self.assertRaises(PathPolicyError):
            validate_target_path(self.harness.sandbox / ".." / "x", allowed_roots=[self.harness.sandbox])

    # 14. Symlink intermedio.
    def test_14_intermediate_symlink_is_rejected(self) -> None:
        outside = self.tmp / "outside"
        outside.mkdir()
        link_dir = self.harness.sandbox / "link_dir"
        link_dir.symlink_to(outside)
        with self.assertRaises(PathPolicyError):
            validate_target_path(link_dir / "x", allowed_roots=[self.harness.sandbox])

    # 15. Symlink final.
    def test_15_final_symlink_is_rejected(self) -> None:
        real = self.harness.sandbox / "real.txt"
        real.write_text("hi")
        final_link = self.harness.sandbox / "final_link"
        final_link.symlink_to(real)
        with self.assertRaises(PathPolicyError):
            validate_target_path(final_link, allowed_roots=[self.harness.sandbox])

    # 16. Idempotencia (second apply is a verifiable no-op).
    def test_16_second_apply_is_an_idempotent_no_op(self) -> None:
        decision = self.harness.decision()
        first = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(first.status, PrepareStatus.COMMITTED)
        contents_before = {p.name: p.read_bytes() for p in self.harness.sandbox.iterdir()}
        second = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(second.status, PrepareStatus.ALREADY_PROVISIONED)
        contents_after = {p.name: p.read_bytes() for p in self.harness.sandbox.iterdir()}
        self.assertEqual(contents_before, contents_after)

    # 17. Capacidad preexistente.
    def test_17_pre_existing_capability_is_already_present_with_no_ownership(self) -> None:
        capability_id = "cap_present"
        marker = _marker_content(capability_id)
        companion = _companion_content(capability_id, marker)
        (self.harness.sandbox / ("%s.marker" % capability_id)).write_bytes(marker)
        (self.harness.sandbox / ("%s.companion" % capability_id)).write_bytes(companion)
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.ALREADY_PRESENT)
        self.assertEqual(journal_mod.read_ownership_records(self.harness.state_root, capability_id), [])

    # 18. Conflicto con componente preexistente.
    def test_18_ownership_conflict_with_divergent_pre_existing_component(self) -> None:
        capability_id = "cap_conflict"
        (self.harness.sandbox / ("%s.marker" % capability_id)).write_bytes(b"unexpected content")
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.OWNERSHIP_CONFLICT)
        self.assertEqual(outcome.error_kind, "ownership_conflict")
        self.assertEqual(journal_mod.read_ownership_records(self.harness.state_root, capability_id), [])

    # 19. Apply exitoso.
    def test_19_successful_apply_commits_with_provenance(self) -> None:
        decision = self.harness.decision()
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        records = journal_mod.read_ownership_records(self.harness.state_root, decision.capability_id)
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record.product_owned for record in records))
        self.assertTrue(all(record.created_by_transaction == outcome.transaction_id for record in records))

    # 20. Verificación fallida.
    def test_20_verification_failure_triggers_rollback(self) -> None:
        decision = self.harness.decision(capability_id="cap_verify_fail")
        calls = {"n": 0}
        real_verify = self.harness.executor.verify_step

        def fake_verify(step, execution, context):
            calls["n"] += 1
            if calls["n"] == 2:
                return VerificationResult(status="verification_failed", error_kind="content_mismatch", error="forced test failure")
            return real_verify(step, execution, context)

        with mock.patch.object(self.harness.executor, "verify_step", side_effect=fake_verify):
            outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.PREPARATION_FAILED)
        self.assertEqual(list(self.harness.sandbox.iterdir()), [])

    # 21. Rollback exitoso.
    def test_21_successful_rollback_has_no_residuals(self) -> None:
        decision = self.harness.decision(capability_id="cap_rollback_ok")
        with mock.patch.object(
            self.harness.executor, "verify_step",
            return_value=VerificationResult(status="verification_failed", error_kind="content_mismatch", error="forced"),
        ):
            outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.PREPARATION_FAILED)
        self.assertEqual(outcome.residuals, ())
        journal = journal_mod.read_journal(self.harness.state_root, outcome.transaction_id)
        self.assertEqual(journal.state, TransactionState.PREPARATION_FAILED)

    def test_21b_allowed_root_identity_loss_after_last_undo_blocks_clean_terminal_state(self) -> None:
        decision = self.harness.decision(capability_id="cap_rollback_identity_loss")
        sandbox_old = self.tmp / "sandbox.old"
        real_run_rollback = engine._run_rollback

        def _rollback_then_swap_allowed_root(*args, **kwargs):
            result = real_run_rollback(*args, **kwargs)
            self.harness.sandbox.rename(sandbox_old)
            self.harness.sandbox.mkdir(mode=0o700)
            return result

        with mock.patch.object(
            self.harness.executor, "verify_step",
            return_value=VerificationResult(status="verification_failed", error_kind="content_mismatch", error="forced"),
        ):
            with mock.patch("compat.provisioning.engine._run_rollback", side_effect=_rollback_then_swap_allowed_root):
                outcome = engine.prepare(decision, self.harness.env, apply=True)

        self.assertEqual(outcome.status, PrepareStatus.RECOVERY_REQUIRED)
        self.assertNotEqual(outcome.status, PrepareStatus.PREPARATION_FAILED)
        journal = journal_mod.read_journal(self.harness.state_root, outcome.transaction_id)
        self.assertNotEqual(journal.state, TransactionState.PREPARATION_FAILED)

    # 22. Rollback parcialmente fallido.
    def test_22_partially_failed_rollback_reports_explicit_residuals(self) -> None:
        decision = self.harness.decision(capability_id="cap_partial_rollback")
        from compat.provisioning.model import RollbackResult

        real_verify = self.harness.executor.verify_step
        real_undo = self.harness.executor.undo_step
        calls = {"n": 0}

        def fake_verify(step, execution, context):
            calls["n"] += 1
            if calls["n"] == 2:
                return VerificationResult(status="verification_failed", error_kind="forced", error="forced test failure")
            return real_verify(step, execution, context)

        def fake_undo(step, execution, context):
            if step.step_id == "create_marker":
                return RollbackResult(status="undo_failed", residual=True, error_kind="forced", error="forced undo failure")
            return real_undo(step, execution, context)

        with mock.patch.object(self.harness.executor, "verify_step", side_effect=fake_verify):
            with mock.patch.object(self.harness.executor, "undo_step", side_effect=fake_undo):
                outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.ROLLBACK_FAILED)
        self.assertIn("create_marker", outcome.residuals)
        journal = journal_mod.read_journal(self.harness.state_root, outcome.transaction_id)
        self.assertEqual(journal.state, TransactionState.ROLLBACK_FAILED)
        # The companion step's undo must still have been attempted independently.
        companion_step = next(s for s in journal.steps if s.step_id == "create_companion")
        self.assertEqual(companion_step.state, StepState.UNDONE)

    # 23. Interrupción antes de aplicar.
    def test_23_interruption_before_apply_rolls_back_cleanly(self) -> None:
        decision = self.harness.decision(capability_id="cap_interrupt_before")
        with mock.patch("compat.provisioning.engine._interruption_guard") as guard:
            flag = engine._SignalFlag()
            flag.value = True
            from contextlib import contextmanager

            @contextmanager
            def fake_guard():
                yield flag

            guard.return_value = fake_guard()
            outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.PREPARATION_FAILED)
        self.assertEqual(list(self.harness.sandbox.iterdir()), [])

    # 24. Interrupción después de aplicar y antes de verificar.
    def test_24_interruption_after_apply_before_verify_recovers_by_resuming(self) -> None:
        decision = self.harness.decision(capability_id="cap_interrupt_mid")
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="mid-txn", now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        record = journal.step(0).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
        journal = journal.with_step(record)
        result = executor.apply_step(record, self.harness.locked_context())  # really writes the file
        self.assertEqual(result.status, "applied")
        # Crash simulated here: undo_record/APPLIED transition never got journaled.
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.RESUME)
        final = journal_mod.read_journal(self.harness.state_root, "mid-txn")
        self.assertEqual(final.state, TransactionState.COMMITTED)

    # 25. Interrupción después de verificar y antes de commit.
    def test_25_interruption_after_verify_before_commit_recovers_by_resuming(self) -> None:
        decision = self.harness.decision(capability_id="cap_interrupt_late")
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="late-txn", now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        locked_context = self.harness.locked_context()
        for step in plan.steps:
            record = journal.step(step.sequence).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
            journal = journal.with_step(record)
            result = executor.apply_step(record, locked_context)
            record = record.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result.undo_record)
            journal = journal.with_step(record)
            record = record.with_state(StepState.VERIFYING)
            journal = journal.with_step(record)
            verification = executor.verify_step(record, result, locked_context)
            record = record.with_state(StepState.VERIFIED, completed_at=_now(), verification=verification.evidence)
            journal = journal.with_step(record)
        journal = journal.with_state(TransactionState.VERIFYING, now=_now())
        # Crash simulated here: postcondition/commit never got journaled.
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.RESUME)
        final = journal_mod.read_journal(self.harness.state_root, "late-txn")
        self.assertEqual(final.state, TransactionState.COMMITTED)

    # 26. Recovery por resume seguro. (covered again explicitly, distinct scenario: step never started)
    def test_26_recovery_resumes_safely_when_a_step_never_started(self) -> None:
        decision = self.harness.decision(capability_id="cap_resume_fresh")
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="resume-txn", now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)  # crashed before any step began

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.RESUME)
        final = journal_mod.read_journal(self.harness.state_root, "resume-txn")
        self.assertEqual(final.state, TransactionState.COMMITTED)

    # 27. Recovery por rollback.
    def test_27_recovery_completes_a_pending_rollback(self) -> None:
        decision = self.harness.decision(capability_id="cap_recovery_rollback")
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="rb-txn", now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        record = journal.step(0).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
        journal = journal.with_step(record)
        locked_context = self.harness.locked_context()
        result = executor.apply_step(record, locked_context)
        record = record.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result.undo_record)
        journal = journal.with_step(record)
        record = record.with_state(StepState.VERIFYING)
        journal = journal.with_step(record)
        verification = executor.verify_step(record, result, locked_context)
        record = record.with_state(StepState.VERIFIED, completed_at=_now(), verification=verification.evidence)
        journal = journal.with_step(record)
        # Second step failed to apply; transaction should have started rolling back.
        record1 = journal.step(1).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
        journal = journal.with_step(record1)
        record1 = record1.with_state(StepState.APPLY_FAILED, completed_at=_now(), error_kind="forced", error="forced failure")
        journal = journal.with_step(record1)
        journal = journal.with_state(TransactionState.ROLLING_BACK, now=_now())
        # Crash simulated here: rollback of step 0 never happened.
        journal_mod.write_journal(self.harness.state_root, journal)

        self.assertTrue((self.harness.sandbox / "cap_recovery_rollback.marker").exists())
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.ROLLBACK)
        final = journal_mod.read_journal(self.harness.state_root, "rb-txn")
        self.assertEqual(final.state, TransactionState.PREPARATION_FAILED)
        self.assertEqual(list(self.harness.sandbox.iterdir()), [])

    # 28. Recovery ambigua.
    def test_28_recovery_is_ambiguous_on_content_divergence(self) -> None:
        decision = self.harness.decision(capability_id="cap_recovery_ambiguous")
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="ambig-txn", now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        record = journal.step(0).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
        journal = journal.with_step(record)
        journal_mod.write_journal(self.harness.state_root, journal)
        # Someone/something else wrote unexpected content at the target path.
        (self.harness.sandbox / "cap_recovery_ambiguous.marker").write_bytes(b"tampered content")

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        final = journal_mod.read_journal(self.harness.state_root, "ambig-txn")
        self.assertEqual(final.state, TransactionState.RECOVERY_REQUIRED)

    # 29. Uninstall product-owned.
    def test_29_uninstall_removes_only_product_owned_resources(self) -> None:
        decision = self.harness.decision(capability_id="cap_uninstall")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        result = engine.uninstall(decision.capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.UNINSTALLED)
        self.assertEqual(list(self.harness.sandbox.iterdir()), [])
        self.assertEqual(journal_mod.read_ownership_records(self.harness.state_root, decision.capability_id), [])

    # 30. Uninstall preservando preexistente.
    def test_30_uninstall_never_touches_a_pre_existing_capability(self) -> None:
        capability_id = "cap_present_uninstall"
        marker = _marker_content(capability_id)
        companion = _companion_content(capability_id, marker)
        (self.harness.sandbox / ("%s.marker" % capability_id)).write_bytes(marker)
        (self.harness.sandbox / ("%s.companion" % capability_id)).write_bytes(companion)
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.ALREADY_PRESENT)
        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OUT_OF_CONTRACT)
        self.assertEqual(result.error_kind, "nothing_to_uninstall")
        self.assertTrue((self.harness.sandbox / ("%s.marker" % capability_id)).exists())
        self.assertTrue((self.harness.sandbox / ("%s.companion" % capability_id)).exists())

    # 31. Drift posterior al install.
    def test_31_uninstall_refuses_removal_on_ownership_drift(self) -> None:
        decision = self.harness.decision(capability_id="cap_drift")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        marker_path = self.harness.sandbox / "cap_drift.marker"
        marker_path.write_bytes(b"the user changed this file after install")
        result = engine.uninstall(decision.capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.UNINSTALL_FAILED)
        self.assertTrue(result.residuals)
        self.assertTrue(marker_path.exists())
        self.assertEqual(marker_path.read_bytes(), b"the user changed this file after install")

    # 32. Segundo uninstall idempotente.
    def test_32_second_uninstall_is_idempotent(self) -> None:
        decision = self.harness.decision(capability_id="cap_double_uninstall")
        engine.prepare(decision, self.harness.env, apply=True)
        first = engine.uninstall(decision.capability_id, self.harness.env, apply=True)
        self.assertEqual(first.status, PrepareStatus.UNINSTALLED)
        second = engine.uninstall(decision.capability_id, self.harness.env, apply=True)
        self.assertEqual(second.status, PrepareStatus.OUT_OF_CONTRACT)
        self.assertEqual(second.error_kind, "nothing_to_uninstall")

    # 33. Redacción de datos sensibles.
    def test_33_journal_redacts_sensitive_data(self) -> None:
        step = journal_mod.StepRecord(
            sequence=0, step_id="s", action_type="create_file", state=StepState.PLANNED,
            intent={"password": "hunter2", "url": "https://user:pass@example.com/x", "content": "fine"},
        )
        journal = journal_mod.TransactionJournal(
            schema_version=1, transaction_id="redact-txn", operation="prepare", state=TransactionState.PLANNED,
            created_at=_now(), updated_at=_now(), plan_digest="a" * 64, capability_id="c", dependency_id="d",
            target="x", architecture="x86_64", support_classification="certified",
            selected_method={"id": "m", "kind": "k"}, executor={"id": "e", "version": "1"}, steps=(step,),
        )
        journal_mod.write_journal(self.harness.state_root, journal)
        loaded = journal_mod.read_journal(self.harness.state_root, "redact-txn")
        self.assertEqual(loaded.steps[0].intent["password"], "***redacted***")
        self.assertNotIn("pass@", loaded.steps[0].intent["url"].split("://")[0])
        self.assertEqual(loaded.steps[0].intent["content"], "fine")

    # 34. Permisos de lock, journal y ownership.
    def test_34_lock_journal_and_ownership_files_are_owner_only(self) -> None:
        decision = self.harness.decision(capability_id="cap_perms")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        journal_path = journal_mod.transaction_path(self.harness.state_root, outcome.transaction_id)
        ownership_file = journal_mod.ownership_path(self.harness.state_root, decision.capability_id)
        with lock_mod.acquire_provisioner_lock(
            self.harness.state_root, global_lock_root=self.harness.global_lock_root, transaction_id="perm-check", timeout=1.0
        ):
            lock_files = list(self.harness.global_lock_root.glob("*.lock"))
            self.assertEqual(len(lock_files), 1)
            self.assertEqual(oct(stat.S_IMODE(lock_files[0].stat().st_mode)), "0o600")
        self.assertEqual(oct(stat.S_IMODE(self.harness.global_lock_root.stat().st_mode)), "0o700")
        self.assertEqual(oct(stat.S_IMODE(journal_path.stat().st_mode)), "0o600")
        self.assertEqual(oct(stat.S_IMODE(ownership_file.stat().st_mode)), "0o600")

    # 35. No uso de shell/eval/comandos procedentes del manifiesto.
    def test_35_no_shell_eval_dynamic_import_in_provisioning_source(self) -> None:
        package_dir = ROOT / "compat" / "provisioning"
        forbidden = ("shell=True", "os.system(", "eval(", "exec(", "sh -c", "importlib.import_module", "__import__(")
        for path in sorted(package_dir.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            for token in forbidden:
                with self.subTest(file=path.name, token=token):
                    self.assertNotIn(token, source)


class OfflineAndNetworkModelingTests(unittest.TestCase):
    """Beyond the enumerated 35: the offline-before-network-step contract."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)

    def test_offline_before_network_requiring_step_is_preparation_blocked_without_mutation(self) -> None:
        harness = _Harness(self.tmp, requires_network=True)
        harness.context = dataclasses.replace(harness.context, network_available=lambda: False)
        harness.env = dataclasses.replace(harness.env, context=harness.context)
        outcome = engine.prepare(harness.decision(), harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.OFFLINE)
        self.assertEqual(list(harness.sandbox.iterdir()), [])

    def test_online_network_requiring_step_proceeds_normally(self) -> None:
        harness = _Harness(self.tmp, requires_network=True)
        harness.context = dataclasses.replace(harness.context, network_available=lambda: True)
        harness.env = dataclasses.replace(harness.env, context=harness.context)
        outcome = engine.prepare(harness.decision(), harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)


class ExecutorErrorWrappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_executor_exception_during_apply_is_contained_and_triggers_rollback(self) -> None:
        decision = self.harness.decision(capability_id="cap_executor_crash")
        with mock.patch.object(self.harness.executor, "apply_step", side_effect=RuntimeError("boom")):
            outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.PREPARATION_FAILED)
        journal = journal_mod.read_journal(self.harness.state_root, outcome.transaction_id)
        self.assertEqual(journal.steps[0].error_kind, "executor_error")


def _valid_ownership_payload(**overrides) -> dict:
    candidate = {
        "artifact_type": "file", "resource_identity": "/tmp/x", "pre_existing": False,
        "method_id": "canary_method", "source": None, "version": None, "integrity": "a" * 64,
        "uid": 0, "gid": 0, "mode": 0o600, "post_install_fingerprint": None,
    }
    candidate.update(overrides.pop("candidate", {}))
    payload = {
        "capability_id": "cap_x", "product_owned": True, "created_by_transaction": None,
        "executor_id": "e", "executor_version": "1", "recorded_at": _now(), "candidate": candidate,
    }
    payload.update(overrides)
    return payload


class IdentifierValidationTests(unittest.TestCase):
    """Point 1: central validation for transaction_id/capability_id/dependency_id."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)

    def test_rejects_path_traversal_empty_and_none(self) -> None:
        for bad in ("../../etc/passwd", "a/b", "a\\b", "", ".", "..", "/abs", "a\x00b", None, "x" * 200):
            with self.subTest(bad=bad):
                with self.assertRaises(IdentifierError):
                    paths_mod.validate_identifier(bad, field="transaction_id")

    def test_accepts_realistic_ids(self) -> None:
        for good in ("cap_python310", "proto_amneziawg_runtime", "a" * 128, "abc-DEF_123"):
            self.assertEqual(paths_mod.validate_identifier(good, field="capability_id"), good)

    def test_journal_path_helpers_reject_malicious_ids(self) -> None:
        state_root = self.tmp / "state"
        with self.assertRaises(IdentifierError):
            journal_mod.transaction_path(state_root, "../../etc/passwd")
        with self.assertRaises(IdentifierError):
            journal_mod.history_path(state_root, "../evil")
        with self.assertRaises(IdentifierError):
            journal_mod.ownership_path(state_root, "../../evil")

    def test_ownership_deserialization_rejects_path_traversal_created_by_transaction(self) -> None:
        state_root = self.tmp / "state"
        payload = [_valid_ownership_payload(created_by_transaction="../../etc/passwd")]
        path = journal_mod.ownership_path(state_root, "cap_x")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(JournalError):
            journal_mod.read_ownership_records(state_root, "cap_x")

    def test_ownership_deserialization_rejects_unknown_field(self) -> None:
        state_root = self.tmp / "state"
        payload = [_valid_ownership_payload(extra_backdoor_field=1)]
        path = journal_mod.ownership_path(state_root, "cap_x")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(JournalError):
            journal_mod.read_ownership_records(state_root, "cap_x")

    def test_ownership_deserialization_rejects_non_bool_product_owned(self) -> None:
        state_root = self.tmp / "state"
        payload = [_valid_ownership_payload(product_owned="true")]
        path = journal_mod.ownership_path(state_root, "cap_x")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(JournalError):
            journal_mod.read_ownership_records(state_root, "cap_x")

    def test_ownership_deserialization_rejects_relative_resource_identity(self) -> None:
        state_root = self.tmp / "state"
        payload = [_valid_ownership_payload(candidate={"resource_identity": "relative/path"})]
        path = journal_mod.ownership_path(state_root, "cap_x")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(JournalError):
            journal_mod.read_ownership_records(state_root, "cap_x")

    def test_ownership_deserialization_rejects_negative_uid_and_bad_mode(self) -> None:
        state_root = self.tmp / "state"
        for bad_candidate in ({"uid": -1}, {"mode": 0o100000}, {"integrity": "not-a-hash"}):
            with self.subTest(bad_candidate=bad_candidate):
                payload = [_valid_ownership_payload(candidate=dict(bad_candidate))]
                path = journal_mod.ownership_path(state_root, "cap_x")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(JournalError):
                    journal_mod.read_ownership_records(state_root, "cap_x")


class PathPolicyChokePointTests(unittest.TestCase):
    """Point 3: every path operation (verify/undo/inspect/postcondition/uninstall)
    goes through validate_target_path, never a raw journal/ownership path."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _outside_target(self) -> Path:
        outside_dir = self.tmp / "outside"
        outside_dir.mkdir(exist_ok=True)
        outside_file = outside_dir / "evil.marker"
        outside_file.write_bytes(b"evil")
        return outside_file

    def test_verify_step_rejects_path_outside_allowlist(self) -> None:
        outside = self._outside_target()
        record = journal_mod.StepRecord(sequence=0, step_id="s", action_type="create_file", state=StepState.APPLIED, intent={"content": "x", "content_sha256": "0" * 64}, target=str(outside))
        execution = engine.ExecutionResult(status="applied", observed={"path": str(outside)})
        result = self.harness.executor.verify_step(record, execution, self.harness.context)
        self.assertEqual(result.status, "verification_failed")
        self.assertEqual(result.error_kind, "path_policy_violation")

    def test_undo_step_rejects_path_outside_allowlist(self) -> None:
        outside = self._outside_target()
        record = journal_mod.StepRecord(sequence=0, step_id="s", action_type="create_file", state=StepState.APPLIED, intent={"content": "x", "content_sha256": "0" * 64}, target=str(outside))
        execution = engine.ExecutionResult(status="applied", undo_record={"path": str(outside), "expected_sha256": "0" * 64})
        result = self.harness.executor.undo_step(record, execution, self.harness.context)
        self.assertEqual(result.status, "undo_failed")
        self.assertEqual(result.error_kind, "path_policy_violation")
        self.assertTrue(outside.exists())

    def test_inspect_step_rejects_path_outside_allowlist(self) -> None:
        outside = self._outside_target()
        record = journal_mod.StepRecord(sequence=0, step_id="s", action_type="create_file", state=StepState.PLANNED, intent={"content": "x", "content_sha256": "0" * 64}, target=str(outside))
        observed = self.harness.executor.inspect_step(record, self.harness.context)
        self.assertIn("path_policy_error", observed)
        self.assertIsNone(observed["exists"])

    def test_verify_postcondition_rejects_path_outside_allowlist(self) -> None:
        outside = self._outside_target()
        plan = ProvisioningPlan(
            capability_id="cap_x", dependency_id="dep_x", resolved_target="t", architecture="x86_64",
            support_classification="certified", selected_method_id="canary_method", selected_method_kind=CANARY_METHOD_KIND,
            postcondition="x", executor_id=self.harness.executor.executor_id, executor_version=CANARY_EXECUTOR_VERSION,
            steps=(ProvisioningStep(sequence=0, step_id="s", action_type="create_file", intent={"content_sha256": "0" * 64}, target=str(outside)),),
        )
        result = self.harness.executor.verify_postcondition(plan, self.harness.context)
        self.assertEqual(result.status, "verification_failed")
        self.assertEqual(result.error_kind, "path_policy_violation")

    def test_run_uninstall_loop_rejects_forged_out_of_allowlist_target(self) -> None:
        outside = self._outside_target()
        step = ProvisioningStep(sequence=0, step_id="uninstall_0", action_type="remove_file", intent={"resource_identity": str(outside), "expected_sha256": None}, target=str(outside))
        plan = UninstallPlan(
            capability_id="cap_x", transaction_id="forgedtxn", target_transaction_id="",
            ownership_records=(
                OwnershipRecord(
                    capability_id="cap_x",
                    candidate=OwnershipCandidate(artifact_type="file", resource_identity=str(outside), pre_existing=False),
                    product_owned=True, created_by_transaction=None, executor_id="e", executor_version="1", recorded_at=_now(),
                ),
            ),
            steps=(step,),
        )
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        with mock.patch("compat.provisioning.engine._uninstall_source_matches", return_value=True):
            result_journal, ok, residuals = engine._run_uninstall_loop(
                self.harness.state_root, journal, self.harness.context,
                registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION,
            )
        self.assertFalse(ok)
        self.assertTrue(outside.exists())
        self.assertEqual(result_journal.step(0).error_kind, "path_policy_violation")


class PathPolicyErrorClassificationTests(unittest.TestCase):
    """Point 4 (fourth correction round): validate_target_path,
    _reject_symlink_components, validate_dedicated_lab_root and
    validate_lab_descendant use os.lstat directly, never
    Path.is_symlink()/Path.exists() (whose internal OSError-handling
    differs across Python versions -- see the round-2 hardening notes,
    where that divergence caused a real cross-version test fragility). A
    FileNotFoundError on a component means absent where the operation
    allows it; any OTHER OSError -- permission denied, EIO, ESTALE -- is
    fail-closed as PathPolicyError, never silently treated as absence.
    These tests run against the REAL policy functions with no bypass, and
    must classify identically regardless of Python version."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)

    @staticmethod
    def _faulty_lstat(target: Path, exc: OSError):
        real_lstat = os.lstat

        def _wrapped(path, *args, **kwargs):
            if Path(path) == target:
                raise exc
            return real_lstat(path, *args, **kwargs)

        return _wrapped

    def _assert_validate_target_path_fails_closed(self, injected_exc: OSError) -> None:
        allowed_root = self.tmp / "allowed"
        allowed_root.mkdir()
        blocked = allowed_root / "blocked_dir"
        blocked.mkdir()
        target = blocked / "leaf.txt"
        with mock.patch("compat.provisioning.paths.os.lstat", side_effect=self._faulty_lstat(blocked, injected_exc)):
            with self.assertRaises(PathPolicyError):
                validate_target_path(target, allowed_roots=(allowed_root,))

    def test_validate_target_path_permission_error_on_intermediate_component_fails_closed(self) -> None:
        self._assert_validate_target_path_fails_closed(PermissionError(errno.EACCES, "permission denied"))

    def test_validate_target_path_eio_on_intermediate_component_fails_closed(self) -> None:
        self._assert_validate_target_path_fails_closed(OSError(errno.EIO, "I/O error"))

    def test_validate_target_path_estale_on_intermediate_component_fails_closed(self) -> None:
        self._assert_validate_target_path_fails_closed(OSError(errno.ESTALE, "stale file handle"))

    def _assert_lab_root_validation_fails_closed(self, injected_exc: OSError) -> None:
        lab_root = self.tmp / "lab_root"
        lab_root.mkdir(mode=0o700)
        os.chmod(lab_root, 0o700)
        blocked = lab_root / "blocked_dir"
        blocked.mkdir()
        sandbox = blocked / "sandbox"
        with mock.patch("compat.provisioning.paths.os.lstat", side_effect=self._faulty_lstat(blocked, injected_exc)):
            with self.assertRaises(PathPolicyError):
                paths_mod.validate_lab_descendant(lab_root, sandbox, label="--sandbox")

    def test_validate_lab_descendant_permission_error_on_intermediate_component_fails_closed(self) -> None:
        self._assert_lab_root_validation_fails_closed(PermissionError(errno.EACCES, "permission denied"))

    def test_validate_lab_descendant_eio_on_intermediate_component_fails_closed(self) -> None:
        self._assert_lab_root_validation_fails_closed(OSError(errno.EIO, "I/O error"))

    def test_validate_lab_descendant_estale_on_intermediate_component_fails_closed(self) -> None:
        self._assert_lab_root_validation_fails_closed(OSError(errno.ESTALE, "stale file handle"))

    def test_validate_dedicated_lab_root_permission_error_on_leaf_fails_closed(self) -> None:
        lab_root = self.tmp / "lab_root_leaf_fault"
        lab_root.mkdir(mode=0o700)
        os.chmod(lab_root, 0o700)
        with mock.patch(
            "compat.provisioning.paths.os.lstat",
            side_effect=self._faulty_lstat(lab_root, PermissionError(errno.EACCES, "permission denied")),
        ):
            with self.assertRaises(PathPolicyError):
                paths_mod.validate_dedicated_lab_root(lab_root)


class PrivateStorageTests(unittest.TestCase):
    """Point 4: provisioning state is always 0700/0600, never the shared-group
    config.persistence primitive, regardless of where state_root lives."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_state_root_directories_are_owner_only(self) -> None:
        decision = self.harness.decision(capability_id="cap_perms_dir")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        for directory in (
            self.harness.state_root,
            journal_mod.transactions_dir(self.harness.state_root),
            journal_mod.ownership_dir(self.harness.state_root),
        ):
            self.assertEqual(oct(stat.S_IMODE(directory.stat().st_mode)), "0o700")

    def test_provisioning_journal_module_never_uses_the_shared_group_primitive(self) -> None:
        source = (ROOT / "compat" / "provisioning" / "journal.py").read_text(encoding="utf-8")
        self.assertNotIn("import config.persistence", source)
        self.assertNotIn("from config.persistence import", source)
        self.assertNotIn("SHARED_FILE_MODE", source)

    def test_ensure_private_dir_tightens_a_pre_existing_own_uid_directory(self) -> None:
        target = self.tmp / "already_there"
        target.mkdir(mode=0o750)
        os.chmod(target, 0o750)
        storage_mod.ensure_private_state_root(target)
        self.assertEqual(oct(stat.S_IMODE(target.stat().st_mode)), "0o700")


class DurabilityTests(unittest.TestCase):
    """Point 11: fsync the parent directory after create/unlink; a fsync
    failure must never be silently declared durable/verified/undone."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)

    def test_create_file_exclusive_raises_durability_error_when_directory_fsync_fails(self) -> None:
        target = self.tmp / "x.marker"
        with mock.patch("compat.provisioning.paths.fsync_parent_directory", side_effect=DurabilityError("boom")):
            with self.assertRaises(DurabilityError):
                paths_mod.create_file_exclusive(target, b"data")
        self.assertTrue(target.exists())

    def test_remove_file_if_owned_raises_durability_error_when_directory_fsync_fails(self) -> None:
        target = self.tmp / "x.marker"
        target.write_bytes(b"data")
        with mock.patch("compat.provisioning.paths.fsync_parent_directory", side_effect=DurabilityError("boom")):
            with self.assertRaises(DurabilityError):
                paths_mod.remove_file_if_owned(target)
        self.assertFalse(target.exists())

    def test_apply_never_falsely_commits_when_directory_durability_fails(self) -> None:
        harness = _Harness(self.tmp)
        decision = harness.decision(capability_id="cap_durability")
        with mock.patch("compat.provisioning.paths.os.fsync", side_effect=_fail_directory_fsync_side_effect(only_within=harness.sandbox)):
            outcome = engine.prepare(decision, harness.env, apply=True)
        self.assertNotEqual(outcome.status, PrepareStatus.COMMITTED)


class OwnershipMetadataTests(unittest.TestCase):
    """Point 12: ownership records capture uid/gid/mode/hash/type; final
    postcondition rechecks content, not just existence; st_nlink == 1."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_ownership_records_capture_uid_gid_mode(self) -> None:
        decision = self.harness.decision(capability_id="cap_metadata")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        records = journal_mod.read_ownership_records(self.harness.state_root, "cap_metadata")
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertEqual(record.candidate.uid, os.getuid())
            self.assertEqual(record.candidate.gid, os.getgid())
            self.assertEqual(record.candidate.mode, 0o600)
            self.assertIsNotNone(record.candidate.integrity)

    def test_verify_step_rejects_hardlinked_target(self) -> None:
        decision = self.harness.decision(capability_id="cap_nlink")
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="nlinktxn", now_value=_now())
        record = journal.step(0).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
        locked_context = self.harness.locked_context()
        result = executor.apply_step(record, locked_context)
        target_path = Path(result.observed["path"])
        hardlink = target_path.with_name(target_path.name + ".hardlink")
        os.link(target_path, hardlink)
        self.addCleanup(lambda: hardlink.unlink(missing_ok=True))
        verification = executor.verify_step(record, result, locked_context)
        self.assertEqual(verification.status, "verification_failed")
        self.assertEqual(verification.error_kind, "unexpected_nlink")


class SelectedAssetPersistenceTests(unittest.TestCase):
    """Point 10: selected_asset is persisted in the prepare journal and
    reconstructed exactly during recovery; tampering breaks the digest."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _decision_with_asset(self, capability_id: str) -> ResolutionDecision:
        decision = self.harness.decision(capability_id)
        asset = SelectedArtifact(
            architecture="x86_64", asset_name="pkg.tar.zst", archive_or_binary_kind="archive",
            official_download_base="https://example.invalid/", sha256="a" * 64, expected_executable="pkg",
        )
        return dataclasses.replace(decision, selected_asset=asset)

    def test_selected_asset_is_persisted_and_survives_recovery(self) -> None:
        decision = self._decision_with_asset("cap_asset")
        plan, _executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="assettxn", now_value=_now())
        self.assertIsNotNone(journal.selected_asset)
        journal_mod.write_journal(self.harness.state_root, journal)
        reloaded = journal_mod.read_journal(self.harness.state_root, "assettxn")
        self.assertEqual(reloaded.selected_asset["asset_name"], "pkg.tar.zst")

        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)  # crashed before any step began

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.RESUME)
        final = journal_mod.read_journal(self.harness.state_root, "assettxn")
        self.assertEqual(final.state, TransactionState.COMMITTED)

    def test_tampered_selected_asset_causes_digest_mismatch_on_recovery(self) -> None:
        decision = self._decision_with_asset("cap_asset_tamper")
        plan, _executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="assettampertxn", now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        tampered_asset = dict(journal.selected_asset)
        tampered_asset["sha256"] = "b" * 64
        journal = dataclasses.replace(journal, selected_asset=tampered_asset)
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        final = journal_mod.read_journal(self.harness.state_root, "assettampertxn")
        self.assertEqual(final.state, TransactionState.RECOVERY_REQUIRED)


class OwnershipAuthorityBindingTests(unittest.TestCase):
    """Points 2, 8: no uninstall right may exist without a full, exact match
    against one committed 'prepare' transaction's own provenance."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_uninstall_refuses_ownership_record_bound_to_nonexistent_transaction(self) -> None:
        decision = self.harness.decision(capability_id="cap_orphan")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        records = journal_mod.read_ownership_records(self.harness.state_root, "cap_orphan")
        forged = [dataclasses.replace(r, created_by_transaction="ffffffffffffffffffffffffffffffff") for r in records]
        journal_mod.write_ownership_records(self.harness.state_root, "cap_orphan", forged)

        result = engine.uninstall("cap_orphan", self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)
        self.assertEqual(result.error_kind, "ownership_invalid")
        self.assertTrue((self.harness.sandbox / "cap_orphan.marker").exists())
        self.assertTrue((self.harness.sandbox / "cap_orphan.companion").exists())

    def test_uninstall_refuses_ownership_published_before_commit(self) -> None:
        decision = self.harness.decision(capability_id="cap_precommit")
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="precommittxn", now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        locked_context = self.harness.locked_context()
        journal, apply_ok, _durability_unknown = engine._apply_and_verify(self.harness.state_root, journal, plan, executor, locked_context)
        self.assertTrue(apply_ok)
        self.assertEqual(journal.state, TransactionState.VERIFYING)
        engine._finalize_provenance(self.harness.state_root, journal, plan, executor, locked_context, _now())
        journal_mod.write_journal(self.harness.state_root, journal)  # crash: still VERIFYING, never COMMITTED

        result = engine.uninstall("cap_precommit", self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)


class _DivergentMetadataExecutor(CanaryExecutor):
    """Test-only executor (fourth correction round, points 2+6) -- NEVER
    registered outside tests. Behaves identically to CanaryExecutor except
    its plan_steps embeds a non-null source/version in each step's intent,
    and expected_ownership_for_step reports a post_install_fingerprint that
    deliberately diverges from the content hash. Used to prove the engine's
    ownership-authority validation is executor-agnostic: it derives
    everything from THIS executor's own expected_ownership_for_step, never
    from canary-specific assumptions (source is always None, fingerprint
    always equals integrity, ...) hardcoded in engine.py."""

    executor_id = "divergent_metadata_test_executor"
    supported_method_kind = "divergent_metadata_test"

    def plan_steps(self, *, capability_id: str, dependency_id: str, context: ExecutionContext):
        steps = super().plan_steps(capability_id=capability_id, dependency_id=dependency_id, context=context)
        return tuple(
            dataclasses.replace(
                step,
                intent={
                    **step.intent,
                    "source": "https://example.invalid/divergent-package",
                    "version": "9.9.9-test",
                },
            )
            for step in steps
        )

    def expected_ownership_for_step(self, plan, step):
        expected = super().expected_ownership_for_step(plan, step)
        return dataclasses.replace(
            expected,
            source=step.intent.get("source"),
            version=step.intent.get("version"),
            post_install_fingerprint="0" * 64,
        )


DIVERGENT_METADATA_METHOD_KIND = "divergent_metadata_test"


class ExecutorAgnosticOwnershipAuthorityTests(unittest.TestCase):
    """Points 2+6 (fourth correction round): validate_ownership_authority
    must derive its expectations from whatever executor produced the plan,
    never from engine-hardcoded canary assumptions. A second, divergent
    test-only executor (non-null source/version, a post_install_fingerprint
    that diverges from the content hash) must still work correctly through
    the exact same generic authority/commit/uninstall machinery -- proving
    the infrastructure is genuinely generic, not secretly canary-specific."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)
        self.divergent_executor = _DivergentMetadataExecutor()
        self.harness.registry.register(
            method_kind=DIVERGENT_METADATA_METHOD_KIND, method_id="divergent_method", executor=self.divergent_executor
        )

    def _decision(self, capability_id: str):
        return _decision(capability_id, method_kind=DIVERGENT_METADATA_METHOD_KIND, method_id="divergent_method")

    def test_divergent_metadata_executor_commits_and_uninstalls_cleanly(self) -> None:
        capability_id = "cap_divergent_lifecycle"
        outcome = engine.prepare(self._decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        self.assertTrue(all(r.candidate.source == "https://example.invalid/divergent-package" for r in records))
        self.assertTrue(all(r.candidate.version == "9.9.9-test" for r in records))
        self.assertTrue(all(r.candidate.post_install_fingerprint == "0" * 64 for r in records))
        self.assertTrue(all(r.candidate.post_install_fingerprint != r.candidate.integrity for r in records))

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.UNINSTALLED)
        self.assertFalse((self.harness.sandbox / ("%s.divergent" % capability_id)).exists())

    def test_divergent_metadata_executor_authority_still_rejects_a_redirected_resource(self) -> None:
        capability_id = "cap_divergent_redirect"
        outcome = engine.prepare(self._decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        foreign = self.tmp / "foreign.txt"
        foreign.write_bytes(b"not part of this plan")
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        tampered = [dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, resource_identity=str(foreign))) for r in records]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, tampered)

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)
        self.assertTrue(foreign.exists())


class _NoneOwnershipFieldsExecutor(CanaryExecutor):
    """Test-only executor (point 7, fifth correction round) -- NEVER
    registered outside tests. Its ``expected_ownership_for_step``
    deliberately leaves ``uid``/``gid`` unset (``None``), unlike
    ``CanaryExecutor`` which always pins them to the real process uid/gid
    -- used to prove ``validate_ownership_authority`` compares EVERY field
    for EXACT equality, including when the executor's own expectation is
    ``None``, rather than skipping the comparison whenever ``expected`` is
    ``None`` (which would let a tampered ``candidate.uid``/``gid`` go
    undetected)."""

    executor_id = "none_fields_test_executor"
    supported_method_kind = "none_fields_test"

    def expected_ownership_for_step(self, plan, step):
        expected = super().expected_ownership_for_step(plan, step)
        return dataclasses.replace(expected, uid=None, gid=None)


NONE_FIELDS_METHOD_KIND = "none_fields_test"


class ExpectedOwnershipNoneFieldExactEqualityTests(unittest.TestCase):
    """Point 7, fifth correction round, mandatory test: a test-only
    executor with some expected fields declared ``None``; tampering the
    persisted record's corresponding field from ``None`` to a concrete
    value must make ``validate_ownership_authority`` return ``False``."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)
        self.executor = _NoneOwnershipFieldsExecutor()
        self.harness.registry.register(method_kind=NONE_FIELDS_METHOD_KIND, method_id="none_fields_method", executor=self.executor)

    def _decision(self, capability_id: str):
        return _decision(capability_id, method_kind=NONE_FIELDS_METHOD_KIND, method_id="none_fields_method")

    def _validate_authority(self, capability_id: str) -> bool:
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        return engine.validate_ownership_authority(
            self.harness.state_root, capability_id, owned,
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context,
        )

    def test_committed_with_none_expected_fields_is_valid(self) -> None:
        capability_id = "cap_none_fields_baseline"
        outcome = engine.prepare(self._decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        self.assertTrue(self._validate_authority(capability_id))

    def test_tampering_uid_from_none_to_a_value_breaks_authority(self) -> None:
        capability_id = "cap_none_fields_uid_tamper"
        outcome = engine.prepare(self._decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        tampered = [dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, uid=0)) for r in records]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, tampered)
        self.assertFalse(self._validate_authority(capability_id))

    def test_tampering_gid_from_none_to_a_value_breaks_authority(self) -> None:
        capability_id = "cap_none_fields_gid_tamper"
        outcome = engine.prepare(self._decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        tampered = [dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, gid=0)) for r in records]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, tampered)
        self.assertFalse(self._validate_authority(capability_id))


class CoordinatedMetadataTamperTests(unittest.TestCase):
    """Point 2 (fourth correction round) mandatory security tests: even a
    COORDINATED tamper -- altering the real resource's metadata AND the
    persisted ownership record to match each other -- must still be
    refused, because authority compares against the executor's canonical,
    PLAN-derived expectation (a fixed value the attacker cannot influence),
    never against a live re-stat or the record's own claims in isolation."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _prepare_committed(self, capability_id: str) -> None:
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

    def test_coordinated_mode_tamper_is_still_refused(self) -> None:
        capability_id = "cap_coord_mode"
        self._prepare_committed(capability_id)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        os.chmod(marker_path, 0o644)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        tampered = [
            dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, mode=0o644))
            if r.candidate.resource_identity == str(marker_path) else r
            for r in records
        ]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, tampered)

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)
        self.assertEqual(result.error_kind, "ownership_invalid")
        self.assertTrue(marker_path.exists())
        self.assertEqual(oct(stat.S_IMODE(marker_path.stat().st_mode)), "0o644")

    def test_coordinated_hardlink_tamper_is_still_refused(self) -> None:
        capability_id = "cap_coord_hardlink"
        self._prepare_committed(capability_id)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        hardlink_path = marker_path.with_name(marker_path.name + ".extra_link")
        os.link(marker_path, hardlink_path)
        self.addCleanup(lambda: hardlink_path.unlink(missing_ok=True))
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        tampered = [
            dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, nlink=2))
            if r.candidate.resource_identity == str(marker_path) else r
            for r in records
        ]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, tampered)

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)
        self.assertNotEqual(result.status, PrepareStatus.UNINSTALLED)
        self.assertTrue(marker_path.exists())
        self.assertTrue(hardlink_path.exists())

    def test_coordinated_uid_gid_tamper_is_still_refused(self) -> None:
        # A real chown to a different uid/gid typically requires privileges
        # this test process does not have; the record is tampered to a
        # DIFFERENT uid/gid than the plan's own deterministic expectation
        # (os.getuid()/os.getgid() at plan-build time) to simulate the
        # coordinated-tamper scenario without needing root.
        capability_id = "cap_coord_uid_gid"
        self._prepare_committed(capability_id)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        tampered = [
            dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, uid=r.candidate.uid + 1, gid=r.candidate.gid + 1))
            if r.candidate.resource_identity == str(marker_path) else r
            for r in records
        ]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, tampered)

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)
        self.assertTrue(marker_path.exists())


class CommittedJournalStructuralIntegrityTests(unittest.TestCase):
    """Point 3 (fourth correction round): before granting authority, a
    COMMITTED source journal's own steps must be structurally IDENTICAL to
    the independently reconstructed plan -- same cardinality, unique
    sequences, same step_id/action_type/target/intent, in every step, and
    every step exactly VERIFIED. plan_digest alone does not protect
    journal.steps: none of a step's own persisted state (its state, its
    step_id/action_type/target/intent as actually written to disk)
    participates in plan_digest, which only covers the ORIGINAL plan at
    journal-creation time."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _prepare_committed(self, capability_id: str) -> str:
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        return outcome.transaction_id

    def _rewrite_source_journal(self, transaction_id: str, mutate) -> journal_mod.TransactionJournal:
        journal = journal_mod.read_journal(self.harness.state_root, transaction_id)
        journal = mutate(journal)
        journal_mod.write_journal(self.harness.state_root, journal)
        return journal

    def _validate_authority(self, capability_id: str) -> bool:
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        return engine.validate_ownership_authority(
            self.harness.state_root, capability_id, owned,
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context,
        )

    def test_mandatory_security_scenario_step_not_verified_and_ownership_shrunk_still_blocked(self) -> None:
        capability_id = "cap_structural_mandatory"
        transaction_id = self._prepare_committed(capability_id)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        companion_path = self.harness.sandbox / ("%s.companion" % capability_id)
        original_digest = journal_mod.read_journal(self.harness.state_root, transaction_id).plan_digest

        self._rewrite_source_journal(
            transaction_id, lambda j: j.with_step(dataclasses.replace(j.step(1), state=StepState.APPLIED))
        )
        self.assertEqual(journal_mod.read_journal(self.harness.state_root, transaction_id).plan_digest, original_digest)

        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        shrunk = [r for r in records if r.candidate.resource_identity == str(marker_path)]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, shrunk)

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)
        self.assertTrue(marker_path.exists())
        self.assertTrue(companion_path.exists())
        self.assertTrue(journal_mod.read_ownership_records(self.harness.state_root, capability_id))

    def test_missing_step_breaks_authority(self) -> None:
        capability_id = "cap_structural_missing_step"
        transaction_id = self._prepare_committed(capability_id)
        self._rewrite_source_journal(transaction_id, lambda j: dataclasses.replace(j, steps=(j.steps[0],)))
        self.assertFalse(self._validate_authority(capability_id))

    def test_duplicate_step_breaks_authority(self) -> None:
        capability_id = "cap_structural_duplicate_step"
        transaction_id = self._prepare_committed(capability_id)
        self._rewrite_source_journal(transaction_id, lambda j: dataclasses.replace(j, steps=j.steps + (j.steps[0],)))
        self.assertFalse(self._validate_authority(capability_id))

    def test_duplicate_sequence_breaks_authority(self) -> None:
        capability_id = "cap_structural_duplicate_sequence"
        transaction_id = self._prepare_committed(capability_id)
        self._rewrite_source_journal(
            transaction_id,
            lambda j: dataclasses.replace(j, steps=(j.steps[0], dataclasses.replace(j.steps[1], sequence=j.steps[0].sequence))),
        )
        self.assertFalse(self._validate_authority(capability_id))

    def test_step_not_verified_breaks_authority(self) -> None:
        capability_id = "cap_structural_not_verified"
        transaction_id = self._prepare_committed(capability_id)
        self._rewrite_source_journal(
            transaction_id, lambda j: j.with_step(dataclasses.replace(j.step(1), state=StepState.VERIFYING))
        )
        self.assertFalse(self._validate_authority(capability_id))

    def test_changed_step_id_breaks_authority(self) -> None:
        capability_id = "cap_structural_step_id"
        transaction_id = self._prepare_committed(capability_id)
        self._rewrite_source_journal(
            transaction_id, lambda j: j.with_step(dataclasses.replace(j.step(1), step_id="not_the_real_step_id"))
        )
        self.assertFalse(self._validate_authority(capability_id))

    def test_changed_action_type_breaks_authority(self) -> None:
        capability_id = "cap_structural_action_type"
        transaction_id = self._prepare_committed(capability_id)
        self._rewrite_source_journal(
            transaction_id, lambda j: j.with_step(dataclasses.replace(j.step(1), action_type="not_the_real_action"))
        )
        self.assertFalse(self._validate_authority(capability_id))

    def test_changed_target_breaks_authority(self) -> None:
        capability_id = "cap_structural_target"
        transaction_id = self._prepare_committed(capability_id)
        self._rewrite_source_journal(
            transaction_id, lambda j: j.with_step(dataclasses.replace(j.step(1), target=j.step(1).target + ".moved"))
        )
        self.assertFalse(self._validate_authority(capability_id))

    def test_changed_intent_breaks_authority(self) -> None:
        capability_id = "cap_structural_intent"
        transaction_id = self._prepare_committed(capability_id)
        self._rewrite_source_journal(
            transaction_id,
            lambda j: j.with_step(dataclasses.replace(j.step(1), intent={**j.step(1).intent, "content_sha256": "0" * 64})),
        )
        self.assertFalse(self._validate_authority(capability_id))


class OwnershipAuthorityDerivedFromPlanTests(unittest.TestCase):
    """Point 3 (third correction round): validate_ownership_authority must
    derive its expectations from the source transaction's own PLAN,
    reconstructed fresh from the trusted executor's code and reverified
    against plan_digest -- never from journal.provenance, a second JSON blob
    living inside the very same mutable journal file that an attacker (or
    corruption) could edit in lockstep with the ownership file itself."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _prepare_committed(self, capability_id: str) -> None:
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

    def test_mandatory_security_scenario_ownership_and_provenance_tampered_in_lockstep_still_refused(self) -> None:
        # The exact scenario the correction specifies: leave the source
        # transaction's steps/plan/plan_digest completely untouched, and
        # tamper ONLY the two blobs the old check cross-referenced against
        # each other (the standalone ownership file and journal.provenance)
        # -- edited consistently, to confirm "they still agree with each
        # other" is no longer treated as sufficient authority.
        capability_id = "cap_lockstep_tamper"
        self._prepare_committed(capability_id)
        foreign = self.tmp / "foreign_resource.txt"
        foreign_bytes = b"not part of this transaction's plan at all"
        foreign.write_bytes(foreign_bytes)

        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        source_transaction_id = records[0].created_by_transaction
        marker_index = next(i for i, r in enumerate(records) if r.candidate.resource_identity.endswith(".marker"))
        tampered = list(records)
        tampered[marker_index] = dataclasses.replace(
            records[marker_index],
            candidate=dataclasses.replace(records[marker_index].candidate, resource_identity=str(foreign)),
        )
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, tampered)

        source_journal = journal_mod.read_journal(self.harness.state_root, source_transaction_id)
        tampered_provenance = json.loads(json.dumps(source_journal.provenance))
        for item in tampered_provenance["ownership_records"]:
            if item["resource_identity"].endswith(".marker"):
                item["resource_identity"] = str(foreign)
        journal_mod.write_journal(self.harness.state_root, dataclasses.replace(source_journal, provenance=tampered_provenance))

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertIn(result.status, (PrepareStatus.OWNERSHIP_INVALID, PrepareStatus.OUT_OF_CONTRACT))
        self.assertTrue(foreign.exists())
        self.assertEqual(foreign.read_bytes(), foreign_bytes)

    def _assert_field_tamper_breaks_authority(self, capability_id: str, mutate_candidate) -> None:
        self._prepare_committed(capability_id)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        tampered = [dataclasses.replace(r, candidate=mutate_candidate(r.candidate)) for r in records]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, tampered)
        self.assertFalse(engine.validate_ownership_authority(
            self.harness.state_root, capability_id, tampered,
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context,
        ))
        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)
        self.assertTrue((self.harness.sandbox / ("%s.marker" % capability_id)).exists())

    def test_tampering_only_source_breaks_authority(self) -> None:
        self._assert_field_tamper_breaks_authority(
            "cap_tamper_source", lambda c: dataclasses.replace(c, source="https://example.invalid/pkg")
        )

    def test_tampering_only_version_breaks_authority(self) -> None:
        self._assert_field_tamper_breaks_authority("cap_tamper_version", lambda c: dataclasses.replace(c, version="9.9.9"))

    def test_tampering_only_post_install_fingerprint_breaks_authority(self) -> None:
        self._assert_field_tamper_breaks_authority(
            "cap_tamper_fingerprint", lambda c: dataclasses.replace(c, post_install_fingerprint="0" * 64)
        )

    def _assert_uid_gid_mode_tamper_alone_breaks_authority(self, capability_id: str, mutate_candidate) -> None:
        # Fourth correction round, point 2: authority now compares uid/gid/
        # mode against the executor's own canonical, plan-derived
        # expectation (never a live re-stat -- see
        # CanaryExecutor.expected_ownership_for_step), so a uid/gid/mode-only
        # tamper of the persisted record is caught by authority itself, not
        # deferred to _detect_ownership_drift.
        self._prepare_committed(capability_id)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        tampered = [dataclasses.replace(r, candidate=mutate_candidate(r.candidate)) for r in records]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, tampered)
        self.assertFalse(engine.validate_ownership_authority(
            self.harness.state_root, capability_id, tampered,
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context,
        ))
        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)
        self.assertTrue((self.harness.sandbox / ("%s.marker" % capability_id)).exists())

    def test_tampering_only_uid_breaks_authority(self) -> None:
        self._assert_uid_gid_mode_tamper_alone_breaks_authority(
            "cap_tamper_uid_only", lambda c: dataclasses.replace(c, uid=c.uid + 1)
        )

    def test_tampering_only_gid_breaks_authority(self) -> None:
        self._assert_uid_gid_mode_tamper_alone_breaks_authority(
            "cap_tamper_gid_only", lambda c: dataclasses.replace(c, gid=c.gid + 1)
        )

    def test_tampering_only_mode_breaks_authority(self) -> None:
        self._assert_uid_gid_mode_tamper_alone_breaks_authority(
            "cap_tamper_mode_only", lambda c: dataclasses.replace(c, mode=0o755)
        )


class ExactIdempotencyTests(unittest.TestCase):
    """Point 9: already_provisioned requires an exact match on every field,
    never a partial/any() match."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_partial_ownership_set_is_a_conflict_not_already_provisioned(self) -> None:
        decision = self.harness.decision(capability_id="cap_partial_idem")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        records = journal_mod.read_ownership_records(self.harness.state_root, "cap_partial_idem")
        self.assertEqual(len(records), 2)
        journal_mod.write_ownership_records(self.harness.state_root, "cap_partial_idem", records[:1])

        second = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(second.status, PrepareStatus.OWNERSHIP_CONFLICT)

    def test_mode_drift_on_owned_resource_is_a_conflict_not_already_provisioned(self) -> None:
        decision = self.harness.decision(capability_id="cap_mode_drift")
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        marker_path = self.harness.sandbox / "cap_mode_drift.marker"
        os.chmod(marker_path, 0o644)

        second = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(second.status, PrepareStatus.OWNERSHIP_CONFLICT)


class RecoveryLockTests(unittest.TestCase):
    """Point 5: recover_pending() acquires the lock itself; the internal
    _recover_pending_locked() never does (prepare()/uninstall() already hold it)."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_public_recover_pending_acquires_the_lock_itself(self) -> None:
        with lock_mod.acquire_provisioner_lock(
            self.harness.state_root, global_lock_root=self.harness.global_lock_root, transaction_id="holder", timeout=1.0
        ):
            with self.assertRaises(ProvisionerLockHeldError):
                engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root, lock_timeout=0.2)

    def test_internal_recover_pending_locked_does_not_acquire_the_lock(self) -> None:
        holder_script = self.tmp / "holder.py"
        holder_script.write_text(
            "import sys, time\n"
            "sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from compat.provisioning.lock import acquire_provisioner_lock\n"
            "with acquire_provisioner_lock(Path(%r), global_lock_root=Path(%r), transaction_id='holder', timeout=2.0):\n"
            "    print('ACQUIRED', flush=True)\n"
            "    time.sleep(1.5)\n" % (str(ROOT), str(self.harness.state_root), str(self.harness.global_lock_root))
        )
        proc = subprocess.Popen([sys.executable, str(holder_script)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.stdout.close)
        line = proc.stdout.readline()
        self.assertEqual(line.strip(), "ACQUIRED")
        try:
            reports = engine._recover_pending_locked(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
            self.assertEqual(reports, [])
        finally:
            proc.wait(60)


class StateRootIdentityRaceTests(unittest.TestCase):
    """Point 1, fifth correction round (hardens the fourth round's
    descriptor-binding): once the canonical, CONFIGURED state_root path no
    longer refers to the exact physical directory a transaction's
    ``StateRootHandle`` was bound to -- renamed away, deleted, or replaced
    by a new directory/symlink -- every subsequent mutating write must fail
    closed with ``StateRootIdentityError`` rather than silently continuing
    to write into the orphaned original directory: invariant 3 explicitly
    requires ``RECOVERY_REQUIRED``/manual failure, never a clean success,
    once the canonical entry has disappeared or diverged. A holder process
    must therefore raise ``StateRootIdentityError`` (never write a journal
    claiming success) and never create a new state root at the vacated
    path either."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        # Deliberately a SIBLING of everything under test, never a
        # descendant of the renamable parent -- exactly what point 1 of
        # the fifth correction round requires of a real global lock root.
        self.global_lock_root = self.tmp / "global-lock-root"

    def _write_holder_script(self, *, state_root: Path, ready: Path, go: Path, done: Path, transaction_id: str) -> Path:
        script = self.tmp / ("holder_%s.py" % transaction_id)
        script.write_text(
            "import sys\n"
            "sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from compat.provisioning import lock as lock_mod, journal as journal_mod\n"
            "from compat.provisioning.journal import TransactionJournal\n"
            "from compat.provisioning.model import TransactionState\n"
            "from compat.provisioning.errors import StateRootIdentityError\n"
            "from tests.test_compat_transactional_provisioning import _fifo_open_reader, _fifo_signal, _fifo_wait\n"
            "state_root = Path(%r)\n"
            "global_lock_root = Path(%r)\n"
            "ready = Path(%r)\n"
            "go = Path(%r)\n"
            "done = Path(%r)\n"
            "go_fd = _fifo_open_reader(go)\n"
            "with lock_mod.acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id=%r, timeout=10.0) as handle:\n"
            "    _fifo_signal(ready)\n"
            "    _fifo_wait(go_fd, timeout=10.0, description='go marker')\n"
            "    journal = TransactionJournal(\n"
            "        schema_version=journal_mod.SCHEMA_VERSION, transaction_id=%r, operation='prepare',\n"
            "        state=TransactionState.PLANNED, created_at='2026-01-01T00:00:00+00:00',\n"
            "        updated_at='2026-01-01T00:00:00+00:00', plan_digest='0' * 64, capability_id='cap_rename_race',\n"
            "        dependency_id='dep_rename_race', target='lab', architecture='x86_64',\n"
            "        support_classification='lab_fixture', selected_method={'id': 'canary_method', 'kind': 'canary_lab'},\n"
            "        executor={'id': 'canary_lab_executor', 'version': '1'}, steps=(),\n"
            "    )\n"
            "    try:\n"
            "        journal_mod.write_journal(handle, journal)\n"
            "    except StateRootIdentityError as exc:\n"
            "        done.write_text('identity_error:' + str(exc))\n"
            "    else:\n"
            "        done.write_text('done')\n"
            % (str(ROOT), str(state_root), str(self.global_lock_root), str(ready), str(go), str(done), transaction_id, transaction_id)
        )
        return script

    def _run_rename_race(self, *, replace_with) -> tuple[Path, Path, str, Path]:
        """Starts a holder process, waits for it to acquire the lock, then
        renames state_root aside (optionally calling ``replace_with`` to
        put something new at the vacated original path) before signaling
        the holder to perform its write. Returns
        (renamed_state_root, original_state_root, transaction_id, done)."""
        parent = self.tmp / "var_lib_watchdogvpn_style_parent"
        parent.mkdir(mode=0o2770)
        os.chmod(parent, 0o2770)
        state_root = parent / "state"
        ready = self.tmp / "ready.marker"
        go = self.tmp / "go.marker"
        done = self.tmp / "done.marker"
        transaction_id = "rename-race-txn"
        script = self._write_holder_script(state_root=state_root, ready=ready, go=go, done=done, transaction_id=transaction_id)

        _fifo_create(ready)
        _fifo_create(go)
        ready_fd = _fifo_open_reader(ready)

        proc = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(proc.wait)

        _fifo_wait(ready_fd, timeout=10.0, description="holder ready signal")

        renamed_state_root = self.tmp / "state_renamed_aside"
        state_root.rename(renamed_state_root)
        if replace_with is not None:
            replace_with(state_root)

        os.close(ready_fd)

        # Invariant 1 (point 1, fifth correction round): two processes
        # configured with the SAME logical installation (the same
        # state_root path) can never acquire distinct locks, no matter what
        # has happened to that path physically -- the global lock's own
        # identity was never inside the renamable tree to begin with. A is
        # still active (holding the lock, waiting on ``go``); a contender
        # using the exact same configured path must be refused right now.
        with self.assertRaises(ProvisionerLockHeldError):
            with lock_mod.acquire_provisioner_lock(
                state_root, global_lock_root=self.global_lock_root, transaction_id="contender-while-active", timeout=0.3
            ):
                pass

        _fifo_signal(go)
        stdout, stderr = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 0, "holder failed: stdout=%r stderr=%r" % (stdout, stderr))
        self.assertTrue(done.exists(), "holder never finished: stderr=%r" % stderr)
        self.assertEqual(oct(stat.S_IMODE(parent.stat().st_mode)), "0o2770")
        return renamed_state_root, state_root, transaction_id, done

    def test_state_root_renamed_aside_holder_still_writes_to_original_directory(self) -> None:
        renamed_state_root, original_path, transaction_id, done = self._run_rename_race(replace_with=None)
        # Fails closed (point 1, fifth correction round): the canonical
        # path is gone, so the write must never be reported as a success --
        # neither in the renamed-aside original directory nor anywhere else.
        self.assertTrue(done.read_text().startswith("identity_error:"), done.read_text())
        self.assertEqual(journal_mod.list_transaction_ids(renamed_state_root), [])
        self.assertFalse(original_path.exists())

    def test_state_root_replaced_by_new_directory_holder_still_writes_to_original(self) -> None:
        def _replace(path: Path) -> None:
            path.mkdir(mode=0o700)

        renamed_state_root, original_path, transaction_id, done = self._run_rename_race(replace_with=_replace)
        self.assertTrue(done.read_text().startswith("identity_error:"), done.read_text())
        self.assertEqual(journal_mod.list_transaction_ids(renamed_state_root), [])
        # The new directory at the vacated path is a genuinely different,
        # empty state root -- it must never receive the holder's journal
        # either (no silent "create a new state root instead").
        self.assertEqual(journal_mod.list_transaction_ids(original_path), [])

    def test_state_root_replaced_by_symlink_holder_still_writes_to_original_and_symlink_rejected(self) -> None:
        decoy = self.tmp / "decoy_target"
        decoy.mkdir()

        def _replace(path: Path) -> None:
            path.symlink_to(decoy)

        renamed_state_root, original_path, transaction_id, done = self._run_rename_race(replace_with=_replace)
        self.assertTrue(done.read_text().startswith("identity_error:"), done.read_text())
        self.assertEqual(journal_mod.list_transaction_ids(renamed_state_root), [])
        # A second process (this test process) must never be able to
        # acquire a lock through the symlink now sitting at the original
        # path -- it fails closed rather than silently following it.
        with self.assertRaises(PathPolicyError):
            with lock_mod.acquire_provisioner_lock(
                original_path, global_lock_root=self.global_lock_root, transaction_id="contender", timeout=0.2
            ):
                pass
        self.assertEqual(sorted(decoy.iterdir()), [])

    def test_transactions_subdir_renamed_mid_transaction_second_write_stays_on_original(self) -> None:
        """A step further than a top-level state-root rename: the
        TRANSACTIONS subdirectory itself is renamed away while the holder
        is still inside its lock-protected critical section, after it has
        already opened/cached that subdirectory's descriptor once (and
        already durably written one journal through it -- a genuine
        success that must survive). The periodic re-verification (point 1,
        fifth correction round) must DETECT this specific subdirectory's
        divergence on the very next mutation and fail closed with
        ``StateRootIdentityError``, rather than silently keep writing
        through the now-orphaned cached descriptor."""
        parent = self.tmp
        state_root = parent / "state_txn_rename"
        state_root.mkdir(mode=0o700)
        ready = self.tmp / "ready2.marker"
        rename_done = self.tmp / "rename_done2.marker"
        done = self.tmp / "done2.marker"
        transaction_id = "txn-subdir-rename-race"
        script = self.tmp / "holder_txn_subdir.py"
        script.write_text(
            "import sys\n"
            "sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from compat.provisioning import lock as lock_mod, journal as journal_mod\n"
            "from compat.provisioning.journal import TransactionJournal\n"
            "from compat.provisioning.model import TransactionState\n"
            "from compat.provisioning.errors import StateRootIdentityError\n"
            "from tests.test_compat_transactional_provisioning import _fifo_open_reader, _fifo_signal, _fifo_wait\n"
            "state_root = Path(%r)\n"
            "global_lock_root = Path(%r)\n"
            "ready = Path(%r); rename_done = Path(%r); done = Path(%r)\n"
            "rename_done_fd = _fifo_open_reader(rename_done)\n"
            "def _journal(txn_id):\n"
            "    return TransactionJournal(\n"
            "        schema_version=journal_mod.SCHEMA_VERSION, transaction_id=txn_id, operation='prepare',\n"
            "        state=TransactionState.PLANNED, created_at='2026-01-01T00:00:00+00:00',\n"
            "        updated_at='2026-01-01T00:00:00+00:00', plan_digest='0' * 64, capability_id='cap_x',\n"
            "        dependency_id='dep_x', target='lab', architecture='x86_64', support_classification='lab_fixture',\n"
            "        selected_method={'id': 'canary_method', 'kind': 'canary_lab'},\n"
            "        executor={'id': 'canary_lab_executor', 'version': '1'}, steps=(),\n"
            "    )\n"
            "with lock_mod.acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id='holder', timeout=10.0) as handle:\n"
            "    journal_mod.write_journal(handle, _journal(%r))\n"  # opens/caches the transactions subdir fd
            "    _fifo_signal(ready)\n"
            "    _fifo_wait(rename_done_fd, timeout=10.0, description='rename_done marker')\n"
            "    try:\n"
            "        journal_mod.write_journal(handle, _journal(%r))\n"
            "    except StateRootIdentityError as exc:\n"
            "        done.write_text('identity_error:' + str(exc))\n"
            "    else:\n"
            "        done.write_text('done')\n"
            % (str(ROOT), str(state_root), str(self.global_lock_root), str(ready), str(rename_done), str(done), transaction_id, transaction_id + "-second")
        )

        _fifo_create(ready)
        _fifo_create(rename_done)
        ready_fd = _fifo_open_reader(ready)

        proc = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(proc.wait)
        _fifo_wait(ready_fd, timeout=10.0, description="holder ready signal")
        os.close(ready_fd)

        renamed_transactions = state_root / "transactions_renamed_aside"
        (state_root / journal_mod.TRANSACTIONS_DIR).rename(renamed_transactions)

        _fifo_signal(rename_done)
        stdout, stderr = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 0, "holder failed: stdout=%r stderr=%r" % (stdout, stderr))
        self.assertTrue(done.exists())
        self.assertTrue(done.read_text().startswith("identity_error:"), done.read_text())

        second_id = transaction_id + "-second"
        # The FIRST write (before the subdirectory swap) is a genuine,
        # already-durable success and must survive untouched.
        self.assertTrue((renamed_transactions / ("%s.json" % transaction_id)).exists())
        # The SECOND write must never have landed anywhere -- neither in
        # the orphaned original (renamed-aside) directory nor in a
        # silently-recreated one at the original name.
        self.assertFalse((renamed_transactions / ("%s.json" % second_id)).exists())
        recreated_transactions = state_root / journal_mod.TRANSACTIONS_DIR
        if recreated_transactions.exists():
            self.assertEqual(sorted(p.name for p in recreated_transactions.iterdir()), [])

    def test_transactions_subdir_swapped_before_first_recovery_access_is_not_misread_as_zero_pending(self) -> None:
        """Point 1, fifth correction round, mandatory scenario: transactions
        already contains a pending (corrupt/unreadable) journal; A acquires
        the lock (which -- per invariant 4 -- EAGERLY opens transactions/
        ownership/history before any recovery use); transactions is then
        renamed away and replaced by a brand new, empty one BEFORE A's
        first ``list_transaction_ids()`` call. A must still see the REAL
        pending entry through its already-cached descriptor -- never
        silently conclude "zero pending" from the new, empty replacement --
        and any caller built on top of this (like ``prepare()``, which
        checks for ``RecoveryAction.REQUIRE_MANUAL`` before ever starting a
        new mutation) would correctly refuse to proceed."""
        state_root = self.tmp / "state_subdir_swap_before_access"
        state_root.mkdir(mode=0o700)
        transactions_dir = state_root / journal_mod.TRANSACTIONS_DIR
        transactions_dir.mkdir(mode=0o700)
        # A genuinely corrupt journal file -- unconditionally REQUIRE_MANUAL
        # once actually read, regardless of the swap.
        (transactions_dir / "corrupt-pending.json").write_bytes(b"{not valid json")
        os.chmod(transactions_dir / "corrupt-pending.json", 0o600)

        ready = self.tmp / "ready3.marker"
        go = self.tmp / "go3.marker"
        result_file = self.tmp / "result3.json"
        script = self.tmp / "holder_subdir_swap.py"
        script.write_text(
            "import sys, json\n"
            "sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from compat.provisioning import lock as lock_mod, engine, journal as journal_mod\n"
            "from compat.provisioning.executors import CANARY_EXECUTOR_VERSION, CANARY_METHOD_KIND, CanaryExecutor, ExecutionContext, TrustedExecutorRegistry\n"
            "from compat.provisioning.model import RecoveryAction\n"
            "from tests.test_compat_transactional_provisioning import _fifo_open_reader, _fifo_signal, _fifo_wait\n"
            "state_root = Path(%r)\n"
            "global_lock_root = Path(%r)\n"
            "ready = Path(%r); go = Path(%r); result_file = Path(%r)\n"
            "go_fd = _fifo_open_reader(go)\n"
            "registry = TrustedExecutorRegistry()\n"
            "registry.register(method_kind=CANARY_METHOD_KIND, method_id='canary_method', executor=CanaryExecutor())\n"
            "context = ExecutionContext(allowed_roots=(Path(%r),), now=lambda: '2026-01-01T00:00:00+00:00')\n"
            "with lock_mod.acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id='holder', timeout=10.0) as handle:\n"
            "    _fifo_signal(ready)\n"  # eager-open of transactions/ownership/history already done by now
            "    _fifo_wait(go_fd, timeout=10.0, description='go marker')\n"
            "    decisions = engine._recover_pending_locked(handle, registry, CANARY_EXECUTOR_VERSION, context)\n"
            "    result_file.write_text(json.dumps([\n"
            "        {'transaction_id': d.transaction_id, 'action': d.action.value} for d in decisions\n"
            "    ]))\n"
            % (
                str(ROOT), str(state_root), str(self.global_lock_root), str(ready), str(go), str(result_file),
                str(self.tmp / "sandbox_subdir_swap"),
            )
        )
        (self.tmp / "sandbox_subdir_swap").mkdir()

        _fifo_create(ready)
        _fifo_create(go)
        ready_fd = _fifo_open_reader(ready)

        proc = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(proc.wait)
        _fifo_wait(ready_fd, timeout=10.0, description="holder ready signal")
        os.close(ready_fd)

        # The swap happens strictly AFTER eager-open (which already ran
        # inside acquire_provisioner_lock, before "ready" was ever
        # written), and strictly BEFORE the holder's own
        # list_transaction_ids() call (gated behind the "go" marker).
        renamed_transactions = state_root / "transactions_swapped_aside"
        transactions_dir.rename(renamed_transactions)
        (state_root / journal_mod.TRANSACTIONS_DIR).mkdir(mode=0o700)  # brand new, empty replacement

        _fifo_signal(go)
        stdout, stderr = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 0, "holder failed: stdout=%r stderr=%r" % (stdout, stderr))
        self.assertTrue(result_file.exists())
        decisions = json.loads(result_file.read_text())
        # Never "zero pending": the real (corrupt) entry, seen through the
        # descriptor cached before the swap, must still be reported.
        self.assertEqual(len(decisions), 1, decisions)
        self.assertEqual(decisions[0]["action"], RecoveryAction.REQUIRE_MANUAL.value)
        # The new, empty replacement directory must never have received
        # anything -- no silently-created state.
        self.assertEqual(sorted(p.name for p in (state_root / journal_mod.TRANSACTIONS_DIR).iterdir()), [])
        self.assertTrue((renamed_transactions / "corrupt-pending.json").exists())


class UninstallRecoveryStateMachineTests(unittest.TestCase):
    """Points 6, 7: uninstall plan digest reverified before the first unlink
    and during recovery; each boundary handled explicitly, never re-executing
    an unlink once APPLIED/VERIFYING has been durably recorded."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _prepare_committed(self, capability_id: str) -> None:
        decision = self.harness.decision(capability_id)
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

    def _build_uninstall_journal(self, capability_id: str) -> journal_mod.TransactionJournal:
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id="uninstall-%s" % capability_id)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        return journal.with_state(TransactionState.UNINSTALLING, now=_now())

    def _marker_step_index(self, journal) -> int:
        return next(i for i, s in enumerate(journal.steps) if s.intent["resource_identity"].endswith(".marker"))

    def test_uninstall_plan_digest_mismatch_blocks_recovery(self) -> None:
        capability_id = "cap_uninstall_digest"
        self._prepare_committed(capability_id)
        journal = self._build_uninstall_journal(capability_id)
        journal = dataclasses.replace(journal, plan_digest="0" * 64)
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.state, TransactionState.UNINSTALL_FAILED)
        self.assertTrue((self.harness.sandbox / ("%s.marker" % capability_id)).exists())
        self.assertTrue((self.harness.sandbox / ("%s.companion" % capability_id)).exists())

    def test_applied_step_never_re_executes_unlink(self) -> None:
        capability_id = "cap_uninstall_applied"
        self._prepare_committed(capability_id)
        journal = self._build_uninstall_journal(capability_id)
        marker_index = self._marker_step_index(journal)
        marker_path = Path(journal.steps[marker_index].intent["resource_identity"])
        marker_path.unlink()
        impostor_content = b"someone else re-created this after the unlink"
        marker_path.write_bytes(impostor_content)
        record = journal.step(marker_index).with_state(StepState.APPLYING, started_at=_now())
        journal = journal.with_step(record)
        record = record.with_state(StepState.APPLIED, completed_at=_now())
        journal = journal.with_step(record)
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        self.assertEqual(marker_path.read_bytes(), impostor_content)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.step(marker_index).state, StepState.VERIFY_FAILED)

    def test_verifying_boundary_never_reattempts_unlink_and_completes(self) -> None:
        capability_id = "cap_uninstall_verifying"
        self._prepare_committed(capability_id)
        journal = self._build_uninstall_journal(capability_id)
        marker_index = self._marker_step_index(journal)
        marker_path = Path(journal.steps[marker_index].intent["resource_identity"])
        marker_path.unlink()
        record = journal.step(marker_index).with_state(StepState.APPLYING, started_at=_now())
        journal = journal.with_step(record)
        record = record.with_state(StepState.APPLIED, completed_at=_now())
        journal = journal.with_step(record)
        record = record.with_state(StepState.VERIFYING)
        journal = journal.with_step(record)
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.RESUME)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.state, TransactionState.UNINSTALLED)
        self.assertEqual(journal_mod.read_ownership_records(self.harness.state_root, capability_id), [])

    def test_symlink_at_target_during_uninstall_resume_is_rejected(self) -> None:
        capability_id = "cap_uninstall_symlink"
        self._prepare_committed(capability_id)
        journal = self._build_uninstall_journal(capability_id)
        marker_index = self._marker_step_index(journal)
        marker_path = Path(journal.steps[marker_index].intent["resource_identity"])
        marker_path.unlink()
        outside = self.tmp / "outside_target"
        outside.write_bytes(b"x")
        marker_path.symlink_to(outside)
        self.addCleanup(lambda: marker_path.unlink(missing_ok=True))
        record = journal.step(marker_index).with_state(StepState.APPLYING, started_at=_now())
        journal = journal.with_step(record)
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        self.assertTrue(marker_path.is_symlink())
        self.assertTrue(outside.exists())
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.step(marker_index).error_kind, "path_policy_violation")


class DryRunReadOnlyTests(unittest.TestCase):
    """Point 13: plan / prepare without --apply / uninstall without --apply /
    status must never create the sandbox or the provisioning state root."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.lab_root = self.tmp / "lab_root"
        self.lab_root.mkdir(mode=0o700)
        os.chmod(self.lab_root, 0o700)
        self.sandbox = self.lab_root / "sandbox"
        self.state_root = self.lab_root / "state"
        self.global_lock_root = self.tmp / "global-lock-root"

    def _parse(self, *argv: str):
        import tools.compat_provision as compat_provision_tool

        return compat_provision_tool, compat_provision_tool.build_parser().parse_args(
            [
                "--lab-root", str(self.lab_root), "--sandbox", str(self.sandbox), "--state-root", str(self.state_root),
                "--global-lock-root", str(self.global_lock_root), *argv,
            ]
        )

    def _assert_nothing_created(self) -> None:
        self.assertFalse(self.sandbox.exists())
        self.assertFalse(self.state_root.exists())

    def test_plan_does_not_create_sandbox_or_state_root(self) -> None:
        tool, args = self._parse("plan", "cap_x", "dep_x")
        tool.cmd_plan(args)
        self._assert_nothing_created()

    def test_prepare_without_apply_does_not_create_sandbox_or_state_root(self) -> None:
        tool, args = self._parse("prepare", "cap_x", "dep_x")
        tool.cmd_prepare(args)
        self._assert_nothing_created()

    def test_status_does_not_create_sandbox_or_state_root(self) -> None:
        tool, args = self._parse("status")
        tool.cmd_status(args)
        self._assert_nothing_created()

    def test_uninstall_without_apply_does_not_create_sandbox_or_state_root(self) -> None:
        tool, args = self._parse("uninstall", "cap_x")
        tool.cmd_uninstall(args)
        self._assert_nothing_created()

    def test_prepare_with_apply_does_create_sandbox_and_state_root(self) -> None:
        tool, args = self._parse("prepare", "--apply", "cap_x", "dep_x")
        tool.cmd_prepare(args)
        self.assertTrue(self.sandbox.exists())
        self.assertTrue(self.state_root.exists())


class OwnershipRevocationTests(unittest.TestCase):
    """Point 1: uninstall cannot reach UNINSTALLED while ownership is still
    live; the journal persists an immutable ownership snapshot that
    participates in the digest; recovery never depends on the live
    ownership file; stale ownership left by a crashed revocation is never
    trusted again."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _prepare_committed(self, capability_id: str) -> None:
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

    def _uninstall_journal_at_revoking_ownership(self, capability_id: str) -> journal_mod.TransactionJournal:
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id="uninstall-%s" % capability_id)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)
        journal, ok, residuals = engine._run_uninstall_loop(
            self.harness.state_root, journal, self.harness.locked_context(),
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION,
        )
        self.assertTrue(ok, residuals)
        journal = journal.with_state(TransactionState.REVOKING_OWNERSHIP, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)
        return journal

    def test_journal_persists_immutable_ownership_snapshot(self) -> None:
        capability_id = "cap_snapshot"
        self._prepare_committed(capability_id)
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id="uninstall-%s" % capability_id)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        self.assertEqual(len(journal.owned_snapshot), 2)
        journal_mod.write_journal(self.harness.state_root, journal)
        reloaded = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(len(reloaded.owned_snapshot), 2)
        self.assertEqual({r.candidate.resource_identity for r in reloaded.owned_snapshot}, {r.candidate.resource_identity for r in owned})

    def test_ownership_snapshot_tampering_is_caught_by_the_uninstall_digest(self) -> None:
        capability_id = "cap_snapshot_tamper"
        self._prepare_committed(capability_id)
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id="uninstall-%s" % capability_id)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        tampered_snapshot = tuple(
            dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, integrity="0" * 64)) for r in journal.owned_snapshot
        )
        journal = dataclasses.replace(journal, owned_snapshot=tampered_snapshot)
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        self.assertTrue((self.harness.sandbox / ("%s.marker" % capability_id)).exists())

    def test_crash_after_all_verified_before_revoking_ownership_recovers_cleanly(self) -> None:
        capability_id = "cap_revoke_pre"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        self.assertEqual(list(journal_mod.read_ownership_records(self.harness.state_root, capability_id)), journal_mod.read_ownership_records(self.harness.state_root, capability_id))
        self.assertTrue(journal_mod.read_ownership_records(self.harness.state_root, capability_id))  # still live: crash simulated here

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.RESUME)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.state, TransactionState.UNINSTALLED)
        self.assertEqual(journal_mod.read_ownership_records(self.harness.state_root, capability_id), [])
        self.assertEqual(list(self.harness.sandbox.iterdir()), [])

    def test_crash_after_revoking_ownership_before_uninstalled_recovers_using_journal_snapshot(self) -> None:
        capability_id = "cap_revoke_post"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        # Simulate the revocation itself already having completed for real,
        # but the crash landing before the UNINSTALLED journal write.
        journal_mod.delete_ownership_records(self.harness.state_root, capability_id)
        self.assertFalse(journal_mod.ownership_path(self.harness.state_root, capability_id).exists())

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.RESUME)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.state, TransactionState.UNINSTALLED)

    def test_mandatory_security_scenario_stale_ownership_never_authorizes_a_manually_recreated_file(self) -> None:
        """The exact scenario from the correction: install, complete
        uninstall up to (but not through) ownership revocation, manually
        recreate the removed file with the identical hash, then try to
        uninstall again -- the manual file must survive untouched and the
        result must be a refusal, never a deletion."""
        capability_id = "cap_security_mandatory"
        self._prepare_committed(capability_id)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        marker_bytes = marker_path.read_bytes()
        self._uninstall_journal_at_revoking_ownership(capability_id)
        self.assertFalse(marker_path.exists())  # resources genuinely removed
        self.assertTrue(journal_mod.read_ownership_records(self.harness.state_root, capability_id))  # ownership not yet revoked

        marker_path.write_bytes(marker_bytes)  # manually recreated, identical hash

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertIn(result.status, (PrepareStatus.OWNERSHIP_INVALID, PrepareStatus.OUT_OF_CONTRACT))
        self.assertTrue(marker_path.exists())
        self.assertEqual(marker_path.read_bytes(), marker_bytes)

    def test_uninstalled_journal_with_still_live_ownership_is_never_trusted_as_authority(self) -> None:
        capability_id = "cap_stale_uninstalled"
        self._prepare_committed(capability_id)
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        self.assertTrue(engine.validate_ownership_authority(
            self.harness.state_root, capability_id, owned,
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context,
        ))

        # Fabricate a completed uninstall journal for this exact source
        # transaction WITHOUT actually revoking the live ownership file --
        # this is the "UNINSTALLED with stale ownership still active" case.
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id="uninstall-%s" % capability_id)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        journal = journal.with_state(TransactionState.REVOKING_OWNERSHIP, now=_now())
        journal = journal.with_state(TransactionState.UNINSTALLED, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)

        self.assertFalse(engine.validate_ownership_authority(
            self.harness.state_root, capability_id, owned,
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context,
        ))
        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)


class RevocationBoundarySafetyTests(unittest.TestCase):
    """Point 5 (third correction round): reaching REVOKING_OWNERSHIP --
    whether just transitioned into or resumed directly at it -- never by
    itself authorizes a revoke. _revocation_boundary_is_safe independently
    reconfirms the snapshot's own digest, the source transaction's
    authority, every step's real VERIFIED state, and a live recheck that
    none of the snapshotted resources are still present; any impossible
    combination means RECOVERY_REQUIRED, never a silent revoke, never
    UNINSTALLED, and ownership stays live."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _prepare_committed(self, capability_id: str) -> None:
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

    def _uninstall_journal_at_revoking_ownership(self, capability_id: str) -> journal_mod.TransactionJournal:
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id="uninstall-%s" % capability_id)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)
        journal, ok, residuals = engine._run_uninstall_loop(
            self.harness.state_root, journal, self.harness.locked_context(),
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION,
        )
        self.assertTrue(ok, residuals)
        journal = journal.with_state(TransactionState.REVOKING_OWNERSHIP, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)
        return journal

    def _assert_ownership_still_live(self, capability_id: str) -> None:
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        self.assertTrue(any(r.product_owned for r in records))

    def _assert_boundary_blocks_revoke(self, capability_id: str, journal: journal_mod.TransactionJournal) -> None:
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertNotEqual(final.state, TransactionState.UNINSTALLED)
        self._assert_ownership_still_live(capability_id)

    def test_step_forced_planned_at_revoking_ownership_blocks_revoke(self) -> None:
        capability_id = "cap_revoke_boundary_planned"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        forced = dataclasses.replace(journal.step(0), state=StepState.PLANNED, completed_at=None, error_kind=None, error=None)
        journal = journal.with_step(forced)
        journal_mod.write_journal(self.harness.state_root, journal)
        self._assert_boundary_blocks_revoke(capability_id, journal)

    def test_step_forced_applying_at_revoking_ownership_blocks_revoke(self) -> None:
        capability_id = "cap_revoke_boundary_applying"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        forced = dataclasses.replace(journal.step(0), state=StepState.APPLYING, completed_at=None, error_kind=None, error=None)
        journal = journal.with_step(forced)
        journal_mod.write_journal(self.harness.state_root, journal)
        self._assert_boundary_blocks_revoke(capability_id, journal)

    def test_step_forced_applied_at_revoking_ownership_blocks_revoke(self) -> None:
        capability_id = "cap_revoke_boundary_applied"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        forced = dataclasses.replace(journal.step(0), state=StepState.APPLIED)
        journal = journal.with_step(forced)
        journal_mod.write_journal(self.harness.state_root, journal)
        self._assert_boundary_blocks_revoke(capability_id, journal)

    def test_step_forced_verifying_at_revoking_ownership_blocks_revoke(self) -> None:
        capability_id = "cap_revoke_boundary_verifying"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        forced = dataclasses.replace(journal.step(0), state=StepState.VERIFYING)
        journal = journal.with_step(forced)
        journal_mod.write_journal(self.harness.state_root, journal)
        self._assert_boundary_blocks_revoke(capability_id, journal)

    def test_tampered_snapshot_at_revoking_ownership_blocks_revoke(self) -> None:
        capability_id = "cap_revoke_boundary_snapshot"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        tampered_record = dataclasses.replace(
            journal.owned_snapshot[0],
            candidate=dataclasses.replace(journal.owned_snapshot[0].candidate, integrity="0" * 64),
        )
        journal = dataclasses.replace(journal, owned_snapshot=(tampered_record,) + journal.owned_snapshot[1:])
        journal_mod.write_journal(self.harness.state_root, journal)
        self._assert_boundary_blocks_revoke(capability_id, journal)

    def test_digest_mismatch_at_revoking_ownership_blocks_revoke(self) -> None:
        capability_id = "cap_revoke_boundary_digest"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        journal = dataclasses.replace(journal, plan_digest="0" * 64)
        journal_mod.write_journal(self.harness.state_root, journal)
        self._assert_boundary_blocks_revoke(capability_id, journal)

    def test_resource_still_present_at_revoking_ownership_blocks_revoke(self) -> None:
        capability_id = "cap_revoke_boundary_present"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        marker_path = Path(journal.owned_snapshot[0].candidate.resource_identity)
        marker_path.write_bytes(b"resurrected after removal")
        self.addCleanup(lambda: marker_path.unlink(missing_ok=True))
        self._assert_boundary_blocks_revoke(capability_id, journal)
        self.assertTrue(marker_path.exists())

    def test_ancestor_swap_disguising_a_present_resource_as_absent_blocks_revoke(self) -> None:
        # Point 5 (fourth correction round) mandatory test: the resource is
        # still genuinely present, but an attacker renames its own parent
        # directory (== the allowed sandbox root, for this single-level
        # executor) aside and drops a symlink to an unrelated EMPTY
        # directory at the original location. A naive os.lstat() on the
        # bare persisted path would see FileNotFoundError (nothing named
        # "<cap>.marker" inside the empty decoy) and wrongly conclude
        # "absent" -- even though the real resource is fully intact in the
        # renamed-away original directory. confirm_absent_descriptor_safe
        # must instead re-validate the path (which now fails: the allowed
        # root itself is a symlink) and refuse to treat this as absence.
        capability_id = "cap_revoke_ancestor_swap"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        marker_path = Path(journal.owned_snapshot[0].candidate.resource_identity)
        sandbox = self.harness.sandbox

        marker_path.write_bytes(b"still here, hidden behind an ancestor swap")

        renamed_sandbox = self.tmp / "sandbox_renamed_aside"
        sandbox.rename(renamed_sandbox)
        empty_decoy = self.tmp / "empty_decoy"
        empty_decoy.mkdir()
        sandbox.symlink_to(empty_decoy)

        def _restore() -> None:
            if sandbox.is_symlink():
                sandbox.unlink()
            if renamed_sandbox.exists() and not sandbox.exists():
                renamed_sandbox.rename(sandbox)

        self.addCleanup(_restore)

        self._assert_boundary_blocks_revoke(capability_id, journal)
        self.assertTrue((renamed_sandbox / marker_path.name).exists())


class UninstallTransactionIdMatchesJournalTests(unittest.TestCase):
    """Point 7 (fourth correction round): PrepareOutcome.transaction_id
    returned by uninstall() must be exactly the uninstall journal's own id,
    never a separate id minted only for the provisioner-lock metadata."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_uninstall_result_transaction_id_matches_the_real_journal(self) -> None:
        capability_id = "cap_txn_id_match"
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.UNINSTALLED)
        self.assertIsNotNone(result.transaction_id)
        journal = journal_mod.read_journal(self.harness.state_root, result.transaction_id)
        self.assertEqual(journal.transaction_id, result.transaction_id)
        self.assertEqual(journal.operation, "uninstall")
        self.assertEqual(journal.capability_id, capability_id)


class RevocationErrorHandlingTests(unittest.TestCase):
    """Point 7 (third correction round): _revoke_ownership_and_verify must
    catch DurabilityError (and any other controlled storage error) from the
    ownership file's own delete, never let it escape as an unhandled
    exception, and never let the transaction reach UNINSTALLED while
    revocation durability is unconfirmed -- the journal stays recoverable."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_revoke_ownership_reports_durability_error_as_structured_failure(self) -> None:
        capability_id = "cap_revoke_durability"
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

        with mock.patch("compat.provisioning.journal.fsync_parent_directory", side_effect=DurabilityError("boom")):
            # Never raises: the DurabilityError from the delete's own
            # directory-fsync is caught and reported as a structured
            # (False, reason) tuple, not an unhandled exception.
            revoked, reason = engine._revoke_ownership_and_verify(self.harness.state_root, capability_id)
        self.assertFalse(revoked)
        self.assertIsNotNone(reason)

    def test_uninstall_never_reaches_uninstalled_when_revocation_durability_fails(self) -> None:
        capability_id = "cap_revoke_durability_full"
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

        # uninstall() holds the provisioner lock for its whole critical
        # section (point 1, fourth correction round), so its own
        # delete_ownership_records call goes through the descriptor-relative
        # path (StateRootHandle), not the legacy Path-based one -- the fault
        # is injected at that same relative primitive.
        with mock.patch("compat.provisioning.journal.delete_private_relative", side_effect=DurabilityError("boom")):
            result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.UNINSTALL_FAILED)
        self.assertEqual(result.error_kind, "ownership_revocation_failed")
        self.assertIsNotNone(result.transaction_id)

        final = journal_mod.read_journal(self.harness.state_root, result.transaction_id)
        self.assertEqual(final.state, TransactionState.UNINSTALL_FAILED)

        # Recovery must still be able to pick this up cleanly once the
        # durability problem is gone (idempotent revoke: the file may
        # already be unlinked for real).
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        recovered = journal_mod.read_journal(self.harness.state_root, result.transaction_id)
        self.assertEqual(recovered.state, TransactionState.RECOVERY_REQUIRED)


class PrivateStateAndLockSecurityTests(unittest.TestCase):
    """Point 2: state root/lock security -- symlinks, wrong type, wrong uid,
    and hard links must all be rejected before any chmod/write; a fsync
    follows every newly created directory."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)

    def test_state_root_itself_a_symlink_is_rejected(self) -> None:
        real = self.tmp / "real_state"
        real.mkdir()
        state_root = self.tmp / "state_link"
        state_root.symlink_to(real)
        with self.assertRaises(PathPolicyError):
            storage_mod.ensure_private_state_root(state_root)

    def test_transactions_subdirectory_a_symlink_is_rejected(self) -> None:
        state_root = self.tmp / "state"
        state_root.mkdir(mode=0o700)
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        (state_root / "transactions").symlink_to(elsewhere)
        with self.assertRaises(PathPolicyError):
            storage_mod.ensure_private_subdir(state_root, journal_mod.TRANSACTIONS_DIR)

    def test_ownership_subdirectory_a_symlink_is_rejected(self) -> None:
        state_root = self.tmp / "state"
        state_root.mkdir(mode=0o700)
        elsewhere = self.tmp / "elsewhere2"
        elsewhere.mkdir()
        (state_root / "ownership").symlink_to(elsewhere)
        with self.assertRaises(PathPolicyError):
            storage_mod.ensure_private_subdir(state_root, journal_mod.OWNERSHIP_DIR)

    def test_lock_path_is_a_symlink_to_a_victim_file_which_survives_untouched(self) -> None:
        # The lock itself lives under the GLOBAL lock root, not inside
        # state_root (point 1, fifth correction round) -- the attack is
        # placed at that stable root, keyed by state_root's own path hash.
        state_root = self.tmp / "state_lock_symlink"
        global_lock_root = self.tmp / "global-lock-root"
        storage_mod.ensure_private_lock_root(global_lock_root)
        victim = self.tmp / "victim.txt"
        victim.write_bytes(b"do not touch me")
        os.chmod(victim, 0o644)  # explicit, umask-independent starting mode
        lock_name = lock_mod._global_lock_file_name(state_root)
        (global_lock_root / lock_name).symlink_to(victim)
        with self.assertRaises(PathPolicyError):
            with lock_mod.acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id="t", timeout=0.2):
                pass
        self.assertEqual(victim.read_bytes(), b"do not touch me")
        self.assertEqual(oct(stat.S_IMODE(victim.stat().st_mode)), "0o644")  # never fchmod'd

    def test_lock_path_is_a_directory_is_rejected(self) -> None:
        state_root = self.tmp / "state_lock_dir"
        global_lock_root = self.tmp / "global-lock-root2"
        storage_mod.ensure_private_lock_root(global_lock_root)
        lock_name = lock_mod._global_lock_file_name(state_root)
        (global_lock_root / lock_name).mkdir()
        with self.assertRaises(PathPolicyError):
            with lock_mod.acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id="t", timeout=0.2):
                pass

    def test_lock_path_is_a_hardlink_is_rejected_and_victim_survives(self) -> None:
        state_root = self.tmp / "state_lock_hardlink"
        global_lock_root = self.tmp / "global-lock-root3"
        storage_mod.ensure_private_lock_root(global_lock_root)
        victim = self.tmp / "victim2.txt"
        victim.write_bytes(b"hardlink victim")
        lock_name = lock_mod._global_lock_file_name(state_root)
        os.link(victim, global_lock_root / lock_name)
        with self.assertRaises(PathPolicyError):
            with lock_mod.acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id="t", timeout=0.2):
                pass
        self.assertEqual(victim.read_bytes(), b"hardlink victim")

    def test_state_root_existing_at_loose_permissions_is_tightened(self) -> None:
        for mode in (0o750, 0o770, 0o777):
            with self.subTest(mode=oct(mode)):
                target = self.tmp / ("loose_%o" % mode)
                target.mkdir(mode=mode)
                os.chmod(target, mode)
                storage_mod.ensure_private_state_root(target)
                self.assertEqual(oct(stat.S_IMODE(target.stat().st_mode)), "0o700")

    def test_fsync_parent_directory_called_after_creating_a_new_directory(self) -> None:
        state_root = self.tmp / "brand_new_state"
        with mock.patch("compat.provisioning.storage.fsync_parent_directory", side_effect=storage_mod.fsync_parent_directory) as spy:
            storage_mod.ensure_private_state_root(state_root)
        self.assertTrue(spy.called)
        self.assertTrue(state_root.is_dir())

    def test_external_parent_at_02770_survives_state_root_creation_untouched(self) -> None:
        # Models the real product's /var/lib/watchdogvpn: a group-shared,
        # setgid parent that must never be chmod'd just because the
        # provisioner's own state_root subdirectory does not exist yet.
        parent = self.tmp / "var_lib_watchdogvpn"
        parent.mkdir(mode=0o2770)
        os.chmod(parent, 0o2770)
        state_root = parent / "provisioning"
        storage_mod.ensure_private_state_root(state_root)
        self.assertEqual(oct(stat.S_IMODE(parent.stat().st_mode)), "0o2770")
        self.assertEqual(oct(stat.S_IMODE(state_root.stat().st_mode)), "0o700")

    def test_external_parent_at_0755_survives_state_root_creation_untouched(self) -> None:
        parent = self.tmp / "opt_style_parent"
        parent.mkdir(mode=0o755)
        os.chmod(parent, 0o755)
        state_root = parent / "provisioning"
        storage_mod.ensure_private_state_root(state_root)
        self.assertEqual(oct(stat.S_IMODE(parent.stat().st_mode)), "0o755")

    def test_external_parent_at_01777_survives_state_root_creation_untouched(self) -> None:
        parent = self.tmp / "tmp_style_parent"
        parent.mkdir(mode=0o1777)
        os.chmod(parent, 0o1777)
        state_root = parent / "provisioning"
        storage_mod.ensure_private_state_root(state_root)
        self.assertEqual(oct(stat.S_IMODE(parent.stat().st_mode)), "0o1777")

    def test_ensure_private_subdir_never_touches_state_root_external_parent(self) -> None:
        parent = self.tmp / "another_var_lib_watchdogvpn"
        parent.mkdir(mode=0o2770)
        os.chmod(parent, 0o2770)
        state_root = parent / "provisioning"
        storage_mod.ensure_private_subdir(state_root, journal_mod.TRANSACTIONS_DIR)
        self.assertEqual(oct(stat.S_IMODE(parent.stat().st_mode)), "0o2770")
        self.assertEqual(oct(stat.S_IMODE(state_root.stat().st_mode)), "0o700")
        self.assertEqual(oct(stat.S_IMODE((state_root / journal_mod.TRANSACTIONS_DIR).stat().st_mode)), "0o700")

    def test_state_root_missing_parent_is_rejected_without_creating_anything(self) -> None:
        parent = self.tmp / "does_not_exist_yet"
        state_root = parent / "provisioning"
        with self.assertRaises(PathPolicyError):
            storage_mod.ensure_private_state_root(state_root)
        self.assertFalse(parent.exists())

    def test_new_subdirectory_defaults_to_0700_under_a_loose_parent(self) -> None:
        parent = self.tmp / "loose_var_lib"
        parent.mkdir(mode=0o777)
        os.chmod(parent, 0o777)
        state_root = parent / "provisioning"
        created = storage_mod.ensure_private_subdir(state_root, journal_mod.OWNERSHIP_DIR)
        self.assertEqual(oct(stat.S_IMODE(created.stat().st_mode)), "0o700")
        self.assertEqual(oct(stat.S_IMODE(parent.stat().st_mode)), "0o777")


class UndoingRecoveryBoundaryTests(unittest.TestCase):
    """Point 3: UNDOING is an explicit resume boundary. A step left in
    UNDOING by a prior crash must never be silently skipped by
    _run_rollback (UNDOING is deliberately not in UNDOABLE_STEP_STATES)."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _journal_with_step0_verified_and_step1_failed(self, capability_id: str):
        decision = self.harness.decision(capability_id)
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="txn-%s" % capability_id, now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        record0 = journal.step(0).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
        journal = journal.with_step(record0)
        locked_context = self.harness.locked_context()
        result0 = executor.apply_step(record0, locked_context)
        record0 = record0.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result0.undo_record)
        journal = journal.with_step(record0)
        record0 = record0.with_state(StepState.VERIFYING)
        journal = journal.with_step(record0)
        verification0 = executor.verify_step(record0, result0, locked_context)
        record0 = record0.with_state(StepState.VERIFIED, completed_at=_now(), verification=verification0.evidence)
        journal = journal.with_step(record0)
        record1 = journal.step(1).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
        journal = journal.with_step(record1)
        record1 = record1.with_state(StepState.APPLY_FAILED, completed_at=_now(), error_kind="forced", error="forced failure")
        journal = journal.with_step(record1)
        journal = journal.with_state(TransactionState.ROLLING_BACK, now=_now())
        return journal, executor

    def test_crash_after_undoing_write_and_before_the_unlink_resumes_and_undoes(self) -> None:
        capability_id = "cap_undoing_before"
        journal, executor = self._journal_with_step0_verified_and_step1_failed(capability_id)
        record0 = journal.step(0).with_state(StepState.UNDOING)
        journal = journal.with_step(record0)
        journal_mod.write_journal(self.harness.state_root, journal)  # crash simulated here: real unlink never ran
        self.assertTrue((self.harness.sandbox / ("%s.marker" % capability_id)).exists())

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.ROLLBACK)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.state, TransactionState.PREPARATION_FAILED)
        self.assertEqual(final.step(0).state, StepState.UNDONE)
        self.assertEqual(list(self.harness.sandbox.iterdir()), [])

    def test_crash_after_the_unlink_and_before_undone_resumes_without_reexecuting(self) -> None:
        capability_id = "cap_undoing_after"
        journal, executor = self._journal_with_step0_verified_and_step1_failed(capability_id)
        record0 = journal.step(0)
        marker_path = Path(record0.undo_record["path"])
        marker_path.unlink()  # the real undo already ran
        record0 = record0.with_state(StepState.UNDOING)
        journal = journal.with_step(record0)
        journal_mod.write_journal(self.harness.state_root, journal)  # crash simulated here: UNDONE write never landed

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.ROLLBACK)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.step(0).state, StepState.UNDONE)

    def test_divergent_resource_during_undoing_becomes_undo_failed_not_silently_skipped(self) -> None:
        capability_id = "cap_undoing_divergent"
        journal, executor = self._journal_with_step0_verified_and_step1_failed(capability_id)
        record0 = journal.step(0)
        marker_path = Path(record0.undo_record["path"])
        marker_path.write_bytes(b"someone else changed this during the crash window")
        record0 = record0.with_state(StepState.UNDOING)
        journal = journal.with_step(record0)
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.step(0).state, StepState.UNDO_FAILED)
        self.assertEqual(final.step(0).error_kind, "content_diverged")
        self.assertTrue(marker_path.exists())  # never silently deleted despite the divergence

    def test_inspection_error_during_undoing_becomes_undo_failed_never_silently_undone(self) -> None:
        capability_id = "cap_undoing_inspect_error"
        journal, executor = self._journal_with_step0_verified_and_step1_failed(capability_id)
        record0 = journal.step(0)
        record0 = record0.with_state(StepState.UNDOING)
        journal = journal.with_step(record0)
        journal_mod.write_journal(self.harness.state_root, journal)

        with mock.patch.object(executor, "inspect_step", return_value={"exists": None, "is_symlink": None, "content_matches": None, "inspect_error": "simulated I/O error"}):
            reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.step(0).state, StepState.UNDO_FAILED)
        self.assertEqual(final.step(0).error_kind, "inspection_error")


class FinalPostconditionExactnessTests(unittest.TestCase):
    """Point 4 (third correction round): the final transaction-level
    postcondition re-verifies every executor invariant -- path, type, no
    symlink, hash, mode, uid, gid, st_nlink. Expected mode/uid/gid come from
    the plan's own step intent (part of plan_digest), never adopted from
    whatever _finalize_provenance happens to find. Tampering the real
    resource strictly between the last per-step verify_step and the
    transaction-level verify_postcondition must never reach COMMITTED,
    must grant no ownership, and must drive an explicit rollback/recovery."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _prepare_with_tamper_before_postcondition(self, capability_id: str, tamper) -> "engine.PrepareOutcome":
        executor = self.harness.executor  # the actual instance registered in the harness
        real_verify_postcondition = executor.verify_postcondition

        def _tamper_then_verify(plan_arg, context_arg):
            tamper(self.harness.sandbox / ("%s.marker" % capability_id))
            return real_verify_postcondition(plan_arg, context_arg)

        decision = self.harness.decision(capability_id)
        with mock.patch.object(executor, "verify_postcondition", side_effect=_tamper_then_verify):
            outcome = engine.prepare(decision, self.harness.env, apply=True)
        return outcome

    def _assert_never_committed_and_no_ownership(self, capability_id: str, outcome) -> None:
        self.assertNotEqual(outcome.status, PrepareStatus.COMMITTED)
        self.assertIn(
            outcome.status,
            (PrepareStatus.PREPARATION_FAILED, PrepareStatus.ROLLBACK_FAILED, PrepareStatus.RECOVERY_REQUIRED),
        )
        self.assertEqual(journal_mod.read_ownership_records(self.harness.state_root, capability_id), [])

    def test_chmod_after_verify_step_before_postcondition_never_commits(self) -> None:
        capability_id = "cap_postcond_chmod"
        outcome = self._prepare_with_tamper_before_postcondition(capability_id, lambda p: os.chmod(p, 0o644))
        self._assert_never_committed_and_no_ownership(capability_id, outcome)

    def test_simulated_chown_after_verify_step_before_postcondition_never_commits(self) -> None:
        # os.chown to a different uid typically requires privileges this
        # test process does not have; the equivalent observable effect (an
        # owner mismatch discovered exactly when verify_postcondition
        # re-stats the resource) is simulated by faking stat_identity's
        # result ONLY for the duration of the postcondition call -- the
        # earlier, already-passed verify_step call is untouched, so the
        # tamper is scoped to precisely the window the correction targets.
        capability_id = "cap_postcond_chown"
        executor = self.harness.executor
        real_verify_postcondition = executor.verify_postcondition
        real_stat_identity_relative = paths_mod.stat_identity_relative

        def _faked_stat_identity(handle, path):
            identity = dict(real_stat_identity_relative(handle, path))
            if str(path).endswith(".marker"):
                identity["uid"] = identity["uid"] + 1
            return identity

        def _tampered_verify_postcondition(plan_arg, context_arg):
            with mock.patch("compat.provisioning.executors.stat_identity_relative", side_effect=_faked_stat_identity):
                return real_verify_postcondition(plan_arg, context_arg)

        decision = self.harness.decision(capability_id)
        with mock.patch.object(executor, "verify_postcondition", side_effect=_tampered_verify_postcondition):
            outcome = engine.prepare(decision, self.harness.env, apply=True)
        self._assert_never_committed_and_no_ownership(capability_id, outcome)

    def test_hardlink_after_verify_step_before_postcondition_never_commits(self) -> None:
        capability_id = "cap_postcond_hardlink"
        extra_links: list[Path] = []

        def _tamper(path: Path) -> None:
            extra = path.with_name(path.name + ".extra_link")
            os.link(path, extra)
            extra_links.append(extra)

        outcome = self._prepare_with_tamper_before_postcondition(capability_id, _tamper)
        for extra in extra_links:
            extra.unlink(missing_ok=True)
        self._assert_never_committed_and_no_ownership(capability_id, outcome)

    def test_type_substitution_after_verify_step_before_postcondition_never_commits(self) -> None:
        capability_id = "cap_postcond_type_swap"

        def _tamper(path: Path) -> None:
            path.unlink()
            outside = self.tmp / "postcond_symlink_target.txt"
            outside.write_bytes(b"symlink target, not the real marker")
            path.symlink_to(outside)

        outcome = self._prepare_with_tamper_before_postcondition(capability_id, _tamper)
        self._assert_never_committed_and_no_ownership(capability_id, outcome)

    def test_verify_postcondition_rejects_unexpected_mode(self) -> None:
        capability_id = "cap_postcond_mode_direct"
        decision = self.harness.decision(capability_id)
        locked_context = self.harness.locked_context()
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=locked_context)
        for step in plan.steps:
            path = Path(step.target)
            path.write_bytes(step.intent["content"].encode("ascii"))
            os.chmod(path, 0o644)
        result = executor.verify_postcondition(plan, locked_context)
        self.assertEqual(result.status, "verification_failed")
        self.assertEqual(result.error_kind, "unexpected_mode")

    def test_verify_postcondition_rejects_unexpected_uid_via_faked_identity(self) -> None:
        capability_id = "cap_postcond_uid_direct"
        decision = self.harness.decision(capability_id)
        locked_context = self.harness.locked_context()
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=locked_context)
        for step in plan.steps:
            path = Path(step.target)
            path.write_bytes(step.intent["content"].encode("ascii"))
            os.chmod(path, 0o600)
        real_stat_identity_relative = paths_mod.stat_identity_relative

        def _faked_stat_identity(handle, path):
            identity = dict(real_stat_identity_relative(handle, path))
            identity["uid"] = identity["uid"] + 1
            return identity

        with mock.patch("compat.provisioning.executors.stat_identity_relative", side_effect=_faked_stat_identity):
            result = executor.verify_postcondition(plan, locked_context)
        self.assertEqual(result.status, "verification_failed")
        self.assertEqual(result.error_kind, "unexpected_uid")


class DurabilityAfterVisibleEffectTests(unittest.TestCase):
    """Point 4: a directory-fsync failure after a genuine create must never
    become a clean PREPARATION_FAILED/COMMITTED -- residuals non-empty,
    evidence preserved, and a later real recovery pass completes cleanly."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_durability_failure_is_recovery_required_with_evidence_and_later_completes(self) -> None:
        decision = self.harness.decision(capability_id="cap_durability_full")
        with mock.patch("compat.provisioning.paths.os.fsync", side_effect=_fail_directory_fsync_side_effect(only_within=self.harness.sandbox)):
            outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.RECOVERY_REQUIRED)
        self.assertEqual(outcome.error_kind, "durability_unknown")
        self.assertNotEqual(outcome.residuals, ())
        marker_path = self.harness.sandbox / "cap_durability_full.marker"
        self.assertTrue(marker_path.exists())  # the effect genuinely happened
        journal = journal_mod.read_journal(self.harness.state_root, outcome.transaction_id)
        self.assertEqual(journal.state, TransactionState.RECOVERY_REQUIRED)
        self.assertIsNotNone(journal.recovery)
        self.assertEqual(journal.recovery.get("reason"), "durability_unknown")

        # A later, real (unmocked) recovery pass must complete cleanly.
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.RESUME)
        final = journal_mod.read_journal(self.harness.state_root, outcome.transaction_id)
        self.assertEqual(final.state, TransactionState.COMMITTED)
        self.assertTrue(marker_path.exists())
        records = journal_mod.read_ownership_records(self.harness.state_root, "cap_durability_full")
        self.assertEqual(len(records), 2)

    def test_durability_failure_during_undo_never_reports_a_clean_undone(self) -> None:
        decision = self.harness.decision(capability_id="cap_durability_undo")
        with mock.patch.object(self.harness.executor, "verify_step", return_value=VerificationResult(status="verification_failed", error_kind="forced", error="forced")):
            with mock.patch("compat.provisioning.paths.os.fsync", side_effect=_fail_directory_fsync_side_effect(only_within=self.harness.sandbox)):
                outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertNotEqual(outcome.status, PrepareStatus.PREPARATION_FAILED)


class ErrorsNeverConfusedWithAbsenceTests(unittest.TestCase):
    """Point 5: a PermissionError/EIO/ESTALE-style OSError during inspection
    must never be treated as confirmed absence -- no case here may end in
    VERIFIED-removed or UNINSTALLED."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _committed(self, capability_id: str):
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

    def test_inspect_step_reports_inspect_error_not_absence_on_permission_error(self) -> None:
        # validate_target_path is bypassed here: pathlib's Path.is_symlink()
        # error-swallowing behavior for a raised OSError changed between
        # Python versions (verified to differ between 3.12 and 3.14), so its
        # own internal lstat use is not a reliable thing to leave "live" in
        # a test that specifically targets inspect_step's OWN existence
        # check -- bypassing it removes that cross-version ambiguity. The
        # actual identity lookup is descriptor-relative (point 2, fifth
        # correction round), so the fault is injected on
        # ``paths.os.lstat``, the primitive ``stat_identity_relative``
        # itself calls, not on ``pathlib.Path.lstat``.
        capability_id = "cap_err_inspect"
        self._committed(capability_id)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        record = journal_mod.StepRecord(sequence=0, step_id="s", action_type="create_file", state=StepState.PLANNED, intent={"content_sha256": "0" * 64}, target=str(marker_path))
        with mock.patch("compat.provisioning.executors.validate_target_path", side_effect=lambda path, **kw: Path(path)):
            with mock.patch("compat.provisioning.paths.os.lstat", side_effect=PermissionError(errno.EACCES, "Permission denied")):
                observed = self.harness.executor.inspect_step(record, self.harness.locked_context())
        self.assertIsNone(observed["exists"])
        self.assertIn("inspect_error", observed)

    def test_uninstall_loop_never_reports_verified_when_applying_stat_raises_permission_error(self) -> None:
        capability_id = "cap_err_uninstall_verify"
        self._committed(capability_id)
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id="uninstall-%s" % capability_id)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        marker_index = next(i for i, s in enumerate(journal.steps) if s.intent["resource_identity"].endswith(".marker"))
        marker_name = Path(journal.steps[marker_index].intent["resource_identity"]).name
        real_lstat = os.lstat

        def faulty_lstat(name, *a, **kw):
            if name == marker_name:
                raise OSError(errno.EIO, "Input/output error")
            return real_lstat(name, *a, **kw)

        locked_context = self.harness.locked_context()
        with mock.patch("compat.provisioning.engine.validate_target_path", side_effect=lambda path, **kw: Path(path)):
            with mock.patch("compat.provisioning.paths.os.lstat", side_effect=faulty_lstat):
                journal, ok, residuals = engine._run_uninstall_loop(
            self.harness.state_root, journal, locked_context,
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION,
        )
        self.assertFalse(ok)
        self.assertIn(journal.steps[marker_index].step_id, residuals)
        self.assertEqual(journal.steps[marker_index].error_kind, "inspection_error")
        self.assertNotEqual(journal.steps[marker_index].state, StepState.VERIFIED)

    def test_uninstall_final_verification_never_confirms_removed_on_estale(self) -> None:
        # The marker step is placed directly at the VERIFYING boundary with
        # its resource already genuinely removed (as a prior real unlink
        # would leave it), isolating exactly the FINAL absence-verification
        # lstat call from the earlier APPLYING-boundary and drift-check
        # lstat calls -- validate_target_path is bypassed for the same
        # cross-version-ambiguity reason as the test above.
        capability_id = "cap_err_estale"
        self._committed(capability_id)
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id="uninstall-%s" % capability_id)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        marker_index = next(i for i, s in enumerate(journal.steps) if s.intent["resource_identity"].endswith(".marker"))
        marker_str = journal.steps[marker_index].intent["resource_identity"]

        record = journal.step(marker_index).with_state(StepState.APPLYING, started_at=_now())
        journal = journal.with_step(record)
        Path(marker_str).unlink()  # the real removal already happened
        record = record.with_state(StepState.APPLIED, completed_at=_now())
        journal = journal.with_step(record)
        record = record.with_state(StepState.VERIFYING)
        journal = journal.with_step(record)

        marker_name = Path(marker_str).name
        real_lstat = os.lstat

        def faulty_lstat(name, *a, **kw):
            if name == marker_name:
                raise OSError(errno.ESTALE, "Stale file handle")
            return real_lstat(name, *a, **kw)

        locked_context = self.harness.locked_context()
        with mock.patch("compat.provisioning.engine.validate_target_path", side_effect=lambda path, **kw: Path(path)):
            with mock.patch("compat.provisioning.paths.os.lstat", side_effect=faulty_lstat):
                journal, ok, residuals = engine._run_uninstall_loop(
            self.harness.state_root, journal, locked_context,
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION,
        )
        self.assertFalse(ok)
        self.assertEqual(journal.steps[marker_index].error_kind, "inspection_error")
        self.assertNotEqual(journal.steps[marker_index].state, StepState.VERIFIED)


class IdempotencyTiedToFullPlanTests(unittest.TestCase):
    """Point 6: already_provisioned requires the source transaction's own
    plan_digest to match the CURRENT plan in full -- capability/dependency
    id, target, architecture, support classification, method, executor and
    selected asset -- never just matching ownership/resource metadata."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_dependency_id_changed_since_commit_is_never_already_provisioned(self) -> None:
        capability_id = "cap_plan_dep_changed"
        first = self.harness.decision(capability_id)
        outcome = engine.prepare(first, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

        changed = dataclasses.replace(first, dependency_id="dep_changed")
        second = engine.prepare(changed, self.harness.env, apply=True)
        self.assertNotEqual(second.status, PrepareStatus.ALREADY_PROVISIONED)

    def test_target_changed_since_commit_is_never_already_provisioned(self) -> None:
        capability_id = "cap_plan_target_changed"
        first = self.harness.decision(capability_id)
        outcome = engine.prepare(first, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

        changed = dataclasses.replace(first, resolved_distribution="a_different_distro")
        second = engine.prepare(changed, self.harness.env, apply=True)
        self.assertNotEqual(second.status, PrepareStatus.ALREADY_PROVISIONED)

    def test_architecture_changed_since_commit_is_never_already_provisioned(self) -> None:
        capability_id = "cap_plan_arch_changed"
        first = self.harness.decision(capability_id)
        outcome = engine.prepare(first, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

        changed = dataclasses.replace(first, machine_architecture="aarch64")
        second = engine.prepare(changed, self.harness.env, apply=True)
        self.assertNotEqual(second.status, PrepareStatus.ALREADY_PROVISIONED)

    def test_support_classification_changed_since_commit_is_never_already_provisioned(self) -> None:
        capability_id = "cap_plan_support_changed"
        first = self.harness.decision(capability_id)
        outcome = engine.prepare(first, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

        changed = dataclasses.replace(first, support_classification="experimental")
        second = engine.prepare(changed, self.harness.env, apply=True)
        self.assertNotEqual(second.status, PrepareStatus.ALREADY_PROVISIONED)

    def test_selected_asset_changed_since_commit_is_never_already_provisioned(self) -> None:
        capability_id = "cap_plan_asset_changed"
        asset = SelectedArtifact(
            architecture="x86_64", asset_name="pkg.tar.zst", archive_or_binary_kind="archive",
            official_download_base="https://example.invalid/", sha256="a" * 64, expected_executable="pkg",
        )
        first = dataclasses.replace(self.harness.decision(capability_id), selected_asset=asset)
        outcome = engine.prepare(first, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

        changed_asset = dataclasses.replace(asset, sha256="b" * 64)
        changed = dataclasses.replace(first, selected_asset=changed_asset)
        second = engine.prepare(changed, self.harness.env, apply=True)
        self.assertNotEqual(second.status, PrepareStatus.ALREADY_PROVISIONED)

    def test_unchanged_plan_is_exactly_already_provisioned(self) -> None:
        capability_id = "cap_plan_unchanged"
        decision = self.harness.decision(capability_id)
        outcome = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        second = engine.prepare(decision, self.harness.env, apply=True)
        self.assertEqual(second.status, PrepareStatus.ALREADY_PROVISIONED)


class FullMetadataAndDriftDetectionTests(unittest.TestCase):
    """Point 7: _finalize_provenance fails without commit if it cannot
    obtain a resource's real identity; uninstall detects chmod/chown/
    hardlink drift and refuses to unlink."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_finalize_provenance_raises_and_never_commits_when_identity_cannot_be_obtained(self) -> None:
        decision = self.harness.decision(capability_id="cap_provenance_fail")
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="provenance-fail-txn", now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        locked_context = self.harness.locked_context()
        journal, apply_ok, durability_unknown = engine._apply_and_verify(self.harness.state_root, journal, plan, executor, locked_context)
        self.assertTrue(apply_ok)
        self.assertFalse(durability_unknown)

        with mock.patch("compat.provisioning.engine.stat_identity_relative", side_effect=OSError(errno.EIO, "boom")):
            with self.assertRaises(Exception):
                engine._finalize_provenance(self.harness.state_root, journal, plan, executor, locked_context, _now())
        # No ownership records were ever written -- never fabricated None metadata.
        self.assertEqual(journal_mod.read_ownership_records(self.harness.state_root, "cap_provenance_fail"), [])

    def test_uninstall_refuses_to_unlink_a_chmod_drifted_resource(self) -> None:
        capability_id = "cap_drift_chmod"
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        os.chmod(marker_path, 0o644)

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.UNINSTALL_FAILED)
        self.assertTrue(result.residuals)
        self.assertTrue(marker_path.exists())
        self.assertEqual(oct(stat.S_IMODE(marker_path.stat().st_mode)), "0o644")

    def test_uninstall_refuses_to_unlink_a_hardlinked_resource(self) -> None:
        capability_id = "cap_drift_hardlink"
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        hardlink_path = marker_path.with_name(marker_path.name + ".extra_link")
        os.link(marker_path, hardlink_path)
        self.addCleanup(lambda: hardlink_path.unlink(missing_ok=True))

        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.UNINSTALL_FAILED)
        self.assertTrue(marker_path.exists())

    def test_ownership_records_capture_full_identity_metadata(self) -> None:
        capability_id = "cap_full_metadata"
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        for record in records:
            self.assertIsNotNone(record.candidate.uid)
            self.assertIsNotNone(record.candidate.gid)
            self.assertIsNotNone(record.candidate.mode)
            self.assertIsNotNone(record.candidate.integrity)
            self.assertTrue(Path(record.candidate.resource_identity).is_absolute())


class OwnershipSnapshotCompletenessTests(unittest.TestCase):
    """Point 6 (third correction round): the ownership snapshot's canonical
    digest representation is truly complete -- source, version,
    post_install_fingerprint, recorded_at and nlink all participate in
    ``compute_uninstall_plan_digest``, so tampering ANY single field of a
    product-owned record changes the digest and is caught by
    ``_uninstall_source_matches``/``_revocation_boundary_is_safe``.
    Credentialed URLs are never persisted verbatim into the standalone
    ownership file."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _base_record(self) -> OwnershipRecord:
        return OwnershipRecord(
            capability_id="cap_snapshot_complete",
            candidate=OwnershipCandidate(
                artifact_type="file",
                resource_identity=str(self.harness.sandbox / "x.marker"),
                pre_existing=False,
                method_id="canary_method",
                source=None,
                version=None,
                integrity="a" * 64,
                uid=1000,
                gid=1000,
                mode=0o600,
                nlink=1,
                post_install_fingerprint="a" * 64,
            ),
            product_owned=True,
            created_by_transaction="deadbeef" * 4,
            executor_id="canary_lab_executor",
            executor_version="1",
            recorded_at="2026-01-01T00:00:00+00:00",
        )

    def _uninstall_plan_digest_for(self, record: OwnershipRecord) -> str:
        plan = UninstallPlan(
            capability_id=record.capability_id,
            transaction_id="uninstalltxn",
            target_transaction_id=record.created_by_transaction,
            ownership_records=(record,),
            steps=(
                ProvisioningStep(
                    sequence=0, step_id="uninstall_0", action_type="remove_file",
                    intent={"resource_identity": record.candidate.resource_identity, "expected_sha256": record.candidate.integrity},
                    target=record.candidate.resource_identity,
                ),
            ),
        )
        return compute_uninstall_plan_digest(plan)

    def _assert_field_change_breaks_digest(self, mutate) -> None:
        base = self._base_record()
        baseline_digest = self._uninstall_plan_digest_for(base)
        mutated = mutate(base)
        self.assertNotEqual(self._uninstall_plan_digest_for(mutated), baseline_digest)

    def test_tampering_source_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(
            lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, source="https://example.invalid/pkg"))
        )

    def test_tampering_version_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, version="9.9.9")))

    def test_tampering_post_install_fingerprint_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(
            lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, post_install_fingerprint="b" * 64))
        )

    def test_tampering_recorded_at_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, recorded_at="2099-01-01T00:00:00+00:00"))

    def test_tampering_nlink_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, nlink=2)))

    def test_tampering_uid_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, uid=r.candidate.uid + 1)))

    def test_tampering_gid_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, gid=r.candidate.gid + 1)))

    def test_tampering_mode_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, mode=0o644)))

    def test_tampering_integrity_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, integrity="c" * 64)))

    def test_tampering_resource_identity_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(
            lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, resource_identity=str(self.harness.sandbox / "y.marker")))
        )

    def test_tampering_pre_existing_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, pre_existing=True)))

    def test_tampering_artifact_type_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, artifact_type="directory")))

    def test_tampering_method_id_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, method_id="other_method")))

    def test_tampering_executor_id_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, executor_id="other_executor"))

    def test_tampering_executor_version_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, executor_version="2"))

    def test_tampering_capability_id_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, capability_id="other_cap"))

    def test_tampering_created_by_transaction_breaks_digest(self) -> None:
        self._assert_field_change_breaks_digest(lambda r: dataclasses.replace(r, created_by_transaction="0" * 32))

    def test_ownership_file_never_persists_credentialed_url_verbatim(self) -> None:
        capability_id = "cap_snapshot_credential"
        base = self._base_record()
        record = dataclasses.replace(
            base, capability_id=capability_id,
            candidate=dataclasses.replace(base.candidate, source="https://user:hunter2@example.invalid/pkg.tar.gz"),
        )
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, (record,))
        raw = journal_mod.ownership_path(self.harness.state_root, capability_id).read_text(encoding="utf-8")
        self.assertNotIn("hunter2", raw)
        self.assertIn("***redacted***", raw)


class CanaryConfinementPolicyTests(unittest.TestCase):
    """Point 2 (third correction round): positive lab-root confinement.
    Unlike a denylist (which only ever rejects the specific roots it
    happens to know about), --sandbox and --state-root must now both be
    strict descendants of ONE explicitly validated, pre-created, pre-approved
    --lab-root -- an arbitrary path like /var/log, /var/spool, /opt or /srv
    is never acceptable just because it fails to match one denylist entry.
    Every check must run, and every rejection must leave zero mutation,
    BEFORE any file is created."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.lab_root = self.tmp / "lab_root"
        self.lab_root.mkdir(mode=0o700)
        os.chmod(self.lab_root, 0o700)
        self.good_sandbox = self.lab_root / "sandbox"
        self.good_state_root = self.lab_root / "state"
        self.global_lock_root = self.tmp / "global-lock-root"

    def _run(self, *, lab_root=None, sandbox=None, state_root=None, mutating: bool = True):
        import tools.compat_provision as compat_provision_tool

        lab_root = str(self.lab_root if lab_root is None else lab_root)
        sandbox = str(self.good_sandbox if sandbox is None else sandbox)
        state_root = str(self.good_state_root if state_root is None else state_root)
        parser = compat_provision_tool.build_parser()
        argv = ["--lab-root", lab_root, "--sandbox", sandbox, "--state-root", state_root, "--global-lock-root", str(self.global_lock_root)]
        argv += ["prepare", "--apply", "cap_x", "dep_x"] if mutating else ["plan", "cap_x", "dep_x"]
        return compat_provision_tool._build_env(parser.parse_args(argv), mutating=mutating)

    def _assert_nothing_created(self, *extra_paths: Path) -> None:
        self.assertFalse(self.good_sandbox.exists())
        self.assertFalse(self.good_state_root.exists())
        for path in extra_paths:
            self.assertFalse(Path(path).exists())

    def test_sandbox_var_log_is_rejected(self) -> None:
        with self.assertRaises(PathPolicyError):
            self._run(sandbox="/var/log")
        self._assert_nothing_created()

    def test_sandbox_var_spool_is_rejected(self) -> None:
        with self.assertRaises(PathPolicyError):
            self._run(sandbox="/var/spool")
        self._assert_nothing_created()

    def test_sandbox_opt_is_rejected(self) -> None:
        with self.assertRaises(PathPolicyError):
            self._run(sandbox="/opt")
        self._assert_nothing_created()

    def test_sandbox_srv_is_rejected(self) -> None:
        with self.assertRaises(PathPolicyError):
            self._run(sandbox="/srv")
        self._assert_nothing_created()

    def test_state_root_var_log_subdir_is_rejected(self) -> None:
        with self.assertRaises(PathPolicyError):
            self._run(state_root="/var/log/wdvpn-state")
        self._assert_nothing_created()

    def test_sandbox_equal_to_state_root_is_rejected(self) -> None:
        same = self.lab_root / "shared"
        with self.assertRaises(PathPolicyError):
            self._run(sandbox=str(same), state_root=str(same))
        self.assertFalse(same.exists())

    def test_sandbox_containing_state_root_is_rejected(self) -> None:
        sandbox = self.lab_root / "outer"
        state_root = sandbox / "inner_state"
        with self.assertRaises(PathPolicyError):
            self._run(sandbox=str(sandbox), state_root=str(state_root))
        self.assertFalse(sandbox.exists())
        self.assertFalse(state_root.exists())

    def test_state_root_containing_sandbox_is_rejected(self) -> None:
        state_root = self.lab_root / "outer_state"
        sandbox = state_root / "inner_sandbox"
        with self.assertRaises(PathPolicyError):
            self._run(sandbox=str(sandbox), state_root=str(state_root))
        self.assertFalse(state_root.exists())
        self.assertFalse(sandbox.exists())

    def test_sandbox_outside_lab_root_is_rejected(self) -> None:
        outside = self.tmp / "sibling_of_lab_root" / "sandbox"
        with self.assertRaises(PathPolicyError):
            self._run(sandbox=str(outside))
        self._assert_nothing_created(outside)

    def test_state_root_outside_lab_root_is_rejected(self) -> None:
        outside = self.tmp / "sibling_of_lab_root" / "state"
        with self.assertRaises(PathPolicyError):
            self._run(state_root=str(outside))
        self._assert_nothing_created(outside)

    def test_lab_root_symlink_is_rejected(self) -> None:
        real = self.tmp / "real_lab_root"
        real.mkdir(mode=0o700)
        link = self.tmp / "lab_root_link"
        link.symlink_to(real)
        with self.assertRaises(PathPolicyError):
            self._run(lab_root=str(link), sandbox=str(link / "sandbox"), state_root=str(link / "state"))
        self.assertFalse((real / "sandbox").exists())
        self.assertFalse((real / "state").exists())

    def test_lab_root_missing_is_rejected_and_never_created(self) -> None:
        missing = self.tmp / "never_created_lab_root"
        with self.assertRaises(PathPolicyError):
            self._run(lab_root=str(missing), sandbox=str(missing / "sandbox"), state_root=str(missing / "state"))
        self.assertFalse(missing.exists())

    def test_lab_root_at_loose_permissions_is_rejected(self) -> None:
        loose = self.tmp / "loose_lab_root"
        loose.mkdir(mode=0o755)
        os.chmod(loose, 0o755)
        with self.assertRaises(PathPolicyError):
            self._run(lab_root=str(loose), sandbox=str(loose / "sandbox"), state_root=str(loose / "state"))

    def test_lab_root_itself_the_filesystem_root_is_rejected(self) -> None:
        with self.assertRaises(PathPolicyError):
            self._run(lab_root="/", sandbox="/sandbox", state_root="/state")

    def test_lab_root_itself_home_is_rejected(self) -> None:
        with self.assertRaises(PathPolicyError):
            self._run(lab_root=str(Path.home()), sandbox=str(Path.home() / "sandbox"), state_root=str(Path.home() / "state"))

    def test_lab_root_overlapping_real_product_state_directory_is_rejected(self) -> None:
        with self.assertRaises(PathPolicyError):
            self._run(
                lab_root="/var/lib/watchdogvpn",
                sandbox="/var/lib/watchdogvpn/sandbox",
                state_root="/var/lib/watchdogvpn/state",
            )

    def test_sandbox_symlink_is_rejected_before_any_creation(self) -> None:
        real = self.lab_root / "real_sandbox"
        real.mkdir()
        link = self.lab_root / "sandbox_link"
        link.symlink_to(real)
        with self.assertRaises(PathPolicyError):
            self._run(sandbox=str(link))
        self._assert_nothing_created()

    def test_state_root_symlink_is_rejected_before_any_creation(self) -> None:
        real = self.lab_root / "real_state"
        real.mkdir()
        link = self.lab_root / "state_link"
        link.symlink_to(real)
        with self.assertRaises(PathPolicyError):
            self._run(state_root=str(link))
        self._assert_nothing_created()

    def test_sandbox_and_state_root_under_a_valid_lab_root_are_accepted(self) -> None:
        env = self._run()
        self.assertTrue(self.good_sandbox.exists())
        self.assertEqual(env.state_root, self.good_state_root)

    def test_dedicated_lab_root_may_live_under_home(self) -> None:
        under_home_lab_root = Path(tempfile.mkdtemp(prefix="wdvpn-lab-test-", dir=str(Path.home())))
        os.chmod(under_home_lab_root, 0o700)
        self.addCleanup(under_home_lab_root.rmdir)
        validated = paths_mod.validate_dedicated_lab_root(under_home_lab_root)
        self.assertEqual(validated, under_home_lab_root)


class AllowedRootSwapDuringUninstallTests(unittest.TestCase):
    """Point 2, fifth correction round: ``AllowedRootHandle`` bound to
    descriptors. A sandbox (allowed root) swap that happens right as
    uninstall begins must fail closed (``RECOVERY_REQUIRED``), never a
    clean ``UNINSTALLED``, and ownership must never be revoked -- resources
    sitting in the renamed-aside original directory remain fully intact
    for an operator to inspect as residuals."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _prepare_committed(self, capability_id: str) -> None:
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

    def _swap_sandbox_then_uninstall(self, capability_id: str, replace_with):
        real_matches = engine._uninstall_source_matches

        def _swap_then_check(*args, **kwargs):
            replace_with()
            return real_matches(*args, **kwargs)

        with mock.patch("compat.provisioning.engine._uninstall_source_matches", side_effect=_swap_then_check):
            return engine.uninstall(capability_id, self.harness.env, apply=True)

    def test_sandbox_renamed_aside_during_uninstall_blocks_completion(self) -> None:
        capability_id = "cap_uninstall_sandbox_rename"
        self._prepare_committed(capability_id)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        companion_path = self.harness.sandbox / ("%s.companion" % capability_id)
        sandbox = self.harness.sandbox
        renamed = self.tmp / "sandbox_old"

        def _replace() -> None:
            sandbox.rename(renamed)

        result = self._swap_sandbox_then_uninstall(capability_id, _replace)
        self.assertEqual(result.status, PrepareStatus.RECOVERY_REQUIRED)
        self.assertNotEqual(result.status, PrepareStatus.UNINSTALLED)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        self.assertTrue(any(r.product_owned for r in records))
        self.assertTrue((renamed / marker_path.name).exists())
        self.assertTrue((renamed / companion_path.name).exists())

    def test_sandbox_replaced_by_new_empty_directory_during_uninstall_blocks_completion(self) -> None:
        capability_id = "cap_uninstall_sandbox_newdir"
        self._prepare_committed(capability_id)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        sandbox = self.harness.sandbox
        renamed = self.tmp / "sandbox_old2"

        def _replace() -> None:
            sandbox.rename(renamed)
            sandbox.mkdir(mode=0o700)  # same-uid, fresh empty directory at the original path

        result = self._swap_sandbox_then_uninstall(capability_id, _replace)
        self.assertEqual(result.status, PrepareStatus.RECOVERY_REQUIRED)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        self.assertTrue(any(r.product_owned for r in records))
        self.assertTrue((renamed / marker_path.name).exists())
        self.assertEqual(sorted(p.name for p in sandbox.iterdir()), [])

    def test_sandbox_replaced_by_symlink_during_uninstall_blocks_completion(self) -> None:
        capability_id = "cap_uninstall_sandbox_symlink"
        self._prepare_committed(capability_id)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        sandbox = self.harness.sandbox
        renamed = self.tmp / "sandbox_old3"
        decoy = self.tmp / "decoy_empty"
        decoy.mkdir()

        def _replace() -> None:
            sandbox.rename(renamed)
            sandbox.symlink_to(decoy)

        result = self._swap_sandbox_then_uninstall(capability_id, _replace)
        self.assertEqual(result.status, PrepareStatus.RECOVERY_REQUIRED)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        self.assertTrue(any(r.product_owned for r in records))
        self.assertTrue((renamed / marker_path.name).exists())
        self.assertEqual(sorted(decoy.iterdir()), [])


class UndoRecordAuthorityTests(unittest.TestCase):
    """Point 4, fifth correction round, mandatory security test: the
    PERSISTED ``undo_record`` is never trusted as authority for rollback --
    it is always cross-checked against a fresh reconstruction from the
    executor's own deterministic logic. Tampering a step's persisted
    ``undo_record.path``/``expected_sha256`` to point at an unrelated
    foreign file inside the allowed root must never cause that foreign
    file to be unlinked."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_tampered_undo_record_pointing_at_foreign_file_is_refused_during_rollback_recovery(self) -> None:
        capability_id = "cap_undo_record_tamper"
        decision = self.harness.decision(capability_id)
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        journal = engine._initial_journal(plan, transaction_id="undo-tamper-txn", now_value=_now())
        journal = journal.with_state(TransactionState.AUTHORIZED, now=_now())
        journal = journal.with_state(TransactionState.APPLYING, now=_now())
        record0 = journal.step(0).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
        journal = journal.with_step(record0)
        locked_context = self.harness.locked_context()
        result0 = executor.apply_step(record0, locked_context)
        record0 = record0.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result0.undo_record)
        journal = journal.with_step(record0)
        record0 = record0.with_state(StepState.VERIFYING)
        journal = journal.with_step(record0)
        verification0 = executor.verify_step(record0, result0, locked_context)
        record0 = record0.with_state(StepState.VERIFIED, completed_at=_now(), verification=verification0.evidence)
        journal = journal.with_step(record0)

        real_marker = Path(record0.undo_record["path"])
        self.assertTrue(real_marker.exists())

        # An unrelated resource this transaction never created or owns.
        foreign_file = self.harness.sandbox / "unrelated_foreign_file.txt"
        foreign_content = b"completely unrelated content, not managed by this transaction"
        foreign_file.write_bytes(foreign_content)
        foreign_sha256 = hashlib.sha256(foreign_content).hexdigest()

        tampered_undo_record = {
            "path": str(foreign_file),
            "expected_content": foreign_content.decode("ascii", errors="replace"),
            "expected_sha256": foreign_sha256,
        }
        record0 = dataclasses.replace(record0, undo_record=tampered_undo_record)
        journal = journal.with_step(record0)

        # Second step never applied -- forces a rollback.
        record1 = journal.step(1).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
        journal = journal.with_step(record1)
        record1 = record1.with_state(StepState.APPLY_FAILED, completed_at=_now(), error_kind="forced", error="forced failure")
        journal = journal.with_step(record1)
        journal = journal.with_state(TransactionState.ROLLING_BACK, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)  # crash simulated here

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertEqual(final.step(0).error_kind, "undo_record_diverged")
        # Zero unlink: the foreign file survives, completely untouched --
        # and the REAL resource this transaction actually created (which
        # the tampered record tried to hide) is also never touched, since
        # the divergence is detected before any undo is even attempted.
        self.assertTrue(foreign_file.exists())
        self.assertEqual(foreign_file.read_bytes(), foreign_content)
        self.assertTrue(real_marker.exists())


class UninstallJournalStructuralIntegrityTests(unittest.TestCase):
    """Point 4, fifth correction round: an uninstall journal's own
    ``journal.steps`` must be structurally IDENTICAL to the plan
    reconstructed from ``owned_snapshot`` -- ``compute_uninstall_plan_digest``
    alone never actually covers ``journal.steps`` (see
    ``_uninstall_journal_steps_match_plan_exactly``'s docstring), so an
    extra/missing/altered/duplicated step could otherwise be silently
    executed without ever moving the digest."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _prepare_committed(self, capability_id: str) -> None:
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

    def _pending_uninstall_journal(self, capability_id: str) -> journal_mod.TransactionJournal:
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id="uninstall-%s" % capability_id)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)
        return journal

    def test_mandatory_security_scenario_extra_step_targeting_foreign_file_is_never_executed(self) -> None:
        capability_id = "cap_uninstall_extra_step"
        self._prepare_committed(capability_id)
        journal = self._pending_uninstall_journal(capability_id)
        foreign_file = self.harness.sandbox / "foreign_extra.txt"
        foreign_content = b"foreign, not owned by this uninstall"
        foreign_file.write_bytes(foreign_content)
        foreign_sha256 = hashlib.sha256(foreign_content).hexdigest()
        extra_record = journal_mod.StepRecord(
            sequence=len(journal.steps), step_id="uninstall_extra", action_type="remove_file",
            state=StepState.PLANNED, intent={"resource_identity": str(foreign_file), "expected_sha256": foreign_sha256},
            target=str(foreign_file),
        )
        journal = dataclasses.replace(journal, steps=journal.steps + (extra_record,))
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, global_lock_root=self.harness.global_lock_root)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        # Zero unlink: the foreign file survives untouched.
        self.assertTrue(foreign_file.exists())
        self.assertEqual(foreign_file.read_bytes(), foreign_content)
        # Ownership remains live; the transaction never reaches UNINSTALLED.
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        self.assertTrue(any(r.product_owned for r in records))
        final = journal_mod.read_journal(self.harness.state_root, journal.transaction_id)
        self.assertNotEqual(final.state, TransactionState.UNINSTALLED)

    def _structural_check(self, capability_id: str, mutate) -> bool:
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id="uninstall-%s" % capability_id)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = mutate(journal)
        return engine._uninstall_journal_steps_match_plan_exactly(journal, plan)

    def test_missing_step_breaks_structural_match(self) -> None:
        capability_id = "cap_uninstall_missing_step"
        self._prepare_committed(capability_id)
        self.assertFalse(self._structural_check(capability_id, lambda j: dataclasses.replace(j, steps=j.steps[:1])))

    def test_duplicate_step_breaks_structural_match(self) -> None:
        capability_id = "cap_uninstall_duplicate_step"
        self._prepare_committed(capability_id)
        self.assertFalse(self._structural_check(capability_id, lambda j: dataclasses.replace(j, steps=j.steps + (j.steps[0],))))

    def test_duplicate_sequence_breaks_structural_match(self) -> None:
        capability_id = "cap_uninstall_duplicate_sequence"
        self._prepare_committed(capability_id)
        self.assertFalse(self._structural_check(
            capability_id,
            lambda j: dataclasses.replace(j, steps=(j.steps[0], dataclasses.replace(j.steps[1], sequence=j.steps[0].sequence))),
        ))

    def test_changed_target_breaks_structural_match(self) -> None:
        capability_id = "cap_uninstall_changed_target"
        self._prepare_committed(capability_id)
        self.assertFalse(self._structural_check(
            capability_id, lambda j: j.with_step(dataclasses.replace(j.step(0), target=j.step(0).target + ".moved"))
        ))

    def test_changed_intent_breaks_structural_match(self) -> None:
        capability_id = "cap_uninstall_changed_intent"
        self._prepare_committed(capability_id)
        self.assertFalse(self._structural_check(
            capability_id,
            lambda j: j.with_step(dataclasses.replace(j.step(0), intent={**j.step(0).intent, "expected_sha256": "0" * 64})),
        ))

    def test_changed_step_id_breaks_structural_match(self) -> None:
        capability_id = "cap_uninstall_changed_step_id"
        self._prepare_committed(capability_id)
        self.assertFalse(self._structural_check(
            capability_id, lambda j: j.with_step(dataclasses.replace(j.step(0), step_id="not_the_real_step_id"))
        ))

    def test_changed_action_type_breaks_structural_match(self) -> None:
        capability_id = "cap_uninstall_changed_action_type"
        self._prepare_committed(capability_id)
        self.assertFalse(self._structural_check(
            capability_id, lambda j: j.with_step(dataclasses.replace(j.step(0), action_type="not_the_real_action"))
        ))

    def test_unmodified_journal_matches_structurally(self) -> None:
        capability_id = "cap_uninstall_unmodified"
        self._prepare_committed(capability_id)
        self.assertTrue(self._structural_check(capability_id, lambda j: j))


class PrivateReadFailClosedTests(unittest.TestCase):
    """Point 6, fifth correction round: journal/ownership reads open with
    ``O_NOFOLLOW`` and ``fstat``-verify regular file / expected uid / mode
    ``0600`` / ``st_nlink == 1`` / a bounded size before ever parsing the
    content; ``list_json_names_relative`` inspects every ``*.json`` entry
    the same way. None of a symlink, a hardlink, a directory named
    ``*.json``, a loose mode, a wrong uid, or an oversized file is ever
    silently followed or ignored -- each blocks recovery instead."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.state_root = self.tmp / "state"
        self.handle = storage_mod.open_state_root(self.state_root)
        self.addCleanup(self.handle.close)
        self.transactions_dir = self.state_root / journal_mod.TRANSACTIONS_DIR
        self.ownership_dir = self.state_root / journal_mod.OWNERSHIP_DIR
        self.handle.subdir_fd(journal_mod.TRANSACTIONS_DIR)
        self.handle.subdir_fd(journal_mod.OWNERSHIP_DIR)

    def test_journal_symlink_is_rejected(self) -> None:
        victim = self.tmp / "victim.json"
        victim.write_text('{"do not": "read me"}')
        (self.transactions_dir / "txn_symlink.json").symlink_to(victim)
        with self.assertRaises(JournalError):
            journal_mod.read_journal(self.handle, "txn_symlink")
        self.assertEqual(victim.read_text(), '{"do not": "read me"}')

    def test_ownership_symlink_is_rejected(self) -> None:
        victim = self.tmp / "victim_ownership.json"
        victim.write_text("[]")
        (self.ownership_dir / "cap_symlink.json").symlink_to(victim)
        with self.assertRaises(JournalError):
            journal_mod.read_ownership_records(self.handle, "cap_symlink")

    def test_journal_hardlink_is_rejected(self) -> None:
        victim = self.tmp / "victim_hardlink.json"
        victim.write_bytes(b'{"a": 1}')
        os.chmod(victim, 0o600)
        os.link(victim, self.transactions_dir / "txn_hardlink.json")
        with self.assertRaises(JournalError):
            journal_mod.read_journal(self.handle, "txn_hardlink")

    def test_journal_directory_with_json_suffix_is_rejected(self) -> None:
        (self.transactions_dir / "dirtxn.json").mkdir()
        with self.assertRaises(JournalError):
            journal_mod.read_journal(self.handle, "dirtxn")
        with self.assertRaises(JournalError):
            journal_mod.list_transaction_ids(self.handle)

    def _write_real_journal(self, transaction_id: str) -> None:
        journal = journal_mod.TransactionJournal(
            schema_version=journal_mod.SCHEMA_VERSION, transaction_id=transaction_id, operation="prepare",
            state=TransactionState.PLANNED, created_at=_now(), updated_at=_now(), plan_digest="a" * 64,
            capability_id="cap_x", dependency_id="dep_x", target="lab", architecture="x86_64",
            support_classification="lab_fixture", selected_method={"id": "canary_method", "kind": "canary_lab"},
            executor={"id": "canary_lab_executor", "version": "1"}, steps=(),
        )
        journal_mod.write_journal(self.handle, journal)

    def test_journal_mode_0644_is_rejected(self) -> None:
        self._write_real_journal("txn_loose_mode")
        os.chmod(self.transactions_dir / "txn_loose_mode.json", 0o644)
        with self.assertRaises(JournalError):
            journal_mod.read_journal(self.handle, "txn_loose_mode")

    def test_journal_wrong_uid_is_rejected(self) -> None:
        self._write_real_journal("txn_wrong_uid")
        with mock.patch("compat.provisioning.storage.os.getuid", return_value=os.getuid() + 1):
            with self.assertRaises(JournalError):
                journal_mod.read_journal(self.handle, "txn_wrong_uid")

    def test_journal_oversized_is_rejected(self) -> None:
        name = "txn_oversized.json"
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self.handle.subdir_fd(journal_mod.TRANSACTIONS_DIR))
        with os.fdopen(fd, "wb") as f:
            f.write(b"{" + b" " * (storage_mod.MAX_PRIVATE_FILE_SIZE + 1) + b"}")
        with self.assertRaises(JournalError):
            journal_mod.read_journal(self.handle, "txn_oversized")


class ConfirmAbsentBoundToHandleTests(unittest.TestCase):
    """Point 5, fifth correction round: ``confirm_absent_descriptor_safe``
    receives an ALREADY-CAPTURED ``AllowedRootHandle``, never reopening the
    allowed root from a string. An allowed root renamed away and replaced
    by a fresh empty directory at the same path must never be reported as
    "resource absent" -- ``confirm_absent_descriptor_safe`` must return
    ``False`` with an identity-mismatch reason, never ``True``."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)

    def test_allowed_root_renamed_and_replaced_never_confirms_absence(self) -> None:
        root = self.tmp / "root"
        root.mkdir(mode=0o700)
        resource = root / "cap.marker"
        resource.write_bytes(b"still here")
        handle = open_allowed_root(root)
        self.addCleanup(handle.close)

        renamed = self.tmp / "root_renamed_aside"
        root.rename(renamed)
        root.mkdir(mode=0o700)  # fresh, empty replacement at the original path

        absent, reason = confirm_absent_descriptor_safe(str(root / "cap.marker"), allowed_root_handles=(handle,))
        self.assertFalse(absent)
        self.assertIsNotNone(reason)
        self.assertIn("identity", reason)
        # The real resource, sitting in the renamed-aside directory, is
        # untouched and was never mistaken for genuinely absent.
        self.assertTrue((renamed / "cap.marker").exists())


class _NestedResourceExecutor(CanaryExecutor):
    """Test-only executor (point 2, sixth correction round) -- NEVER
    registered outside tests. Places its marker/companion one directory
    level deeper (``sandbox/nested/...``) than ``CanaryExecutor``, to
    exercise intermediate-component identity binding in
    ``AllowedRootHandle``."""

    executor_id = "nested_resource_test_executor"
    supported_method_kind = "nested_resource_test"

    def plan_steps(self, *, capability_id: str, dependency_id: str, context: ExecutionContext):
        steps = super().plan_steps(capability_id=capability_id, dependency_id=dependency_id, context=context)
        nested_steps = []
        for step in steps:
            original = Path(step.target)
            nested_target = original.parent / "nested" / original.name
            nested_steps.append(dataclasses.replace(step, target=str(nested_target)))
        return tuple(nested_steps)


class NestedIntermediateComponentSwapTests(unittest.TestCase):
    """Point 2, sixth correction round, mandatory test: an intermediate
    directory between the allowed root and a resource's parent is renamed
    aside and replaced by a new, same-uid, empty real directory strictly
    between eager-caching (which happens as soon as the lock is acquired
    and the ownership/plan set is known) and the resource's actual use
    during uninstall. The swap must be detected -- ``RECOVERY_REQUIRED``,
    ownership intact, the real resource still sitting untouched in the
    renamed-aside directory, never a false ``UNINSTALLED``."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)
        (self.harness.sandbox / "nested").mkdir(mode=0o700)
        self.executor = _NestedResourceExecutor()
        self.harness.registry.register(
            method_kind="nested_resource_test", method_id="nested_resource_method", executor=self.executor
        )

    def _decision(self, capability_id: str):
        return _decision(capability_id, method_kind="nested_resource_test", method_id="nested_resource_method")

    def test_intermediate_swap_between_eager_cache_and_uninstall_blocks_completion(self) -> None:
        capability_id = "cap_nested_swap"
        outcome = engine.prepare(self._decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        marker_path = self.harness.sandbox / "nested" / ("%s.marker" % capability_id)
        companion_path = self.harness.sandbox / "nested" / ("%s.companion" % capability_id)
        self.assertTrue(marker_path.exists())
        self.assertTrue(companion_path.exists())

        nested_dir = self.harness.sandbox / "nested"
        renamed = self.harness.sandbox / "nested.old"
        real_matches = engine._uninstall_source_matches

        def _swap_then_check(*args, **kwargs):
            nested_dir.rename(renamed)
            nested_dir.mkdir(mode=0o700)  # same-uid, empty replacement at the original path
            return real_matches(*args, **kwargs)

        with mock.patch("compat.provisioning.engine._uninstall_source_matches", side_effect=_swap_then_check):
            result = engine.uninstall(capability_id, self.harness.env, apply=True)

        self.assertEqual(result.status, PrepareStatus.RECOVERY_REQUIRED)
        self.assertNotEqual(result.status, PrepareStatus.UNINSTALLED)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        self.assertTrue(any(r.product_owned for r in records))
        self.assertTrue((renamed / marker_path.name).exists())
        self.assertTrue((renamed / companion_path.name).exists())
        self.assertEqual(sorted(p.name for p in nested_dir.iterdir()), [])

    def test_ownership_records_persist_intermediate_component_identity(self) -> None:
        capability_id = "cap_nested_identity_record"
        outcome = engine.prepare(self._decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        nested_stat = (self.harness.sandbox / "nested").stat()

        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        self.assertTrue(records)
        for record in records:
            identities = record.candidate.intermediate_identities
            self.assertEqual(len(identities), 1)
            identity = identities[0]
            self.assertEqual(identity.relative_name, "nested")
            self.assertEqual((identity.dev, identity.ino), (nested_stat.st_dev, nested_stat.st_ino))
            self.assertEqual(identity.uid, nested_stat.st_uid)
            self.assertEqual(identity.mode, stat.S_IMODE(nested_stat.st_mode))

    def test_intermediate_swap_before_uninstall_entry_is_rejected_by_persisted_identity(self) -> None:
        capability_id = "cap_nested_persistent_swap"
        outcome = engine.prepare(self._decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        marker_path = self.harness.sandbox / "nested" / ("%s.marker" % capability_id)
        companion_path = self.harness.sandbox / "nested" / ("%s.companion" % capability_id)

        nested_dir = self.harness.sandbox / "nested"
        renamed = self.harness.sandbox / "nested.old"
        nested_dir.rename(renamed)
        nested_dir.mkdir(mode=0o700)

        result = engine.uninstall(capability_id, self.harness.env, apply=True)

        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)
        self.assertNotEqual(result.status, PrepareStatus.UNINSTALLED)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        self.assertTrue(any(r.product_owned for r in records))
        self.assertTrue((renamed / marker_path.name).exists())
        self.assertTrue((renamed / companion_path.name).exists())
        self.assertEqual(sorted(p.name for p in nested_dir.iterdir()), [])

    def test_nested_ownership_without_persisted_intermediate_identity_is_invalid(self) -> None:
        capability_id = "cap_nested_missing_identity"
        outcome = engine.prepare(self._decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        stripped = [
            dataclasses.replace(
                record,
                candidate=dataclasses.replace(record.candidate, intermediate_identities=()),
            )
            for record in records
        ]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, stripped)

        result = engine.uninstall(capability_id, self.harness.env, apply=True)

        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)
        self.assertTrue((self.harness.sandbox / "nested" / ("%s.marker" % capability_id)).exists())

    def test_intermediate_swap_during_apply_blocks_commit(self) -> None:
        """Variant: the same swap, but during a fresh apply/commit rather
        than uninstall -- the swap happens after eager-caching (which
        already ran once the plan is known) but before
        ``check_idempotency`` actually touches the nested resource."""
        capability_id = "cap_nested_apply_swap"
        nested_dir = self.harness.sandbox / "nested"
        renamed = self.harness.sandbox / "nested.old"
        real_check_idempotency = engine.check_idempotency

        def _swap_then_check(*args, **kwargs):
            nested_dir.rename(renamed)
            nested_dir.mkdir(mode=0o700)
            return real_check_idempotency(*args, **kwargs)

        with mock.patch("compat.provisioning.engine.check_idempotency", side_effect=_swap_then_check):
            outcome = engine.prepare(self._decision(capability_id), self.harness.env, apply=True)

        self.assertEqual(outcome.status, PrepareStatus.RECOVERY_REQUIRED)
        self.assertNotEqual(outcome.status, PrepareStatus.COMMITTED)
        # Nothing was ever committed under the new, substitute directory.
        self.assertEqual(journal_mod.read_ownership_records(self.harness.state_root, capability_id), [])

    def test_confirm_absent_descriptor_safe_detects_intermediate_swap(self) -> None:
        """Variant: ``confirm_absent_descriptor_safe`` itself, called
        directly with a handle whose intermediate is already cached, must
        detect an intermediate swap the same way it detects a root swap."""
        sandbox = self.harness.sandbox
        handle = open_allowed_root(sandbox)
        self.addCleanup(handle.close)
        nested_dir = sandbox / "nested"
        marker = nested_dir / "cap_confirm_absent.marker"
        marker.write_bytes(b"still here")
        # Prime the cache for the "nested" intermediate.
        handle.intermediate_fd(("nested",))

        renamed = sandbox / "nested.old"
        nested_dir.rename(renamed)
        nested_dir.mkdir(mode=0o700)

        absent, reason = confirm_absent_descriptor_safe(str(marker), allowed_root_handles=(handle,))
        self.assertFalse(absent)
        self.assertIsNotNone(reason)
        self.assertIn("identity", reason)
        self.assertTrue((renamed / marker.name).exists())


class GlobalLockRootHardeningTests(unittest.TestCase):
    """Point 3, sixth correction round: the global lock root's own FINAL
    (leaf) component -- the caller's actual configured ``global_lock_root``
    -- must always be enforced as our own dedicated private root (owned by
    us, mode exactly ``0700``), exactly like ``state_root`` itself, not just
    verified to be "a directory" like its ancestors. Its own identity is
    also re-confirmed right after the flock is acquired, and a SECOND,
    non-blocking flock directly on ``state_root``'s own directory fd
    provides defense in depth against a same-privilege actor who can
    rename/replace ``global_lock_root`` itself."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)

    def test_preexisting_immediate_parent_at_0770_is_rejected(self) -> None:
        parent = self.tmp / "lock-parent-770"
        parent.mkdir(mode=0o700)
        os.chmod(parent, 0o770)
        with self.assertRaises(PathPolicyError):
            storage_mod.ensure_private_lock_root(parent / "global-lock-root")
        self.assertFalse((parent / "global-lock-root").exists())

    def test_preexisting_immediate_parent_at_02770_is_rejected(self) -> None:
        parent = self.tmp / "lock-parent-2770"
        parent.mkdir(mode=0o700)
        os.chmod(parent, 0o2770)
        with self.assertRaises(PathPolicyError):
            storage_mod.ensure_private_lock_root(parent / "global-lock-root")
        self.assertFalse((parent / "global-lock-root").exists())

    def test_preexisting_immediate_parent_world_writable_is_rejected(self) -> None:
        parent = self.tmp / "lock-parent-777"
        parent.mkdir(mode=0o700)
        os.chmod(parent, 0o777)
        with self.assertRaises(PathPolicyError):
            storage_mod.ensure_private_lock_root(parent / "global-lock-root")
        self.assertFalse((parent / "global-lock-root").exists())

    def test_preexisting_leaf_at_0770_is_tightened_to_0700(self) -> None:
        root = self.tmp / "global-lock-root-770"
        root.mkdir(mode=0o770)
        os.chmod(root, 0o770)
        storage_mod.ensure_private_lock_root(root)
        self.assertEqual(oct(stat.S_IMODE(root.stat().st_mode)), "0o700")

    def test_preexisting_leaf_at_0777_is_tightened_to_0700(self) -> None:
        root = self.tmp / "global-lock-root-777"
        root.mkdir(mode=0o777)
        os.chmod(root, 0o777)
        storage_mod.ensure_private_lock_root(root)
        self.assertEqual(oct(stat.S_IMODE(root.stat().st_mode)), "0o700")

    def test_preexisting_leaf_owned_by_different_uid_is_rejected(self) -> None:
        root = self.tmp / "global-lock-root-wronguid"
        root.mkdir(mode=0o700)
        with mock.patch("compat.provisioning.storage.os.getuid", return_value=os.getuid() + 1):
            with self.assertRaises(PathPolicyError):
                storage_mod.ensure_private_lock_root(root)

    def test_global_lock_root_swapped_between_open_and_flock_is_detected(self) -> None:
        global_lock_root = self.tmp / "global-lock-root-swap"
        state_root = self.tmp / "state_swap_root"
        renamed = self.tmp / "global-lock-root-swap.old"

        real_flock = fcntl.flock
        call_count = {"n": 0}

        def _flock_then_swap(fd, operation):
            call_count["n"] += 1
            if call_count["n"] == 1 and operation == (fcntl.LOCK_EX | fcntl.LOCK_NB):
                global_lock_root.rename(renamed)
                global_lock_root.mkdir(mode=0o700)
            return real_flock(fd, operation)

        with mock.patch("compat.provisioning.lock.fcntl.flock", side_effect=_flock_then_swap):
            with self.assertRaises(PathPolicyError):
                with lock_mod.acquire_provisioner_lock(
                    state_root, global_lock_root=global_lock_root, transaction_id="t", timeout=1.0
                ):
                    pass

    def test_second_process_via_swapped_global_lock_root_is_still_refused_via_state_root_flock(self) -> None:
        state_root = self.tmp / "state_secondary_lock"
        global_lock_root = self.tmp / "global-lock-root-secondary"
        ready = self.tmp / "ready_secondary.marker"
        go = self.tmp / "go_secondary.marker"
        script = self.tmp / "holder_secondary.py"
        script.write_text(
            "import sys\n"
            "sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from compat.provisioning.lock import acquire_provisioner_lock\n"
            "from tests.test_compat_transactional_provisioning import _fifo_open_reader, _fifo_signal, _fifo_wait\n"
            "state_root = Path(%r); global_lock_root = Path(%r)\n"
            "ready = Path(%r); go = Path(%r)\n"
            "go_fd = _fifo_open_reader(go)\n"
            "with acquire_provisioner_lock(state_root, global_lock_root=global_lock_root, transaction_id='holder', timeout=10.0):\n"
            "    _fifo_signal(ready)\n"
            "    _fifo_wait(go_fd, timeout=10.0, description='go marker')\n"
            % (str(ROOT), str(state_root), str(global_lock_root), str(ready), str(go))
        )
        _fifo_create(ready)
        _fifo_create(go)
        ready_fd = _fifo_open_reader(ready)

        proc = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(proc.wait)
        _fifo_wait(ready_fd, timeout=10.0, description="holder ready signal")
        os.close(ready_fd)

        # Swap global_lock_root WHILE the holder is active.
        renamed = self.tmp / "global-lock-root-secondary.old"
        global_lock_root.rename(renamed)
        global_lock_root.mkdir(mode=0o700)

        # A genuine second process, configured with the SAME state_root and
        # the SAME (now swapped) global_lock_root, gets its own independent
        # primary lock via the substitute directory -- but must still be
        # refused via the secondary flock directly on the real, unswapped
        # state_root directory.
        with self.assertRaises(ProvisionerLockHeldError):
            with lock_mod.acquire_provisioner_lock(
                state_root, global_lock_root=global_lock_root, transaction_id="contender", timeout=0.3
            ):
                pass

        _fifo_signal(go)
        stdout, stderr = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 0, "holder failed: stdout=%r stderr=%r" % (stdout, stderr))


class UnreadableUninstallJournalNeverReactivatesOwnershipTests(unittest.TestCase):
    """Point 4, sixth correction round, mandatory test: an uninstall journal
    that legitimately completed resource removal and reached
    ``REVOKING_OWNERSHIP`` (crash simulated before ownership was actually
    revoked, so the ownership record is still live) becomes unreadable
    (mode ``0644``, now rejected by the fail-closed private reads from the
    fifth round). If someone then recreates a file at the original path
    with matching content/hash, ``_capability_has_completed_uninstall`` must
    NOT silently skip the unreadable journal as irrelevant -- it must
    report ``UNKNOWN`` and deny authority, never letting the recreated file
    be reactivated as product-owned and removed."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def _prepare_and_stall_at_revoking_ownership(self, capability_id: str) -> tuple[Path, bytes]:
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        marker_content = marker_path.read_bytes()

        # Real uninstall loop: both resources are genuinely removed and
        # verified, the journal durably reaches REVOKING_OWNERSHIP -- then a
        # crash is simulated before ownership is ever actually revoked, so
        # the ownership record remains live on disk.
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        uninstall_transaction_id = "uninstall-%s" % capability_id
        plan = engine._build_uninstall_plan(capability_id, owned, transaction_id=uninstall_transaction_id)
        uninstall_journal = engine._initial_uninstall_journal(plan, now_value=_now())
        uninstall_journal = uninstall_journal.with_state(TransactionState.UNINSTALLING, now=_now())
        journal_mod.write_journal(self.harness.state_root, uninstall_journal)
        uninstall_journal, ok, residuals = engine._run_uninstall_loop(
            self.harness.state_root, uninstall_journal, self.harness.locked_context(),
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION,
        )
        self.assertTrue(ok, residuals)
        uninstall_journal = uninstall_journal.with_state(TransactionState.REVOKING_OWNERSHIP, now=_now())
        journal_mod.write_journal(self.harness.state_root, uninstall_journal)
        self.assertTrue(journal_mod.read_ownership_records(self.harness.state_root, capability_id))  # still live
        self.assertFalse(marker_path.exists())  # genuinely removed by the real loop above
        return marker_path, marker_content

    def _assert_reactivation_blocked(self, capability_id: str, marker_path: Path, marker_content: bytes) -> None:
        marker_path.write_bytes(marker_content)
        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertIn(result.status, (PrepareStatus.OWNERSHIP_INVALID, PrepareStatus.RECOVERY_REQUIRED))
        self.assertNotEqual(result.status, PrepareStatus.UNINSTALLED)
        self.assertTrue(marker_path.exists())
        self.assertEqual(marker_path.read_bytes(), marker_content)

    def test_uninstall_journal_chmod_0644_blocks_reactivation_of_recreated_resource(self) -> None:
        capability_id = "cap_unreadable_uninstall_journal"
        marker_path, marker_content = self._prepare_and_stall_at_revoking_ownership(capability_id)
        uninstall_journal_path = journal_mod.transaction_path(self.harness.state_root, "uninstall-%s" % capability_id)
        os.chmod(uninstall_journal_path, 0o644)
        self._assert_reactivation_blocked(capability_id, marker_path, marker_content)

    def test_uninstall_journal_hardlinked_blocks_reactivation_of_recreated_resource(self) -> None:
        capability_id = "cap_hardlinked_uninstall_journal"
        marker_path, marker_content = self._prepare_and_stall_at_revoking_ownership(capability_id)
        uninstall_journal_path = journal_mod.transaction_path(self.harness.state_root, "uninstall-%s" % capability_id)
        victim = self.tmp / "victim_uninstall_journal_hardlink.json"
        os.link(uninstall_journal_path, victim)
        self._assert_reactivation_blocked(capability_id, marker_path, marker_content)

    def test_uninstall_journal_corrupt_json_blocks_reactivation_of_recreated_resource(self) -> None:
        capability_id = "cap_corrupt_uninstall_journal"
        marker_path, marker_content = self._prepare_and_stall_at_revoking_ownership(capability_id)
        uninstall_journal_path = journal_mod.transaction_path(self.harness.state_root, "uninstall-%s" % capability_id)
        uninstall_journal_path.write_bytes(b"{not valid json")
        os.chmod(uninstall_journal_path, 0o600)
        self._assert_reactivation_blocked(capability_id, marker_path, marker_content)

    def test_uninstall_journal_wrong_uid_blocks_reactivation_of_recreated_resource(self) -> None:
        capability_id = "cap_wrong_uid_uninstall_journal"
        marker_path, marker_content = self._prepare_and_stall_at_revoking_ownership(capability_id)
        with mock.patch("compat.provisioning.storage.os.getuid", return_value=os.getuid() + 1):
            self._assert_reactivation_blocked(capability_id, marker_path, marker_content)

    def test_uninstall_journal_oversized_blocks_reactivation_of_recreated_resource(self) -> None:
        capability_id = "cap_oversized_uninstall_journal"
        marker_path, marker_content = self._prepare_and_stall_at_revoking_ownership(capability_id)
        uninstall_journal_path = journal_mod.transaction_path(self.harness.state_root, "uninstall-%s" % capability_id)
        uninstall_journal_path.write_bytes(b"{" + b" " * (storage_mod.MAX_PRIVATE_FILE_SIZE + 1) + b"}")
        os.chmod(uninstall_journal_path, 0o600)
        self._assert_reactivation_blocked(capability_id, marker_path, marker_content)


class HashUnlinkToctouTests(unittest.TestCase):
    """Point 3, fifth correction round, mandatory multiprocess test:
    process A opens and hashes an owned resource; before the actual
    unlink, process B substitutes the basename for a foreign file. A must
    detect the substitution (re-verified identity right before the unlink
    diverges from what was just hashed) and refuse to remove it -- the
    foreign file must survive untouched, no false ``UNINSTALLED``, and the
    step must fail as ``ownership_drift``/``recovery_required``."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.harness = _Harness(self.tmp)

    def test_concurrent_substitution_between_hash_and_unlink_is_refused(self) -> None:
        capability_id = "cap_toctou_hash_unlink"
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        original_content = marker_path.read_bytes()

        ready = self.tmp / "toctou_ready.marker"
        go = self.tmp / "toctou_go.marker"
        result_file = self.tmp / "toctou_result.json"
        script = self.tmp / "holder_toctou.py"
        script.write_text(
            "import sys, json\n"
            "sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from compat.provisioning import engine, paths as paths_mod\n"
            "from compat.provisioning.executors import CANARY_EXECUTOR_VERSION, CANARY_METHOD_KIND, CanaryExecutor, ExecutionContext, TrustedExecutorRegistry\n"
            "from tests.test_compat_transactional_provisioning import _fifo_open_reader, _fifo_signal, _fifo_wait\n"
            "state_root = Path(%r); sandbox = Path(%r); global_lock_root = Path(%r)\n"
            "ready = Path(%r); go = Path(%r); result_file = Path(%r)\n"
            "go_fd = _fifo_open_reader(go)\n"
            "registry = TrustedExecutorRegistry()\n"
            "registry.register(method_kind=CANARY_METHOD_KIND, method_id='canary_method', executor=CanaryExecutor())\n"
            "context = ExecutionContext(allowed_roots=(sandbox,), now=lambda: '2026-01-01T00:00:00+00:00')\n"
            "env = engine.ProvisioningEnvironment(\n"
            "    state_root=state_root, registry=registry, expected_executor_version=CANARY_EXECUTOR_VERSION,\n"
            "    context=context, global_lock_root=global_lock_root,\n"
            ")\n"
            "def _pause():\n"
            "    _fifo_signal(ready)\n"
            "    _fifo_wait(go_fd, timeout=10.0, description='go marker')\n"
            "paths_mod.UNLINK_REVERIFY_HOOK = _pause\n"
            "result = engine.uninstall(%r, env, apply=True)\n"
            "result_file.write_text(json.dumps({'status': result.status.value, 'error_kind': result.error_kind, 'residuals': list(result.residuals)}))\n"
            % (
                str(ROOT), str(self.harness.state_root), str(self.harness.sandbox), str(self.harness.global_lock_root),
                str(ready), str(go), str(result_file), capability_id,
            )
        )

        _fifo_create(ready)
        _fifo_create(go)
        ready_fd = _fifo_open_reader(ready)

        proc = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(proc.wait)
        _fifo_wait(ready_fd, timeout=10.0, description="holder (process A) ready signal")
        os.close(ready_fd)

        # Process B: substitutes the basename for a foreign file, strictly
        # between A's own hash verification and its final re-verify+unlink.
        marker_path.unlink()
        marker_path.write_bytes(b"foreign content planted by process B")

        _fifo_signal(go)
        stdout, stderr = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 0, "process A failed: stdout=%r stderr=%r" % (stdout, stderr))
        self.assertTrue(result_file.exists())
        result = json.loads(result_file.read_text())

        self.assertNotEqual(result["status"], PrepareStatus.UNINSTALLED.value)
        self.assertIn(result["status"], (PrepareStatus.UNINSTALL_FAILED.value, PrepareStatus.RECOVERY_REQUIRED.value))
        # The foreign file must survive, completely untouched.
        self.assertTrue(marker_path.exists())
        self.assertEqual(marker_path.read_bytes(), b"foreign content planted by process B")
        self.assertNotEqual(marker_path.read_bytes(), original_content)
        # Ownership must still be live -- never silently revoked.
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        self.assertTrue(any(r.product_owned for r in records))

class RoundSevenQuarantineProtocolTests(unittest.TestCase):
    """Round 7: deletion is tied to the verified inode and post-move
    content, quarantine/restore use no-replace semantics, and unsafe
    residues stay recoverable."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)
        self.root = self.tmp / "root"
        self.root.mkdir(mode=0o700)

    def _handle(self) -> AllowedRootHandle:
        handle = open_allowed_root(self.root)
        self.addCleanup(handle.close)
        return handle

    def _restore_hooks(self) -> None:
        paths_mod.UNLINK_REVERIFY_HOOK = paths_mod._default_unlink_pause
        paths_mod.QUARANTINE_POST_VERIFY_HOOK = paths_mod._default_unlink_pause
        paths_mod.QUARANTINE_BEFORE_RESTORE_HOOK = paths_mod._default_unlink_pause
        paths_mod.QUARANTINE_NAME_FACTORY = paths_mod._default_quarantine_name

    def test_quarantine_entry_substitution_before_unlink_preserves_foreign_inode(self) -> None:
        self.addCleanup(self._restore_hooks)
        target = self.root / "owned"
        target.write_bytes(b"owned")
        quarantine = self.root / ".wdvpn-quarantine.owned.test"
        paths_mod.QUARANTINE_NAME_FACTORY = lambda basename: quarantine.name

        def _replace_quarantine() -> None:
            quarantine.unlink()
            quarantine.write_bytes(b"foreign")

        paths_mod.QUARANTINE_POST_VERIFY_HOOK = _replace_quarantine
        with self.assertRaises(PathPolicyError):
            paths_mod.remove_file_if_owned_relative(
                self._handle(), target, expected_sha256=hashlib.sha256(b"owned").hexdigest()
            )
        self.assertTrue(quarantine.exists())
        self.assertEqual(quarantine.read_bytes(), b"foreign")
        self.assertFalse(target.exists())

    def test_in_place_modification_after_initial_hash_leaves_quarantine_residue(self) -> None:
        self.addCleanup(self._restore_hooks)
        target = self.root / "owned"
        target.write_bytes(b"owned")
        quarantine = self.root / ".wdvpn-quarantine.owned.test"
        paths_mod.QUARANTINE_NAME_FACTORY = lambda basename: quarantine.name

        def _mutate_in_place() -> None:
            with target.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"pwned")
                handle.truncate()

        paths_mod.UNLINK_REVERIFY_HOOK = _mutate_in_place
        with self.assertRaises(PathPolicyError):
            paths_mod.remove_file_if_owned_relative(
                self._handle(), target, expected_sha256=hashlib.sha256(b"owned").hexdigest()
            )
        self.assertTrue(quarantine.exists())
        self.assertEqual(quarantine.read_bytes(), b"pwned")

    def test_restore_uses_noreplace_when_basename_reappears(self) -> None:
        self.addCleanup(self._restore_hooks)
        target = self.root / "owned"
        target.write_bytes(b"owned")
        quarantine = self.root / ".wdvpn-quarantine.owned.test"
        paths_mod.QUARANTINE_NAME_FACTORY = lambda basename: quarantine.name

        def _swap_original_before_quarantine() -> None:
            target.unlink()
            target.write_bytes(b"foreign")

        def _basename_reappears_before_restore() -> None:
            if not target.exists():
                target.write_bytes(b"new-basename")

        paths_mod.UNLINK_REVERIFY_HOOK = _swap_original_before_quarantine
        paths_mod.QUARANTINE_BEFORE_RESTORE_HOOK = _basename_reappears_before_restore
        with self.assertRaises(PathPolicyError):
            paths_mod.remove_file_if_owned_relative(
                self._handle(), target, expected_sha256=hashlib.sha256(b"owned").hexdigest()
            )
        self.assertTrue(quarantine.exists())
        self.assertTrue(target.exists())
        self.assertNotEqual(target.read_bytes(), b"owned")

    def test_quarantine_name_collision_is_rejected_without_replacement(self) -> None:
        self.addCleanup(self._restore_hooks)
        target = self.root / "owned"
        target.write_bytes(b"owned")
        quarantine = self.root / ".wdvpn-quarantine.owned.test"
        quarantine.write_bytes(b"preexisting")
        paths_mod.QUARANTINE_NAME_FACTORY = lambda basename: quarantine.name
        with self.assertRaises(PathPolicyError):
            paths_mod.remove_file_if_owned_relative(
                self._handle(), target, expected_sha256=hashlib.sha256(b"owned").hexdigest()
            )
        self.assertEqual(quarantine.read_bytes(), b"preexisting")
        self.assertTrue(target.exists())

    def test_restore_failure_keeps_quarantine_residue(self) -> None:
        self.addCleanup(self._restore_hooks)
        target = self.root / "owned"
        target.write_bytes(b"owned")
        quarantine = self.root / ".wdvpn-quarantine.owned.test"
        paths_mod.QUARANTINE_NAME_FACTORY = lambda basename: quarantine.name

        def _swap_original_before_quarantine() -> None:
            target.unlink()
            target.write_bytes(b"foreign")

        def _force_restore_collision() -> None:
            target.write_bytes(b"occupied")

        paths_mod.UNLINK_REVERIFY_HOOK = _swap_original_before_quarantine
        paths_mod.QUARANTINE_BEFORE_RESTORE_HOOK = _force_restore_collision
        with self.assertRaises(PathPolicyError):
            paths_mod.remove_file_if_owned_relative(
                self._handle(), target, expected_sha256=hashlib.sha256(b"owned").hexdigest()
            )
        self.assertTrue(quarantine.exists())
        self.assertEqual(target.read_bytes(), b"occupied")


class NestedAllowedRootPathTests(unittest.TestCase):
    """Point 2, fifth correction round, "intermediate subdirectory
    replaced" variant: descendant resolution walks intermediate components
    relative to the handle -- a swap of an INTERMEDIATE directory (not the
    allowed root itself) after the handle was captured must also fail
    closed, never silently follow whatever now sits at that name."""

    def setUp(self) -> None:
        self._tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp_ctx.name)
        self.addCleanup(self._tmp_ctx.cleanup)

    def test_intermediate_subdirectory_replaced_after_handle_open_is_rejected(self) -> None:
        root = self.tmp / "root"
        root.mkdir(mode=0o700)
        (root / "subdir").mkdir(mode=0o700)
        handle = open_allowed_root(root)
        self.addCleanup(handle.close)
        target = root / "subdir" / "file.marker"
        validated = validate_target_path(target, allowed_roots=(root,))

        # Swap the INTERMEDIATE directory for a symlink to an empty decoy,
        # strictly after the handle was opened but before the write.
        decoy = self.tmp / "decoy"
        decoy.mkdir()
        os.rmdir(root / "subdir")
        (root / "subdir").symlink_to(decoy)

        with self.assertRaises(PathPolicyError):
            paths_mod.create_file_exclusive_relative(handle, validated, b"data")
        self.assertEqual(sorted(decoy.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
