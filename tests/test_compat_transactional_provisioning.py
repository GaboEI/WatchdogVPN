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
import json
import os
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
from compat.provisioning.paths import canary_forbidden_roots, validate_target_path

ROOT = Path(__file__).resolve().parents[1]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        self.sandbox.mkdir()
        self.state_root = tmp / "state"
        self.executor = CanaryExecutor(requires_network=requires_network)
        self.registry = TrustedExecutorRegistry()
        self.registry.register(method_kind=CANARY_METHOD_KIND, method_id="canary_method", executor=self.executor)
        self.context = ExecutionContext(allowed_roots=(self.sandbox,), now=_now, forbidden_roots=forbidden_roots)
        self.env = ProvisioningEnvironment(
            state_root=self.state_root, registry=self.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.context
        )

    def decision(self, capability_id: str = "cap_test", **kwargs) -> ResolutionDecision:
        return _decision(capability_id, **kwargs)


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
        lock_path = journal_mod.lock_path(self.harness.state_root)
        holder_script = self.tmp / "holder.py"
        holder_script.write_text(
            "import sys, time\n"
            "sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from compat.provisioning.lock import acquire_provisioner_lock\n"
            "with acquire_provisioner_lock(Path(%r), transaction_id='holder', timeout=2.0):\n"
            "    print('ACQUIRED', flush=True)\n"
            "    time.sleep(1.5)\n" % (str(ROOT), str(lock_path))
        )
        proc = subprocess.Popen([sys.executable, str(holder_script)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.stdout.close)
        line = proc.stdout.readline()
        self.assertEqual(line.strip(), "ACQUIRED")
        with self.assertRaises(ProvisionerLockHeldError) as ctx:
            with lock_mod.acquire_provisioner_lock(lock_path, transaction_id="contender", timeout=0.3):
                pass
        self.assertIsNotNone(ctx.exception.holder_pid)
        proc.wait(5)

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
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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
        result = executor.apply_step(record, self.harness.context)  # really writes the file
        self.assertEqual(result.status, "applied")
        # Crash simulated here: undo_record/APPLIED transition never got journaled.
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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
        for step in plan.steps:
            record = journal.step(step.sequence).with_state(StepState.APPLYING, started_at=_now(), before_state={"exists": False})
            journal = journal.with_step(record)
            result = executor.apply_step(record, self.harness.context)
            record = record.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result.undo_record)
            journal = journal.with_step(record)
            record = record.with_state(StepState.VERIFYING)
            journal = journal.with_step(record)
            verification = executor.verify_step(record, result, self.harness.context)
            record = record.with_state(StepState.VERIFIED, completed_at=_now(), verification=verification.evidence)
            journal = journal.with_step(record)
        journal = journal.with_state(TransactionState.VERIFYING, now=_now())
        # Crash simulated here: postcondition/commit never got journaled.
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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
        result = executor.apply_step(record, self.harness.context)
        record = record.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result.undo_record)
        journal = journal.with_step(record)
        record = record.with_state(StepState.VERIFYING)
        journal = journal.with_step(record)
        verification = executor.verify_step(record, result, self.harness.context)
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
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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
        with lock_mod.acquire_provisioner_lock(journal_mod.lock_path(self.harness.state_root), transaction_id="perm-check", timeout=1.0):
            lock_file = journal_mod.lock_path(self.harness.state_root)
            self.assertEqual(oct(stat.S_IMODE(lock_file.stat().st_mode)), "0o600")
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
        with mock.patch("compat.provisioning.paths.fsync_parent_directory", side_effect=DurabilityError("boom")):
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
        result = executor.apply_step(record, self.harness.context)
        target_path = Path(result.observed["path"])
        hardlink = target_path.with_name(target_path.name + ".hardlink")
        os.link(target_path, hardlink)
        self.addCleanup(lambda: hardlink.unlink(missing_ok=True))
        verification = executor.verify_step(record, result, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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
        journal, apply_ok, _durability_unknown = engine._apply_and_verify(self.harness.state_root, journal, plan, executor, self.harness.context)
        self.assertTrue(apply_ok)
        self.assertEqual(journal.state, TransactionState.VERIFYING)
        engine._finalize_provenance(self.harness.state_root, journal, plan, executor, self.harness.context, _now())
        journal_mod.write_journal(self.harness.state_root, journal)  # crash: still VERIFYING, never COMMITTED

        result = engine.uninstall("cap_precommit", self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.OWNERSHIP_INVALID)


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

    def _assert_uid_gid_mode_tamper_alone_is_refused_via_drift(self, capability_id: str, mutate_candidate) -> None:
        # Authority is a purely structural/digest check (path, hash, method,
        # executor, transaction) -- it deliberately never re-stats the live
        # filesystem (see validate_ownership_authority's docstring), so a
        # uid/gid/mode-only tamper of the persisted record does not by
        # itself change WHICH resource is being claimed and still passes
        # authority. It must still never be able to cause an actual unlink:
        # the real, untouched file's identity diverges from the tampered
        # record, and _detect_ownership_drift refuses the removal.
        self._prepare_committed(capability_id)
        records = journal_mod.read_ownership_records(self.harness.state_root, capability_id)
        tampered = [dataclasses.replace(r, candidate=mutate_candidate(r.candidate)) for r in records]
        journal_mod.write_ownership_records(self.harness.state_root, capability_id, tampered)
        self.assertTrue(engine.validate_ownership_authority(
            self.harness.state_root, capability_id, tampered,
            registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context,
        ))
        result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.UNINSTALL_FAILED)
        self.assertTrue(result.residuals)
        self.assertTrue((self.harness.sandbox / ("%s.marker" % capability_id)).exists())

    def test_tampering_only_uid_is_refused_via_drift_detection(self) -> None:
        self._assert_uid_gid_mode_tamper_alone_is_refused_via_drift(
            "cap_tamper_uid_only", lambda c: dataclasses.replace(c, uid=c.uid + 1)
        )

    def test_tampering_only_gid_is_refused_via_drift_detection(self) -> None:
        self._assert_uid_gid_mode_tamper_alone_is_refused_via_drift(
            "cap_tamper_gid_only", lambda c: dataclasses.replace(c, gid=c.gid + 1)
        )

    def test_tampering_only_mode_is_refused_via_drift_detection(self) -> None:
        self._assert_uid_gid_mode_tamper_alone_is_refused_via_drift(
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
        lock_path = journal_mod.lock_path(self.harness.state_root)
        with lock_mod.acquire_provisioner_lock(lock_path, transaction_id="holder", timeout=1.0):
            with self.assertRaises(ProvisionerLockHeldError):
                engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context, lock_timeout=0.2)

    def test_internal_recover_pending_locked_does_not_acquire_the_lock(self) -> None:
        lock_path = journal_mod.lock_path(self.harness.state_root)
        holder_script = self.tmp / "holder.py"
        holder_script.write_text(
            "import sys, time\n"
            "sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from compat.provisioning.lock import acquire_provisioner_lock\n"
            "with acquire_provisioner_lock(Path(%r), transaction_id='holder', timeout=2.0):\n"
            "    print('ACQUIRED', flush=True)\n"
            "    time.sleep(1.5)\n" % (str(ROOT), str(lock_path))
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
            proc.wait(5)


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
        plan = engine._build_uninstall_plan(capability_id, owned)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

    def _parse(self, *argv: str):
        import tools.compat_provision as compat_provision_tool

        return compat_provision_tool, compat_provision_tool.build_parser().parse_args(
            ["--lab-root", str(self.lab_root), "--sandbox", str(self.sandbox), "--state-root", str(self.state_root), *argv]
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
        plan = engine._build_uninstall_plan(capability_id, owned)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)
        journal, ok, residuals = engine._run_uninstall_loop(
            self.harness.state_root, journal, self.harness.context,
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
        plan = engine._build_uninstall_plan(capability_id, owned)
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
        plan = engine._build_uninstall_plan(capability_id, owned)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        tampered_snapshot = tuple(
            dataclasses.replace(r, candidate=dataclasses.replace(r.candidate, integrity="0" * 64)) for r in journal.owned_snapshot
        )
        journal = dataclasses.replace(journal, owned_snapshot=tampered_snapshot)
        journal_mod.write_journal(self.harness.state_root, journal)

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        self.assertTrue((self.harness.sandbox / ("%s.marker" % capability_id)).exists())

    def test_crash_after_all_verified_before_revoking_ownership_recovers_cleanly(self) -> None:
        capability_id = "cap_revoke_pre"
        self._prepare_committed(capability_id)
        journal = self._uninstall_journal_at_revoking_ownership(capability_id)
        self.assertEqual(list(journal_mod.read_ownership_records(self.harness.state_root, capability_id)), journal_mod.read_ownership_records(self.harness.state_root, capability_id))
        self.assertTrue(journal_mod.read_ownership_records(self.harness.state_root, capability_id))  # still live: crash simulated here

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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
        plan = engine._build_uninstall_plan(capability_id, owned)
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
        plan = engine._build_uninstall_plan(capability_id, owned)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        journal_mod.write_journal(self.harness.state_root, journal)
        journal, ok, residuals = engine._run_uninstall_loop(
            self.harness.state_root, journal, self.harness.context,
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
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

    def _find_uninstall_transaction_id(self, capability_id: str) -> str:
        for transaction_id in journal_mod.list_transaction_ids(self.harness.state_root):
            candidate = journal_mod.read_journal(self.harness.state_root, transaction_id)
            if candidate.operation == "uninstall" and candidate.capability_id == capability_id:
                return transaction_id
        raise AssertionError("no uninstall journal found for %s" % capability_id)

    def test_uninstall_never_reaches_uninstalled_when_revocation_durability_fails(self) -> None:
        # Note: the PrepareOutcome.transaction_id returned by uninstall() is
        # the outer provisioner-lock's id, not the uninstall journal's own
        # (a separate uuid minted inside _build_uninstall_plan) -- the
        # journal is located by scanning for it directly.
        capability_id = "cap_revoke_durability_full"
        outcome = engine.prepare(self.harness.decision(capability_id), self.harness.env, apply=True)
        self.assertEqual(outcome.status, PrepareStatus.COMMITTED)

        with mock.patch("compat.provisioning.journal.fsync_parent_directory", side_effect=DurabilityError("boom")):
            result = engine.uninstall(capability_id, self.harness.env, apply=True)
        self.assertEqual(result.status, PrepareStatus.UNINSTALL_FAILED)
        self.assertEqual(result.error_kind, "ownership_revocation_failed")

        uninstall_transaction_id = self._find_uninstall_transaction_id(capability_id)
        final = journal_mod.read_journal(self.harness.state_root, uninstall_transaction_id)
        self.assertEqual(final.state, TransactionState.UNINSTALL_FAILED)

        # Recovery must still be able to pick this up cleanly once the
        # durability problem is gone (idempotent revoke: the file may
        # already be unlinked for real).
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
        self.assertEqual(reports[0].action, RecoveryAction.REQUIRE_MANUAL)
        recovered = journal_mod.read_journal(self.harness.state_root, uninstall_transaction_id)
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
        victim = self.tmp / "victim.txt"
        victim.write_bytes(b"do not touch me")
        os.chmod(victim, 0o644)  # explicit, umask-independent starting mode
        lock_path = self.tmp / "provisioner.lock"
        lock_path.symlink_to(victim)
        with self.assertRaises(PathPolicyError):
            with lock_mod.acquire_provisioner_lock(lock_path, transaction_id="t", timeout=0.2):
                pass
        self.assertEqual(victim.read_bytes(), b"do not touch me")
        self.assertEqual(oct(stat.S_IMODE(victim.stat().st_mode)), "0o644")  # never fchmod'd

    def test_lock_path_is_a_directory_is_rejected(self) -> None:
        lock_path = self.tmp / "provisioner.lock"
        lock_path.mkdir()
        with self.assertRaises(PathPolicyError):
            with lock_mod.acquire_provisioner_lock(lock_path, transaction_id="t", timeout=0.2):
                pass

    def test_lock_path_is_a_hardlink_is_rejected_and_victim_survives(self) -> None:
        victim = self.tmp / "victim2.txt"
        victim.write_bytes(b"hardlink victim")
        lock_path = self.tmp / "provisioner.lock"
        os.link(victim, lock_path)
        with self.assertRaises(PathPolicyError):
            with lock_mod.acquire_provisioner_lock(lock_path, transaction_id="t", timeout=0.2):
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
        result0 = executor.apply_step(record0, self.harness.context)
        record0 = record0.with_state(StepState.APPLIED, completed_at=_now(), undo_record=result0.undo_record)
        journal = journal.with_step(record0)
        record0 = record0.with_state(StepState.VERIFYING)
        journal = journal.with_step(record0)
        verification0 = executor.verify_step(record0, result0, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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

        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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
            reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
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
        real_stat_identity = paths_mod.stat_identity

        def _faked_stat_identity(path):
            identity = dict(real_stat_identity(path))
            if str(path).endswith(".marker"):
                identity["uid"] = identity["uid"] + 1
            return identity

        def _tampered_verify_postcondition(plan_arg, context_arg):
            with mock.patch("compat.provisioning.executors.stat_identity", side_effect=_faked_stat_identity):
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
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        for step in plan.steps:
            path = Path(step.target)
            path.write_bytes(step.intent["content"].encode("ascii"))
            os.chmod(path, 0o644)
        result = executor.verify_postcondition(plan, self.harness.context)
        self.assertEqual(result.status, "verification_failed")
        self.assertEqual(result.error_kind, "unexpected_mode")

    def test_verify_postcondition_rejects_unexpected_uid_via_faked_identity(self) -> None:
        capability_id = "cap_postcond_uid_direct"
        decision = self.harness.decision(capability_id)
        plan, executor = engine.build_plan(decision, registry=self.harness.registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=self.harness.context)
        for step in plan.steps:
            path = Path(step.target)
            path.write_bytes(step.intent["content"].encode("ascii"))
            os.chmod(path, 0o600)
        real_stat_identity = paths_mod.stat_identity

        def _faked_stat_identity(path):
            identity = dict(real_stat_identity(path))
            identity["uid"] = identity["uid"] + 1
            return identity

        with mock.patch("compat.provisioning.executors.stat_identity", side_effect=_faked_stat_identity):
            result = executor.verify_postcondition(plan, self.harness.context)
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
        with mock.patch("compat.provisioning.paths.fsync_parent_directory", side_effect=DurabilityError("boom")):
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
        reports = engine.recover_pending(self.harness.state_root, self.harness.registry, CANARY_EXECUTOR_VERSION, self.harness.context)
        self.assertEqual(reports[0].action, RecoveryAction.RESUME)
        final = journal_mod.read_journal(self.harness.state_root, outcome.transaction_id)
        self.assertEqual(final.state, TransactionState.COMMITTED)
        self.assertTrue(marker_path.exists())
        records = journal_mod.read_ownership_records(self.harness.state_root, "cap_durability_full")
        self.assertEqual(len(records), 2)

    def test_durability_failure_during_undo_never_reports_a_clean_undone(self) -> None:
        decision = self.harness.decision(capability_id="cap_durability_undo")
        with mock.patch.object(self.harness.executor, "verify_step", return_value=VerificationResult(status="verification_failed", error_kind="forced", error="forced")):
            with mock.patch("compat.provisioning.paths.fsync_parent_directory", side_effect=DurabilityError("boom during undo")):
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
        # check -- bypassing it removes that cross-version ambiguity.
        capability_id = "cap_err_inspect"
        self._committed(capability_id)
        marker_path = self.harness.sandbox / ("%s.marker" % capability_id)
        record = journal_mod.StepRecord(sequence=0, step_id="s", action_type="create_file", state=StepState.PLANNED, intent={"content_sha256": "0" * 64}, target=str(marker_path))
        with mock.patch("compat.provisioning.executors.validate_target_path", side_effect=lambda path, **kw: Path(path)):
            with mock.patch("pathlib.Path.lstat", side_effect=PermissionError(errno.EACCES, "Permission denied")):
                observed = self.harness.executor.inspect_step(record, self.harness.context)
        self.assertIsNone(observed["exists"])
        self.assertIn("inspect_error", observed)

    def test_uninstall_loop_never_reports_verified_when_applying_stat_raises_permission_error(self) -> None:
        capability_id = "cap_err_uninstall_verify"
        self._committed(capability_id)
        owned = [r for r in journal_mod.read_ownership_records(self.harness.state_root, capability_id) if r.product_owned]
        plan = engine._build_uninstall_plan(capability_id, owned)
        journal = engine._initial_uninstall_journal(plan, now_value=_now())
        journal = journal.with_state(TransactionState.UNINSTALLING, now=_now())
        marker_index = next(i for i, s in enumerate(journal.steps) if s.intent["resource_identity"].endswith(".marker"))
        marker_str = journal.steps[marker_index].intent["resource_identity"]
        real_lstat = os.lstat

        def faulty_lstat(path, *a, **kw):
            if str(path) == marker_str:
                raise OSError(errno.EIO, "Input/output error")
            return real_lstat(path, *a, **kw)

        with mock.patch("compat.provisioning.engine.validate_target_path", side_effect=lambda path, **kw: Path(path)):
            with mock.patch("compat.provisioning.engine.os.lstat", side_effect=faulty_lstat):
                journal, ok, residuals = engine._run_uninstall_loop(
            self.harness.state_root, journal, self.harness.context,
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
        plan = engine._build_uninstall_plan(capability_id, owned)
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

        real_lstat = os.lstat

        def faulty_lstat(path, *a, **kw):
            if str(path) == marker_str:
                raise OSError(errno.ESTALE, "Stale file handle")
            return real_lstat(path, *a, **kw)

        with mock.patch("compat.provisioning.engine.validate_target_path", side_effect=lambda path, **kw: Path(path)):
            with mock.patch("compat.provisioning.engine.os.lstat", side_effect=faulty_lstat):
                journal, ok, residuals = engine._run_uninstall_loop(
            self.harness.state_root, journal, self.harness.context,
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
        journal, apply_ok, durability_unknown = engine._apply_and_verify(self.harness.state_root, journal, plan, executor, self.harness.context)
        self.assertTrue(apply_ok)
        self.assertFalse(durability_unknown)

        with mock.patch("compat.provisioning.engine.stat_identity", side_effect=OSError(errno.EIO, "boom")):
            with self.assertRaises(Exception):
                engine._finalize_provenance(self.harness.state_root, journal, plan, executor, self.harness.context, _now())
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

    def _run(self, *, lab_root=None, sandbox=None, state_root=None, mutating: bool = True):
        import tools.compat_provision as compat_provision_tool

        lab_root = str(self.lab_root if lab_root is None else lab_root)
        sandbox = str(self.good_sandbox if sandbox is None else sandbox)
        state_root = str(self.good_state_root if state_root is None else state_root)
        parser = compat_provision_tool.build_parser()
        argv = ["--lab-root", lab_root, "--sandbox", sandbox, "--state-root", state_root]
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


if __name__ == "__main__":
    unittest.main()
