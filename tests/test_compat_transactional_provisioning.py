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

from compat.dependency_resolution import ResolutionDecision
from compat.provisioning import engine, journal as journal_mod, lock as lock_mod
from compat.provisioning.engine import PrepareStatus, ProvisioningEnvironment
from compat.provisioning.errors import InvalidTransitionError, PathPolicyError, ProvisionerLockHeldError
from compat.provisioning.executors import (
    CANARY_EXECUTOR_VERSION,
    CANARY_METHOD_KIND,
    CanaryExecutor,
    ExecutionContext,
    TrustedExecutorRegistry,
    _companion_content,
    _marker_content,
)
from compat.provisioning.digest import compute_plan_digest
from compat.provisioning.model import (
    RecoveryAction,
    StepState,
    TransactionState,
    VerificationResult,
    transition_step,
    transition_transaction,
)
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


if __name__ == "__main__":
    unittest.main()
