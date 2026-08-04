"""L1 tests for Task 23.7.5.6b AmneziaWG userspace provisioning."""

from __future__ import annotations

import getpass
import hashlib
import importlib.util
import io
import json
import os
import stat
from pathlib import Path
import tempfile
from types import SimpleNamespace
from contextlib import redirect_stdout
import unittest

from compat import detection
from compat.dependency_resolution import ResolutionDecision
from compat.provisioning import engine, journal as journal_mod
from compat.provisioning.amneziawg import (
    AMNEZIAWG_OUTPUTS,
    AMNEZIAWG_SOURCE_BUILD_EXECUTOR_VERSION,
    AMNEZIAWG_SOURCE_BUILD_METHOD_KIND,
    AmneziaWGUserspaceSourceBuildExecutor,
    SourceComponent,
)
from compat.provisioning.executors import ExecutionContext, TrustedExecutorRegistry
from compat.provisioning.model import TransactionState
from compat.provisioning.paths import LAB_CUSTODY_ISOLATION_POLICY
from compat.provisioning.process import CommandResult, CommandRunner
from tools import compat_runtime_prepare


TOOLS_REVISION = "61e741780e8465a67a7d7fb6cffe14a8a15d624a"
GO_REVISION = "0527dfa47639714dd8f5c9ffbd9d40d19083f0ba"
VM_HARNESS = Path(__file__).resolve().parent / "vm" / "phase23_7_5_6b_amneziawg_validation.py"


class FakeRunner(CommandRunner):
    def __init__(self, *, wrong_commit: bool = False) -> None:
        self.calls = []
        self.wrong_commit = wrong_commit

    def run(self, argv, *, cwd=None, env=None, run_as_user=None, timeout=120.0):
        argv = tuple(argv)
        self.calls.append({"argv": argv, "env": dict(env or {}), "run_as_user": run_as_user})
        if argv[:2] == ("git", "init"):
            Path(argv[2]).mkdir(parents=True, exist_ok=True)
            return CommandResult(argv, None, 0, "", "")
        if argv[:2] == ("git", "-C") and argv[3] in {"remote", "fetch", "checkout"}:
            return CommandResult(argv, None, 0, "", "")
        if argv[:2] == ("git", "-C") and argv[3:] == ("rev-parse", "HEAD"):
            worktree = argv[2]
            if self.wrong_commit:
                return CommandResult(argv, None, 0, "0" * 40 + "\n", "")
            if worktree.endswith("amneziawg_tools"):
                return CommandResult(argv, None, 0, TOOLS_REVISION + "\n", "")
            return CommandResult(argv, None, 0, GO_REVISION + "\n", "")
        if argv[0] == "make" and "amneziawg_tools/src" in argv[2]:
            src = Path(argv[2])
            (src / "wg-quick").mkdir(parents=True, exist_ok=True)
            (src / "wg").write_bytes(b"fake-awg-binary")
            (src / "wg-quick" / "linux.bash").write_bytes(b"#!/bin/sh\nexec awg \"$@\"\n")
            return CommandResult(argv, None, 0, "built tools\n", "")
        if argv[0] == "make" and argv[2].endswith("amneziawg_transport"):
            worktree = Path(argv[2])
            worktree.mkdir(parents=True, exist_ok=True)
            (worktree / "amneziawg-go").write_bytes(b"fake-amneziawg-go")
            return CommandResult(argv, None, 0, "built transport\n", "")
        return CommandResult(argv, None, 1, "", "unexpected argv")


def _components() -> tuple[SourceComponent, ...]:
    return (
        SourceComponent(
            "amneziawg_tools",
            "https://github.com/amnezia-vpn/amneziawg-tools",
            "v1.0.20260618-2",
            TOOLS_REVISION,
            ("awg", "awg-quick"),
        ),
        SourceComponent(
            "amneziawg_transport",
            "https://github.com/amnezia-vpn/amneziawg-go",
            "v3.0.2",
            GO_REVISION,
            ("amneziawg-go",),
        ),
    )


def _decision() -> ResolutionDecision:
    return ResolutionDecision(
        capability_id="proto_amneziawg_runtime",
        dependency_id="dep_amneziawg_runtime",
        resolved_distribution="debian",
        resolved_release="debian_13",
        technical_family="debian_apt",
        release_model="stable",
        support_classification="supported",
        machine_architecture="x86_64",
        observed_capability_status="absent",
        candidate_chain=("amneziawg_pinned_source_build_apt_stable_future",),
        selected_method_id="amneziawg_pinned_source_build_apt_stable_future",
        selected_method_kind=AMNEZIAWG_SOURCE_BUILD_METHOD_KIND,
        resolution_status="method_selected",
        execution_ready=True,
        rejected_candidates=(),
        evidence=("fixture source revision available",),
        reason="fixture",
        provider_type="fixture",
        provider_authoritative=True,
        availability_observations=(),
        all_availability_observations=(),
    )


class AmneziaWGProvisioningTests(unittest.TestCase):
    def _env(self, root: Path, runner: CommandRunner) -> engine.ProvisioningEnvironment:
        bin_root = root / "usr-local-bin"
        bin_root.mkdir()
        state_root = root / "state"
        lock_root = root / "locks"
        workspace = state_root / "build" / "amneziawg"
        build_user = getpass.getuser()
        if build_user == "root":
            build_user = "nobody"
        registry = TrustedExecutorRegistry()
        executor = AmneziaWGUserspaceSourceBuildExecutor(
            method_id="amneziawg_pinned_source_build_apt_stable_future",
            components=_components(),
            build_user=build_user,
            workspace_root=workspace,
            install_root=bin_root,
            runner=runner,
            require_root_install=False,
        )
        registry.register(
            method_kind=AMNEZIAWG_SOURCE_BUILD_METHOD_KIND,
            method_id="amneziawg_pinned_source_build_apt_stable_future",
            executor=executor,
        )
        context = ExecutionContext(
            allowed_roots=(bin_root,),
            now=lambda: "2026-07-29T00:00:00+00:00",
            custody_isolation_policy=LAB_CUSTODY_ISOLATION_POLICY,
        )
        return engine.ProvisioningEnvironment(
            state_root=state_root,
            registry=registry,
            expected_executor_version=AMNEZIAWG_SOURCE_BUILD_EXECUTOR_VERSION,
            context=context,
            global_lock_root=lock_root,
        )

    def test_prepare_records_dynamic_output_digests_and_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner()
            env = self._env(Path(tmp), runner)
            outcome = engine.prepare(_decision(), env, apply=True)
            self.assertEqual(outcome.status.value, "committed")
            self.assertTrue(runner.calls)
            self.assertTrue(all(call["run_as_user"] is not None for call in runner.calls))
            self.assertTrue(all(call["env"] for call in runner.calls))
            records = journal_mod.read_ownership_records(env.state_root, "proto_amneziawg_runtime")
            self.assertEqual({Path(record.candidate.resource_identity).name for record in records}, {"awg", "awg-quick", "amneziawg-go"})
            by_name = {Path(record.candidate.resource_identity).name: record for record in records}
            self.assertEqual(by_name["awg"].candidate.integrity, hashlib.sha256(b"fake-awg-binary").hexdigest())
            for record in records:
                self.assertEqual(record.candidate.path_authority_v2.components[-1].integrity, record.candidate.integrity)
                self.assertEqual(record.candidate.post_install_fingerprint, record.candidate.integrity)
            self.assertTrue(
                engine.validate_ownership_authority(
                    env.state_root,
                    "proto_amneziawg_runtime",
                    records,
                    registry=env.registry,
                    expected_executor_version=env.expected_executor_version,
                    context=env.context,
                )
            )

    def test_prepare_enforces_exact_output_modes_under_restrictive_umask(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = FakeRunner()
            env = self._env(root, runner)
            old_umask = os.umask(0o077)
            try:
                outcome = engine.prepare(_decision(), env, apply=True)
            finally:
                os.umask(old_umask)
            self.assertEqual(outcome.status.value, "committed")
            for name in AMNEZIAWG_OUTPUTS:
                target = env.context.allowed_roots[0] / name
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)

    def test_preexisting_output_is_conflict_and_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), FakeRunner())
            awg = env.context.allowed_roots[0] / "awg"
            awg.write_bytes(b"foreign")
            outcome = engine.prepare(_decision(), env, apply=True)
            self.assertEqual(outcome.status.value, "ownership_conflict")
            self.assertEqual(awg.read_bytes(), b"foreign")
            self.assertEqual(journal_mod.read_ownership_records(env.state_root, "proto_amneziawg_runtime"), [])

    def test_commit_mismatch_fails_before_installing_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), FakeRunner(wrong_commit=True))
            outcome = engine.prepare(_decision(), env, apply=True)
            self.assertEqual(outcome.status.value, "preparation_failed")
            self.assertEqual(list(env.context.allowed_roots[0].iterdir()), [])

    def test_recovery_apply_failure_rolls_back_without_invalid_transition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), FakeRunner(wrong_commit=True))
            plan, _executor = engine.build_plan(
                _decision(),
                registry=env.registry,
                expected_executor_version=env.expected_executor_version,
                context=env.context,
            )
            journal = engine._initial_journal(plan, transaction_id="pending_apply_failure", now_value="2026-07-29T00:00:00+00:00")
            journal_mod.write_journal(env.state_root, journal)
            journal = journal.with_state(TransactionState.AUTHORIZED, now="2026-07-29T00:00:01+00:00")
            journal_mod.write_journal(env.state_root, journal)
            journal = journal.with_state(TransactionState.APPLYING, now="2026-07-29T00:00:02+00:00")
            journal_mod.write_journal(env.state_root, journal)

            reports = engine.recover_pending(
                env.state_root,
                env.registry,
                env.expected_executor_version,
                env.context,
                global_lock_root=env.global_lock_root,
            )

            self.assertEqual([(item.transaction_id, item.action.value) for item in reports], [("pending_apply_failure", "rollback")])
            recovered = journal_mod.read_journal(env.state_root, "pending_apply_failure")
            self.assertEqual(recovered.state.value, "preparation_failed")

    def test_uninstall_removes_only_owned_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), FakeRunner())
            prepared = engine.prepare(_decision(), env, apply=True)
            self.assertEqual(prepared.status.value, "committed")
            outcome = engine.uninstall("proto_amneziawg_runtime", env, apply=True)
            self.assertEqual(outcome.status.value, "uninstalled")
            self.assertEqual([path.name for path in env.context.allowed_roots[0].iterdir() if path.is_file()], [])

    def test_second_prepare_is_already_provisioned_with_dynamic_digests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp), FakeRunner())
            first = engine.prepare(_decision(), env, apply=True)
            self.assertEqual(first.status.value, "committed")
            second = engine.prepare(_decision(), env, apply=True)
            self.assertEqual(second.status.value, "already_provisioned")

    def test_internal_cli_plan_reports_already_present_without_fake_plan(self) -> None:
        decision = _decision()
        decision = ResolutionDecision(
            capability_id=decision.capability_id,
            dependency_id=decision.dependency_id,
            resolved_distribution=decision.resolved_distribution,
            resolved_release=decision.resolved_release,
            technical_family=decision.technical_family,
            release_model=decision.release_model,
            support_classification=decision.support_classification,
            machine_architecture=decision.machine_architecture,
            observed_capability_status="present",
            candidate_chain=decision.candidate_chain,
            selected_method_id=None,
            selected_method_kind=None,
            resolution_status="already_present",
            execution_ready=True,
            rejected_candidates=(),
            evidence=("observed capability already present",),
            reason="dependency already satisfied on this host",
            provider_type="fixture",
            provider_authoritative=True,
            availability_observations=(),
            all_availability_observations=(),
        )
        seen = []
        original_context = compat_runtime_prepare._context
        original_print = compat_runtime_prepare._print
        try:
            compat_runtime_prepare._context = lambda args: (detection.load_product_manifest(), decision)
            compat_runtime_prepare._print = seen.append
            rc = compat_runtime_prepare.cmd_plan(SimpleNamespace())
        finally:
            compat_runtime_prepare._context = original_context
            compat_runtime_prepare._print = original_print
        self.assertEqual(rc, 0)
        self.assertEqual(seen[0]["plan"], None)
        self.assertEqual(seen[0]["reason"], "dependency already satisfied on this host")

    def test_build_subprocesses_receive_sanitized_env_not_parent_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.environ.get("WATCHDOGVPN_PARENT_ENV_CANARY")
            os.environ["WATCHDOGVPN_PARENT_ENV_CANARY"] = "must-not-leak"
            try:
                runner = FakeRunner()
                env = self._env(Path(tmp), runner)
                outcome = engine.prepare(_decision(), env, apply=True)
            finally:
                if previous is None:
                    os.environ.pop("WATCHDOGVPN_PARENT_ENV_CANARY", None)
                else:
                    os.environ["WATCHDOGVPN_PARENT_ENV_CANARY"] = previous
            self.assertEqual(outcome.status.value, "committed")
            allowed = {"HOME", "PATH", "LANG", "LC_ALL", "USER", "LOGNAME", "GIT_TERMINAL_PROMPT"}
            for call in runner.calls:
                self.assertEqual(set(call["env"]), allowed)
                self.assertNotIn("WATCHDOGVPN_PARENT_ENV_CANARY", call["env"])
                self.assertEqual(call["env"]["PATH"], "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
                self.assertEqual(call["env"]["LANG"], "C.UTF-8")
                self.assertEqual(call["env"]["LC_ALL"], "C.UTF-8")
                self.assertEqual(call["env"]["GIT_TERMINAL_PROMPT"], "0")

    def test_internal_cli_registers_all_source_build_executors_for_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = SimpleNamespace(
                build_user=getpass.getuser() if getpass.getuser() != "root" else "nobody",
                workspace_root=str(root / "workspace"),
                install_root=str(root / "bin"),
                state_root=str(root / "state"),
                global_lock_root=str(root / "locks"),
            )
            manifest = detection.load_product_manifest()
            env = compat_runtime_prepare._build_env(args, manifest, _decision(), mutating=False)
            source_candidates = [
                candidate
                for candidate in manifest["dependency_requirements"]["dep_amneziawg_runtime"]["method_chain"]
                if candidate["kind"] == AMNEZIAWG_SOURCE_BUILD_METHOD_KIND
            ]
            for candidate in source_candidates:
                executor = env.registry.resolve(
                    method_kind=AMNEZIAWG_SOURCE_BUILD_METHOD_KIND,
                    method_id=candidate["id"],
                    expected_executor_version=env.expected_executor_version,
                )
                self.assertEqual(executor.method_id, candidate["id"])

    def test_vm_recover_after_reboot_requires_changed_boot_id(self) -> None:
        harness = _load_vm_harness()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pre = root / "pre.json"
            pre.write_text(json.dumps({"observations": {"before": {"boot_id": "boot-a"}}}), encoding="utf-8")
            args = SimpleNamespace(
                pre_evidence=str(pre),
                evidence=str(root / "post.json"),
                cleanup=False,
                state_root=str(root / "state"),
                global_lock_root=str(root / "locks"),
                install_root=str(root / "bin"),
                workspace_root=str(root / "workspace"),
                os_release=None,
                build_user="nobody",
                force_runtime_absent=False,
            )
            original_baseline = harness._baseline
            original_run = harness._run
            original_tool_args = harness._tool_args
            try:
                harness._baseline = lambda _args, phase: {"phase": phase, "boot_id": "boot-a"}
                harness._run = lambda argv: {"argv": argv, "returncode": 0, "stdout": [], "stderr": ""}
                harness._tool_args = lambda _args: ["tool"]
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(harness.cmd_recover_after_reboot(args), 2)
                harness._baseline = lambda _args, phase: {"phase": phase, "boot_id": "boot-b"}
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(harness.cmd_recover_after_reboot(args), 0)
            finally:
                harness._baseline = original_baseline
                harness._run = original_run
                harness._tool_args = original_tool_args

    def test_vm_recover_after_reboot_requires_seeded_pending_prepare_to_commit(self) -> None:
        harness = _load_vm_harness()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pre = root / "pre.json"
            pre.write_text(
                json.dumps(
                    {
                        "observations": {"before": {"boot_id": "boot-a"}},
                        "pending_prepare": {"transaction_id": "vm6b_reboot_fixture"},
                    }
                ),
                encoding="utf-8",
            )
            args = SimpleNamespace(
                pre_evidence=str(pre),
                evidence=str(root / "post.json"),
                cleanup=False,
                state_root=str(root / "state"),
                global_lock_root=str(root / "locks"),
                install_root=str(root / "bin"),
                workspace_root=str(root / "workspace"),
                os_release=None,
                build_user="nobody",
                force_runtime_absent=False,
            )
            original_baseline = harness._baseline
            original_run = harness._run
            original_tool_args = harness._tool_args
            try:
                harness._baseline = lambda _args, phase: {"phase": phase, "boot_id": "boot-b"}
                harness._tool_args = lambda _args: ["tool"]
                harness._run = lambda argv: {"argv": argv, "returncode": 0, "stdout": [], "stderr": ""}
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(harness.cmd_recover_after_reboot(args), 2)

                def recovered_run(argv):
                    if argv[-1] == "recover":
                        return {
                            "argv": argv,
                            "returncode": 0,
                            "stdout": [{"transaction_id": "vm6b_reboot_fixture", "action": "resume", "reason": "resumed and committed"}],
                            "stderr": "",
                        }
                    if argv[-1] == "status":
                        return {
                            "argv": argv,
                            "returncode": 0,
                            "stdout": [{"transaction_id": "vm6b_reboot_fixture", "operation": "prepare", "state": "committed"}],
                            "stderr": "",
                        }
                    return {"argv": argv, "returncode": 0, "stdout": [], "stderr": ""}

                harness._run = recovered_run
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(harness.cmd_recover_after_reboot(args), 0)
            finally:
                harness._baseline = original_baseline
                harness._run = original_run
                harness._tool_args = original_tool_args


def _load_vm_harness():
    spec = importlib.util.spec_from_file_location("phase23_7_5_6b_amneziawg_validation", VM_HARNESS)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load VM harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    raise SystemExit(unittest.main())
