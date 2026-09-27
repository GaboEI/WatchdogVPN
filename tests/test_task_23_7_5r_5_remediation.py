"""Task 23.7.5R.5 regression tests for the three reproduced findings.

Covers:
  * T-PR23-05 — kernel-backed runtime availability diagnostic contract.
  * T-PR23-10 — recovery binds to the interrupted journal's exact release pair.
  * T-PR23-13 — complete-pair atomicity of the installed-release registry.

Every finding gets a negative proof (the reproduced unsafe result is rejected
or fails closed) and a positive proof (the supported behavior still works).
"""

from __future__ import annotations

import getpass
import json
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from compat.dependency_resolution import ResolutionDecision
from compat.provisioning import engine, journal as journal_mod
from compat.provisioning.amneziawg import (
    AMNEZIAWG_SOURCE_BUILD_EXECUTOR_VERSION,
    AMNEZIAWG_SOURCE_BUILD_METHOD_KIND,
    AmneziaWGUserspaceSourceBuildExecutor,
    SourceComponent,
    _components_from_journal_steps,
)
from compat.provisioning.errors import ProvisioningError
from compat.provisioning.executors import ExecutionContext, TrustedExecutorRegistry
from compat.provisioning.model import TransactionState
from compat.provisioning.paths import LAB_CUSTODY_ISOLATION_POLICY
from compat.provisioning.process import CommandResult, CommandRunner
from diagnostics import amneziawg_lifecycle as lifecycle
from diagnostics.amneziawg_lifecycle import (
    AMNEZIAWG_TOOLS_REPO,
    AMNEZIAWG_TRANSPORT_REPO,
    InstalledRelease,
    ResolvedRelease,
    RuntimeComponent,
    RuntimeProbe,
)


METHOD_ID = "amneziawg_pinned_source_build_apt_stable_future"
TOOLS_REV = "a" * 40
GO_REV = "b" * 40
RUNNER_REV = "c" * 40


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _component(name: str, *, present: bool = True, sha: str = "11" * 32, provenance: str = "unknown") -> RuntimeComponent:
    return RuntimeComponent(
        name=name,
        present=present,
        path=f"/usr/local/bin/{name}" if present else None,
        version="v1" if present else None,
        sha256=sha if present else None,
        mode="0o755" if present else None,
        uid=0,
        gid=0,
        provenance=provenance if present else "missing",
    )


def _probe(sha: str = "11" * 32) -> RuntimeProbe:
    components = {
        name: _component(name, present=True, sha=sha) for name in ("awg", "awg-quick", "amneziawg-go")
    }
    return RuntimeProbe(components=components, all_present=True, runtime_available=True)


class _Runner(CommandRunner):
    """Deterministic git/make runner that reports the configured revisions."""

    def __init__(self, tools_rev: str, go_rev: str) -> None:
        self.tools_rev = tools_rev
        self.go_rev = go_rev
        self.calls: list[tuple] = []

    def run(self, argv, *, cwd=None, env=None, run_as_user=None, timeout=120.0):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[:2] == ("git", "init"):
            Path(argv[2]).mkdir(parents=True, exist_ok=True)
            return CommandResult(argv, None, 0, "", "")
        if argv[:2] == ("git", "-C") and argv[3] in {"remote", "fetch", "checkout"}:
            return CommandResult(argv, None, 0, "", "")
        if argv[:2] == ("git", "-C") and argv[3:] == ("rev-parse", "HEAD"):
            worktree = argv[2]
            revision = self.tools_rev if worktree.endswith("amneziawg_tools") else self.go_rev
            return CommandResult(argv, None, 0, revision + "\n", "")
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


def _pair_components(tools_tag="vT", tools_rev=TOOLS_REV, go_tag="vG", go_rev=GO_REV) -> tuple[SourceComponent, ...]:
    return (
        SourceComponent(
            "amneziawg_tools",
            "https://github.com/amnezia-vpn/amneziawg-tools",
            tools_tag,
            tools_rev,
            ("awg", "awg-quick"),
        ),
        SourceComponent(
            "amneziawg_transport",
            "https://github.com/amnezia-vpn/amneziawg-go",
            go_tag,
            go_rev,
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
        candidate_chain=(METHOD_ID,),
        selected_method_id=METHOD_ID,
        selected_method_kind=AMNEZIAWG_SOURCE_BUILD_METHOD_KIND,
        resolution_status="method_selected",
        execution_ready=True,
        rejected_candidates=(),
        evidence=("fixture",),
        reason="fixture",
        provider_type="fixture",
        provider_authoritative=True,
        availability_observations=(),
        all_availability_observations=(),
    )


def _build_executor(root: Path, components, runner: CommandRunner) -> AmneziaWGUserspaceSourceBuildExecutor:
    bin_root = root / "usr-local-bin"
    bin_root.mkdir(exist_ok=True)
    state_root = root / "state"
    build_user = getpass.getuser()
    if build_user == "root":
        build_user = "nobody"
    return AmneziaWGUserspaceSourceBuildExecutor(
        method_id=METHOD_ID,
        components=tuple(components),
        build_user=build_user,
        workspace_root=state_root / "build" / "amneziawg",
        workspace_authority_root=state_root / "build",
        install_root=bin_root,
        runner=runner,
        require_root_install=False,
    )


def _env(root: Path, executor) -> engine.ProvisioningEnvironment:
    registry = TrustedExecutorRegistry()
    registry.register(
        method_kind=AMNEZIAWG_SOURCE_BUILD_METHOD_KIND, method_id=METHOD_ID, executor=executor
    )
    context = ExecutionContext(
        allowed_roots=(root / "usr-local-bin",),
        now=lambda: "2026-09-27T00:00:00+00:00",
        custody_isolation_policy=LAB_CUSTODY_ISOLATION_POLICY,
    )
    return engine.ProvisioningEnvironment(
        state_root=root / "state",
        registry=registry,
        expected_executor_version=AMNEZIAWG_SOURCE_BUILD_EXECUTOR_VERSION,
        context=context,
        global_lock_root=root / "locks",
    )


# ---------------------------------------------------------------------------
# T-PR23-05 — kernel-backed runtime availability
# ---------------------------------------------------------------------------


class TPR2305KernelRuntimeTests(unittest.TestCase):
    def _runtime_available(self, *, awg: bool, awg_quick: bool, go: bool, kernel: bool) -> bool:
        present = {"awg": awg, "awg-quick": awg_quick, "amneziawg-go": go}

        def fake_find(name: str, root=None):
            return Path(f"/usr/local/bin/{name}") if present[name] else None

        real_exists = Path.exists

        def fake_exists(self):
            if str(self) == "/sys/module/amneziawg":
                return kernel
            return real_exists(self)

        with (
            mock.patch.object(lifecycle, "_find_binary", side_effect=fake_find),
            mock.patch.object(lifecycle, "_run_version", return_value="v1"),
            mock.patch.object(lifecycle, "_sha256_of", return_value="aa" * 32),
            mock.patch.object(Path, "exists", fake_exists),
        ):
            return lifecycle.probe_runtime().runtime_available

    def test_truth_table_matches_awg_and_awg_quick_and_kernel_or_go(self) -> None:
        for awg in (False, True):
            for awg_quick in (False, True):
                for go in (False, True):
                    for kernel in (False, True):
                        expected = awg and awg_quick and (go or kernel)
                        with self.subTest(awg=awg, awg_quick=awg_quick, go=go, kernel=kernel):
                            self.assertEqual(
                                self._runtime_available(awg=awg, awg_quick=awg_quick, go=go, kernel=kernel),
                                expected,
                            )

    def test_kernel_backed_runtime_available_without_go(self) -> None:
        # The reproduced defect: awg + awg-quick + loaded kernel module, no go.
        self.assertTrue(self._runtime_available(awg=True, awg_quick=True, go=False, kernel=True))

    def test_missing_awg_quick_is_rejected(self) -> None:
        self.assertFalse(self._runtime_available(awg=True, awg_quick=False, go=True, kernel=True))

    def test_missing_awg_is_rejected(self) -> None:
        self.assertFalse(self._runtime_available(awg=False, awg_quick=True, go=True, kernel=True))

    def test_userspace_runtime_still_available_without_kernel_module(self) -> None:
        self.assertTrue(self._runtime_available(awg=True, awg_quick=True, go=True, kernel=False))

    def test_kernel_backed_runtime_is_available_lifecycle_state(self) -> None:
        components = {
            "awg": _component("awg"),
            "awg-quick": _component("awg-quick"),
            "amneziawg-go": _component("amneziawg-go", present=False),
        }
        probe = RuntimeProbe(components=components, all_present=False, runtime_available=True)
        self.assertEqual(
            lifecycle.lifecycle_state(awg_profiles=1, probe=probe),
            lifecycle.STATE_PROFILE_AVAILABLE,
        )


# ---------------------------------------------------------------------------
# T-PR23-13 — complete-pair atomicity
# ---------------------------------------------------------------------------


class TPR2313CompletePairTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "WATCHDOGVPN_CONFIG_DIR": self._tmp.name,
                "WATCHDOGVPN_PROFILES_FILE": str(Path(self._tmp.name) / "profiles.json"),
            },
            clear=False,
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._tmp.cleanup()

    def _raw_entry(self, repository: str, *, recorded_at: str, commit: str, manifest=None, distro="opensuse_leap"):
        return {
            "repository": repository,
            "tag": "v1",
            "commit": commit,
            "resolved_at": "2026-09-27T00:00:00Z",
            "recorded_at": recorded_at,
            "arch": "x86_64",
            "distro": distro,
            "binary_sha256": {"awg": "11" * 32},
            "build_manifest_sha256": manifest,
        }

    def _write_registry(self, entries) -> None:
        path = Path(self._tmp.name) / "amneziawg_installed.json"
        path.write_text(json.dumps({"installed": entries, "pending": []}), encoding="utf-8")

    def _pair(self, tag="vA"):
        return [
            ResolvedRelease(AMNEZIAWG_TOOLS_REPO, tag, (tag * 20)[:40], "2026-09-27T00:00:00Z"),
            ResolvedRelease(AMNEZIAWG_TRANSPORT_REPO, tag + "2", ((tag + "2") * 20)[:40], "2026-09-27T00:00:00Z"),
        ]

    def test_negative_record_incomplete_pair_is_rejected(self) -> None:
        # The reproduced defect passed only amneziawg-tools.
        with self.assertRaises(ValueError):
            lifecycle.record_installed_release(
                [ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "vA", "aa" * 20, "2026-09-27T00:00:00Z")],
                _probe(),
                platform={"distro": "opensuse_leap", "version": "15.6", "arch": "x86_64"},
            )
        self.assertEqual(lifecycle.load_installed_history(), [])

    def test_negative_record_duplicate_component_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            lifecycle.record_installed_release(
                [
                    ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "vA", "aa" * 20, "2026-09-27T00:00:00Z"),
                    ResolvedRelease(AMNEZIAWG_TOOLS_REPO, "vA", "aa" * 20, "2026-09-27T00:00:00Z"),
                ],
                _probe(),
                platform={"distro": "opensuse_leap", "version": "15.6", "arch": "x86_64"},
            )

    def test_negative_load_ignores_incomplete_group(self) -> None:
        self._write_registry([self._raw_entry(AMNEZIAWG_TOOLS_REPO, recorded_at="t1", commit="aa" * 20)])
        self.assertEqual(lifecycle.load_installed_history(), [])
        self.assertEqual(lifecycle.previous_installed_release(_probe()), [])

    def test_negative_load_ignores_mixed_time_group(self) -> None:
        self._write_registry(
            [
                self._raw_entry(AMNEZIAWG_TOOLS_REPO, recorded_at="t1", commit="aa" * 20),
                self._raw_entry(AMNEZIAWG_TRANSPORT_REPO, recorded_at="t2", commit="bb" * 20),
            ]
        )
        self.assertEqual(lifecycle.load_installed_history(), [])

    def test_negative_load_ignores_mixed_provenance_group(self) -> None:
        self._write_registry(
            [
                self._raw_entry(AMNEZIAWG_TOOLS_REPO, recorded_at="t1", commit="aa" * 20, manifest="m1"),
                self._raw_entry(AMNEZIAWG_TRANSPORT_REPO, recorded_at="t1", commit="bb" * 20, manifest="m2"),
            ]
        )
        self.assertEqual(lifecycle.load_installed_history(), [])

    def test_negative_previous_never_returns_incomplete_group(self) -> None:
        self._write_registry([self._raw_entry(AMNEZIAWG_TOOLS_REPO, recorded_at="t1", commit="aa" * 20)])
        self.assertEqual(lifecycle.previous_installed_release(_probe()), [])

    def test_positive_complete_pair_is_recorded_and_selected(self) -> None:
        created = lifecycle.record_installed_release(
            self._pair("vA"),
            _probe("11" * 32),
            platform={"distro": "opensuse_leap", "version": "15.6", "arch": "x86_64"},
        )
        self.assertEqual(sorted(e.repository for e in created), sorted([AMNEZIAWG_TOOLS_REPO, AMNEZIAWG_TRANSPORT_REPO]))
        self.assertEqual(len(lifecycle.load_installed_history()), 2)

    def test_valid_history_is_preserved_when_ignoring_invalid_group(self) -> None:
        lifecycle.record_installed_release(
            self._pair("vA"),
            _probe("11" * 32),
            platform={"distro": "opensuse_leap", "version": "15.6", "arch": "x86_64"},
        )
        # Append an invalid group directly; it must be ignored, not deleted.
        path = Path(self._tmp.name) / "amneziawg_installed.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["installed"].append(self._raw_entry(AMNEZIAWG_TOOLS_REPO, recorded_at="tX", commit="cc" * 20))
        path.write_text(json.dumps(data), encoding="utf-8")

        loaded = lifecycle.load_installed_history()
        self.assertEqual(len(loaded), 2)  # only the valid pair
        after = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(after["installed"]), 3)  # invalid entry never deleted

    def test_previous_release_returns_older_complete_group(self) -> None:
        lifecycle.record_installed_release(
            self._pair("vA"), _probe("11" * 32),
            platform={"distro": "opensuse_leap", "version": "15.6", "arch": "x86_64"},
        )
        lifecycle.record_installed_release(
            self._pair("vB"), _probe("22" * 32),
            platform={"distro": "opensuse_leap", "version": "15.6", "arch": "x86_64"},
        )
        previous = lifecycle.previous_installed_release(_probe("22" * 32))
        self.assertEqual(sorted(e.tag for e in previous), ["vA", "vA2"])


# ---------------------------------------------------------------------------
# T-PR23-10 — recovery binds to the journal's exact release pair
# ---------------------------------------------------------------------------


def _step(intent) -> SimpleNamespace:
    return SimpleNamespace(intent=intent)


def _journal_steps(components) -> list[SimpleNamespace]:
    steps = []
    for component in components:
        for output in component.expected_outputs:
            steps.append(
                _step(
                    {
                        "component_id": component.component_id,
                        "repository": component.repository,
                        "tag": component.tag,
                        "revision": component.revision,
                        "output_name": output,
                    }
                )
            )
    return steps


class TPR2310RecoveryBindingTests(unittest.TestCase):
    def test_components_reconstructed_from_journal_steps(self) -> None:
        components = _pair_components(tools_tag="vOld", tools_rev="1" * 40, go_tag="vOldGo", go_rev="2" * 40)
        rebuilt = _components_from_journal_steps(_journal_steps(components))
        self.assertIsNotNone(rebuilt)
        by_id = {c.component_id: c for c in rebuilt}
        self.assertEqual(by_id["amneziawg_tools"].tag, "vOld")
        self.assertEqual(by_id["amneziawg_tools"].revision, "1" * 40)
        self.assertEqual(by_id["amneziawg_transport"].tag, "vOldGo")
        self.assertEqual(by_id["amneziawg_transport"].revision, "2" * 40)

    def test_incomplete_journal_pair_fails_closed(self) -> None:
        components = _pair_components()
        steps = [s for s in _journal_steps(components) if s.intent["component_id"] != "amneziawg_transport"]
        self.assertIsNone(_components_from_journal_steps(steps))

    def test_swapped_journal_pair_fails_closed(self) -> None:
        steps = _journal_steps(_pair_components())
        # Swap the repository of the tools steps to the transport repo.
        for step in steps:
            if step.intent["component_id"] == "amneziawg_tools":
                step.intent["repository"] = "https://github.com/amnezia-vpn/amneziawg-go"
        self.assertIsNone(_components_from_journal_steps(steps))

    def test_non_official_journal_pair_fails_closed(self) -> None:
        steps = _journal_steps(_pair_components())
        steps[0].intent["repository"] = "https://github.com/attacker/amneziawg-tools"
        self.assertIsNone(_components_from_journal_steps(steps))

    def test_duplicated_output_fails_closed(self) -> None:
        steps = _journal_steps(_pair_components())
        steps.append(_step(dict(steps[0].intent)))
        self.assertIsNone(_components_from_journal_steps(steps))

    def test_inconsistent_tag_within_component_fails_closed(self) -> None:
        steps = _journal_steps(_pair_components())
        # Two tools steps that disagree on the tag: one component, two pins.
        self.assertEqual(steps[0].intent["component_id"], "amneziawg_tools")
        steps[0].intent["tag"] = "vChanged"
        self.assertIsNone(_components_from_journal_steps(steps))

    def test_recovery_bound_executor_uses_journal_pair_without_resolver(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executor = _build_executor(root, _pair_components(), _Runner(TOOLS_REV, GO_REV))
            journal_steps = _journal_steps(_pair_components(tools_tag="vJ", tools_rev="3" * 40, go_tag="vJG", go_rev="4" * 40))
            journal = SimpleNamespace(steps=[_step(dict(s.intent)) for s in journal_steps])

            with mock.patch.object(
                lifecycle.OfficialReleaseResolver, "resolve", side_effect=AssertionError("live resolver must not be called")
            ):
                bound = executor.recovery_bound_executor(journal)

            self.assertIsNot(bound, executor)
            by_id = {c.component_id: c for c in bound.components}
            self.assertEqual(by_id["amneziawg_tools"].revision, "3" * 40)
            self.assertEqual(by_id["amneziawg_transport"].revision, "4" * 40)
            self.assertEqual(bound._built_outputs, {})

    def test_recovery_bound_executor_fails_closed_on_invalid_journal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executor = _build_executor(Path(tmp), _pair_components(), _Runner(TOOLS_REV, GO_REV))
            journal = SimpleNamespace(steps=[_step({})])
            with self.assertRaises(ProvisioningError):
                executor.recovery_bound_executor(journal)

    def test_engine_recovery_binds_to_journal_when_upstream_changed_and_offline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared = _env(root, _build_executor(root, _pair_components(tools_rev="5" * 40, go_rev="6" * 40), _Runner("5" * 40, "6" * 40)))
            plan, _exec = engine.build_plan(
                _decision(),
                registry=prepared.registry,
                expected_executor_version=prepared.expected_executor_version,
                context=prepared.context,
            )
            journal = engine._initial_journal(plan, transaction_id="bind_ok", now_value="2026-09-27T00:00:00+00:00")
            journal_mod.write_journal(prepared.state_root, journal)
            journal = journal.with_state(TransactionState.AUTHORIZED, now="2026-09-27T00:00:01+00:00")
            journal_mod.write_journal(prepared.state_root, journal)
            journal = journal.with_state(TransactionState.APPLYING, now="2026-09-27T00:00:02+00:00")
            journal_mod.write_journal(prepared.state_root, journal)

            # Recovery registry has deferred (empty) components and the upstream
            # resolver is forced to fail: recovery must still bind to the journal.
            recover_executor = _build_executor(root, (), _Runner("5" * 40, "6" * 40))
            env = _env(root, recover_executor)
            with mock.patch.object(
                lifecycle.OfficialReleaseResolver, "resolve", side_effect=AssertionError("live resolver must not be called")
            ):
                reports = engine.recover_pending(
                    env.state_root, env.registry, env.expected_executor_version, env.context,
                    global_lock_root=env.global_lock_root,
                )
            self.assertNotEqual([r.action.value for r in reports], ["require_manual"])
            self.assertEqual(journal_mod.read_journal(env.state_root, "bind_ok").state.value, "committed")

    def test_engine_recovery_fails_closed_when_binding_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executor = _build_executor(root, _pair_components(), _Runner(TOOLS_REV, GO_REV))
            env = _env(root, executor)
            plan, _ = engine.build_plan(
                _decision(), registry=env.registry, expected_executor_version=env.expected_executor_version, context=env.context
            )
            journal = engine._initial_journal(plan, transaction_id="bind_fail", now_value="2026-09-27T00:00:00+00:00")
            journal_mod.write_journal(env.state_root, journal)
            journal = journal.with_state(TransactionState.AUTHORIZED, now="2026-09-27T00:00:01+00:00")
            journal_mod.write_journal(env.state_root, journal)
            journal = journal.with_state(TransactionState.APPLYING, now="2026-09-27T00:00:02+00:00")
            journal_mod.write_journal(env.state_root, journal)

            with mock.patch.object(
                AmneziaWGUserspaceSourceBuildExecutor,
                "recovery_bound_executor",
                side_effect=ProvisioningError("journal pair invalid"),
            ):
                reports = engine.recover_pending(
                    env.state_root, env.registry, env.expected_executor_version, env.context,
                    global_lock_root=env.global_lock_root,
                )
            self.assertEqual([r.action.value for r in reports], ["require_manual"])


class TPR2310DeferredRegistrationTests(unittest.TestCase):
    def test_cmd_recover_defers_release_resolution(self) -> None:
        # The internal recover command must not construct executors with a live
        # release resolution before recovery can bind to each journal.
        from tools import compat_runtime_prepare

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = SimpleNamespace(
                build_user=getpass.getuser() if getpass.getuser() != "root" else "nobody",
                workspace_root=str(root / "workspace"),
                install_root=str(root / "bin"),
                state_root=str(root / "state"),
                global_lock_root=str(root / "locks"),
            )
            from compat import detection

            manifest = detection.load_product_manifest()
            seen = []

            def boom():
                seen.append("resolved")
                raise AssertionError("live resolver must not be called while building the recovery env")

            with mock.patch.object(lifecycle, "OfficialReleaseResolver", side_effect=boom):
                env = compat_runtime_prepare._build_env(
                    args, manifest, _decision(), mutating=True, defer_release_resolution=True
                )
            self.assertEqual(seen, [])
            source_candidates = [
                c
                for c in manifest["dependency_requirements"]["dep_amneziawg_runtime"]["method_chain"]
                if c["kind"] == AMNEZIAWG_SOURCE_BUILD_METHOD_KIND
            ]
            for candidate in source_candidates:
                executor = env.registry.resolve(
                    method_kind=AMNEZIAWG_SOURCE_BUILD_METHOD_KIND,
                    method_id=candidate["id"],
                    expected_executor_version=env.expected_executor_version,
                )
                self.assertEqual(executor.components, ())


if __name__ == "__main__":
    unittest.main()
