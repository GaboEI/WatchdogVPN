"""AmneziaWG userspace source-build executor for Task 23.7.5.6b."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import pwd
import shutil
import stat as stat_module
from typing import Mapping

from compat.provisioning.errors import PathPolicyError
from compat.provisioning.executors import ExecutionContext, Executor, handle_for_allowed_root
from compat.provisioning.journal import StepRecord
from compat.provisioning.model import (
    ExecutionResult,
    OwnershipCandidate,
    ProvisioningPlan,
    ProvisioningStep,
    RollbackResult,
    StepState,
    VerificationResult,
)
from compat.provisioning.paths import (
    create_file_exclusive_relative,
    read_bytes_relative,
    remove_file_if_owned_relative,
    stat_identity_relative,
    validate_identifier,
    validate_target_path,
)
from compat.provisioning.process import CommandResult, CommandRunner, SubprocessCommandRunner


AMNEZIAWG_SOURCE_BUILD_METHOD_KIND = "pinned_source_build"
AMNEZIAWG_SOURCE_BUILD_EXECUTOR_ID = "amneziawg_userspace_source_build"
AMNEZIAWG_SOURCE_BUILD_EXECUTOR_VERSION = "1"
AMNEZIAWG_INSTALL_ROOT = Path("/usr/local/bin")
AMNEZIAWG_OUTPUTS = ("awg", "awg-quick", "amneziawg-go")
AMNEZIAWG_BUILD_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
AMNEZIAWG_BUILD_LOCALE = "C.UTF-8"
_DYNAMIC_SHA256 = "__watchdogvpn_dynamic_verified_sha256__"


@dataclass(frozen=True)
class SourceComponent:
    component_id: str
    repository: str
    tag: str
    revision: str
    expected_outputs: tuple[str, ...]


class AmneziaWGUserspaceSourceBuildExecutor(Executor):
    executor_id = AMNEZIAWG_SOURCE_BUILD_EXECUTOR_ID
    executor_version = AMNEZIAWG_SOURCE_BUILD_EXECUTOR_VERSION
    supported_method_kind = AMNEZIAWG_SOURCE_BUILD_METHOD_KIND

    def __init__(
        self,
        *,
        method_id: str,
        components: tuple[SourceComponent, ...],
        build_user: str,
        workspace_root: Path,
        install_root: Path = AMNEZIAWG_INSTALL_ROOT,
        runner: CommandRunner | None = None,
        require_root_install: bool = True,
    ) -> None:
        validate_identifier(method_id, field="method_id")
        self.method_id = method_id
        self.components = components
        self.build_user = _validate_build_user(build_user)
        self.workspace_root = Path(workspace_root)
        self.install_root = Path(install_root)
        self.runner = runner or SubprocessCommandRunner()
        self.require_root_install = require_root_install
        self._built_outputs: dict[str, bytes] = {}
        info = pwd.getpwnam(self.build_user)
        self._build_uid = info.pw_uid
        self._build_gid = info.pw_gid
        self._build_home = info.pw_dir or "/nonexistent"

    def declares_network_required(self) -> bool:
        return True

    def step_is_replay_safe(self, step: StepRecord) -> bool:
        return True

    def plan_steps(self, *, capability_id: str, dependency_id: str, context: ExecutionContext) -> tuple[ProvisioningStep, ...]:
        validate_identifier(capability_id, field="capability_id")
        validate_identifier(dependency_id, field="dependency_id")
        if {component.component_id for component in self.components} != {"amneziawg_tools", "amneziawg_transport"}:
            raise ValueError("AmneziaWG userspace source build requires tools and transport components")
        output_to_component = {}
        for component in self.components:
            for output in component.expected_outputs:
                output_to_component[output] = component
        if set(output_to_component) != set(AMNEZIAWG_OUTPUTS):
            raise ValueError("AmneziaWG userspace source build must install exactly %s" % (AMNEZIAWG_OUTPUTS,))
        steps = []
        for sequence, output in enumerate(AMNEZIAWG_OUTPUTS):
            component = output_to_component[output]
            target = self.install_root / output
            steps.append(
                ProvisioningStep(
                    sequence=sequence,
                    step_id="install_%s" % output.replace("-", "_"),
                    action_type="install_amneziawg_userspace_output",
                    target=str(target),
                    intent={
                        "component_id": component.component_id,
                        "repository": component.repository,
                        "tag": component.tag,
                        "revision": component.revision,
                        "output_name": output,
                        "install_root": str(self.install_root),
                        "expected_mode": 0o755,
                        "expected_uid": 0 if self.require_root_install else os.getuid(),
                        "expected_gid": 0 if self.require_root_install else os.getgid(),
                        "integrity_policy": "record_verified_sha256",
                        "source": component.repository,
                        "version": component.tag,
                    },
                )
            )
        return tuple(steps)

    def apply_step(self, step: StepRecord, context: ExecutionContext) -> ExecutionResult:
        if self.require_root_install and os.geteuid() != 0:
            return ExecutionResult(status="apply_failed", error_kind="privilege_required", error="install requires root")
        try:
            data = self._output_bytes(step)
            path = Path(step.target)
            validated = validate_target_path(path, allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            handle = handle_for_allowed_root(context, validated)
            create_file_exclusive_relative(handle, validated, data, mode=0o755)
        except FileExistsError as exc:
            return ExecutionResult(status="apply_failed", error_kind="target_already_exists", error=str(exc))
        except (OSError, PathPolicyError, ValueError) as exc:
            return ExecutionResult(status="apply_failed", error_kind="apply_failed", error=str(exc))
        sha256 = hashlib.sha256(data).hexdigest()
        return ExecutionResult(
            status="applied",
            observed={"path": str(validated), "sha256": sha256, "component_id": step.intent["component_id"]},
            undo_record={"path": str(validated), "expected_sha256": sha256},
        )

    def verify_step(self, step: StepRecord, execution: ExecutionResult, context: ExecutionContext) -> VerificationResult:
        path = Path(execution.observed.get("path", step.target))
        expected_sha256 = execution.observed.get("sha256")
        if not _is_sha256(expected_sha256):
            return VerificationResult(status="verification_failed", error_kind="missing_digest", error="apply did not report a sha256")
        result = self._verify_installed_path(path, expected_sha256, context)
        if result.status != "verified":
            return result
        return VerificationResult(
            status="verified",
            evidence={**dict(result.evidence), "component_id": step.intent["component_id"], "repository": step.intent["repository"], "tag": step.intent["tag"], "revision": step.intent["revision"]},
        )

    def undo_step(self, step: StepRecord, execution: ExecutionResult, context: ExecutionContext) -> RollbackResult:
        undo_record = execution.undo_record or {}
        path = Path(undo_record.get("path", step.target))
        try:
            validated = validate_target_path(path, allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            handle = handle_for_allowed_root(context, validated)
            removed = remove_file_if_owned_relative(
                handle,
                validated,
                expected_sha256=undo_record.get("expected_sha256"),
                isolation_policy=context.custody_isolation_policy,
            )
        except (OSError, PathPolicyError) as exc:
            return RollbackResult(status="undo_failed", residual=True, error_kind="undo_failed", error=str(exc))
        return RollbackResult(status="undone", residual=False, evidence={"path": str(validated), "removed": removed})

    def verify_postcondition(self, plan: ProvisioningPlan, context: ExecutionContext) -> VerificationResult:
        for step in plan.steps:
            record = StepRecord(step.sequence, step.step_id, step.action_type, StepState.PLANNED, step.intent, step.target)
            inspected = self.inspect_step(record, context)
            if not inspected.get("exists"):
                return VerificationResult(status="verification_failed", error_kind="missing", error=str(step.target))
            if inspected.get("is_symlink") or inspected.get("executable") is not True:
                return VerificationResult(status="verification_failed", error_kind="invalid_output", error=str(step.target))
        return VerificationResult(status="verified", evidence={"outputs": list(AMNEZIAWG_OUTPUTS), "install_root": str(self.install_root)})

    def inspect_step(self, step: StepRecord, context: ExecutionContext) -> Mapping[str, object]:
        try:
            validated = validate_target_path(Path(step.target), allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            handle = handle_for_allowed_root(context, validated)
            identity = stat_identity_relative(handle, validated)
        except FileNotFoundError:
            return {"exists": False, "is_symlink": False, "content_matches": None}
        except (OSError, PathPolicyError) as exc:
            return {"exists": None, "is_symlink": None, "content_matches": None, "inspect_error": str(exc)}
        if identity["is_symlink"] or not identity["is_regular"]:
            return {"exists": True, "is_symlink": identity["is_symlink"], "content_matches": None, "executable": False}
        try:
            data = read_bytes_relative(handle, validated)
        except (OSError, PathPolicyError) as exc:
            return {"exists": True, "is_symlink": False, "content_matches": None, "inspect_error": str(exc)}
        expected_sha256 = step.intent.get("content_sha256")
        actual_sha256 = hashlib.sha256(data).hexdigest()
        return {
            "exists": True,
            "is_symlink": False,
            "content_matches": actual_sha256 == expected_sha256 if _is_sha256(expected_sha256) else True,
            "sha256": actual_sha256,
            "mode": identity["mode"],
            "uid": identity["uid"],
            "gid": identity["gid"],
            "nlink": identity["nlink"],
            "executable": bool(identity["mode"] & stat_module.S_IXUSR),
        }

    def reconstruct_undo_record(self, step: StepRecord) -> Mapping[str, object]:
        sha256 = None
        if step.verification and _is_sha256(step.verification.get("sha256")):
            sha256 = step.verification["sha256"]
        if step.undo_record and _is_sha256(step.undo_record.get("expected_sha256")):
            sha256 = step.undo_record["expected_sha256"]
        if sha256 is None:
            raise ValueError("cannot reconstruct undo record without verified sha256")
        return {"path": step.target, "expected_sha256": sha256}

    def expected_ownership_for_step(self, plan: ProvisioningPlan, step: ProvisioningStep) -> OwnershipCandidate:
        return OwnershipCandidate(
            artifact_type="file",
            resource_identity=step.target,
            pre_existing=False,
            method_id=plan.selected_method_id,
            source=step.intent["source"],
            version=step.intent["version"],
            integrity=_DYNAMIC_SHA256,
            uid=step.intent["expected_uid"],
            gid=step.intent["expected_gid"],
            mode=step.intent["expected_mode"],
            nlink=1,
            post_install_fingerprint=_DYNAMIC_SHA256,
        )

    def postcondition_description(self) -> str:
        return "AmneziaWG userspace runtime installed as awg, awg-quick and amneziawg-go under /usr/local/bin"

    def _output_bytes(self, step: StepRecord) -> bytes:
        output_name = str(step.intent["output_name"])
        if output_name not in self._built_outputs:
            self._build_component(str(step.intent["component_id"]))
        if output_name not in self._built_outputs:
            raise ValueError("component build did not produce %s" % output_name)
        return self._built_outputs[output_name]

    def _build_component(self, component_id: str) -> None:
        component = next((item for item in self.components if item.component_id == component_id), None)
        if component is None:
            raise ValueError("unknown component %s" % component_id)
        worktree = self.workspace_root / component.component_id
        if worktree.exists():
            shutil.rmtree(worktree)
        self._prepare_build_workspace_parent(worktree.parent)
        self._run_ok(("git", "init", str(worktree)), cwd=None, run_as_user=self.build_user)
        self._run_ok(("git", "-C", str(worktree), "remote", "add", "origin", component.repository), cwd=None, run_as_user=self.build_user)
        self._run_ok(("git", "-C", str(worktree), "fetch", "--depth", "1", "origin", "refs/tags/%s" % component.tag), cwd=None, run_as_user=self.build_user)
        self._run_ok(("git", "-C", str(worktree), "checkout", "--detach", "FETCH_HEAD"), cwd=None, run_as_user=self.build_user)
        observed = self._run_ok(("git", "-C", str(worktree), "rev-parse", "HEAD"), cwd=None, run_as_user=self.build_user).stdout.strip()
        if observed != component.revision:
            raise ValueError("component %s resolved to %s, expected %s" % (component.component_id, observed, component.revision))
        if component.component_id == "amneziawg_tools":
            self._run_ok(
                ("make", "-C", str(worktree / "src"), "WITH_WGQUICK=yes", "WITH_SYSTEMDUNITS=no", "WITH_BASHCOMPLETION=no"),
                cwd=None,
                run_as_user=self.build_user,
            )
            self._built_outputs["awg"] = (worktree / "src" / "wg").read_bytes()
            self._built_outputs["awg-quick"] = (worktree / "src" / "wg-quick" / "linux.bash").read_bytes()
        elif component.component_id == "amneziawg_transport":
            self._run_ok(("make", "-C", str(worktree)), cwd=None, run_as_user=self.build_user)
            self._built_outputs["amneziawg-go"] = (worktree / "amneziawg-go").read_bytes()
        else:
            raise ValueError("unsupported component %s" % component.component_id)

    def _prepare_build_workspace_parent(self, path: Path) -> None:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        if os.geteuid() == 0:
            os.chown(path, self._build_uid, self._build_gid)
        st = path.stat()
        if (st.st_uid, st.st_gid) != (self._build_uid, self._build_gid):
            raise ValueError("build workspace parent %s is not owned by build user %s" % (path, self.build_user))
        os.chmod(path, 0o700)

    def _run_ok(self, argv, *, cwd: Path | None, run_as_user: str | None) -> CommandResult:
        result = self.runner.run(argv, cwd=cwd, env=self._sanitized_build_env(), run_as_user=run_as_user, timeout=600.0)
        if result.returncode != 0:
            raise ValueError("command failed rc=%d argv=%r stderr=%s" % (result.returncode, result.argv, result.stderr))
        return result

    def _sanitized_build_env(self) -> Mapping[str, str]:
        return {
            "HOME": self._build_home,
            "PATH": AMNEZIAWG_BUILD_PATH,
            "LANG": AMNEZIAWG_BUILD_LOCALE,
            "LC_ALL": AMNEZIAWG_BUILD_LOCALE,
            "USER": self.build_user,
            "LOGNAME": self.build_user,
            "GIT_TERMINAL_PROMPT": "0",
        }

    def _verify_installed_path(self, path: Path, expected_sha256: str, context: ExecutionContext) -> VerificationResult:
        try:
            validated = validate_target_path(path, allowed_roots=context.allowed_roots, forbidden_roots=context.forbidden_roots)
            handle = handle_for_allowed_root(context, validated)
            identity = stat_identity_relative(handle, validated)
        except FileNotFoundError as exc:
            return VerificationResult(status="verification_failed", error_kind="missing", error=str(exc))
        except (OSError, PathPolicyError) as exc:
            return VerificationResult(status="verification_failed", error_kind="inspection_error", error=str(exc))
        if identity["is_symlink"] or not identity["is_regular"]:
            return VerificationResult(status="verification_failed", error_kind="unexpected_file_type", error=str(validated))
        if identity["mode"] != 0o755:
            return VerificationResult(status="verification_failed", error_kind="unexpected_mode", error="mode is %o" % identity["mode"])
        if self.require_root_install and (identity["uid"], identity["gid"]) != (0, 0):
            return VerificationResult(status="verification_failed", error_kind="unexpected_owner", error="uid/gid is %d/%d" % (identity["uid"], identity["gid"]))
        if identity["nlink"] != 1:
            return VerificationResult(status="verification_failed", error_kind="unexpected_nlink", error="nlink is %d" % identity["nlink"])
        try:
            actual_sha256 = hashlib.sha256(read_bytes_relative(handle, validated)).hexdigest()
        except (OSError, PathPolicyError) as exc:
            return VerificationResult(status="verification_failed", error_kind="inspection_error", error=str(exc))
        if actual_sha256 != expected_sha256:
            return VerificationResult(status="verification_failed", error_kind="content_mismatch", error="sha256 mismatch")
        return VerificationResult(status="verified", evidence={"path": str(validated), "sha256": actual_sha256, "mode": "0o755", "uid": identity["uid"], "gid": identity["gid"], "nlink": identity["nlink"]})


def components_from_candidate(candidate: Mapping) -> tuple[SourceComponent, ...]:
    return tuple(
        SourceComponent(
            component_id=str(item["component_id"]),
            repository=str(item["repository"]),
            tag=str(item["tag"]),
            revision=str(item["revision"]),
            expected_outputs=tuple(str(output) for output in item["expected_outputs"]),
        )
        for item in candidate.get("components", ())
    )


def _validate_build_user(build_user: str) -> str:
    if not build_user or "/" in build_user or "\x00" in build_user:
        raise ValueError("build user must be an explicit local user name")
    info = pwd.getpwnam(build_user)
    if info.pw_uid == 0:
        raise ValueError("build user must not be root")
    return build_user


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)
