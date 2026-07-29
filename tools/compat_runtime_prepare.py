#!/usr/bin/env python3
"""Internal runtime provisioning tool for Phase 23.7.5.6b.

This is not a public WatchdogVPN CLI. It exists to validate and operate the
AmneziaWG userspace source-build executor through the transactional
provisioner. It does not integrate profile activation, public CLI commands,
install/update/doctor, package-manager repositories, DKMS or kernel modules.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from compat import dependency_resolution as resolver
from compat import detection
from compat.provisioning import engine, journal as journal_mod
from compat.provisioning.amneziawg import (
    AMNEZIAWG_SOURCE_BUILD_EXECUTOR_VERSION,
    AmneziaWGUserspaceSourceBuildExecutor,
    components_from_candidate,
)
from compat.provisioning.executors import ExecutionContext, TrustedExecutorRegistry
from tools import compat_read


DEPENDENCY_ID = "dep_amneziawg_runtime"
CAPABILITY_ID = "proto_amneziawg_runtime"
EXIT_USAGE = 1
EXIT_ERROR = 2


class AmneziaWGSourceOnlyProvider(resolver.AvailabilityProvider):
    provider_type = "amneziawg_6b_internal_source_only"
    authoritative = True

    def repository_supports_exact_target(self, candidate, target_id):
        return resolver.AvailabilityObservation(
            resolver.AvailabilityStatus.UNAVAILABLE.value,
            evidence="23.7.5.6b internal CLI does not execute package-manager repository candidates",
            reason="package_manager_execution_out_of_scope_for_23_7_5_6b",
            error_kind="package_manager_out_of_scope",
        )

    def package_exists(self, candidate, exact_target, package_name):
        return resolver.AvailabilityObservation(
            resolver.AvailabilityStatus.UNAVAILABLE.value,
            evidence="23.7.5.6b internal CLI is limited to AmneziaWG userspace source build",
            reason="package_manager_execution_out_of_scope_for_23_7_5_6b",
            error_kind="package_manager_out_of_scope",
        )

    def source_revision_available(self, candidate, target_id):
        if candidate.kind != "pinned_source_build":
            return resolver.AvailabilityObservation(
                resolver.AvailabilityStatus.UNAVAILABLE.value,
                evidence="not an AmneziaWG pinned source-build candidate",
                reason="candidate_kind_not_executed_by_23_7_5_6b",
                error_kind="candidate_kind_out_of_scope",
            )
        return resolver.AvailabilityObservation(
            resolver.AvailabilityStatus.AVAILABLE.value,
            evidence="all source components declare release tags and exact Git commits for target %s" % target_id,
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _print(value) -> None:
    print(detection.stable_json(detection.to_jsonable(value)))


def _load_manifest(path: str | None):
    manifest_path = Path(path) if path else Path(compat_read.DEFAULT_MANIFEST_PATH)
    manifest = compat_read.load_manifest_file(manifest_path, product_path=path is None)
    compat_read.validate_manifest(manifest)
    return manifest


def _load_os_release(args) -> detection.OsReleaseData:
    if args.os_release:
        return detection.read_os_release(
            etc_path=Path(args.os_release),
            usr_path=Path(args.usr_os_release) if args.usr_os_release else Path(args.os_release),
        )
    return detection.read_os_release(
        usr_path=Path(args.usr_os_release) if args.usr_os_release else Path("/usr/lib/os-release"),
    )


def _context(args):
    manifest = _load_manifest(args.manifest)
    env = detection.ProbeEnvironment()
    facts = detection.distro_facts_from_os_release(
        _load_os_release(args),
        manifest,
        kernel_release=env.kernel_release,
        machine_architecture=env.machine_architecture,
    )
    core = tuple(detection.probe_core_capabilities(manifest, facts, env))
    protocol = tuple(detection.probe_protocol_capabilities(manifest, env))
    if args.force_runtime_absent:
        protocol = tuple(
            detection.CapabilityResult(
                item.capability_id,
                "absent",
                "provisionable",
                item.evidence,
                item.probe_method,
                "forced absent by explicit internal 23.7.5.6b option",
                item.error_kind,
            )
            if item.capability_id == CAPABILITY_ID
            else item
            for item in protocol
        )
    support_report = detection.evaluate(
        manifest,
        facts,
        core,
        protocol,
        now=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    capability_results = tuple(support_report.core_capabilities) + tuple(support_report.protocol_capabilities)
    decision = resolver.resolve_dependency(
        manifest,
        facts,
        support_report.support_classification,
        capability_results,
        args.dependency,
        availability=AmneziaWGSourceOnlyProvider(),
    )
    return manifest, decision


def _selected_candidate(manifest, decision):
    for candidate in manifest["dependency_requirements"][decision.dependency_id]["method_chain"]:
        if candidate["id"] == decision.selected_method_id:
            return candidate
    raise ValueError("selected method is absent from manifest: %s" % decision.selected_method_id)


def _source_build_candidates(manifest):
    for candidate in manifest["dependency_requirements"][DEPENDENCY_ID]["method_chain"]:
        if candidate["kind"] == "pinned_source_build":
            yield candidate


def _register_source_build_executors(registry: TrustedExecutorRegistry, manifest, args, build_user: str) -> None:
    for candidate in _source_build_candidates(manifest):
        executor = AmneziaWGUserspaceSourceBuildExecutor(
            method_id=candidate["id"],
            components=components_from_candidate(candidate),
            build_user=build_user,
            workspace_root=Path(args.workspace_root),
            install_root=Path(args.install_root),
        )
        registry.register(method_kind=candidate["kind"], method_id=candidate["id"], executor=executor)


def _build_env(args, manifest, decision, *, mutating: bool) -> engine.ProvisioningEnvironment:
    if mutating:
        if not args.build_user:
            raise ValueError("--build-user is required for mutating provisioning commands")
        build_user = args.build_user
    else:
        build_user = args.build_user or _default_plan_user()
    registry = TrustedExecutorRegistry()
    _register_source_build_executors(registry, manifest, args, build_user)
    context = ExecutionContext(
        allowed_roots=(Path(args.install_root),),
        forbidden_roots=(),
        now=_now,
        network_available=lambda: True,
    )
    return engine.ProvisioningEnvironment(
        state_root=Path(args.state_root),
        registry=registry,
        expected_executor_version=AMNEZIAWG_SOURCE_BUILD_EXECUTOR_VERSION,
        context=context,
        global_lock_root=Path(args.global_lock_root),
    )


def _default_plan_user() -> str:
    import getpass

    user = getpass.getuser()
    if user != "root":
        return user
    return "nobody"


def cmd_plan(args) -> int:
    manifest, decision = _context(args)
    if decision.selected_method_id is None:
        _print({"decision": decision, "plan": None, "reason": decision.reason})
        return 0
    env = _build_env(args, manifest, decision, mutating=False)
    description = engine.dry_run(decision, registry=env.registry, expected_executor_version=env.expected_executor_version, context=env.context)
    _print({"decision": decision, "plan": description})
    return 0


def cmd_prepare(args) -> int:
    manifest, decision = _context(args)
    if decision.selected_method_id is None:
        _print({"status": decision.resolution_status, "transaction_id": None, "reason": decision.reason, "residuals": [], "error_kind": decision.error_kind, "plan": None})
        return 0
    env = _build_env(args, manifest, decision, mutating=args.apply)
    outcome = engine.prepare(decision, env, apply=args.apply)
    _print({"status": outcome.status.value, "transaction_id": outcome.transaction_id, "reason": outcome.reason, "residuals": list(outcome.residuals), "error_kind": outcome.error_kind, "plan": outcome.plan})
    return 0


def cmd_recover(args) -> int:
    manifest, decision = _context(args)
    env = _build_env(args, manifest, decision, mutating=True)
    reports = engine.recover_pending(env.state_root, env.registry, env.expected_executor_version, env.context, global_lock_root=env.global_lock_root)
    _print([{"transaction_id": item.transaction_id, "action": item.action.value, "reason": item.reason} for item in reports])
    return 0


def cmd_uninstall(args) -> int:
    manifest, decision = _context(args)
    env = _build_env(args, manifest, decision, mutating=args.apply)
    outcome = engine.uninstall(CAPABILITY_ID, env, apply=args.apply)
    _print({"status": outcome.status.value, "transaction_id": outcome.transaction_id, "reason": outcome.reason, "residuals": list(outcome.residuals), "error_kind": outcome.error_kind})
    return 0


def cmd_status(args) -> int:
    ids = journal_mod.list_transaction_ids(Path(args.state_root))
    report = []
    for transaction_id in ids:
        try:
            journal = journal_mod.read_journal(Path(args.state_root), transaction_id)
            report.append({"transaction_id": transaction_id, "operation": journal.operation, "state": journal.state.value})
        except Exception as exc:  # noqa: BLE001
            report.append({"transaction_id": transaction_id, "error": str(exc)})
    _print(report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", help="manifest path; defaults to product manifest")
    parser.add_argument("--os-release", help="explicit /etc/os-release fixture path")
    parser.add_argument("--usr-os-release", help="explicit /usr/lib/os-release fallback fixture path")
    parser.add_argument("--dependency", default=DEPENDENCY_ID, choices=(DEPENDENCY_ID,))
    parser.add_argument("--state-root", default="/var/lib/watchdogvpn/provisioning")
    parser.add_argument("--global-lock-root", default="/run/lock/watchdogvpn/provisioning")
    parser.add_argument("--install-root", default="/usr/local/bin")
    parser.add_argument("--workspace-root", default="/var/lib/watchdogvpn/provisioning/build/amneziawg")
    parser.add_argument("--build-user", help="required explicit non-root user for mutating provisioning commands")
    parser.add_argument("--force-runtime-absent", action="store_true", help="internal fixture/audit mode: force AWG runtime absent before resolving")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan").set_defaults(func=cmd_plan)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--apply", action="store_true")
    prepare.set_defaults(func=cmd_prepare)
    sub.add_parser("recover").set_defaults(func=cmd_recover)
    uninstall = sub.add_parser("uninstall")
    uninstall.add_argument("--apply", action="store_true")
    uninstall.set_defaults(func=cmd_uninstall)
    sub.add_parser("status").set_defaults(func=cmd_status)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (compat_read.ManifestError, detection.DetectionError, resolver.DependencyResolutionError, ValueError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR if not isinstance(exc, ValueError) else EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
