#!/usr/bin/env python3
"""Internal transactional-provisioning fixture/VM harness for Phase 23.7.5.6a.

This is not a public WatchdogVPN CLI. It drives the lab-only CanaryExecutor
through compat.provisioning.engine for L1 fixtures and VM validation. It
never registers a production executor, never touches a real package manager,
repository, network, DNS, firewall, service or protocol, and never migrates
AmneziaWG (23.7.5.6b) or any legacy consumer.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from compat import detection
from compat.dependency_resolution import ResolutionDecision
from compat.provisioning import engine, journal as journal_mod
from compat.provisioning.errors import PathPolicyError
from compat.provisioning.executors import (
    CANARY_EXECUTOR_VERSION,
    CANARY_METHOD_KIND,
    CanaryExecutor,
    ExecutionContext,
    TrustedExecutorRegistry,
)
from compat.provisioning.paths import validate_dedicated_lab_root, validate_lab_descendant

EXIT_USAGE = 1
EXIT_PROVISIONING_ERROR = 2


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lab_decision(capability_id: str, dependency_id: str, *, execution_ready: bool = True) -> ResolutionDecision:
    """A synthetic, lab-only decision. Real dependency ids from the product
    manifest are never wired to the canary executor; this exists purely to
    demonstrate the transactional infrastructure ahead of 23.7.5.6b+."""
    return ResolutionDecision(
        capability_id=capability_id,
        dependency_id=dependency_id,
        resolved_distribution="lab",
        resolved_release=None,
        technical_family="lab_fixture",
        release_model="rolling",
        support_classification="lab_fixture",
        machine_architecture="x86_64",
        observed_capability_status="absent",
        candidate_chain=("canary_method",),
        selected_method_id="canary_method",
        selected_method_kind=CANARY_METHOD_KIND,
        resolution_status="method_selected",
        execution_ready=execution_ready,
        rejected_candidates=(),
        evidence=(),
        reason="internal fixture/VM harness decision for 23.7.5.6a",
        provider_type="lab_fixture",
        provider_authoritative=False,
        availability_observations=(),
        all_availability_observations=(),
    )


def _path_contains(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _build_env(args, *, mutating: bool) -> engine.ProvisioningEnvironment:
    """``mutating`` gates whether the sandbox root is created. Read-only
    operations (``plan``, ``prepare``/``uninstall`` without ``--apply``,
    ``status``) must never create the sandbox or provisioning state root --
    root creation happens only on an explicitly authorized mutating path.

    Positive lab-root confinement, enforced before any mutation and
    regardless of ``mutating``: ``--sandbox`` and ``--state-root`` must both
    be strict descendants of ONE dedicated, pre-created, pre-approved
    ``--lab-root`` (owned by us, mode 0700, never a symlink, never the
    filesystem root/a reserved system path/the real product state
    directory/``$HOME`` itself) -- an arbitrary path such as ``/var/log``,
    ``/var/spool``, ``/opt`` or ``/srv`` is never acceptable just because it
    fails to match one specific denylist entry. Neither argument may equal
    the lab root, equal each other, or contain the other."""
    lab_root = validate_dedicated_lab_root(Path(args.lab_root))
    sandbox = validate_lab_descendant(lab_root, Path(args.sandbox), label="--sandbox")
    state_root = validate_lab_descendant(lab_root, Path(args.state_root), label="--state-root")
    if sandbox == state_root:
        raise PathPolicyError("--sandbox and --state-root must not be the same path: %s" % sandbox)
    if _path_contains(sandbox, state_root):
        raise PathPolicyError("--sandbox must not contain --state-root: %s / %s" % (sandbox, state_root))
    if _path_contains(state_root, sandbox):
        raise PathPolicyError("--state-root must not contain --sandbox: %s / %s" % (state_root, sandbox))
    if mutating:
        sandbox.mkdir(parents=True, exist_ok=True)
    registry = TrustedExecutorRegistry()
    registry.register(method_kind=CANARY_METHOD_KIND, method_id="canary_method", executor=CanaryExecutor())
    context = ExecutionContext(allowed_roots=(sandbox,), now=_now)
    return engine.ProvisioningEnvironment(
        state_root=state_root, registry=registry, expected_executor_version=CANARY_EXECUTOR_VERSION, context=context,
        global_lock_root=Path(args.global_lock_root),
    )


def _print(value) -> None:
    print(detection.stable_json(detection.to_jsonable(value)))


def cmd_plan(args) -> int:
    env = _build_env(args, mutating=False)
    decision = _lab_decision(args.capability_id, args.dependency_id)
    description = engine.dry_run(decision, registry=env.registry, expected_executor_version=env.expected_executor_version, context=env.context)
    _print(description)
    return 0


def cmd_prepare(args) -> int:
    env = _build_env(args, mutating=args.apply)
    decision = _lab_decision(args.capability_id, args.dependency_id)
    outcome = engine.prepare(decision, env, apply=args.apply)
    _print(
        {
            "status": outcome.status.value,
            "transaction_id": outcome.transaction_id,
            "reason": outcome.reason,
            "residuals": list(outcome.residuals),
            "error_kind": outcome.error_kind,
            "plan": outcome.plan,
        }
    )
    return 0


def cmd_recover(args) -> int:
    env = _build_env(args, mutating=True)
    reports = engine.recover_pending(env.state_root, env.registry, env.expected_executor_version, env.context, global_lock_root=env.global_lock_root)
    _print([{"transaction_id": r.transaction_id, "action": r.action.value, "reason": r.reason} for r in reports])
    return 0


def cmd_uninstall(args) -> int:
    env = _build_env(args, mutating=args.apply)
    outcome = engine.uninstall(args.capability_id, env, apply=args.apply)
    _print(
        {
            "status": outcome.status.value,
            "transaction_id": outcome.transaction_id,
            "reason": outcome.reason,
            "residuals": list(outcome.residuals),
            "error_kind": outcome.error_kind,
        }
    )
    return 0


def cmd_status(args) -> int:
    env = _build_env(args, mutating=False)
    ids = journal_mod.list_transaction_ids(env.state_root)
    report = []
    for transaction_id in ids:
        try:
            j = journal_mod.read_journal(env.state_root, transaction_id)
            report.append({"transaction_id": transaction_id, "operation": j.operation, "state": j.state.value})
        except Exception as exc:  # noqa: BLE001 - a corrupt journal is itself reportable status
            report.append({"transaction_id": transaction_id, "error": str(exc)})
    _print(report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lab-root", required=True, help="dedicated, pre-created lab root (owned by us, mode 0700) that --sandbox and --state-root must both descend from"
    )
    parser.add_argument("--sandbox", required=True, help="lab-only sandbox root the canary executor is confined to")
    parser.add_argument("--state-root", required=True, help="provisioning state root (journal/ownership)")
    parser.add_argument(
        "--global-lock-root", required=True,
        help="dedicated, stable root the global provisioner lock lives under (e.g. /run/lock/watchdogvpn/provisioning); "
        "never inside --state-root or --sandbox, and never renamed/replaced together with them",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="read-only dry-run plan description")
    plan.add_argument("capability_id")
    plan.add_argument("dependency_id")
    plan.set_defaults(func=cmd_plan)

    prepare = sub.add_parser("prepare")
    prepare.add_argument("capability_id")
    prepare.add_argument("dependency_id")
    prepare.add_argument("--apply", action="store_true", help="authorize mutation; without this flag, prepare behaves like plan")
    prepare.set_defaults(func=cmd_prepare)

    recover = sub.add_parser("recover")
    recover.set_defaults(func=cmd_recover)

    uninstall = sub.add_parser("uninstall")
    uninstall.add_argument("capability_id")
    uninstall.add_argument("--apply", action="store_true")
    uninstall.set_defaults(func=cmd_uninstall)

    status = sub.add_parser("status")
    status.set_defaults(func=cmd_status)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - controlled CLI error surface
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_PROVISIONING_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
