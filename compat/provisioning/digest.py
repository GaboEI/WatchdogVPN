"""Canonical, stable plan_digest computation (Phase 23.7.5.6a).

A later edit to the compatibility manifest must never silently reinterpret
an incomplete transaction: apply, recovery, rollback and uninstall all verify
that the journal's stored plan_digest still matches the plan being acted on.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json

from compat.provisioning.model import OwnershipRecord, ProvisioningPlan, UninstallPlan


def canonical_plan_mapping(plan: ProvisioningPlan) -> dict:
    return {
        "capability_id": plan.capability_id,
        "dependency_id": plan.dependency_id,
        "resolved_target": plan.resolved_target,
        "architecture": plan.architecture,
        "support_classification": plan.support_classification,
        "selected_method_id": plan.selected_method_id,
        "selected_method_kind": plan.selected_method_kind,
        "postcondition": plan.postcondition,
        "executor_id": plan.executor_id,
        "executor_version": plan.executor_version,
        "selected_asset": _jsonable(plan.selected_asset),
        "steps": [
            {
                "sequence": step.sequence,
                "step_id": step.step_id,
                "action_type": step.action_type,
                "intent": _jsonable(step.intent),
                "target": step.target,
            }
            for step in plan.steps
        ],
    }


def compute_plan_digest(plan: ProvisioningPlan) -> str:
    canonical = canonical_plan_mapping(plan)
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_ownership_record_mapping(record: OwnershipRecord) -> dict:
    candidate = record.candidate
    return {
        "capability_id": record.capability_id,
        "product_owned": record.product_owned,
        "created_by_transaction": record.created_by_transaction,
        "executor_id": record.executor_id,
        "executor_version": record.executor_version,
        "recorded_at": record.recorded_at,
        "candidate": {
            "artifact_type": candidate.artifact_type,
            "resource_identity": candidate.resource_identity,
            "pre_existing": candidate.pre_existing,
            "method_id": candidate.method_id,
            "source": candidate.source,
            "version": candidate.version,
            "integrity": candidate.integrity,
            "uid": candidate.uid,
            "gid": candidate.gid,
            "mode": candidate.mode,
            "nlink": candidate.nlink,
            "post_install_fingerprint": candidate.post_install_fingerprint,
            "intermediate_identities": [
                {
                    "relative_name": identity.relative_name,
                    "dev": identity.dev,
                    "ino": identity.ino,
                    "uid": identity.uid,
                    "mode": identity.mode,
                }
                for identity in candidate.intermediate_identities
            ],
            "path_authority": (
                {
                    "root_path": candidate.path_authority.root_path,
                    "target_relative_path": candidate.path_authority.target_relative_path,
                    "component_count": candidate.path_authority.component_count,
                    "components": [
                        {
                            "index": component.index,
                            "relative_name": component.relative_name,
                            "dev": component.dev,
                            "ino": component.ino,
                            "uid": component.uid,
                            "mode": component.mode,
                        }
                        for component in candidate.path_authority.components
                    ],
                }
                if candidate.path_authority is not None
                else None
            ),
            "path_authority_v2": (
                {
                    "schema": candidate.path_authority_v2.schema,
                    "transaction_id": candidate.path_authority_v2.transaction_id,
                    "plan_digest": candidate.path_authority_v2.plan_digest,
                    "resource_id": candidate.path_authority_v2.resource_id,
                    "configured_root": candidate.path_authority_v2.configured_root,
                    "root_path": candidate.path_authority_v2.root_path,
                    "target_relative_path": candidate.path_authority_v2.target_relative_path,
                    "component_count": candidate.path_authority_v2.component_count,
                    "components": [
                        {
                            "index": component.index,
                            "name": component.name,
                            "role": component.role,
                            "dev": component.dev,
                            "ino": component.ino,
                            "uid": component.uid,
                            "gid": component.gid,
                            "mode": component.mode,
                            "nlink": component.nlink,
                            "integrity": component.integrity,
                        }
                        for component in candidate.path_authority_v2.components
                    ],
                    "chain_digest": candidate.path_authority_v2.chain_digest,
                    "authority_digest": candidate.path_authority_v2.authority_digest,
                }
                if candidate.path_authority_v2 is not None
                else None
            ),
        },
    }


def canonical_uninstall_plan_mapping(plan: UninstallPlan) -> dict:
    return {
        "capability_id": plan.capability_id,
        "target_transaction_id": plan.target_transaction_id,
        # The exact ownership set that authorized this plan participates in
        # the digest: recovery must detect any divergence between the
        # journal's immutable snapshot and what it originally authorized,
        # never silently re-deriving a different authorization set.
        "ownership_records": [canonical_ownership_record_mapping(record) for record in plan.ownership_records],
        "steps": [
            {
                "sequence": step.sequence,
                "step_id": step.step_id,
                "action_type": step.action_type,
                "intent": _jsonable(step.intent),
                "target": step.target,
            }
            for step in plan.steps
        ],
    }


def compute_uninstall_plan_digest(plan: UninstallPlan) -> str:
    canonical = canonical_uninstall_plan_mapping(plan)
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _jsonable(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    raise TypeError("plan digest input must be JSON-representable, got %r" % type(value))
