from __future__ import annotations

import os
from pathlib import Path

from config.paths import resolve_config_dir
from config.persistence import dump_json, file_lock, load_json, require_list
from node_groups.models import NodeGroup, NodeGroupResiliencePolicy, NodeGroupSelectionMode


def _node_groups_path() -> Path:
    override = os.environ.get("WATCHDOGVPN_NODE_GROUPS_FILE")
    if override:
        return Path(override)
    return resolve_config_dir() / "node_groups.json"


class NodeGroupStoreError(RuntimeError):
    pass


class NodeGroupStore:
    """Flat JSON-array store (node_groups.json), same shape as
    ProfileStore/ProviderStore - not one-file-per-group like RuleStore,
    since there is no bulk import/export/backup semantics to justify that
    pattern here (no `node-group import`/`export` command exists or is
    planned). Every mutation follows the mature 13.3 pattern: lock, load,
    mutate, reconstruct through NodeGroup.from_dict()/to_dict() to validate,
    then write atomically - an invalid group is never persisted.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _node_groups_path()

    def _load_raw(self) -> list[dict]:
        items = require_list(load_json(self.path, []), self.path)
        return [dict(item) for item in items]

    def _save_raw(self, items: list[dict]) -> None:
        dump_json(self.path, items)

    def add(self, group: NodeGroup) -> None:
        """Upsert by name: replaces an existing group with the same name.

        Named `add` to match ProfileStore/ProviderStore's convention
        (their `add` is also an upsert), not because insertion and update
        are the same operation conceptually - `update()` is provided as an
        explicit alias for callers where that reads more clearly.
        """
        with file_lock(self.path):
            items = self._load_raw()
            validated = NodeGroup.from_dict(group.to_dict())
            items = [item for item in items if item.get("name") != validated.name]
            items.append(validated.to_dict())
            self._save_raw(items)

    def update(self, group: NodeGroup) -> None:
        self.add(group)

    def get(self, name: str) -> NodeGroup | None:
        with file_lock(self.path):
            for item in self._load_raw():
                if item.get("name") == name:
                    return NodeGroup.from_dict(item)
        return None

    def list(self) -> list[NodeGroup]:
        with file_lock(self.path):
            return [NodeGroup.from_dict(item) for item in self._load_raw()]

    def remove(self, name: str) -> None:
        with file_lock(self.path):
            items = [item for item in self._load_raw() if item.get("name") != name]
            self._save_raw(items)

    def add_member_profile(self, group_name: str, profile_id: str) -> NodeGroup:
        with file_lock(self.path):
            items = self._load_raw()
            group = self._require_group_unlocked(items, group_name)
            if profile_id not in group.member_profile_ids:
                group.member_profile_ids.append(profile_id)
            return self._replace_unlocked(items, group)

    def remove_member_profile(self, group_name: str, profile_id: str) -> NodeGroup:
        with file_lock(self.path):
            items = self._load_raw()
            group = self._require_group_unlocked(items, group_name)
            group.member_profile_ids = [
                pid for pid in group.member_profile_ids if pid != profile_id
            ]
            return self._replace_unlocked(items, group)

    def set_selection(
        self,
        group_name: str,
        mode: NodeGroupSelectionMode,
        profile_id: str | None = None,
    ) -> NodeGroup:
        with file_lock(self.path):
            items = self._load_raw()
            group = self._require_group_unlocked(items, group_name)
            group.selection_mode = mode
            group.manual_profile_id = profile_id
            return self._replace_unlocked(items, group)

    def add_member_provider(self, group_name: str, provider_id: str) -> NodeGroup:
        with file_lock(self.path):
            items = self._load_raw()
            group = self._require_group_unlocked(items, group_name)
            if provider_id not in group.member_provider_ids:
                group.member_provider_ids.append(provider_id)
            return self._replace_unlocked(items, group)

    def remove_member_provider(self, group_name: str, provider_id: str) -> NodeGroup:
        with file_lock(self.path):
            items = self._load_raw()
            group = self._require_group_unlocked(items, group_name)
            group.member_provider_ids = [
                pid for pid in group.member_provider_ids if pid != provider_id
            ]
            return self._replace_unlocked(items, group)

    def add_exclude_profile(self, group_name: str, profile_id: str) -> NodeGroup:
        with file_lock(self.path):
            items = self._load_raw()
            group = self._require_group_unlocked(items, group_name)
            if profile_id not in group.exclude_profile_ids:
                group.exclude_profile_ids.append(profile_id)
            return self._replace_unlocked(items, group)

    def remove_exclude_profile(self, group_name: str, profile_id: str) -> NodeGroup:
        with file_lock(self.path):
            items = self._load_raw()
            group = self._require_group_unlocked(items, group_name)
            group.exclude_profile_ids = [
                pid for pid in group.exclude_profile_ids if pid != profile_id
            ]
            return self._replace_unlocked(items, group)

    def set_resilience_policy(
        self, group_name: str, policy: NodeGroupResiliencePolicy
    ) -> NodeGroup:
        with file_lock(self.path):
            items = self._load_raw()
            group = self._require_group_unlocked(items, group_name)
            group.resilience_policy = policy
            return self._replace_unlocked(items, group)

    def set_enabled(self, group_name: str, enabled: bool) -> NodeGroup:
        with file_lock(self.path):
            items = self._load_raw()
            group = self._require_group_unlocked(items, group_name)
            group.enabled = enabled
            return self._replace_unlocked(items, group)

    def _require_group_unlocked(self, items: list[dict], name: str) -> NodeGroup:
        for item in items:
            if item.get("name") == name:
                return NodeGroup.from_dict(item)
        raise NodeGroupStoreError(f"node group not found: {name}")

    def _replace_unlocked(self, items: list[dict], group: NodeGroup) -> NodeGroup:
        validated = NodeGroup.from_dict(group.to_dict())
        items = [item for item in items if item.get("name") != validated.name]
        items.append(validated.to_dict())
        self._save_raw(items)
        return validated
