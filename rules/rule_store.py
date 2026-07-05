from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from config.paths import resolve_config_dir
from config.persistence import dump_json, file_lock, load_json, require_mapping
from rules.models import DEFAULT_RULE_GROUPS, Rule, RuleGroup, validate_group_name


def _rules_dir() -> Path:
    override = os.environ.get("WATCHDOGVPN_RULES_DIR")
    if override:
        return Path(override)
    return resolve_config_dir() / "rules"


class RuleStoreError(RuntimeError):
    pass


class RuleStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _rules_dir()

    def _group_path(self, name: str) -> Path:
        return self.path / f"{validate_group_name(name)}.json"

    def _backup_path(self, name: str) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        base = self.path / "backups" / f"{validate_group_name(name)}-{timestamp}.json"
        if not base.exists():
            return base
        suffix = 2
        while True:
            candidate = self.path / "backups" / f"{validate_group_name(name)}-{timestamp}-{suffix}.json"
            if not candidate.exists():
                return candidate
            suffix += 1

    def add_group(self, group: RuleGroup) -> None:
        target = self._group_path(group.name)
        with file_lock(target):
            self.path.mkdir(parents=True, exist_ok=True)
            validated = RuleGroup.from_dict(group.to_dict())
            dump_json(target, validated.to_dict())

    def replace_group(self, group: RuleGroup, *, backup_existing: bool = False) -> Path | None:
        target = self._group_path(group.name)
        with file_lock(target):
            self.path.mkdir(parents=True, exist_ok=True)
            validated = RuleGroup.from_dict(group.to_dict())
            backup_path = None
            if backup_existing and target.exists():
                existing = RuleGroup.from_dict(require_mapping(load_json(target, {}), target))
                backup_path = self._backup_path(existing.name)
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                dump_json(backup_path, existing.to_dict())
            dump_json(target, validated.to_dict())
            return backup_path

    def get_group(self, name: str) -> RuleGroup | None:
        target = self._group_path(name)
        with file_lock(target):
            if not target.exists():
                return None
            data = require_mapping(load_json(target, {}), target)
            return RuleGroup.from_dict(data)

    def list_groups(self) -> list[RuleGroup]:
        if not self.path.exists():
            return []
        groups = []
        for file in sorted(self.path.glob("*.json")):
            data = require_mapping(load_json(file, {}), file)
            groups.append(RuleGroup.from_dict(data))
        return groups

    def update_group(self, group: RuleGroup) -> None:
        self.add_group(group)

    def remove_group(self, name: str) -> None:
        target = self._group_path(name)
        with file_lock(target):
            if target.exists():
                target.unlink()

    def enable_group(self, name: str) -> None:
        group = self._require_group(name)
        group.enabled = True
        self.update_group(group)

    def disable_group(self, name: str) -> None:
        group = self._require_group(name)
        group.enabled = False
        self.update_group(group)

    def add_rule(self, group_name: str, rule: Rule) -> RuleGroup:
        target = self._group_path(group_name)
        with file_lock(target):
            group = self._load_required_group_unlocked(target, group_name)
            if any(existing.id == rule.id for existing in group.rules):
                raise RuleStoreError(f"rule already exists: {rule.id}")
            group.rules.append(rule)
            validated = RuleGroup.from_dict(group.to_dict())
            dump_json(target, validated.to_dict())
            return validated

    def remove_rule(self, group_name: str, rule_id: str) -> RuleGroup:
        target = self._group_path(group_name)
        with file_lock(target):
            group = self._load_required_group_unlocked(target, group_name)
            original_count = len(group.rules)
            group.rules = [rule for rule in group.rules if rule.id != rule_id]
            if len(group.rules) == original_count:
                raise RuleStoreError(f"rule not found: {rule_id}")
            validated = RuleGroup.from_dict(group.to_dict())
            dump_json(target, validated.to_dict())
            return validated

    def ensure_default_groups(self) -> None:
        for name in DEFAULT_RULE_GROUPS:
            if self.get_group(name) is None:
                self.add_group(RuleGroup(name=name))

    def import_group(self, rules: list[Rule], *, prefix: str = "imported") -> RuleGroup:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        name = f"{prefix}-{timestamp}"
        suffix = 1
        while self.get_group(name) is not None:
            suffix += 1
            name = f"{prefix}-{timestamp}-{suffix}"
        group = RuleGroup(name=name, rules=list(rules))
        self.add_group(group)
        return group

    def _require_group(self, name: str) -> RuleGroup:
        group = self.get_group(name)
        if group is None:
            raise RuleStoreError(f"rule group not found: {name}")
        return group

    def _load_required_group_unlocked(self, target: Path, name: str) -> RuleGroup:
        if not target.exists():
            raise RuleStoreError(f"rule group not found: {validate_group_name(name)}")
        data = require_mapping(load_json(target, {}), target)
        return RuleGroup.from_dict(data)
