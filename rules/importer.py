from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config.persistence import PersistentStoreError
from rules.models import Rule, RuleGroup, validate_group_name


DOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
SLUG_RE = re.compile(r"[^a-z0-9_-]+")
SUPPORTED_SINGBOX_MATCH_FIELDS = {
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "process_name",
    "process_path",
    "port",
    "port_range",
    "protocol",
    "network",
}
SINGBOX_UNSUPPORTED_STRUCTURAL_FIELDS = {
    "type",
    "mode",
    "rules",
    "rule_set",
    "rule_set_ip_cidr_match_source",
    "source_ip_cidr",
    "source_port",
    "source_port_range",
    "user",
    "auth_user",
    "wifi_ssid",
    "wifi_bssid",
    "clash_mode",
}
CLASH_ACTION_MAP = {
    "DIRECT": "direct",
    "REJECT": "block",
    "REJECT-DROP": "block",
    "BLOCK": "block",
    "PROXY": "current_profile",
    "GLOBAL": "current_profile",
}
SINGBOX_ACTION_MAP = {
    "direct": "direct",
    "block": "block",
    "reject": "block",
    "current": "current_profile",
    "current_profile": "current_profile",
    "proxy": "current_profile",
}


class RuleImportError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RejectedRule:
    source: str
    reason: str
    item: object

    def to_dict(self) -> dict[str, object]:
        return {"source": self.source, "reason": self.reason, "item": self.item}


@dataclass(frozen=True, slots=True)
class RuleImportPlan:
    group: RuleGroup
    source_format: str
    rejected: tuple[RejectedRule, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "source_format": self.source_format,
            "group": self.group.to_dict(),
            "accepted_rule_count": len(self.group.rules),
            "rejected": [item.to_dict() for item in self.rejected],
            "warnings": list(self.warnings),
        }


def build_rule_import_plan(
    path: Path,
    *,
    name: str | None = None,
    default_action: str = "block",
    allow_partial: bool = False,
) -> RuleImportPlan:
    text = _read_text(path)
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuleImportError(f"invalid rule import JSON in {path}: {exc}") from exc
        plan = _plan_from_json(raw, source_name=path.stem, name=name, default_action=default_action)
    else:
        plan = _plan_from_simple_list(text, source_name=path.stem, name=name, default_action=default_action)
    if plan.rejected and not allow_partial:
        raise RuleImportError(
            "rule import contains unsupported entries; rerun with --allow-partial to import accepted rules"
        )
    if not plan.group.rules:
        raise RuleImportError("rule import produced no supported rules")
    return plan


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleImportError(f"cannot read rule import file {path}: {exc}") from exc


def _plan_from_json(
    raw: object,
    *,
    source_name: str,
    name: str | None,
    default_action: str,
) -> RuleImportPlan:
    if isinstance(raw, dict) and _looks_like_watchdog_group(raw):
        data = dict(raw)
        if name is not None:
            data["name"] = name
        try:
            return RuleImportPlan(group=RuleGroup.from_dict(data), source_format="watchdogvpn-rule-group")
        except (KeyError, TypeError, ValueError, PersistentStoreError) as exc:
            raise RuleImportError(f"invalid rule group schema: {exc}") from exc
    if isinstance(raw, dict) and isinstance(raw.get("route"), dict):
        route = raw["route"]
        if isinstance(route.get("rules"), list):
            return _plan_from_singbox_rules(
                route["rules"],
                source_name=source_name,
                name=name,
                default_action=default_action,
                source_format="sing-box-route-rules",
            )
    if isinstance(raw, dict) and isinstance(raw.get("rules"), list):
        return _plan_from_singbox_rules(
            raw["rules"],
            source_name=source_name,
            name=name,
            default_action=default_action,
            source_format="sing-box-route-rules",
        )
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        lines = [str(item) for item in raw]
        if any(_looks_like_clash_line(line) for line in lines):
            return _plan_from_clash_rules(lines, source_name=source_name, name=name)
        return _plan_from_simple_entries(
            lines,
            source_name=source_name,
            name=name,
            default_action=default_action,
            source_format="simple-domain-ip-list",
        )
    if isinstance(raw, list):
        return _plan_from_clash_rules(
            [str(item) for item in raw if isinstance(item, str)],
            rejected=[
                RejectedRule(source="json-list", reason="list item is not a string", item=item)
                for item in raw
                if not isinstance(item, str)
            ],
            source_name=source_name,
            name=name,
        )
    raise RuleImportError("unsupported rule import format")


def _looks_like_watchdog_group(raw: dict[str, object]) -> bool:
    return "name" in raw and "rules" in raw


def _plan_from_simple_list(
    text: str,
    *,
    source_name: str,
    name: str | None,
    default_action: str,
) -> RuleImportPlan:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        entries.append(line)
    return _plan_from_simple_entries(
        entries,
        source_name=source_name,
        name=name,
        default_action=default_action,
        source_format="simple-domain-ip-list",
    )


def _plan_from_simple_entries(
    entries: list[str],
    *,
    source_name: str,
    name: str | None,
    default_action: str,
    source_format: str,
) -> RuleImportPlan:
    rules: list[Rule] = []
    rejected: list[RejectedRule] = []
    for index, entry in enumerate(entries, start=1):
        condition = _simple_entry_condition(entry)
        if condition is None:
            rejected.append(RejectedRule(source=f"line:{index}", reason="not a supported domain or IP CIDR", item=entry))
            continue
        rules.append(_rule(rule_id=_rule_id("simple", index), action=default_action, conditions=condition))
    return RuleImportPlan(
        group=RuleGroup(name=_import_group_name(name, source_name), rules=rules),
        source_format=source_format,
        rejected=tuple(rejected),
    )


def _simple_entry_condition(entry: str) -> dict[str, list[str]] | None:
    value = entry.strip()
    if not value:
        return None
    try:
        network = ipaddress.ip_network(value, strict=False)
        return {"ip_cidr": [str(network)]}
    except ValueError:
        pass
    if value.startswith("."):
        domain = value[1:].strip()
        if _valid_domain(domain):
            return {"domain_suffix": [f".{domain.lower()}"]}
        return None
    if _valid_domain(value):
        return {"domain": [value.lower()]}
    return None


def _plan_from_clash_rules(
    lines: list[str],
    *,
    rejected: list[RejectedRule] | None = None,
    source_name: str,
    name: str | None,
) -> RuleImportPlan:
    rules: list[Rule] = []
    rejected_items = rejected or []
    for index, line in enumerate(lines, start=1):
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 3:
            rejected_items.append(RejectedRule(source=f"clash:{index}", reason="rule must have type,value,action", item=line))
            continue
        rule_type, value, action_token = parts[0].upper(), parts[1], parts[2].upper()
        action = CLASH_ACTION_MAP.get(action_token)
        if action is None:
            rejected_items.append(RejectedRule(source=f"clash:{index}", reason=f"unsupported action: {action_token}", item=line))
            continue
        condition = _clash_condition(rule_type, value)
        if condition is None:
            rejected_items.append(RejectedRule(source=f"clash:{index}", reason=f"unsupported rule type or value: {rule_type}", item=line))
            continue
        rules.append(_rule(rule_id=_rule_id("clash", index), action=action, conditions=condition))
    return RuleImportPlan(
        group=RuleGroup(name=_import_group_name(name, source_name), rules=rules),
        source_format="clash-rule-list",
        rejected=tuple(rejected_items),
    )


def _looks_like_clash_line(line: str) -> bool:
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 3:
        return False
    return parts[0].upper() in {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "IP-CIDR",
        "IP-CIDR6",
        "PROCESS-NAME",
    }


def _clash_condition(rule_type: str, value: str) -> dict[str, list[str]] | None:
    value = value.strip()
    if rule_type == "DOMAIN" and _valid_domain(value):
        return {"domain": [value.lower()]}
    if rule_type == "DOMAIN-SUFFIX" and _valid_domain(value.lstrip(".")):
        return {"domain_suffix": [f".{value.lstrip('.').lower()}"]}
    if rule_type == "DOMAIN-KEYWORD" and value:
        return {"domain_keyword": [value.lower()]}
    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            return {"ip_cidr": [str(ipaddress.ip_network(value, strict=False))]}
        except ValueError:
            return None
    if rule_type == "PROCESS-NAME" and value:
        return {"process_name": [value]}
    return None


def _plan_from_singbox_rules(
    items: list[object],
    *,
    source_name: str,
    name: str | None,
    default_action: str,
    source_format: str,
) -> RuleImportPlan:
    rules: list[Rule] = []
    rejected: list[RejectedRule] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            rejected.append(RejectedRule(source=f"sing-box:{index}", reason="rule is not an object", item=item))
            continue
        structural = sorted(set(item) & SINGBOX_UNSUPPORTED_STRUCTURAL_FIELDS)
        if structural:
            rejected.append(RejectedRule(source=f"sing-box:{index}", reason=f"unsupported structural fields: {', '.join(structural)}", item=item))
            continue
        conditions = _singbox_conditions(item)
        if not conditions:
            rejected.append(RejectedRule(source=f"sing-box:{index}", reason="no supported match fields", item=item))
            continue
        action = _singbox_action(item, default_action)
        if action is None:
            rejected.append(RejectedRule(source=f"sing-box:{index}", reason="unsupported action/outbound", item=item))
            continue
        rules.append(_rule(rule_id=_rule_id("singbox", index), action=action, conditions=conditions))
    return RuleImportPlan(
        group=RuleGroup(name=_import_group_name(name, source_name), rules=rules),
        source_format=source_format,
        rejected=tuple(rejected),
    )


def _singbox_conditions(item: dict[str, object]) -> dict[str, list[str]]:
    conditions: dict[str, list[str]] = {}
    for key in SUPPORTED_SINGBOX_MATCH_FIELDS:
        value = item.get(key)
        if value is None:
            continue
        values = _string_list(value)
        if values:
            conditions[key] = values
    return conditions


def _singbox_action(item: dict[str, object], default_action: str) -> str | None:
    raw = item.get("action") or item.get("outbound") or default_action
    action = str(raw).strip()
    if action in SINGBOX_ACTION_MAP:
        return SINGBOX_ACTION_MAP[action]
    if action in {"direct", "current_profile", "block", "auto_select"} or action.startswith("group:"):
        return action
    return None


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        items = value
    else:
        items = [value]
    return [str(item).strip() for item in items if str(item).strip()]


def _rule(*, rule_id: str, action: str, conditions: dict[str, list[str]]) -> Rule:
    try:
        return Rule(id=rule_id, action=action, conditions=conditions)
    except ValueError as exc:
        raise RuleImportError(str(exc)) from exc


def _valid_domain(value: str) -> bool:
    return bool(value) and len(value) <= 253 and "." in value and DOMAIN_RE.match(value) is not None


def _rule_id(prefix: str, index: int) -> str:
    return f"{prefix}-{index:04d}"


def _import_group_name(name: str | None, source_name: str) -> str:
    if name:
        return validate_group_name(name)
    slug = SLUG_RE.sub("-", source_name.lower()).strip("-_")
    if not slug:
        slug = "imported"
    return validate_group_name(slug[:64])
