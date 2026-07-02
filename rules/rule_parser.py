from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from config.persistence import PersistentValidationError
from rules.models import Rule


class RuleParseError(ValueError):
    pass


def _load_json_payload(data: str | Any) -> Any:
    if isinstance(data, (dict, list)):
        return data
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        raise RuleParseError(f"invalid JSON: {exc}") from exc


# ---- WatchdogVPN native JSON format ----


def parse_watchdogvpn_json(data: str | list[Any]) -> list[Rule]:
    payload = _load_json_payload(data)
    if not isinstance(payload, list):
        raise RuleParseError("WatchdogVPN rule JSON must be an array of rule objects")
    try:
        return [Rule.from_dict(item) for item in payload]
    except (ValueError, TypeError, KeyError, PersistentValidationError) as exc:
        raise RuleParseError(f"invalid WatchdogVPN rule entry: {exc}") from exc


def export_watchdogvpn_json(rules: list[Rule]) -> str:
    return json.dumps([rule.to_dict() for rule in rules], indent=2, sort_keys=True) + "\n"


def _build_rule(rule_id: str, action: str, conditions: dict[str, list[str]]) -> Rule:
    try:
        return Rule(id=rule_id, action=action, conditions=conditions)
    except ValueError as exc:
        raise RuleParseError(str(exc)) from exc


# ---- sing-box rule-set (JSON source and compiled .srs) ----

_SINGBOX_RULE_SET_FIELDS = {
    "domain": "domain",
    "domain_suffix": "domain_suffix",
    "domain_keyword": "domain_keyword",
    "domain_regex": "domain_regex",
    "ip_cidr": "ip_cidr",
    "port": "port",
    "port_range": "port_range",
    "network": "network",
    "process_name": "process_name",
    "process_path": "process_path",
}


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _singbox_rule_entry_to_conditions(entry: dict[str, Any]) -> dict[str, list[str]]:
    if entry.get("type") == "logical" or "rules" in entry:
        raise RuleParseError("nested/logical sing-box rule-set entries are not supported")
    conditions: dict[str, list[str]] = {}
    for singbox_field, condition_key in _SINGBOX_RULE_SET_FIELDS.items():
        if singbox_field in entry:
            conditions.setdefault(condition_key, []).extend(_as_string_list(entry[singbox_field]))
    unknown = set(entry) - set(_SINGBOX_RULE_SET_FIELDS) - {"invert"}
    if unknown:
        raise RuleParseError(f"unsupported sing-box rule-set fields: {sorted(unknown)}")
    if not conditions:
        raise RuleParseError("sing-box rule-set entry has no supported conditions")
    return conditions


def parse_singbox_ruleset_json(
    data: str | dict[str, Any],
    *,
    action: str = "current_profile",
    id_prefix: str = "ruleset",
) -> list[Rule]:
    payload = _load_json_payload(data)
    if not isinstance(payload, dict) or "rules" not in payload:
        raise RuleParseError("sing-box rule-set JSON must contain a 'rules' array")
    raw_rules = payload["rules"]
    if not isinstance(raw_rules, list):
        raise RuleParseError("sing-box rule-set 'rules' must be an array")
    rules: list[Rule] = []
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise RuleParseError(f"sing-box rule-set entry {index} must be an object")
        conditions = _singbox_rule_entry_to_conditions(raw_rule)
        rules.append(_build_rule(f"{id_prefix}-{index}", action, conditions))
    if not rules:
        raise RuleParseError("sing-box rule-set contains no rules")
    return rules


def parse_singbox_ruleset_srs(
    path: str | Path,
    *,
    action: str = "current_profile",
    singbox_binary: str = "sing-box",
) -> list[Rule]:
    src = Path(path)
    if not src.exists():
        raise RuleParseError(f"rule-set file not found: {src}")
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "decompiled.json"
        try:
            subprocess.run(
                [singbox_binary, "rule-set", "decompile", str(src), "-o", str(out_path)],
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise RuleParseError(
                "sing-box binary not found; cannot decompile .srs rule-set"
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise RuleParseError(
                f"failed to decompile .srs rule-set: {exc.stderr.strip()}"
            ) from exc
        return parse_singbox_ruleset_json(
            out_path.read_text(encoding="utf-8"), action=action, id_prefix=src.stem
        )


# ---- Clash-compatible rule provider YAML ----

_CLASH_RULE_TYPE_MAP = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-REGEX": "domain_regex",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "DST-PORT": "port",
    "NETWORK": "network",
    "PROCESS-NAME": "process_name",
    "PROCESS-PATH": "process_path",
    "GEOIP": "ruleset_builtin",
    "GEOSITE": "ruleset_builtin",
    "RULE-SET": "ruleset_remote",
}
_CLASH_RULE_TYPES_SKIPPED = {"MATCH"}


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _load_clash_payload_entries(text: str) -> list[str]:
    lines = (text or "").splitlines()
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("payload:"):
            remainder = stripped.split(":", 1)[1].strip()
            if remainder:
                raise RuleParseError("inline payload values are not supported")
            entries: list[str] = []
            for lookahead in lines[index + 1 :]:
                if not lookahead.strip():
                    continue
                if not lookahead.lstrip().startswith("- "):
                    break
                entries.append(_strip_quotes(lookahead.lstrip()[2:]))
            return entries
    raise RuleParseError("Clash rule YAML missing payload section")


def parse_clash_yaml_rules(
    text: str,
    *,
    action: str = "current_profile",
    id_prefix: str = "clash",
) -> list[Rule]:
    entries = _load_clash_payload_entries(text)
    rules: list[Rule] = []
    for index, entry in enumerate(entries):
        parts = [part.strip() for part in entry.split(",")]
        rule_type = parts[0].upper()
        if rule_type in _CLASH_RULE_TYPES_SKIPPED:
            continue
        if rule_type not in _CLASH_RULE_TYPE_MAP:
            raise RuleParseError(f"unsupported Clash rule type: {parts[0]!r}")
        if len(parts) < 2 or not parts[1]:
            raise RuleParseError(f"Clash rule {entry!r} is missing a value")
        condition_key = _CLASH_RULE_TYPE_MAP[rule_type]
        value = parts[1]
        if rule_type == "GEOIP":
            value = f"geoip:{value.lower()}"
        elif rule_type == "GEOSITE":
            value = f"geosite:{value.lower()}"
        rules.append(_build_rule(f"{id_prefix}-{index}", action, {condition_key: [value]}))
    if not rules:
        raise RuleParseError("Clash rule YAML contains no supported rules")
    return rules
