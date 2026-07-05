# Phase 13 Task 13.4 - Logical Rule Decision

> Date: 2026-07-05
> Status: CLOSED - explicit logical rule trees are deferred.

## Decision

WatchdogVPN does not add a new nested AND/OR rule model in Task 13.4.

The current rule model stays intentionally simple:

- values inside one condition key are OR
- different condition keys inside one rule are AND
- different rules are OR by ordered first match
- rule groups keep the existing priority order

This is enough for the current CLI-first policy workflow and matches the
existing local evaluator and sing-box route generation behavior.

## Evidence

The local evaluator already implements the useful subset:

- `_condition_matches()` returns true if any value under one condition key
  matches.
- `rule_matches()` requires all condition keys in a rule to match.
- `RuleEngine.evaluate()` walks rules in priority order and returns the first
  match.

The sing-box generator preserves the same shape for evaluable rules by emitting
one route rule with the same condition keys and list values. The official
sing-box route rule documentation describes default route-rule matching as
field-family ORs combined by ANDs, and documents separate `type: logical`
rules for explicit nested `and`/`or` structures:
https://sing-box.sagernet.org/configuration/route/rule/

## Why Not Add Nested Logic Now

Adding explicit logical groups would not be a small model-only change. It would
need coordinated support across:

- persistent schema and migration behavior
- local rule evaluation
- sing-box route generation
- import/export
- `watchdog rules add-rule`
- `watchdog rules explain`
- confidence and skipped-condition reporting

The explainer would need to describe nested partial matches honestly, for
example "left branch matched but right branch was runtime-required." That is a
larger diagnostic contract than Task 13.4 needs.

## Current Supported Examples

One domain OR another domain:

```json
{
  "id": "example-or",
  "action": "direct",
  "conditions": {
    "domain": ["a.example", "b.example"]
  }
}
```

Domain AND port:

```json
{
  "id": "example-and",
  "action": "block",
  "conditions": {
    "domain_suffix": [".example"],
    "port": ["443"]
  }
}
```

Rule A OR rule B:

```json
[
  {
    "id": "domain-rule",
    "action": "direct",
    "conditions": {"domain": ["example.com"]}
  },
  {
    "id": "process-rule",
    "action": "direct",
    "conditions": {"process_name": ["curl"]}
  }
]
```

## Deferred Scope

Deferred logical features:

- nested `and` / `or` trees
- negation / invert support
- branch-level explanation output
- generated sing-box `type: logical` rules
- import of sing-box logical rule-set entries

This is scheduled, not blocked. Revisit it when a concrete user workflow cannot
be expressed with the current implicit semantics.

## Acceptance

Task 13.4 is closed by documenting the deferral and preserving the simpler
priority model. No runtime, TUN, daemon, or TUI work is involved.
