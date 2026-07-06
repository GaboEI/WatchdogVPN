# WatchdogVPN QA Audit - Phase 13 Policy Diagnostics & Rule UX Foundation

> Date: 2026-07-05
> Task: PHASE 13 - Policy Diagnostics & Rule UX Foundation, Task 13.6 - Policy diagnostics audit closure
> Status: CLOSED. No unresolved HIGH or MEDIUM findings remain.

## 1. Scope

This audit covers Phase 13 Tasks 13.1 through 13.5:

- structured rule explanation model
- `watchdog rules explain`
- custom group operations
- logical rule decision
- built-in and remote rule-set trust model

The audit focuses on correctness of explanations, misleading output, import
safety, backup behavior, malformed rules, and rule-set trust failures.

No live TUN, daemon, network mutation, or TUI work is required for this phase.

## 2. Coverage Checklist

| Surface | Reviewed criteria | Result |
| --- | --- | --- |
| Rule explanation model | Structured output, stable `to_dict()`, confidence ordering, skipped conditions, unevaluated rule sets, local AND/OR semantics, incomplete input. | Reviewed. No open finding. Tests cover definitive, partial, runtime-required, unknown, local mismatch, and JSON serialization. |
| CLI renderer | Human wording must not overstate non-definitive confidence, JSON must expose the model, command must explain configured policy rather than live traffic. | Reviewed. No open finding. Tests verify `partial`, `runtime-required`, and `unknown` do not print `would use action`; definitive output is conditional on configured policy. |
| Rule group mutation | Store consistency, model validation before write, atomic JSON writes, duplicate IDs, import/export, backup on destructive replace, no clobber on invalid input. | Reviewed. No open finding. Tests cover invalid condition no mutation, duplicate import rejection, replace backup, invalid schema no mutation, unknown fields, duplicate rule IDs, and export. |
| Logical rule decision | Whether explicit AND/OR is implemented or deferred, no half-support, evaluator/generator/explainer consistency. | Reviewed. No open finding. Explicit nested logic is deferred; implicit OR values / AND condition keys / OR ordered rules are documented and tested. |
| Rule-set trust | Remote source integrity, checksum pinning, stale/update semantics, failure behavior, diagnostics for failed/stale/not-evaluated states. | Reviewed. AUD-P13-001 was found and resolved during this audit. |

## 3. Acceptance Matrix

| Criterion | Audit result | Evidence |
| --- | --- | --- |
| `watchdog rules explain` produces human and JSON output | PASS | `tests/test_cli_rules_commands.py` covers JSON and human output paths. |
| Diagnostics distinguish definitive vs partial results | PASS | `tests/test_rule_explanation.py` and CLI wording tests cover all confidence levels. |
| Rule mutations validate schema and create backups | PASS | `RuleStore` validates through `RuleGroup`/`Rule`; `rules import --replace` creates backups; tests cover invalid no-clobber behavior. |
| Remote/built-in rule-set failures are explicit and tested | PASS after AUD-P13-001 | `RuleSetTrustStore` loads a trust registry; `watchdog rules explain --ruleset-trust-file` reports `state=failed`, `behavior=fail-closed`, and error text. |
| AND/OR support is implemented or deferred | PASS | Deferred in `docs/phase-13-task-13-4-logical-rule-decision.md`; tests reject nested logical imports and pin implicit semantics. |
| Phase-specific QA audit has no unresolved HIGH or MEDIUM findings | PASS | AUD-P13-001 resolved. No other HIGH/MEDIUM findings found. |

## 4. Findings

### AUD-P13-001 - Rule-set failure diagnostics were modeled but not reachable from CLI

- Layer: 5 - CLI/Operator control; Layer 8 - Network policy resilience
- Severity: MEDIUM
- Status: RESOLVED on 2026-07-05
- Description: Task 13.5 added `RuleSetTrustPolicy`, `RuleSetStatus`, and
  explainer support for reporting rule-set states such as `failed` and
  `stale`, but `watchdog rules explain` did not load a trust registry. In
  practice, the operator-facing CLI could only report `state=not-evaluated`,
  even for a critical remote rule-set whose status was known to be failed.
- Impact before the fix: The model was honest, but the primary diagnostic view
  could not surface a failed critical rule-set. This created a gap between the
  Task 13.5 security contract and the CLI output: a checksum mismatch or load
  failure could be collapsed into ordinary runtime-required uncertainty.
- Resolution:
  - Added `RuleSetTrustStore`, reading a registry from
    `WATCHDOGVPN_RULESET_TRUST_FILE` or `--ruleset-trust-file`.
  - Wired `watchdog rules explain` to pass the loaded registry into
    `RuleExplainer`.
  - Added tests proving the CLI reports `state=failed`,
    `behavior=fail-closed`, and the verification error for a critical remote
    rule-set.
- Residual risk: Runtime download/cache/enforcement remains intentionally
  deferred by Task 13.5. The diagnostic contract is now reachable from CLI.

## 5. Deferred Work

The following items are scheduled for later phases/tasks and are not blockers
for Phase 13 closure:

- remote rule-set downloader and cache maintenance
- live sing-box remote rule-set declarations
- runtime fail-closed enforcement for critical rule-set failures
- update scheduler and operator commands for rule-set trust policy management
- explicit nested AND/OR rule trees

These are documented deferrals, not open audit blockers.
The active v2 roadmap promotes the runtime downloader/cache/enforcement work
into the later routing/capture architecture phase before the final CLI is
frozen.

## 6. Validation

Commands run:

```bash
python3 -m unittest tests.test_ruleset_trust tests.test_cli_rules_commands tests.test_cli_app_policy_commands tests.test_cli_config_commands tests.test_cli_dns_commands tests.test_cli_profile_commands tests.test_cli_provider_commands tests.test_cli_connection_commands tests.test_rule_store tests.test_rule_parser tests.test_rule_explanation tests.test_rule_engine tests.test_rules_singbox tests.test_singbox_driver
bash tests/unit.sh
bash tests/syntax.sh
python3 -m compileall -q .
git diff --check
```

Results:

- 255 targeted CLI/rules/singbox tests passed.
- Unit behavior checks passed.
- Syntax checks passed.
- Compileall passed.
- Diff whitespace check passed.

## 7. Closure Status

Phase 13 is closed for HIGH/MEDIUM audit purposes.

No unresolved HIGH or MEDIUM findings remain.
