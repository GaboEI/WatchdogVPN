# QA Audit 2026-07-09 - Phase 21.5 Route Chains

Date: 2026-07-09
Branch: `phase-21-5-proxy-route-chain-runtime`
Status: closed

## Scope

This audit closes Phase 21.5, Proxy & Route Chain Runtime. It covers:

- chain syntax and persistent model validation;
- `chain_id` slug validation;
- supported hop types and rejected hop shapes;
- direct and indirect loop prevention within the v2.0 model;
- missing, disabled, invalid, missing-hop and empty-group fail-closed behavior;
- chain-owned DNS path behavior and DNS-unavailable fail-closed behavior;
- sing-box outbound tag, detour and final route-rule contracts;
- first-class `chain:<id>` route action behavior without fallback;
- rule, DNS, unified and support-export diagnostics;
- privacy boundaries for provider/profile/chain/runtime data;
- backup, restore and merge behavior;
- installed-VM evidence from Task 21.5.5.

## Verdict

No HIGH or MEDIUM findings were identified. No LOW findings remain unresolved.
Final local validation passed for this closure commit. Phase 21.5 is
technically ready for maintainer merge preparation. The branch gate still
applies: do not merge to `main` without explicit maintainer approval and a
merge commit.

## Findings

| ID | Severity | Status | Finding |
| --- | --- | --- | --- |
| AUD-P21.5-001 | INFO | Accepted | External real providers and external egress IP were not validated. Installed VM validation used synthetic local SOCKS hops and a local HTTP proof target for safety, reproducibility and to avoid handling provider credentials or cutting the operator session. |
| AUD-P21.5-002 | INFO | Accepted | Chain diagnostics intentionally report configured plans as `confidence=predicted`, `live_observed_state=not-observed`, `validation_state=unsupported-not-vm-validated` and `installed_vm_validated=false`. Task 21.5.5 VM evidence validates the phase, but the diagnostics surface does not claim live observation unless a future live observer is added. |
| AUD-P21.5-003 | INFO | Accepted | The installed VM DNS proof validates final-hop proxy DNS detour for global-chain routing. Rules-mode chain traffic was separately proven through final-hop route targeting and hop order. This matches the Task 21.5.3 contract and keeps rule-specific DNS claims constrained to diagnostics/configured-state evidence. |

## Syntax And Model Validation

The persistent model is schema-versioned and strict:

- `RouteChainDocument` accepts only `schema_version = 1` and a list of chains.
- Duplicate chain IDs are rejected.
- Unknown top-level, chain and hop fields are rejected.
- `chain:<id>` parsing is canonical through `chain_target()`.
- Chain IDs must match `^[a-z0-9][a-z0-9_-]{0,63}$`.
- Chains must contain at least one hop.
- `dns_strategy` is fixed to `chain`.
- `failure_policy` is fixed to `fail_closed`.
- `health_policy` is fixed to `all_required`.

Only these hop types are accepted in v2.0:

- `profile`
- `group`

The model rejects nested chains, `direct`, `current`, `current_profile`,
provider wildcard hops, inline URL/subscription hops, raw runtime outbound tags,
optional hops, non-chain DNS strategy, non-fail-closed failure policy and
non-all-required health policy. Inline URL/subscription and raw runtime outbound
forms have no accepted schema fields; unknown fields are rejected before they can
be interpreted.

## Loop Prevention

Nested chain hops are rejected, so direct chain-to-chain and multi-chain cycles
are not representable in the v2.0 persistent model. Runtime dependency
validation covers the representable cycle shape: a chain selecting a profile, or
a group-selected profile, whose route action points back to the same chain.

Because `chain` is not an accepted hop type, indirect cycles such as
`chain:a -> chain:b -> chain:a` cannot be encoded. If a future phase introduces
nested chains, that phase must add graph-wide cycle detection before enabling
the new hop type.

## Fail-Closed Behavior

`ChainRuntimeResolver` returns blocked plans, never fallback plans, for:

- missing chain;
- disabled chain;
- missing profile hop target;
- missing group hop target;
- empty group resolution;
- disabled, unhealthy or unsupported profiles;
- unknown or unavailable chain-owned DNS path.

`rules.singbox.build_singbox_route_rules()` maps blocked chain plans to reject
rules. It does not silently fall back to `current`, `direct`, `group:<name>` or a
shorter chain. Missing chain runtime plans also reject.

## DNS Ownership

The chain contract requires chain-owned proxy DNS for resolved chain actions.
`ChainRuntimeResolver` blocks a chain when the proxy DNS channel is missing,
disabled or has no enabled resolvers. The sing-box runtime maps global
`chain:<id>` routing so proxy DNS detours through the final chain hop.

Task 21.5.5 installed-VM evidence includes
`PHASE21_5_GLOBAL_CHAIN_DNS_DETOUR_OK` and
`PHASE21_5_FAIL_CLOSED_CONFIG_OK`. No direct/system resolver fallback is part of
the chain contract. The VM harness used a local bootstrap resolver only to
satisfy sing-box outbound-domain resolver requirements; that bootstrap resolver
does not replace the chain-owned proxy DNS path under test.

## Outbound Tag And Route Contract

Resolved chain hop tags are deterministic:

```text
watchdogvpn-chain-<chain_id>-hop-<index>
```

The first hop has no chain detour. Each later hop detours through the previous
hop tag, preserving the operator-visible order "traffic enters hop 1, then hop
2, then exits through the final hop." Route rules for `chain:<id>` target the
final hop tag.

Task 21.5.5 installed-VM evidence proves:

- `sing-box check` accepts the generated config;
- route rules target the final chain hop;
- hop 2 detours through hop 1;
- real local traffic traverses the synthetic chain;
- local listeners are removed after teardown.

## Route Action Behavior

`chain:<id>` is accepted as a first-class route action in route rules,
app-policy rules and the global default route action. It is not an alias for
`current`, `direct`, `group:<name>` or `auto_select`.

Unresolved chain actions fail closed. This applies to configured rules,
app-policy decisions and global default routing.

## Diagnostics

The audit covered:

- `rules explain` chain diagnostic sections and JSON `chain` object;
- `dns diagnose` chain diagnostic section and JSON `chain` object;
- unified diagnostics `routing.chain_diagnostics`;
- support-export redaction.

Diagnostics expose safe configured-state facts: route action, chain ID,
configured state, runtime plan state, live-observed state, validation state,
status, confidence, route-action status, DNS path status, final outbound status,
redacted hop order, failure reason, support-export safety and installed-VM
validation claim state.

Fail-closed diagnostics use `fail-closed-unknown`,
`fail-closed-unavailable` and `fail-closed-partial` for missing, disabled,
invalid, partial and DNS-unavailable chain states.

## Privacy

The audited surfaces avoid exporting:

- provider URLs;
- endpoint tokens;
- private keys;
- raw profile config;
- raw chain hop targets in support export;
- raw runtime outbound tags in support export;
- raw chain usage history;
- browsing history;
- destination history;
- DNS query history.

Support export requires explicit review and recursively redacts sensitive keys,
including chain hop `target`, `outbound_tag` and `route_outbound_tag`. Canary
tests cover false secrets in chain diagnostics and support export.

## Backup, Restore And Merge

Backups include route chains in `route-chains.json`. Restore validates
`RouteChainDocument` before writing and snapshots existing config state so a
broken route-chain payload rolls back without mutation. Merge restore validates
the imported document and renames colliding chain IDs with an imported timestamp
prefix.

## Installed VM Evidence

Task 21.5.5 installed-VM validation passed at:

```text
84d8d6c1ab9c27b2cd75eacf13f1ac5afd58ae0e
```

Evidence path:

```text
/tmp/watchdogvpn-phase21-5-chain-evidence/phase21_5_chain_installed_validation.json
```

The installed runtime matched the source checkout, `doctor` completed with
`FAIL=0`, expected warnings were limited to VPN truth state `DOWN`,
unsynchronized NTP and optional protocol tooling absent, and the runner
reported:

```text
PHASE21_5_SINGBOX_CHECK_OK
PHASE21_5_GLOBAL_CHAIN_DNS_DETOUR_OK
PHASE21_5_FAIL_CLOSED_CONFIG_OK
PHASE21_5_SINGBOX_RUNTIME_STARTED_OK
PHASE21_5_CHAIN_TRAFFIC_PROOF_OK
PHASE21_5_CHAIN_TEARDOWN_OK
PHASE21_5_CHAIN_INSTALLED_VM_VALIDATION_OK
PHASE21_5_NO_ROUTE_RULE_DNS_FIREWALL_DRIFT_OK
PHASE21_5_NO_STALE_PROXY_LISTENERS_OK
PHASE21_5_CHAIN_INSTALLED_VALIDATION_SCRIPT_OK
```

The evidence remains valid for this audit because Task 21.5.6 does not change
runtime mapping, DNS mapping, route-rule generation or the VM harness behavior.

## Closure Validation

Final closure validation passed:

```text
bash tests/unit.sh
OK

bash tests/syntax.sh
OK

python3 -m unittest discover -s tests -p 'test_*.py'
OK - 1184 tests, 1 skipped

git diff --check
OK

PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
OK
```

The installed VM harness does not need to be re-run for this audit closure
unless a fix touches runtime mapping, DNS mapping, sing-box route generation or
the installed VM proof helpers.
