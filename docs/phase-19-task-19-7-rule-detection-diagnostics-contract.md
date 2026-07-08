# Phase 19 Task 19.7 - Rule Detection and Diagnostics Contract

> Date: 2026-07-08
> Status: CLOSED - route diagnostics implemented as read-only configured-policy prediction.

## Scope

Task 19.7 defines and implements the route diagnostic contract for answering:

```text
For this domain, IP or process, which rule would match and which route action
would apply?
```

The diagnostic is read-only. It does not apply routes, start capture, mutate
system proxy settings, start sing-box, refresh rule sets or observe live
traffic.

## Implemented Contract

`diagnostics.routing.diagnose_route()` is the shared route-decision diagnostic.
It reads the Phase 19 versioned routing shape:

- `routing_policy`;
- `capture_modes`;
- `default_route_action`;
- `active_mode` as compatibility/display only.

Runtime decisions and diagnostics do not use `active_mode` as the decision
source.

### Rule Policy

When `routing_policy = "rule"`, the diagnostic evaluates configured route rule
groups with the existing `RuleExplainer`:

- domain, domain suffix, keyword and regex conditions;
- IP CIDR conditions;
- port, protocol and network conditions;
- process name and process path conditions;
- app-policy process rules where available;
- remote and built-in rule-set references as runtime-required conditions.

If no rule matches, the diagnostic reports `no_rule_match=true` and applies
`default_route_action`.

### Global Policy

When `routing_policy = "global"`, route rules are intentionally ignored. The
diagnostic reports:

- `rule_evaluation = "ignored-by-global-policy"`;
- `route_source.source = "routing-policy"`;
- `route_action = default_route_action`;
- `confidence = "definitive"`.

This matches the Phase 19 product contract: global means all captured traffic
uses the selected default route action.

### Rule-Set Diagnostics

The diagnostic does not expand or locally evaluate remote or built-in rule-set
contents. It reports them as runtime-required and includes trust/cache status
from `ruleset-trust.json` when available:

- missing trust policy;
- `not-evaluated`;
- `loaded`;
- `stale`;
- `failed`;
- `fail-closed`;
- `warn-and-skip`;
- rule-set error text such as malformed source or checksum failures.

This preserves the Phase 13/19 rule-set honesty rule: Python diagnostics can
explain configuration and trust state, but sing-box/runtime rule-set matching
is not claimed as static proof.

## CLI Behavior

`watchdog rules explain` now emits the route diagnostic contract while
preserving the older rule-explanation JSON fields:

- `matched`;
- `priority_path`;
- `skipped_conditions`;
- `unevaluated_rule_sets`;
- `confidence`.

New JSON fields include:

- `diagnostic_scope = "configured-policy-only"`;
- `runtime_observation = false`;
- `routing`;
- `route_action`;
- `route_action_status`;
- `route_source`;
- `rule_evaluation`;
- `no_rule_match`;
- `rule_explanation`.

Human output now states the routing policy, capture modes, default route
action, compatibility role of `active_mode`, rule-evaluation behavior and
route-action status.

`watchdog dns diagnose` uses the same route diagnostic before selecting a DNS
channel. Its JSON output includes `route_diagnostic` so route and DNS
diagnostics cannot diverge.

## Confidence Semantics

- `definitive`: configured static policy is enough to state the route action.
- `partial`: more input is required or app-policy matchers exist that cannot
  be evaluated from the supplied fields.
- `runtime-required`: rule-set contents can affect the result.
- `unknown`: no useful rule-policy decision can be made from the supplied
  input.

`route_action_status` is:

- `applies` for definitive decisions;
- `candidate` for partial or runtime-required decisions;
- `unknown` when no route action can be stated.

## Validation Notes

Local focused validation covered:

- domain match;
- IP match;
- process/app-policy match;
- no-match fallback to `default_route_action`;
- `routing_policy=global` ignoring a rule that would otherwise match;
- missing rule-set trust policy;
- stale rule-set status;
- failed critical rule-set status;
- `watchdog rules explain --json`;
- `watchdog dns diagnose --json`.

No installed-VM live routing/capture validation was required for this task
because the implementation is read-only diagnostics and does not apply routes,
capture state, DNS state or system proxy settings.

Additional maintainer-run installed VM read-only validation passed:

- External VPN was brought down before update and restored afterward.
- `./update.sh --yes` completed successfully.
- `./doctor.sh` reported installed/source match at
  `e3f6784131e9ee4a662972f208b7825d8276a833`, daemon IPC reachable,
  `OK=107 WARN=3 FAIL=0`.
- Installed `/usr/local/bin/watchdog rules explain --domain example.com --json`
  returned the route diagnostic contract with `runtime_observation=false`,
  `routing_policy=rule`, `default_route_action=current`, `active_mode_role`
  set to compatibility-display-only, no rule match and route action `current`.
- Installed `/usr/local/bin/watchdog dns diagnose --domain example.com --json`
  returned `route_diagnostic` with the same route decision and DNS path
  `unavailable` because the temporary policy had no configured proxy resolver.
- The smokes used temporary config/rules/DNS policy paths and did not apply
  routes, capture, DNS state or system proxy settings.
