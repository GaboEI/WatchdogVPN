# Rule detection and diagnostics

The route diagnostic answers:

```text
For this domain, IP or process, which rule would match and which route action
would apply?
```

The diagnostic is read-only. It does not apply routes, start capture, mutate
system proxy settings, start sing-box, refresh rule sets or observe live
traffic.

## Implemented contract

`diagnostics.routing.diagnose_route()` is the shared route-decision diagnostic.
It reads the versioned routing shape:

- `routing_policy`;
- `capture_modes`;
- `default_route_action`;
- `active_mode` as compatibility/display only.

Runtime decisions and diagnostics do not use `active_mode` as the decision
source.

### Rule policy

When `routing_policy = "rule"`, the diagnostic evaluates configured route rule
groups with `RuleExplainer`:

- domain, domain suffix, keyword and regex conditions;
- IP CIDR conditions;
- port, protocol and network conditions;
- process name and process path conditions;
- app-policy process rules where available;
- remote and built-in rule-set references as runtime-required conditions.

If no rule matches, the diagnostic reports `no_rule_match=true` and applies
`default_route_action`.

### Global policy

When `routing_policy = "global"`, route rules are intentionally ignored. The
diagnostic reports:

- `rule_evaluation = "ignored-by-global-policy"`;
- `route_source.source = "routing-policy"`;
- `route_action = default_route_action`;
- `confidence = "definitive"`.

Global means all captured traffic uses the selected default route action.

### Rule-set diagnostics

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

Python diagnostics explain configuration and trust state, but sing-box/runtime
rule-set matching is not claimed as static proof.

## CLI behavior

`watchdog rules explain` emits the route diagnostic contract while preserving
the older rule-explanation JSON fields:

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

Human output states the routing policy, capture modes, default route action,
compatibility role of `active_mode`, rule-evaluation behavior and route-action
status.

`watchdog dns diagnose` uses the same route diagnostic before selecting a DNS
channel. Its JSON output includes `route_diagnostic` so route and DNS diagnostics
cannot diverge.

## Confidence semantics

- `definitive`: configured static policy is enough to state the route action.
- `partial`: more input is required or app-policy matchers exist that cannot be
  evaluated from the supplied fields.
- `runtime-required`: rule-set contents can affect the result.
- `unknown`: no useful rule-policy decision can be made from the supplied input.

`route_action_status` is:

- `applies` for definitive decisions;
- `candidate` for partial or runtime-required decisions;
- `unknown` when no route action can be stated.
