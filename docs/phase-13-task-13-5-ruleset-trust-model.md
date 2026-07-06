# Phase 13 Task 13.5 - Built-in and Remote Rule-Set Trust Model

> Date: 2026-07-05
> Status: CLOSED - trust model defined, runtime downloading deferred.

## Decision

Remote and built-in rule sets are treated as security-sensitive policy inputs.
A remote rule set can influence whether traffic exits through the current
profile, direct egress, a group, or block. WatchdogVPN must not treat a failed
or changed rule set as a harmless miss.

Task 13.5 defines the trust contract and diagnostics model. It does not add a
runtime downloader or live TUN behavior.

## Current sing-box Baseline

sing-box supports remote rule-set objects with URL, download detour,
update interval, format, and cache behavior. The official configuration
reference does not document a checksum/pinning field for remote rule-set
content:

https://sing-box.sagernet.org/configuration/rule-set/

Because no checksum field is exposed in that configuration surface, WatchdogVPN
must own integrity policy before enabling remote rule-set runtime use.

## Trust Policy

Every remote rule set must have:

- stable id
- source URL
- expected SHA-256 content digest
- update interval
- maximum stale age
- criticality flag
- failure behavior

Remote rule sets without an expected SHA-256 digest are invalid. TLS alone is
not enough because a compromised source or unexpected upstream content change
can silently alter routing policy.

Built-in rule sets do not require a remote source checksum by default, but they
still need status reporting because missing or incompatible local assets can
change policy behavior.

## Failure Behavior

Failure behavior is not global. It depends on what the rule set protects.

Default behavior:

- critical rule set: `fail-closed`
- non-critical rule set: `warn-and-skip`

`fail-closed` means traffic that depends on the unavailable or unverifiable
rule set must not silently fall through to a less protective route.

`warn-and-skip` is acceptable only when failure reduces optimization or
classification quality without weakening a protection boundary.

Examples:

- A rule set used to keep sensitive destinations on the current profile is
  critical and should fail closed.
- A rule set used only for optional routing optimization may warn and skip.

## Update And Staleness

Remote rule-set policy must define both:

- `update_interval_seconds`: when WatchdogVPN should attempt refresh.
- `max_stale_seconds`: maximum age at which cached content remains acceptable.

If refresh fails but cached content is still within `max_stale_seconds`, runtime
may use the cached content and report `stale` with a warning. If cached content
exceeds `max_stale_seconds`, failure behavior applies:

- critical: fail closed
- non-critical: warn and skip

Checksum mismatch is never a normal stale condition. It is a verification
failure and must be reported as `failed`.

## Diagnostic States

Diagnostics distinguish these states:

- `not-evaluated`: rule set requires runtime evaluation and was not evaluated
  locally.
- `loaded`: rule set is present and verified.
- `stale`: cached content exists but refresh or freshness is degraded.
- `failed`: download, verification, format, or local asset loading failed.

These states are different from rule-match confidence. A route explanation can
remain `runtime-required` while still reporting whether the relevant rule set is
not evaluated, loaded, stale, or failed.

## Model Added In Task 13.5

`rules.ruleset_trust` defines:

- `RuleSetTrustPolicy`
- `RuleSetStatus`
- `RuleSetTrustRegistry`
- `RuleSetKind`
- `RuleSetLoadState`
- `RuleSetFailureBehavior`

`RuleSetTrustPolicy` enforces SHA-256 pinning for remote rule sets and derives
default failure behavior from criticality.

`RuleExplanationUnevaluatedRuleSet` now carries optional trust/status fields:

- `state`
- `failure_behavior`
- `critical`
- `error`

## Deferred Runtime Work

Deferred to later implementation work:

- downloading remote rule sets
- maintaining rule-set cache files
- invoking sing-box remote rule-set objects
- enforcing fail-closed behavior in the live route generator
- rule-set update scheduler
- operator commands for adding/updating trust policies

This is scheduled work, not a blocker for Task 13.5. The security contract is
now explicit so later runtime work has a precise target. The active v2 roadmap
promotes this runtime lifecycle into Phase 19 before the final CLI is frozen.

## Acceptance

Task 13.5 closes when:

- remote rule-set pinning policy is explicit and tested
- failure behavior is explicit and tested
- stale/update semantics are documented
- diagnostics distinguish not-evaluated, loaded, stale, and failed rule sets
- runtime downloader work remains clearly scheduled in the later routing/capture
  architecture phase
