# Rule-Set Trust Model

## Decision

Remote and built-in rule sets are security-sensitive policy inputs. A remote
rule set can influence whether traffic exits through the current profile, direct
egress, a group, or block. A failed or changed rule set must not be treated as a
harmless miss.

WatchdogVPN defines the trust contract and diagnostics model here; runtime
download and cache behavior implements it.

## sing-box Baseline

sing-box supports remote rule-set objects with URL, download detour, update
interval, format, and cache behavior. Its configuration reference does not
document a checksum or pinning field for remote rule-set content:
<https://sing-box.sagernet.org/configuration/rule-set/>.

Because no checksum field is exposed in that configuration surface, WatchdogVPN
owns integrity policy before enabling remote rule-set runtime use.

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

## Update and Staleness

Remote rule-set policy defines both:

- `update_interval_seconds`: when WatchdogVPN should attempt refresh.
- `max_stale_seconds`: maximum age at which cached content remains acceptable.

If refresh fails but cached content is still within `max_stale_seconds`, runtime
may use the cached content and report `stale` with a warning. If cached content
exceeds `max_stale_seconds`, failure behavior applies:

- critical: fail closed
- non-critical: warn and skip

Checksum mismatch is never a normal stale condition. It is a verification
failure and is reported as `failed`.

## Runtime Lifecycle

WatchdogVPN owns remote downloads and emits local sing-box rule-set
declarations instead of sing-box `remote` rule-set objects. The runtime:

- downloads remote rule sets;
- maintains rule-set cache files;
- invokes verified local sing-box rule-set objects generated from
  WatchdogVPN-owned cache files;
- enforces fail-closed behavior in the live route generator;
- schedules due refreshes at runtime connect preflight;
- exposes manual operator refresh and status commands.

Trust policies remain explicit; remote policies still require SHA-256 pins.

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

## Model

`rules.ruleset_trust` defines:

- `RuleSetTrustPolicy`
- `RuleSetStatus`
- `RuleSetTrustRegistry`
- `RuleSetKind`
- `RuleSetLoadState`
- `RuleSetFailureBehavior`

`RuleSetTrustPolicy` enforces SHA-256 pinning for remote rule sets and derives
default failure behavior from criticality.

`RuleExplanationUnevaluatedRuleSet` carries optional trust/status fields:

- `state`
- `failure_behavior`
- `critical`
- `error`
