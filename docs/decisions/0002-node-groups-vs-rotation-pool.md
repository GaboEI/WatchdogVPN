# 0002 - Node groups vs the rotation pool

## Status

Accepted

## Context

WatchdogVPN offers named node groups with membership, filters, and an
auto-selection policy that rule and app-policy actions can target (`group:<id>`).
Node groups must not become a second, competing source of truth for "which
profiles are candidates for rotation," so this decision fixes what already
exists at runtime before the persistent node-group model is defined.

### What a rotation pool is

There is no persistent pool object. `rotation/pool_builder.py::build_pool()`
computes an ephemeral list on every rotation attempt by filtering
`ProfileStore.list()`:

- `profile.enabled` is true.
- `profile.in_rotation_pool` is true. This is a plain boolean on `Profile`
  (`models/profile.py`), set per profile. It is the only membership signal, and
  it is implicit and global: there is exactly one unnamed set.
- Origin/provider is enabled: for `SUBSCRIPTION` profiles, the owning
  `Provider.rotation_enabled` must also be true (`_origin_enabled`).
- The profile is not inside its failure cooldown window
  (`rotation.health_status_cooldown_seconds`, `_recently_failed`).

The result feeds `RotationEngine.rotate()` (`rotation/rotation_engine.py`),
which classifies pool size, tracks recently-tried/blocked profile ids, retries
candidates in order, and falls back to `_last_good_profile_id` on repeated
failure. `core/watchdog.py` calls this through `_attempt_rotation` ->
`_compatible_pool` -> `pool_builder.build_pool`, and on success writes
`active_profile_id` into `state.toml`. This is the only runtime path that
changes which profile is actually connected via the single active sing-box
outbound.

A second, weaker filter exists: `ProfileStore.get_rotation_pool()`
(`config/profile_store.py`) checks only `enabled` and `in_rotation_pool`, with
no provider or cooldown check. It is used only by
`watchdog provider list --pool` for display and can drift from the real runtime
filter in `pool_builder.build_pool`. This is pre-existing, low-severity
duplication, noted below.

`in_rotation_pool` is read/written in `config/profile_store.py`,
`rotation/pool_builder.py`, `cli/main.py`, `providers/manual_provider.py`, and
`providers/subscription_provider.py` (preserved across subscription refresh).
It is a load-bearing flag across many call sites.

### Two rule-action systems anticipate groups, inconsistently

- `rules/models.py` (`SIMPLE_RULE_ACTIONS`) accepts `auto_select` and
  `group:<id>` as syntactically valid rule actions.
  `rules/singbox.py::build_singbox_route_rules` documents that both collapse to
  `current_outbound_tag` because `SingBoxDriver` only ever configures one active
  outbound at a time — there is no multi-outbound selector to route to.
- `app_policy/models.py` takes the opposite, fail-closed stance:
  `AppPolicyAction` and `_validate_action` reject `"auto"` and `"group:<id>"`
  (`UNAVAILABLE_ACTIONS`, `GROUP_ACTION_RE`) with a validation error stating
  they are not yet supported.

Both were deliberate choices to avoid pretending a selector exists before node
groups define one. Once `NodeGroup` exists, `group:<id>` needs one real runtime
meaning, honored the same way by both the rules engine and the app-policy
engine.

### The single-outbound constraint drives the design

`SingBoxDriver` connects exactly one profile at a time; there is no
multi-outbound sing-box config. A `group:<id>` action therefore cannot route
packet-by-packet to "the best node in group X" the way a true multi-outbound
proxy selector could. The only way to honor `group:<id>` under the current
driver architecture is to change which single profile is currently connected to
the group's auto-selected best member — the same kind of mutation the
background `RotationEngine` already performs, but scoped to a named group and
triggered by policy instead of a failed health check.

That introduces a second actor that can rewrite `active_profile_id`, alongside
the existing background rotation loop, so their precedence has to be defined
explicitly.

## Decision

1. **`NodeGroup` is additive and orthogonal to the existing rotation pool, not
   a replacement.** A node group is a named, persistent set with its own
   identity: id/name, explicit membership (profile ids and/or profile/provider
   filters), an enabled flag, and its own auto-selection policy. It answers
   "which profiles are candidates for *this* named scope," a different question
   from "which profiles are candidates for the default background rotation
   loop."

2. **`in_rotation_pool` stays as-is.** It continues to mean "member of the
   default/legacy global rotation scope" used by the unattended background
   `RotationEngine` loop. It is not renamed, migrated, or reinterpreted as
   node-group membership. No profile is implicitly enrolled into a `NodeGroup`
   because of this flag. The legacy boolean keeps its current, narrow job;
   `NodeGroup` does a new, different job.

3. **The health/eligibility filter in `pool_builder.build_pool` is the
   reusable runtime layer, not something `NodeGroup` reimplements.** When
   node-group selection needs "healthy, enabled, non-cooldown members of group
   X," it must reuse the same origin-enabled / `enabled` / cooldown checks
   `pool_builder` already applies — either by generalizing `build_pool` to
   accept a candidate list (default: legacy `in_rotation_pool` scope; node-group
   case: the group's membership) or by extracting the filter into a shared
   function both callers use. There must be exactly one implementation of "is
   this profile currently a viable candidate."

4. **Node-group selection and background rotation stay conceptually orthogonal
   — "which candidate set" vs. "which candidate now" — but their precedence
   must be defined explicitly** for the case where both want to rewrite the
   single active profile at the same time (for example, an enabled rule or
   app-policy action pins a node group while the background loop independently
   detects a health failure). This decision does not pick that precedence rule;
   it is called out as a required part of wiring group selection into the
   runtime, not left as an unowned gap.

5. **`group:<id>` gets one real runtime meaning, and both `rules/singbox.py`
   and `app_policy` must honor it consistently.** Until that meaning is
   implemented, `rules/singbox.py`'s collapse-to-`current_outbound_tag`
   behavior and `app_policy`'s fail-closed rejection of `group:<id>` both remain
   correct and unchanged.

## Consequences

### Positive

- No second source of truth is created: the legacy global pool and named node
  groups answer different questions and do not compete for the same boolean.
- The single-outbound constraint and the rotation/node-group precedence risk are
  documented before the persistent model is designed, rather than discovered
  mid-implementation.
- `rules/models.py` and `app_policy/models.py` already agree, in spirit, that
  `group:<id>` has no real effect yet; this gives that integration one place to
  make it real for both instead of two divergent implementations.

### Negative

- Two parallel "which profiles are eligible" concepts (`in_rotation_pool` and
  `NodeGroup` membership) exist side by side. An operator could put a profile in
  a node group but forget `in_rotation_pool`, or vice versa, and see different
  behavior in the background loop versus group-targeted rules. This must be
  made legible in CLI diagnostics, not hidden.
- Wiring group selection into the runtime inherits a real unsolved scheduling
  question (background rotation vs. group-pinned selection) that this decision
  intentionally does not close.

### Neutral

- `ProfileStore.get_rotation_pool()`'s weaker duplicate filter (no provider or
  cooldown check) is pre-existing drift, unrelated to node groups. It is left
  unchanged here and is worth folding into the shared-filter cleanup from
  Decision 3 when that code is touched.
- This decision does not fix the app-policy vs. rules inconsistency; it records
  that both already treat `group:<id>` as not-yet-real, so the runtime
  integration starts from a consistent baseline.
