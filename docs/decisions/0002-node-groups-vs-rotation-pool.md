# 0002 - Node groups vs the rotation pool

## Status

Accepted - 2026-07-05

## Context

PHASE 14 (Node Groups & Auto-Selection Policy) asks for named node groups with
membership, filters, and an auto-selection policy that rule/app-policy actions
can target (`group:<id>`). Before designing the persistent `NodeGroup` model
(Task 14.1), this ADR fixes what already exists at runtime, so the new model
does not create a second, competing source of truth for "which profiles are
candidates for rotation."

### What a rotation pool is today

There is no persistent pool object. `rotation/pool_builder.py::build_pool()`
computes an ephemeral list on every rotation attempt by filtering
`ProfileStore.list()`:

- `profile.enabled` is true.
- `profile.in_rotation_pool` is true. This is a plain boolean on `Profile`
  (`models/profile.py`), set per profile. It is the only membership signal
  today, and it is implicit and global: there is exactly one unnamed set.
- Origin/provider is enabled: for `SUBSCRIPTION` profiles, the owning
  `Provider.rotation_enabled` must also be true (`_origin_enabled`).
- The profile is not inside its failure cooldown window
  (`rotation.health_status_cooldown_seconds`, `_recently_failed`).

The result feeds `RotationEngine.rotate()` (`rotation/rotation_engine.py`),
which classifies pool size (`unavailable`/`single`/`conservative`/`full`),
tracks recently-tried/blocked profile ids, retries candidates in order, and
falls back to `_last_good_profile_id` on repeated failure. `core/watchdog.py`
calls this through `_attempt_rotation` -> `_compatible_pool` ->
`pool_builder.build_pool`, and on success writes `active_profile_id` into
`state.toml`. This is the only runtime path that changes which profile is
actually connected via the single active sing-box outbound.

A second, weaker filter already exists: `ProfileStore.get_rotation_pool()`
(`config/profile_store.py`) checks only `enabled` and `in_rotation_pool`, with
no provider or cooldown check. It is used solely by
`watchdog provider list --pool` for display. It already risks drifting from
the real runtime filter in `pool_builder.build_pool`; this ADR does not fix
that today, but flags it as pre-existing, low-severity duplication (see
Consequences).

`in_rotation_pool` is read/written in `config/profile_store.py`,
`rotation/pool_builder.py`, `cli/main.py` (list/enable/disable, provider
status counts), `providers/manual_provider.py` (import prompt), and
`providers/subscription_provider.py` (preserved across subscription refresh).
It is a real, load-bearing flag across ~15 call sites and matching tests.

### Two rule-action systems already anticipate groups, inconsistently

- `rules/models.py` (`SIMPLE_RULE_ACTIONS`) already accepts `auto_select` and
  `group:<id>` as syntactically valid rule actions.
  `rules/singbox.py::build_singbox_route_rules` documents, in a comment, that
  both collapse to `current_outbound_tag` today because `SingBoxDriver` only
  ever configures one active outbound at a time — there is no multi-outbound
  selector to route to yet. This is explicitly called "deferred debt for a
  future multi-outbound rotation task," not a bug.
- `app_policy/models.py` (Phase 12) takes the opposite, fail-closed stance:
  `AppPolicyAction` and `_validate_action` explicitly reject `"auto"` and
  `"group:<id>"` (`UNAVAILABLE_ACTIONS`, `GROUP_ACTION_RE`) with a
  `PersistentValidationError` stating they are "scheduled for later
  multi-outbound support."

Both were deliberate Phase 12/13 decisions to avoid pretending a selector
exists before Phase 14 defines it. Phase 14 is what has to resolve this
inconsistency: once `NodeGroup` exists, `group:<id>` needs one real runtime
meaning, honored the same way by both the rules engine and the app-policy
engine.

### The single-outbound constraint drives the design

`SingBoxDriver` connects exactly one profile at a time; there is no
multi-outbound sing-box config today. This means a `group:<id>` action cannot
route packet-by-packet to "the best node in group X" the way a true
multi-outbound proxy selector could. The only way to honor `group:<id>` under
the current driver architecture is to change *which single profile is
currently connected* to the group's auto-selected best member — the same kind
of mutation the background `RotationEngine` already performs, but scoped to a
named group instead of the global implicit pool, and triggered by policy
instead of a failed health check.

That means Task 14.3 (Runtime integration) will introduce a second actor that
can rewrite `active_profile_id`, alongside the existing background rotation
loop. The master plan already names the risk: "Ensure recovery/rotation
cannot fight the node-group selector." This ADR does not resolve that
precedence question — it belongs to Task 14.3, once `NodeGroup` and its
auto-selection scoring (Task 14.2) exist to reason about. It is recorded here
so Task 14.1's model does not accidentally foreclose the answer (for example,
by omitting a way to represent "this group is the one currently pinned as
active").

## Decision

1. **`NodeGroup` is additive and orthogonal to the existing rotation pool, not
   a replacement.** A node group is a named, persistent set with its own
   identity: id/name, explicit membership (profile ids and/or
   profile/provider filters), an enabled flag, and its own auto-selection
   policy fields (Task 14.1's scope). It answers "which profiles are
   candidates for *this* named scope," a different question from "which
   profiles are candidates for the default background rotation loop."

2. **`in_rotation_pool` stays exactly as-is for this phase.** It continues to
   mean "member of the default/legacy global rotation scope" used by the
   unattended background `RotationEngine` loop. It is not renamed, migrated,
   or reinterpreted as node-group membership. No profile is implicitly
   auto-enrolled into any `NodeGroup` because of this flag. This avoids two
   objects claiming authority over the same set: the legacy boolean keeps
   its current, narrow job; `NodeGroup` does a new, different job.

3. **The health/eligibility filter in `pool_builder.build_pool` is the
   reusable runtime layer, not something `NodeGroup` reimplements.**
   Concretely, when Task 14.1/14.3 need "healthy, enabled, non-cooldown
   members of group X," they must reuse the same origin-enabled /
   `enabled` / cooldown checks `pool_builder` already applies — either by
   generalizing `build_pool` to accept a candidate list (default: legacy
   `in_rotation_pool` scope; node-group case: the group's membership) or by
   extracting the filter into a shared function `pool_builder` and the
   node-group selector both call. There must be exactly one implementation of
   "is this profile currently a viable candidate," reused by both scopes.

4. **Node-group auto-selection (Phase 14) and background rotation (Phase 8)
   stay conceptually orthogonal — "which candidate set" vs. "which candidate
   now" — but Task 14.3 must define explicit precedence** for the case where
   both want to rewrite the single active profile at the same time (e.g., an
   enabled rule/app-policy action pins a node group while the background loop
   independently detects a health failure). This ADR does not pick that
   precedence rule; it is deferred to Task 14.3 by name, not left as an
   unowned gap.

5. **`group:<id>` gets one real runtime meaning, defined once Task 14.3 lands,
   and both `rules/singbox.py` and `app_policy` must honor it consistently.**
   Until then, `rules/singbox.py`'s current collapse-to-`current_outbound_tag`
   behavior and `app_policy`'s current fail-closed rejection of `group:<id>`
   both remain correct and are not touched by Task 14.1.

## Consequences

### Positive

- No second source of truth is created: the legacy global pool and named
  node groups answer different questions and do not compete for the same
  boolean.
- The single-outbound constraint and the rotation/node-group precedence risk
  are documented before the persistent model is designed, instead of being
  discovered mid-implementation of Task 14.3.
- `rules/models.py` and `app_policy/models.py` already agree, in spirit, that
  `group:<id>` has no real effect yet; this ADR gives Task 14.3 a single place
  to make it real for both instead of two divergent implementations.

### Negative

- Two parallel "which profiles are eligible" concepts (`in_rotation_pool` and
  `NodeGroup` membership) exist side by side for at least this phase. An
  operator could put a profile in a node group but forget `in_rotation_pool`,
  or vice versa, and see different behavior in the background loop vs.
  group-targeted rules. This must be made legible in CLI diagnostics
  (Task 14.5/14.6), not hidden.
- Task 14.3 inherits a real unsolved scheduling question (background rotation
  vs. group-pinned selection) that this ADR intentionally does not close.

### Neutral

- `ProfileStore.get_rotation_pool()`'s weaker duplicate filter (no provider or
  cooldown check) is pre-existing drift, unrelated to node groups. Left
  unchanged here; worth folding into the same shared-filter cleanup from
  Decision 3 if it is touched during Task 14.1/14.3 implementation.
- This ADR does not fix the app-policy vs. rules inconsistency; it only
  records that both already treat `group:<id>` as not-yet-real, so Task 14.3
  starts from an already-consistent baseline.
