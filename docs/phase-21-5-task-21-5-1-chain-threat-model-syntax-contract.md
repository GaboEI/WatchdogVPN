# Proxy Chain: Threat Model and Syntax

A proxy chain is an ordered sequence of hops that traffic must traverse before it
exits. Chains are high-risk because they can change where traffic exits, how DNS
is resolved, which health decision controls failover, and whether an unavailable
hop fails closed or leaks to a less protected path.

## Threat Model

Primary risks:

- silent collapse to `current`, `direct`, `group:<name>` or `auto_select`;
- looped chains, group recursion or imported policy cycles;
- DNS resolving outside the selected chain path;
- partially resolved chains that continue with fewer hops than configured;
- stale health state selecting an unavailable or unintended hop;
- diagnostics that hide the selected hop order or failure reason;
- support exports leaking provider, profile, node-group or chain names that
  reveal operator topology;
- metrics becoming destination or browsing history.

The chain contract is therefore fail-closed by default. A chain that cannot be
fully validated and resolved must not silently use a shorter chain, direct
network access or the current profile.

## Product Concepts

Chains preserve the existing separation of concerns:

- routing policy decides whether rules are evaluated;
- capture mode decides how traffic enters WatchdogVPN;
- route action decides where matched traffic goes.

`chain:<id>` is a route action. It is not a routing policy, capture mode,
profile alias, node-group alias or compatibility `active_mode`.

## Route Action Syntax

The route-action namespace is:

```text
chain:<chain_id>
```

`chain_id` must use the same lowercase slug family as node groups:

```text
^[a-z0-9][a-z0-9_-]{0,63}$
```

Supported use sites once the persistent model and runtime mapping are in place:

- route rules;
- app-policy rules;
- app-policy default action;
- `default_route_action`, once global-chain runtime behavior and DNS behavior
  are proven.

Parsers must reject `chain:<id>` until the persistent model and runtime mapping
exist. No parser should accept it earlier.

## Persistent Chain Store

The planned persistent store is a separate `chains.json` document:

```json
{
  "schema_version": 1,
  "chains": [
    {
      "id": "work-safe",
      "enabled": true,
      "description": "Operator label for local review only",
      "hops": [
        {
          "type": "profile",
          "target": "profile-id-a",
          "required": true
        },
        {
          "type": "group",
          "target": "resilient-exit",
          "selection_policy": "group_policy",
          "required": true
        }
      ],
      "dns_strategy": "chain",
      "failure_policy": "fail_closed",
      "health_policy": "all_required",
      "created_at": "2026-07-08T00:00:00+00:00",
      "updated_at": "2026-07-08T00:00:00+00:00"
    }
  ]
}
```

The persistent model must preserve these constraints:

- `schema_version = 1`;
- chain IDs are immutable lowercase slugs;
- chain labels/descriptions are local metadata and redacted from normal support
  export;
- hops are ordered and non-empty;
- every hop has explicit `type`, `target` and required/failover semantics;
- unknown fields fail validation;
- disabled chains remain persisted but cannot be selected by route action;
- imports must validate before writing.

## Supported Hop Types

The v2.0 hop types are:

| Hop type | Target | Meaning | Runtime requirement |
| --- | --- | --- | --- |
| `profile` | `Profile.id` | Use one concrete profile as a hop. | Profile exists, is enabled, has supported protocol/runtime mapping and is healthy enough for the chain policy. |
| `group` | `NodeGroup.name` | Resolve one concrete profile from a node group at runtime. | Group exists, is enabled, resolves deterministically under its selection policy, and the selected profile satisfies the chain health policy. |

Rejected hop types for v2.0:

- nested `chain` hops;
- `direct` hops;
- `current` or `current_profile` hops;
- `auto_select` hops outside a named node group;
- provider-wide wildcard hops;
- URL/subscription inline hops;
- raw runtime outbound tags supplied by the user.

Nested chains are intentionally rejected in v2.0. They multiply cycle and DNS
ownership risk. A future version may revisit nested chains only after v2.0 ships
with direct chain behavior validated.

## Hop Order

Operator wording must describe chain order as:

```text
traffic enters hop 1, then hop 2, then exits through the final hop
```

Diagnostics must show the same order. Runtime mapping may invert that order
internally if a backend needs detour-style configuration, but human and JSON
diagnostics must keep the operator order stable.

## DNS Contract

DNS behavior must be explicit before any runtime chain action is accepted.

Default v2.0 DNS strategy:

```text
dns_strategy = "chain"
```

Meaning:

- domain decisions for matched traffic are resolved through the protected chain
  path, not through the LAN/router/default resolver;
- chain diagnostics must report DNS path as chain-owned, unavailable or
  blocked;
- DNS rules may still reject or explicitly divert domains, but diagnostics must
  explain when a DNS rule overrides normal chain ownership;
- missing chain DNS capability is fail-closed for domain traffic unless a
  narrower explicit exception is defined and validated.

Rejected DNS behavior:

- silently using direct DNS for a chain route action;
- using direct bootstrap DNS as a general chain resolver;
- reporting DNS as protected without runtime proof;
- storing domain query history to explain chains.

## Failure Behavior

Default v2.0 chain failure policy:

```text
failure_policy = "fail_closed"
health_policy = "all_required"
```

Fail closed means:

- missing chain target: block/reject route action and explain missing target;
- disabled chain: block/reject route action and explain disabled chain;
- missing profile/group: block/reject route action and explain missing hop;
- empty group resolution: block/reject route action and explain empty group;
- unhealthy required hop: block/reject route action and explain unhealthy hop;
- stale required health state: block/reject route action and explain stale
  health;
- unsupported protocol/runtime mapping: block/reject route action and explain
  unsupported hop;
- runtime chain generation failure: do not connect with a shorter or different
  route.

Optional failover may only be added inside explicit group selection or
explicitly modeled alternate hops. It must never downgrade to direct/current by
default.

## Loop And Cycle Contract

These states are invalid before persistence or runtime use:

- a chain references itself;
- a chain references another chain, because nested chains are rejected;
- a group selected inside a chain resolves to a profile that would require the
  same chain route action;
- imported route/app-policy data creates a chain action targeting a missing or
  disabled chain;
- a default action and app/rule action create an ambiguous chain fallback.

Cycle diagnostics must name the chain IDs and target categories involved while
redacting local labels in support export.

## Import And Migration Behavior

Migration from pre-chain state:

- no automatic chain definitions are created;
- existing route/app-policy/default actions remain unchanged;
- existing rejected `chain:<id>` values remain rejected until the persistent
  model and runtime mapping are in place;
- backup restore must validate chain documents before replacing local state.

Importer behavior:

- imported route actions that map cleanly to `direct`, `current_profile`,
  `block`, `group:<name>` or `auto_select` keep existing behavior;
- imported chain-like constructs must be rejected unless the user explicitly
  maps them to a local `chain:<id>` that already validates;
- partial imports must report rejected chain entries with reasons;
- importers must not create provider URLs, inline private keys or raw outbound
  JSON inside chain definitions.

## Operator Wording

Use precise wording:

- "Chain route action" for `chain:<id>`;
- "Hop" for each ordered profile or group target;
- "Resolved profile" for the concrete profile selected from a group hop;
- "Fail closed" for blocked/rejected behavior when a chain cannot be fully
  resolved;
- "Candidate" only when diagnostics cannot prove runtime state and are
  reporting configured policy;
- "Runtime observed" only when the daemon/backend was actually observed.

Avoid wording that implies a chain is simply a group, current profile, global
mode, capture mode or automatic privacy upgrade.

## Diagnostics Contract

Human and JSON diagnostics must expose:

- chain ID;
- route action source: route rule, app-policy rule, app-policy default or
  default route action;
- hop order;
- hop target type and redacted/local target identity;
- resolved profile status for group hops;
- DNS strategy and selected DNS path;
- failure policy;
- health policy;
- route action status: `applies`, `candidate`, `blocked`, `unavailable` or
  `unknown`;
- confidence: configured-only, partial, runtime-required or observed;
- unavailable hop reasons.

Support export must redact chain descriptions, profile names, provider names,
provider URLs, local group labels where sensitive, raw endpoint identifiers and
any token-like metadata. It may keep chain IDs, counts, status enums and
redacted hop markers.

## Metrics And Privacy

Allowed metrics:

- aggregate chain status counters;
- chain health bucket counts;
- unavailable-hop reason counters;
- validation error categories.

Forbidden by default:

- destination domains or IP history;
- per-process route history;
- DNS query names;
- per-network chain automation history;
- provider endpoint URLs or subscription tokens;
- raw profile config values.
