# Phase 21 Task 21.2 - Network-Aware Policy Model

Date: 2026-07-08
Status: closed

## Scope

Task 21.2 implements the persisted network-context policy model under the Task
21.1 privacy contract.

This task is policy-only. It does not subscribe to NetworkManager or system
events, observe live interfaces, start or stop daemon connections, apply
autoconnect or autodisconnect, mutate DNS, routes, firewall, forwarding, LAN
sharing, gateway mode or system proxy state.

## Persisted Schema

The persisted store is `network-context-policy.json` with schema version `1`.
The default policy is disabled and every trigger defaults to manual mode.

Top-level fields:

- `schema_version`: persisted schema version, currently `1`;
- `enabled`: network-context policy enablement, default `false`;
- `profiles`: user-authored trusted, untrusted or unknown network profiles;
- `triggers`: policy intents for trusted networks, untrusted networks,
  interface changes, captive-portal signals and offline signals;
- `redaction`: support-export redaction preferences, default redacted.

Network profiles contain:

- `id`: stable opaque profile identifier;
- `label`: local user label, redacted from normal support export;
- `trust`: `trusted`, `untrusted` or `unknown`;
- `enabled`: profile enablement;
- `matches`: explicit match keys.

Match kinds:

- default-safe match kinds: `profile_tag`, `ssid_sha256`, `bssid_sha256`,
  `interface_name_sha256`, `interface_type`,
  `gateway_identifier_sha256`;
- explicit-consent match kinds: `raw_ssid`, `raw_bssid`,
  `raw_interface_name`, `raw_gateway_identifier`.

Action intents contain:

- `enabled`: default `false`;
- `action`: `manual`, `warn_only`, `keep_current`, `connect` or `disconnect`;
- `explanation`: user-facing reason for the modeled action;
- `disable_hint`: user-facing way to disable the modeled action;
- `reversible`: action reversibility marker;
- `reversal`: user-facing reversal semantics.

## Privacy Boundaries

The model rejects raw sensitive or history-like fields by default, including:

- raw SSID/BSSID;
- raw interface names;
- gateway or link-layer identifiers;
- public exit IP history;
- captive-portal history;
- network transition history;
- per-network automation history;
- DNS query or destination history.

Raw SSID, BSSID, interface name and gateway identifier match values are
accepted only as explicit-consent match kinds, and only when both
`explicit_consent = true` and a non-empty `consent_note` are present.

`to_redacted_dict()` redacts profile labels, raw values, hash values and
consent notes so normal support export can avoid leaking local network
identifiers by default.

## Automation Safety

Every modeled automatic action must remain explainable, disableable and
reversible. `connect` and `disconnect` intents are schema-only in this task:
they persist optional intent but do not execute. Enabled intents cannot use the
`manual` action, and connect/disconnect intents must be reversible.

Unsupported or invalid policy shapes fail validation instead of being treated
as healthy configuration.

## Validation

Task 21.2 adds tests for:

- disabled/manual defaults;
- invalid policy, profile, trigger and redaction shapes;
- invalid hashed identifiers;
- raw sensitive match rejection without explicit consent;
- explicit-consent raw match acceptance;
- redaction boundaries;
- store load/save round-trip behavior;
- missing-file defaults;
- corrupt JSON fail-closed load behavior.

## Task 21.2 Acceptance

Task 21.2 closes when:

- the persisted network-aware policy model exists;
- defaults are disabled/manual;
- sensitive raw identifiers and history fields are not persisted by default;
- explicit-consent raw match fields are validated;
- every modeled automatic action has explainable, disableable and reversible
  semantics;
- model/store tests pass;
- no runtime or network behavior changes.
