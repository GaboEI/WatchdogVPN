# Phase 21 Task 21.3 - Network Monitor Integration

Date: 2026-07-08
Status: closed

## Scope

Task 21.3 wires read-only NetworkManager and default-route observations into
the Task 21.2 network-context policy model.

This task does not subscribe to long-running events, start or stop daemon
connections, execute autoconnect or autodisconnect, mutate DNS, routes,
firewall, forwarding, LAN sharing, gateway mode or system proxy state. It
collects transient local facts and returns an explainable policy decision.

## Read-Only Inputs

The monitor uses bounded read-only commands when available:

- `nmcli -t -f CONNECTIVITY general`
- `nmcli -t -f NAME,TYPE,DEVICE,STATE connection show --active`
- `nmcli -t -f ACTIVE,SSID,BSSID,DEVICE dev wifi`
- `ip -j route show default`

The command runner is injectable for tests. The default runner uses
`subprocess.run` with list-form arguments, captured output and a short timeout.

## Observation Model

`NetworkObservation` reports:

- monitor status: `observed`, `partial`, `unsupported` or `error`;
- connectivity: `online`, `limited`, `captive_portal`, `offline` or
  `unknown`;
- active transient networks;
- default-route interfaces;
- in-memory interface/default-route change flags when a previous observation is
  supplied;
- honest diagnostics for missing tools or partial command failures.

`ActiveNetwork` may hold transient raw SSID/BSSID/interface/gateway values only
in memory for immediate policy evaluation. The default `to_dict()` path redacts
SSID, BSSID, interface names and gateway identifiers.

## Policy Evaluation

`evaluate_network_context(policy, observation)` maps transient observations to
the persisted policy model:

- disabled policies always return manual mode;
- unsupported monitors return manual mode with an honest diagnostic;
- offline and captive-portal states select advisory triggers first;
- interface/default-route changes select the interface-change trigger;
- untrusted matches take precedence over trusted matches;
- trusted matches select the trusted-network trigger;
- no match returns manual mode.

Every decision includes `runtime_action_executed = false`. Even when a policy
contains an enabled `connect` or `disconnect` intent, Task 21.3 only reports the
modeled intent and does not execute it.

## Privacy Boundaries

Task 21.3 preserves the Task 21.1 and Task 21.2 privacy boundaries:

- observations are transient and are not persisted;
- raw SSID/BSSID/interface/gateway identifiers are redacted by default in
  observation output;
- hashed policy matches are computed in memory;
- explicit-consent raw match policies can be evaluated, but raw observation
  values still remain redacted in normal output;
- route/interface changes compare in-memory snapshots and do not create
  persistent history.

## Unsupported Environments

If both `nmcli` and `ip` are unavailable, the monitor returns
`status = unsupported` and policy evaluation degrades to manual mode.

If only one source is unavailable, the monitor returns `status = partial`,
keeps any available read-only observation, and includes a diagnostic explaining
the missing source.

## Validation

Task 21.3 adds tests for:

- NetworkManager/default-route observation;
- `nmcli` escaped separator parsing for BSSID values;
- default redaction of SSID/BSSID/interface values;
- missing `nmcli` partial fallback;
- missing `nmcli` and `ip` unsupported fallback;
- transient interface/default-route change detection;
- disabled policy manual fallback;
- modeled untrusted-network connect intent without execution;
- captive-portal and offline advisory triggers;
- interface-change precedence;
- explicit-consent raw match evaluation with redacted observation output.

## Task 21.3 Acceptance

Task 21.3 closes when:

- NetworkManager/default-route observations can feed the policy model where
  available;
- unsupported environments degrade to manual mode with honest diagnostics;
- raw local network identifiers remain transient and redacted by default;
- modeled automatic actions are never executed by this task;
- tests and standard validation pass;
- no runtime/network mutation is introduced.
