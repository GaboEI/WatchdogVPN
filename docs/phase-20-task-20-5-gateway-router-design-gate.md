# Phase 20 Task 20.5 - Gateway/Router Mode Design Gate

Date: 2026-07-08
Status: closed

## Scope

Task 20.5 decides whether full gateway/router mode stays in Phase 20 or is
split into a later phase, and defines the contract Task 20.6 must satisfy
before any runtime implementation is accepted.

This task is design-only. It does not add NAT, forwarding, route advertisement,
DNS listener exposure, firewall mutation, daemon behavior, sing-box behavior or
new routing/capture behavior.

## Decision

Gateway/router mode is accepted for the Phase 20 branch, not split into a later
phase, but only as a bounded sub-track with stricter rules than LAN proxy
sharing.

Task 20.6 may implement gateway/router mode only if it remains:

- disabled by default;
- outside `main` on the dedicated Phase 20 branch until Task 20.7 closes;
- VM/lab-only for all live forwarding tests;
- explicit about the LAN-facing interface and client setup;
- reversible after normal disconnect, failed connect and daemon restart;
- fail-closed for LAN-originated traffic when the protected path is
  unavailable.

IPv4 gateway mode is the accepted Task 20.6 target. IPv6 forwarding,
router-advertisement behavior and automatic LAN router/DHCP changes remain
rejected until a later explicit design task accepts them.

## Gateway Contract

Task 20.6 must not expose a "gateway" mode unless LAN-originated packets are
actually constrained to the protected path and covered by teardown.

Minimum runtime contract:

- The operator must explicitly enable gateway mode.
- The operator must select a concrete LAN-facing interface by name.
- The implementation must verify that the selected interface exists and has a
  usable IPv4 address before applying runtime state.
- The implementation must refuse wildcard, implicit "all interfaces" and
  loopback gateway selection.
- The protected upstream path must be explicit and observable in diagnostics.
- Local loopback SOCKS/HTTP inbounds and authenticated LAN proxy behavior must
  remain unchanged.
- Gateway mode must not be activated from legacy `active_mode`.

## Forwarding Contract

Task 20.6 may enable IPv4 forwarding only for the active gateway session.

Required behavior:

- Snapshot the pre-apply `net.ipv4.ip_forward` value.
- Enable forwarding only after the gateway apply plan is complete enough to
  install kill-switch/firewall constraints.
- Restore the snapshot on disconnect, failed connect and daemon restart cleanup.
- Do not write persistent sysctl configuration.
- Do not enable IPv6 forwarding.
- Report forwarding state in diagnostics without hiding externally managed
  forwarding state.

If the previous IPv4 forwarding value was already enabled, teardown must leave
it enabled and report that it was externally enabled before WatchdogVPN applied
gateway state.

## NAT And Firewall Contract

Gateway mode requires product-owned, reversible firewall state. Task 20.6 must
not rely on the LAN router as the access-control boundary.

Required behavior:

- Use a dedicated WatchdogVPN-owned ruleset/table/chain naming scheme.
- NAT only LAN-client traffic from the selected LAN-facing interface and
  configured LAN client range.
- Do not add broad NAT for all local traffic.
- Do not mutate unrelated firewall tables or external firewall manager state.
- Install forward-path rules that reject or drop LAN traffic when the protected
  path is unavailable.
- Remove every product-owned rule on disconnect, failed connect, reset and
  crash-recovery cleanup.
- Diagnostics must distinguish "not applied", "applied by WatchdogVPN" and
  "external/unmanaged" firewall state.

Task 20.6 chose nftables for the first gateway implementation. If nftables is
not available, gateway apply fails closed instead of installing partial
iptables-equivalent state. This backend must be validated in VM before Task
20.7 can close.

## DNS Contract

Gateway/router mode must not imply DNS protection by accident.

Task 20.6 must implement one explicit DNS behavior before gateway mode can be
reported as supported:

- a WatchdogVPN-owned LAN DNS path with teardown and leak validation; or
- a documented manual-client DNS mode that clearly reports when WatchdogVPN is
  not handling LAN client DNS.

For fail-closed profiles, no fallback to the LAN/router resolver is allowed when
WatchdogVPN claims to provide protected DNS for LAN clients. Diagnostics must
make the DNS mode visible.

## Client Setup Contract

Phase 20 gateway/router mode uses manual client setup only.

Rejected in Task 20.6:

- automatic DHCP mutation;
- router advertisement;
- NetworkManager connection mutation;
- silent changes to the LAN router;
- automatic persistent routes on client devices.

The CLI/docs may show the operator the gateway IP and manual client settings,
but must not claim automatic route advertisement.

## Kill-Switch Contract

LAN-originated traffic must not bypass the host kill-switch model.

Task 20.6 must prove:

- upstream unavailable means LAN client traffic fails closed;
- gateway teardown does not leave a direct egress path;
- DNS behavior follows the selected DNS contract under upstream failure;
- route/firewall cleanup works after normal disconnect, failed connect and
  daemon restart cleanup;
- diagnostics distinguish gateway disabled, gateway configured, gateway applied
  and gateway degraded states.

## Validation Contract For Task 20.6 And 20.7

Live gateway validation must run only in VM/lab.

Minimum topology:

- WatchdogVPN gateway VM on the Phase 20 branch;
- separate LAN client VM or isolated network namespace that is not the gateway
  process namespace;
- controlled upstream protected path or fake upstream that can be forced down;
- before/after captures of `ip -br addr`, `ip route`, `ip rule`, forwarding
  sysctls, firewall ruleset, active listeners and daemon logs.

Task 20.6 may add implementation and focused VM helpers, but Task 20.7 remains
responsible for the full matrix and the final no-HIGH/MEDIUM audit before this
branch can merge to `main`.

## Validation

Task 20.5 is design-only. No installed runtime, route, DNS, forwarding,
firewall, daemon or listener state was changed.

Local validation passed:

```bash
bash tests/unit.sh
bash tests/syntax.sh
python3 -m unittest discover -s tests -p 'test_*.py'
git diff --check
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
```
