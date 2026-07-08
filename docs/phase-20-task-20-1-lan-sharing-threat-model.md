# Phase 20 Task 20.1 - LAN Sharing Architecture Threat Model

Date: 2026-07-08
Status: closed

## Scope

Task 20.1 defines the security and validation contract for Phase 20 before any
LAN listener, forwarding or gateway behavior is implemented.

Phase 20 remains branch-only and VM-only until the final Phase 20 audit closes.
This document is a design gate: it does not enable LAN sharing, change bind
addresses, change firewall state, start sing-box, enable forwarding, mutate DNS
or expose any new service.

## Product Boundary

WatchdogVPN may intentionally share a protected path with LAN devices only when
the operator opts into a specific sharing mode and understands the bind,
firewall, DNS and teardown consequences.

Phase 20 has two tracks:

- LAN proxy sharing: selected LAN clients use WatchdogVPN's SOCKS/HTTP proxy
  listener through an explicit LAN bind address.
- Gateway/router mode: selected LAN clients use the WatchdogVPN host as a
  routed gateway. This is not automatically accepted by Task 20.1; it requires
  the later Task 20.5 design gate before implementation.

The current local-host behavior remains unchanged: loopback SOCKS/HTTP
listeners stay available for local applications and health checks.

## Trust Boundaries

| Boundary | Trust decision |
| --- | --- |
| Local host process to WatchdogVPN daemon | Trusted only through existing daemon/systemd permissions and validated config. |
| LAN client to WatchdogVPN LAN proxy | Untrusted by default; must be explicitly allowed and authenticated where protocol support exists. |
| LAN client DNS to WatchdogVPN | Untrusted input; DNS path must be explicit and leak-tested, never assumed from proxy connectivity alone. |
| WatchdogVPN host to upstream protected path | Existing tunnel/proxy trust boundary; LAN traffic must not weaken kill-switch behavior. |
| LAN network/router | Not trusted to enforce WatchdogVPN policy; firewall and bind choices belong to WatchdogVPN/operator. |
| VM/lab validation network | Disposable validation environment only; no successful VM result permits workstation live experiments. |

## Supported Modes

### LAN Proxy Sharing

Supported only after Tasks 20.2-20.4 implement and validate it:

- disabled by default;
- explicit non-loopback bind address required;
- no wildcard bind by default;
- local loopback inbounds remain unchanged;
- SOCKS authentication required if supported by the runtime;
- HTTP proxy authentication required if supported by the runtime; if unsupported,
  the implementation must document a protocol-specific exception and compensate
  with explicit bind plus firewall allowlist warnings;
- operator-visible warning before apply;
- reset/teardown command must close the listener and remove any product-owned
  firewall state.

### Gateway/Router Mode

Not accepted for implementation by Task 20.1. Task 20.5 must decide whether to
keep it in Phase 20 or split it into a later dedicated phase.

If accepted later, it must define:

- explicit LAN-facing interface;
- explicit upstream/protected path;
- no automatic persistent `net.ipv4.ip_forward` or IPv6 forwarding changes
  without rollback;
- NAT/firewall ownership and teardown;
- DNS behavior for LAN clients;
- route advertisement or manual client setup wording;
- kill-switch behavior for LAN-originated traffic;
- multi-VM validation with a separate LAN client.

## Rejected Modes

The following remain rejected until a later task explicitly changes this
contract and validates the change:

- wildcard bind (`0.0.0.0`, `::`) as default behavior;
- implicit bind to every LAN interface;
- unauthenticated LAN proxy exposure when the protocol/runtime supports auth;
- gateway/router forwarding without explicit operator enablement;
- persistent IP forwarding changes without a stored rollback point;
- automatic LAN DHCP, router advertisement or network-manager mutation;
- enabling LAN sharing from legacy `active_mode`;
- silently converting LAN sharing intent into local-proxy-only behavior;
- merging LAN behavior into `main` before VM-only validation clears HIGH/MEDIUM
  findings.

## Authentication Expectations

LAN sharing turns WatchdogVPN into a network service. Authentication is required
where the runtime supports it.

Minimum contract:

- generated credentials must not be logged in normal output;
- CLI JSON must not print secrets unless a future explicit secret-output flag is
  designed;
- credentials must be stored with the same or stricter permissions as other
  sensitive local config;
- auth failures must be visible in diagnostics without exposing passwords;
- unauthenticated protocol paths require a written exception, explicit bind,
  operator warning and firewall allowlist guidance.

## Bind And Firewall Expectations

LAN proxy bind rules:

- local proxy defaults stay `127.0.0.1:2080` and `127.0.0.1:2081`;
- LAN proxy bind must be a concrete address assigned to a local interface;
- wildcard bind is invalid outside explicit test fixtures;
- loopback-only mode must remain valid and unchanged;
- firewall apply must be explicit and reversible;
- firewall status must distinguish "not applied", "applied by WatchdogVPN" and
  "external/unmanaged".

The implementation must never rely on the LAN router as the only access control
boundary.

## DNS Expectations

LAN proxy sharing does not automatically mean LAN client DNS is protected.
Task 20.4 must validate and document at least these paths:

- client resolves through the proxy when the client/protocol supports proxy DNS;
- client uses a configured WatchdogVPN DNS path, if exposed by a later task;
- client leaks to the LAN/router resolver when misconfigured, and diagnostics
  report that honestly;
- disconnect/reset closes any WatchdogVPN-owned DNS listener and removes
  firewall state;
- no fallback to the LAN/router resolver is allowed when a protected DNS path is
  configured fail-closed.

## Kill-Switch Expectations

LAN-originated traffic must not create a bypass around the local host protection
model.

For LAN proxy sharing:

- if the upstream protected path is unavailable and policy is fail-closed, LAN
  proxy requests must fail closed rather than use direct egress;
- diagnostics must distinguish upstream failure from LAN bind/firewall/auth
  failure;
- teardown must leave no stale listener that can later route direct.

For gateway/router mode, if accepted later:

- forwarding/NAT must be covered by kill-switch behavior;
- route and firewall teardown must be proven after normal disconnect, failed
  connect and daemon crash/restart scenarios.

## VM Topology And Validation Plan

All Phase 20 runtime validation must run in VM/lab only.

Current read-only VM baseline observed on 2026-07-08:

- host: `gabodev`;
- LAN interface: `enp0s8`;
- address: `192.168.0.228/24`;
- default route: `192.168.0.1 dev enp0s8`;
- policy rules: local/main/default only;
- nftables tables: none reported by read-only inspection.

Minimum LAN proxy validation topology:

- WatchdogVPN server VM with the Phase 20 branch installed;
- separate LAN client VM or isolated network namespace that is not the
  WatchdogVPN host process namespace;
- controlled upstream profile or test proxy path;
- before/after capture of `ip -br addr`, `ip route`, `ip rule`,
  `nft list ruleset` or iptables equivalent, active listeners and daemon logs.

Minimum gateway validation topology, if accepted:

- WatchdogVPN gateway VM with two interfaces or an equivalent isolated lab
  topology;
- separate LAN client VM using the gateway path;
- proof of NAT/forwarding state, DNS path, kill-switch behavior, teardown and
  rollback.

## Merge Gates

No Phase 20 implementation may merge to `main` until all of these are true:

- branch-only development was used for the full phase;
- LAN sharing is disabled by default;
- explicit bind address is required;
- authentication is implemented or a protocol-specific exception is documented;
- firewall/port warnings are implemented;
- reset/teardown removes listeners and product-owned firewall state;
- LAN client DNS behavior is validated and documented;
- kill-switch behavior covers supported LAN-originated traffic;
- VM-only validation completed for supported modes;
- phase audit finds no unresolved HIGH or MEDIUM findings.

## Task 20.1 Validation

Task 20.1 is design-only. It did not require installed runtime mutation or live
network changes.

Read-only VM baseline collection was performed with `ssh archvm` and did not
modify routes, firewall, DNS, services or files.

Local validation passed:

```bash
bash tests/unit.sh
bash tests/syntax.sh
python3 -m unittest discover -s tests -p 'test_*.py'
git diff --check
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
```

Full Python discovery result: 1082 tests OK.
