# LAN Sharing Architecture and Threat Model

WatchdogVPN may intentionally share a protected network path with LAN devices.
Sharing is always an explicit operator choice: the product never broadens
exposure on its own, and it must make the bind, firewall, DNS and teardown
consequences of that choice visible before they are applied.

## Product Boundary

WatchdogVPN may share a protected path with LAN devices only when the operator
opts into a specific sharing mode and understands the bind, firewall, DNS and
teardown consequences.

Two sharing tracks are defined:

- **LAN proxy sharing** — selected LAN clients use WatchdogVPN's SOCKS/HTTP
  proxy listener through an explicit LAN bind address.
- **Gateway/router mode** — selected LAN clients use the WatchdogVPN host as a
  routed gateway, under the stricter contract described in the gateway/router
  mode contract.

The current local-host behavior remains unchanged: loopback SOCKS/HTTP listeners
stay available for local applications and health checks.

## Trust Boundaries

| Boundary | Trust decision |
| --- | --- |
| Local host process to WatchdogVPN daemon | Trusted only through existing daemon/systemd permissions and validated config. |
| LAN client to WatchdogVPN LAN proxy | Untrusted by default; must be explicitly allowed and authenticated where protocol support exists. |
| LAN client DNS to WatchdogVPN | Untrusted input; the DNS path must be explicit and leak-tested, never assumed from proxy connectivity alone. |
| WatchdogVPN host to upstream protected path | Existing tunnel/proxy trust boundary; LAN traffic must not weaken kill-switch behavior. |
| LAN network/router | Not trusted to enforce WatchdogVPN policy; firewall and bind choices belong to WatchdogVPN and the operator. |

## Supported Modes

### LAN Proxy Sharing

- disabled by default;
- explicit non-loopback bind address required;
- no wildcard bind by default;
- local loopback inbounds remain unchanged;
- SOCKS authentication required if supported by the runtime;
- HTTP proxy authentication required if supported by the runtime; if
  unsupported, the implementation must document a protocol-specific exception
  and compensate with explicit bind plus firewall allowlist warnings;
- operator-visible warning before apply;
- reset/teardown must close the listener and remove any product-owned firewall
  state.

### Gateway/Router Mode

Gateway/router mode is a bounded sub-track with stricter rules than LAN proxy
sharing. IPv4 gateway mode is the accepted target; IPv6 forwarding,
router-advertisement behavior and automatic LAN router/DHCP changes remain
rejected until an explicit design accepts them.

Minimum contract:

- explicit LAN-facing interface;
- explicit upstream/protected path;
- no automatic persistent `net.ipv4.ip_forward` changes;
- IPv4 forwarding may be enabled only for the active gateway session with
  snapshot/rollback;
- IPv6 forwarding, router advertisements and automatic DHCP/router mutation
  remain rejected;
- NAT/firewall ownership and teardown;
- DNS behavior for LAN clients;
- manual client setup wording;
- kill-switch behavior for LAN-originated traffic.

## Rejected Modes

The following remain rejected until the contract is explicitly changed and the
change is validated:

- wildcard bind (`0.0.0.0`, `::`) as default behavior;
- implicit bind to every LAN interface;
- unauthenticated LAN proxy exposure when the protocol/runtime supports auth;
- gateway/router forwarding without explicit operator enablement;
- persistent IP forwarding changes without a stored rollback point;
- automatic LAN DHCP, router advertisement or network-manager mutation;
- enabling LAN sharing from legacy `active_mode`;
- silently converting LAN sharing intent into local-proxy-only behavior.

## Authentication Expectations

LAN sharing turns WatchdogVPN into a network service. Authentication is required
where the runtime supports it.

Minimum contract:

- generated credentials must not be logged in normal output;
- CLI JSON must not print secrets unless an explicit secret-output flag is
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

The implementation must never rely on the LAN router as the only access-control
boundary.

## DNS Expectations

LAN proxy sharing does not automatically mean LAN client DNS is protected. The
following paths must be understood and documented:

- the client resolves through the proxy when the client/protocol supports proxy
  DNS;
- the client uses a configured WatchdogVPN DNS path, if one is exposed;
- the client leaks to the LAN/router resolver when misconfigured, and
  diagnostics report that honestly;
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
- diagnostics must distinguish upstream failure from LAN
  bind/firewall/auth failure;
- teardown must leave no stale listener that can later route direct.

For gateway/router mode:

- forwarding/NAT must be covered by kill-switch behavior;
- route and firewall teardown must hold after normal disconnect, failed connect
  and daemon crash/restart scenarios.
