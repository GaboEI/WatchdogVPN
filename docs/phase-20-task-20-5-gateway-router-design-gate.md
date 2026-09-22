# Gateway/Router Mode Contract

Gateway/router mode lets selected LAN clients use the WatchdogVPN host as a
routed gateway. It is a bounded sub-track with stricter rules than LAN proxy
sharing, and it stays disabled by default.

Gateway/router mode is accepted only as a bounded sub-track, not as a
general-purpose router. It must remain:

- disabled by default;
- explicit about the LAN-facing interface and client setup;
- reversible after normal disconnect, failed connect and daemon restart;
- fail-closed for LAN-originated traffic when the protected path is
  unavailable.

IPv4 gateway mode is the accepted target. IPv6 forwarding, router-advertisement
behavior and automatic LAN router/DHCP changes remain rejected until an explicit
design accepts them.

## Gateway Contract

A "gateway" mode must not be exposed unless LAN-originated packets are actually
constrained to the protected path and covered by teardown.

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

IPv4 forwarding may be enabled only for the active gateway session.

Required behavior:

- Snapshot the pre-apply `net.ipv4.ip_forward` value.
- Enable forwarding only after the gateway apply plan is complete enough to
  install kill-switch/firewall constraints.
- Restore the snapshot on disconnect, failed connect and daemon restart cleanup.
- Do not write persistent sysctl configuration.
- Do not enable IPv6 forwarding.
- Report forwarding state in diagnostics without hiding externally managed
  forwarding state.

If the previous IPv4 forwarding value was already enabled, teardown must leave it
enabled and report that it was externally enabled before WatchdogVPN applied
gateway state.

## NAT And Firewall Contract

Gateway mode requires product-owned, reversible firewall state. The
implementation must not rely on the LAN router as the access-control boundary.

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

nftables is the first gateway implementation backend. If nftables is not
available, gateway apply fails closed instead of installing partial
iptables-equivalent state.

## DNS Contract

Gateway/router mode must not imply DNS protection by accident.

One explicit DNS behavior must be implemented before gateway mode can be
reported as supported:

- a WatchdogVPN-owned LAN DNS path with teardown and leak validation; or
- a documented manual-client DNS mode that clearly reports when WatchdogVPN is
  not handling LAN client DNS.

For fail-closed profiles, no fallback to the LAN/router resolver is allowed when
WatchdogVPN claims to provide protected DNS for LAN clients. Diagnostics must
make the DNS mode visible.

## Client Setup Contract

Gateway/router mode uses manual client setup only.

Rejected:

- automatic DHCP mutation;
- router advertisement;
- NetworkManager connection mutation;
- silent changes to the LAN router;
- automatic persistent routes on client devices.

The CLI and docs may show the operator the gateway IP and manual client
settings, but must not claim automatic route advertisement.

## Kill-Switch Contract

LAN-originated traffic must not bypass the host kill-switch model.

The implementation must guarantee:

- upstream unavailable means LAN client traffic fails closed;
- gateway teardown does not leave a direct egress path;
- DNS behavior follows the selected DNS contract under upstream failure;
- route/firewall cleanup works after normal disconnect, failed connect and
  daemon restart cleanup;
- diagnostics distinguish gateway disabled, gateway configured, gateway applied
  and gateway degraded states.
