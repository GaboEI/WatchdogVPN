# Native transport and policy companion

## Problem

AmneziaWG, OpenVPN, and OpenVPN+Cloak own a real native tunnel, but historically
accepted WatchdogVPN's shared DNS, routing, capture, app-policy, chain, and LAN
arguments without enforcing them. The native drivers now declare no policy
capabilities, and the default secure state rejects those arguments before any
mutation.

The default configuration is not a niche case:

```
routing_policy=rule
capture_modes=local_proxy,tun
default_route_action=current
```

It requires capture, routing, and DNS, and may additionally require app policy,
chains, and LAN sharing. Leaving native profiles unusable under that state is a
functional gap. Declaring capabilities without real enforcement would recreate
a high-severity security regression: a driver that reports policy support while
not applying it.

## Chosen architecture: native transport plus policy companion

A native connection is a two-owner transaction:

1. The native driver owns only its private process(es), interface, endpoint
   transport, native routes, and native teardown.
2. A dedicated sing-box policy companion owns the local SOCKS/HTTP listeners,
   WatchdogVPN TUN, transparent capture, DNS engine and hijack, routing rule
   groups, app policy, route chains, and LAN state.
3. The companion's current-profile route target is a plain `direct` outbound.
   Once the native tunnel is connected, that outbound follows the native
   driver's verified default/policy route. The companion never owns, rewrites,
   or guesses the native private keys or endpoint transport.
4. The native driver starts first. The companion starts only after the native
   driver reports healthy. If companion startup or health proof fails, both
   owners are torn down in reverse order and the connection fails closed.
5. Disconnect tears down the companion before the native tunnel. A failed
   companion teardown is a lifecycle barrier: the native tunnel is not
   discarded as if cleanup had succeeded, and status reports the owned residue.

This reuses the proven sing-box policy engine instead of attempting to
duplicate DNS diversion, FakeIP, route groups, app routing, chains, LAN
firewalling, TUN cleanup, and ownership checks in three native implementations.

## Control-plane invariant

A remote operator must not lose an established SSH control path when the
companion enables transparent TUN capture.

Before any native or companion mutation, the implementation must:

- enumerate established SSH peers using the existing safe `ss` observation;
- resolve each peer's current physical egress interface with `ip route get`;
- reject activation if either observation is unavailable or ambiguous;
- add a per-peer companion outbound bound to that physical interface; and
- put those per-peer direct rules before DNS and ordinary routing rules.

The ordinary companion `direct` outbound must **not** be physically bound: it
must follow the native tunnel route. The management outbound is separate and
may only carry the exact ephemeral SSH peers observed at activation. It is never
persisted in a profile.

A local-console activation with no SSH peer is valid. An SSH activation without
this proof is refused, not downgraded.

## DNS and routing invariant

The companion must generate the same structured sing-box DNS configuration, DNS
inbounds/hijack routes, rule groups, app-policy rules, chain plans, and LAN
configuration as a normal sing-box profile. Its DNS proxy channel and
current-profile rule target both resolve to the native-transport `direct`
outbound.

TUN readiness requires the owned sing-box process, both owned local proxy
listeners, `wdvpn-tun0`, complete sing-box nftables auto-redirect state, and no
unexplained route/rule residue. Native readiness is also required. A connected
result requires both owners, never merely one.

The companion's unmarked egress must take the native interface/route while an
exact SSH peer takes the bound physical management outbound; activation is
refused if this cannot be established.

## Capability and status contract

The composed `NativePolicyDriver` may declare the complete
`DRIVER_POLICY_CAPABILITIES` set only after it performs the transaction above.
The underlying native driver keeps an empty capability set and is never exposed
directly to WatchdogRuntime's policy capability check.

Its status is truthful:

- `connected` only when native and companion status are both healthy;
- `runtime_mismatch` when either owner or its artifacts disagree;
- `degraded`/failed health if either side loses readiness;
- active profile identity is the native profile, while `tun_active` and
  `proxy_active` come from the companion.

The runtime runs the same profile-qualified egress health checker for the
composed driver as it does for a normal sing-box driver.

## Non-goals and prohibited shortcuts

- Do not change the default routing/DNS/capture state to make native profiles
  start.
- Do not add a hidden or generic compatibility override.
- Do not mark the raw native drivers as capable.
- Do not silently omit DNS, FakeIP, rule, app, chain, capture, or LAN behavior.
- Do not bind all companion traffic to the physical interface; that would
  bypass the native tunnel.
- Do not rely on `finally` for recovery; both owners retain durable runtime
  ownership and teardown barriers.

A separately disclosed, user-consented reduced mode may be designed later, but
it is not a substitute for enforcing the shared policy.
