# R28-006 - Native driver policy companion design

Status: CLOSED. This is the original design record, retained with its final
implementation and installed evidence below.

## Problem

AmneziaWG, OpenVPN, and OpenVPN+Cloak own a real native tunnel, but historically
accepted WatchdogVPN's shared DNS, routing, capture, app-policy, chain, and LAN
arguments without enforcing them. Commit `8bbbd38` correctly made that
impossible: all native drivers declare no policy capabilities and default secure
state rejects them before mutation.

The installed default is not a niche configuration:

```
routing_policy=rule
capture_modes=local_proxy,tun
default_route_action=current
```

It requires capture, routing, and DNS, and may additionally require app policy,
chains, and LAN sharing. Keeping native profiles permanently unusable under that
state is a HIGH functional release blocker. Declaring capabilities without real
enforcement would recreate AUD-022, a HIGH security regression.

## Chosen architecture: native transport plus policy companion

A native connection is a two-owner transaction:

1. The native driver owns only its private process(es), interface, endpoint
   transport, native routes, and native teardown evidence.
2. A dedicated sing-box policy companion owns the local SOCKS/HTTP listeners,
   WatchdogVPN TUN, transparent capture, DNS engine and hijack, routing rule
   groups, app policy, route chains, and LAN state.
3. The companion's current-profile route target is a plain `direct` outbound.
   Once the native tunnel is connected, that outbound follows the native
   driver's verified default/policy route. The companion never owns, rewrites,
   or guesses the native private keys or endpoint transport.
4. The native driver starts first. The companion starts only after the native
   driver reports healthy. If companion startup or health proof fails, both
   owners are torn down in reverse order and connection fails closed.
5. Disconnect tears down the companion before the native tunnel. A failed
   companion teardown is a lifecycle barrier: the native tunnel is not
   discarded as if cleanup had succeeded, and status reports the owned residue.

This reuses the already proven sing-box policy engine instead of attempting to
duplicate DNS diversion, FakeIP, route groups, app routing, chains, LAN
firewalling, TUN cleanup, and ownership checks in three native implementations.

## Control-plane invariant

A remote operator must not lose an established SSH control path when the
companion enables transparent TUN capture.

Before *any* native or companion mutation, the implementation must:

- enumerate established SSH peers using the existing safe `ss` observation;
- resolve each peer's current physical egress interface with `ip route get`;
- reject activation if either observation is unavailable or ambiguous;
- add a per-peer companion outbound bound to that physical interface; and
- put those per-peer direct rules before DNS and ordinary routing rules.

The ordinary companion `direct` outbound must **not** be physically bound:
it must follow the native tunnel route. The management outbound is separate and
may only carry the exact ephemeral SSH peers observed at activation. It is never
persisted in a profile.

A local-console activation with no SSH peer is valid. An SSH activation without
this proof is refused, not downgraded.

## DNS and routing invariant

The companion must generate the same structured sing-box DNS configuration,
DNS inbounds/hijack routes, rule groups, app-policy rules, chain plans, and
LAN configuration as a normal sing-box profile. Its DNS proxy channel and
current-profile rule target both resolve to the native-transport `direct`
outbound.

The existing TUN readiness proof remains mandatory: owned sing-box process,
both owned local proxy listeners, `wdvpn-tun0`, complete sing-box nftables
auto-redirect state, and no unexplained route/rule residue. Native readiness
also remains mandatory. A connected result requires both owners, never merely
one.

The implementation must prove, in an installed VM, that the companion's
unmarked egress takes the native interface/route while an exact SSH peer takes
the bound physical management outbound. It must reject if either proof cannot
be made.

## Capability and status contract

The composed `NativePolicyDriver` may declare the complete
`DRIVER_POLICY_CAPABILITIES` set only after it performs the transaction above.
The underlying native driver keeps an empty capability set and is never exposed
directly to WatchdogRuntime's policy gate.

Its status is truthful:

- `connected` only when native and companion status are both healthy;
- `runtime_mismatch` when either owner or its artifacts disagree;
- `degraded`/failed health if either side loses readiness;
- active profile identity is the native profile, while `tun_active` and
  `proxy_active` come from the companion.

The runtime must run the same profile-qualified egress health checker for the
composed driver as it does for a normal sing-box driver.

## Explicit non-goals and prohibited shortcuts

- Do not change the default routing/DNS/capture state to make native profiles
  start.
- Do not add a hidden or generic compatibility override.
- Do not mark the raw native drivers as capable.
- Do not silently omit DNS, FakeIP, rule, app, chain, capture, or LAN behavior.
- Do not bind all companion traffic to the physical interface; that would
  bypass the native tunnel.
- Do not rely on `finally` for recovery; both owners retain existing durable
  runtime ownership and teardown barriers.

A separately disclosed, user-consented reduced mode may be designed later, but
it is not the remediation for this HIGH finding and cannot close R28-006.

## Implementation slices

1. Extract a direct-transport variant of sing-box config generation. It must
   produce all policy artifacts while selecting the existing `direct` outbound
   as current-profile target, and support exact management-peer outbounds.
2. Add `NativePolicyDriver`, composing one native driver and one policy
   companion with strict startup/rollback/teardown ownership.
3. Route native protocol selection through the composed driver. Preserve the
   existing raw native capability contract for isolated driver tests.
4. Add unit/contract tests for config shape, management-rule precedence,
   native-success/companion-failure rollback, disconnect ordering, status
   honesty, capability gate coverage, rotation/startup/node-group paths, and
   all policy options.
5. Perform source gates and installed field proof with real AmneziaWG,
   OpenVPN, and OpenVPN+Cloak fixtures. Test default policy and every supported
   alternative state, failure injection on each owner, SSH control-plane
   preservation, DNS resolution, proxy and TUN egress, kill switch, and clean
   restoration.
6. Re-run the independent R28 detection audit. Only then may R28-006 close.

## Release gate

R28-006, Task 23.4, Phase 23, PR, and merge remain blocked until all slices
pass and the installed evidence is documented.

## Implementation and installed evidence - 2026-07-15

Implementation commits: `c57bf4d`, `4f4b673`, `287ec05`, `963f13c`,
`fc9f88b`, and `7450a22`.

The native policy companion is now selected for AmneziaWG, OpenVPN, and
OpenVPN+Cloak. It starts the native transport first, requires native health,
then starts a sing-box TUN/DNS/routing companion; companion failure rolls the
native transport back, and teardown is companion before native. The companion
uses a direct transport route for the native tunnel and separate,
physical-interface-bound routes for established SSH peers.

Installed evidence at `7450a22`:

- OpenVPN connected with owned OpenVPN and sing-box processes, TUN, DNS,
  listeners, and sing-box routing. SOCKS and normal TUN egress both returned
  `138.124.58.47`; disconnect returned clean standby.
- OpenVPN+Cloak connected with owned ck-client, OpenVPN, and sing-box
  processes, TUN, DNS, listeners, and routing. Both egress paths returned
  `138.124.58.47`; disconnect returned clean standby.
- AmneziaWG reached the native driver but failed during native interface
  configuration (`ip link set mtu ... watchdogvpn_awg`) with amneziawg-go
  requesting the kernel module. The connection failed closed and explicit
  disconnect restored clean standby. This was a runtime/dependency blocker,
  not a policy bypass.

## Final closure evidence - 2026-07-15

The remaining AmneziaWG runtime dependency was resolved without weakening
policy: the supported LTS kernel has the DKMS module installed, while the
unsupported mainline kernel continues to fail closed. The native tunnel now
uses the policy companion's reserved output-bypass mark, preventing its UDP
transport from being captured into sing-box and looping back to itself.

The approved AmneziaWG field profile connected in native-policy mode with an
owned TUN, proxy, kill switch, handshake, and real SOCKS egress. An explicit
disconnect restored clean desired-off standby. The same profile's historical
duplicate import also connected after the routing-mark correction, confirming
the prior divergence was runtime policy state rather than profile content.

Dedicated regressions cover policy composition, deep native egress proof,
manual failed-connect cleanup, native endpoint bypass, and the reserved
routing mark. R28-006 is CLOSED. This closure does not authorize automatic
deletion of historical duplicate imports; that remains separate reversible
maintenance work.
