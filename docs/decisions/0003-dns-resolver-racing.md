# 0003 - DNS resolver racing

## Status

Rejected for runtime DNS - 2026-07-06

## Context

PHASE 15 Task 15.2 asks whether concurrent resolver racing belongs in
WatchdogVPN. The existing DNS v2 design is channel-based: direct traffic uses
the direct DNS channel, proxy traffic uses the proxy/FakeIP path, and final
fallbacks are explicit. The live sing-box configuration currently preserves
resolver order within each channel and uses the first enabled server for
single-resolver fields such as `final`, profile outbound self-resolution, and
domain resolver metadata.

`watchdog dns test` already probes candidate resolvers with bounded
concurrency. That is diagnostic and policy-building work: it ranks resolvers
before they are written into a DNS policy. It is not runtime racing of live
user DNS queries.

## Decision

Do not implement runtime resolver racing in v2.0.

WatchdogVPN will keep deterministic, ordered resolver selection at runtime.
Operators can still use `watchdog dns test` to measure configured resolvers
and then place the preferred resolvers first in each channel.

The `DNSChannel.strategy` field remains accepted only as `auto`, which maps to
the current deterministic behavior. Unsupported strategies such as racing or
parallel live resolution are rejected during policy load instead of being
silently ignored.

## Rationale

Runtime resolver racing does not improve WatchdogVPN's current safety contract
enough to justify the added ambiguity:

- Cross-resolver answers can legitimately differ because of cache state,
  filtering policy, split-horizon DNS, ECS behavior, DNS64/NAT64, geolocation,
  or captive/intercepting networks. Picking the fastest answer would hide that
  inconsistency instead of explaining it.
- Racing inside a channel can blur direct/proxy/final intent. A direct channel
  answer and a proxy channel answer have different leak and trust properties,
  so they should remain explicit policy decisions rather than timing outcomes.
- Runtime racing would require new answer comparison, quorum, cancellation,
  cache and reporting semantics across UDP, TCP, TLS, HTTPS, local and DHCP
  transports. Without that full contract it would create false confidence.
- The current fail-closed posture is clearer: if the selected channel cannot
  provide a safe answer, the failure is visible through the existing resolver,
  DNS hijack, and kill-switch paths instead of being masked by a faster
  secondary resolver.

## Consequences

### Positive

- Runtime DNS remains deterministic and easier to audit.
- DNS channel boundaries remain explicit.
- `dns test` can keep using bounded concurrency without changing live traffic
  semantics.
- Hand-edited policies cannot opt into a nonexistent racing mode silently.

### Negative

- WatchdogVPN will not shave per-query latency by taking the fastest live
  resolver response.
- Detecting inconsistent answers remains a future diagnostic/reporting
  problem, not a runtime selection behavior. That belongs with DNS diagnostics,
  where answers can be shown honestly without affecting live traffic.

### Future Work

If answer comparison is needed later, implement it as a non-mutating
diagnostic command first. It must report inconsistent answers per channel,
show resolver identity and route context, bound concurrency and timeout, and
avoid changing runtime resolver choice.
