# WatchdogVPN QA Audit - Phase 15 Task 15.1 DNS Refinement

> Date: 2026-07-06
> Task: PHASE 15 - DNS Policy Refinement, Time Diagnostics & Safe LAN Services, Task 15.1 - DNS refinement audit
> Status: COMPLETE. AUD-P15-001 was found and resolved. No unresolved HIGH or MEDIUM findings remain for Task 15.1.

## 1. Scope

This audit reviewed DNS v2 against the current routing policy without
redesigning Phase 10/12 DNS behavior:

- direct/proxy/final channel behavior
- FakeIP and ECS boundaries
- static IP priority
- DNS diversion rule ordering
- TUN hijack behavior
- system resolver apply/reset/restore behavior

The audit intentionally stayed on the CLI/core/driver surface. It did not
start Task 15.2 resolver racing, Task 15.3 diagnostics, Task 15.4 time checks,
or Task 15.5 LAN sharing.

## 2. Coverage Checklist

| Surface | Reviewed criteria | Result |
| --- | --- | --- |
| DNS channel generation | Direct, proxy and final channels produce stable sing-box server tags and final fallback order without deprecated DNS outbound matchers. | PASS. Covered by `dns/singbox.py` and `tests/test_dns_singbox.py`; Phase 10 AUD-DNS-004 remains closed. |
| Outbound self-resolution | A profile outbound resolves its own server through direct/bootstrap or a non-proxy final resolver, never through FakeIP or the same proxy outbound. | PASS. Covered by `SingBoxDriver.generate_singbox_config()` and `tests/test_singbox_driver.py`. |
| App-policy DNS inheritance | `direct` uses the direct DNS channel or rejects when unavailable; `block` rejects; current/group-like actions follow proxy/FakeIP or final policy. | PASS. Phase 12 AUD-P12-002 remains closed; tests pin rule prepending before domain DNS rules. |
| FakeIP boundary | FakeIP is used only as proxy domain resolver when `proxy_resolution_channel = fakeip` and a proxy channel exists. It is not used as the profile outbound resolver. | PASS. |
| ECS boundary | ECS client subnet is only attached to direct domain resolver metadata when explicitly enabled and configured. | PASS. |
| Static IP priority | Static host mappings are emitted before DNS diversion rules and upstream fallback. | PASS. |
| DNS diversion ordering | Rules are sorted by priority and insertion order, after static IP and before final fallback. Missing selected channels fail visibly. | PASS. |
| TUN DNS hijack | Hijack route sniffs DNS and hijacks destination-independent DNS protocol traffic before catch-all route rules. | PASS. |
| System resolver apply/reset | Apply is confirmed or dry-run only, saves rollback snapshot, reset restores and removes snapshot, disconnect auto-restores if a snapshot exists. | PASS after AUD-P15-001. |

## 3. Finding

### AUD-P15-001 - `dns apply` accepted non-53 entrypoint ports that system resolvers cannot preserve

- Layer: 5 - CLI/Operator diagnostics; Layer 7 - DNS/system integration
- Severity: MEDIUM
- Status: RESOLVED on 2026-07-06
- Description: `watchdog dns apply --yes` accepted `--entrypoint-port` values
  other than 53. The command checked reachability at the requested
  address/port, but system resolver managers are configured by nameserver
  address only in the current implementation. `resolvectl dns`, NetworkManager
  `ipv4.dns`/`ipv6.dns`, and plain `resolv.conf` do not preserve an arbitrary
  per-nameserver port through `SystemDNSStateManager`.
- Scenario: A user runs `watchdog dns apply --yes --entrypoint-address
  127.0.0.1 --entrypoint-port 1053` while a local test service is reachable
  on 1053. The reachability check can pass and a snapshot can be saved, but
  the host resolver is still pointed at `127.0.0.1` with normal DNS queries
  going to port 53.
- Impact before the fix: DNS apply could report success while the host was
  configured to use an address where DNS might not answer on the standard
  port, causing broken name resolution until reset/rescue. This is a
  resilience and operator-honesty issue, not a traffic leak.
- Resolution: Confirmed `dns apply` now rejects non-53 entrypoint ports before
  mutation. `--dry-run` still accepts non-53 ports for planning output.
  Documentation now explains that confirmed system DNS mutation requires port
  53 because resolver managers are configured by address only.
- Evidence:
  - `cli/main.py::_dns_apply()` rejects confirmed non-53 apply with
    `dns apply requires --entrypoint-port 53`.
  - `tests/test_cli_dns_commands.py` covers rejection before snapshot creation
    and dry-run planning with a non-53 port.
  - `docs/dns-cli.md` documents the behavior.

## 4. Checked Scenarios Without New Findings

- `DNSMode.OFF` still avoids sing-box DNS generation and DNS hijack apply.
- Direct/proxy/final channel behavior uses `domain_resolver` on outbounds,
  not deprecated `dns.rules[].outbound` matchers.
- DNS policy is still threaded through `WatchdogRuntime.connect()`,
  `startup()`, reconnect, and rotation paths.
- FakeIP remains scoped to proxy-side client DNS resolution and is not used
  for the profile outbound's own remote hostname.
- ECS remains direct-only.
- Static IP rules precede DNS diversion rules.
- DNS diversion rules fail visibly when the selected channel has no server.
- TUN DNS hijack rules are merged before route catch-all rules.
- `watchdog dns reset --yes` restores snapshots and removes the snapshot file
  after a successful restore.
- `WatchdogRuntime.disconnect()` still attempts snapshot restore and logs
  restore failures without blocking disconnect.

## 5. Validation

Task-focused validation:

```bash
python3 -m unittest tests.test_cli_dns_commands tests.test_dns_state_manager tests.test_dns_hijack tests.test_dns_singbox tests.test_singbox_driver
git diff --check
```

Result:

- 121 tests passed.
- `git diff --check` passed.

Full closure validation is recorded in the Task 15.1 master-plan notes.

## 6. Closure Status

Task 15.1 is complete. No unresolved HIGH or MEDIUM findings remain for this
task. Resolver racing, route/DNS diagnostics, time diagnostics, and LAN proxy
sharing remain sequenced future Phase 15 tasks and were not started here.
