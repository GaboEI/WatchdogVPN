# WatchdogVPN Diagnostic Report - Phase 12, Task 12.5 Real Traffic Validation

> Date: 2026-07-03/04 (overnight session)
> Task: PHASE 12 - Linux Split Tunneling & App Policy, Task 12.5 - Real traffic
> validation matrix
> Status: NOT CLOSED. Real, confirmed progress made; one blocking root cause
> still open. Session paused deliberately after two severe real-machine
> incidents, not because the task was abandoned.

---

## 1. What task/phase we are trying to complete

Task 12.5 is the first task in Phase 12 that requires validating the app
policy / split tunneling feature against **real network traffic** on the real
development machine, through the real systemd daemon - not generated JSON,
not unit tests with mocked config directories. Tasks 12.1-12.4 (design audit,
app policy model, runtime wiring, minimal CLI) were already implemented and
validated at the unit-test level. Task 12.5 exists specifically to prove (or
disprove) that the generated sing-box configuration actually behaves
correctly when real processes generate real traffic through a real TUN
interface.

## 2. Original technical objective of this task

Per the master plan, Task 12.5 must validate on the real machine:

- one app forced `direct` while another goes through the VPN
- one app forced through the VPN while default traffic goes direct
- a blocked app cannot reach the network
- DNS follows the chosen traffic policy
- kill switch does not allow non-tunnel leaks
- disconnect/reset leaves no stale routes, DNS state, or orphan process state

It also owns closing four audit findings carried over from Task 12.1/12.3:
AUD-P12-002 (DNS follows app-policy action), AUD-P12-003 (kill switch does
not leak with the real TUN interface), AUD-P12-004 (TUN route hardening
behavior on the real machine), AUD-P12-006 (disconnect/restart/crash cleanup
leaves no stale state).

## 3. What was attempted during this session

In rough chronological order:

1. Real CLI/daemon smoke checks - found the operator's own user session was
   not in the `watchdogvpn` group in the running shell (stale login), and
   that `sudo` inside the VS Code integrated terminal panel silently strips
   TTY access (`NoNewPrivs=1`), unrelated to WatchdogVPN itself. Resolved by
   using a real terminal and a fresh login.
2. First profile add + first `watchdog connect` attempts - failed with a
   generic `connect failed`. Root-caused to `find_singbox_binary()` never
   finding a system-wide sing-box binary: it was only installed at
   `~/.local/bin/sing-box`, invisible to the daemon (different user,
   `ProtectHome=read-only`, restricted `PATH`). Fixed for this machine by
   installing sing-box to `/usr/local/bin/sing-box` (the installer's own
   canonical path).
3. First successful TUN connect, but immediately after, a **full network
   outage** requiring a normal reboot to recover (see Incident 1 below).
4. Root-caused the AdGuard VPN CLI + legacy v1 bash rotation/watchdog
   automation (`vpn-rotate`/`vpn-watchdog` systemd units, NetworkManager
   dispatcher) still being installed and periodically forcing AdGuard back
   online on this machine, despite the repo saying it was fully removed in
   PHASE 2.6. Removed with explicit user authorization (systemd units,
   dispatcher script, AdGuard CLI binary/service user). This is a real
   "repo says removed, live machine says otherwise" gap, tracked separately
   in section 7.
5. Reconnect attempts kept failing at the DNS layer (`Resolving timed out`).
   Traced to the daemon running a **stale, pre-Phase-12 installed copy** of
   the code (`/usr/local/lib/watchdogvpn`, last synced before Task 12.2).
   `update.sh` re-synced it; this is the first time the daemon ever ran any
   Phase 12 code end-to-end.
6. Traced a further DNS failure to `AdGuardHome` (a separate, legitimate ad
   blocker product) occupying `127.0.0.1:53`, colliding with WatchdogVPN's
   DNS hijack listener. Removed with explicit user authorization (official
   `-s uninstall`, then binary removal).
7. Found and fixed, in order, four real code bugs in the sing-box config
   generator and DNS module (full detail in section 6). Added regression
   tests for all four and updated the three tests whose assertions encoded
   the old, buggy behavior.
8. Validated the fixes manually (root-run `sing-box run` against a
   generated config, bypassing the daemon) - three of four traffic-matrix
   cases passed cleanly in this mode.
9. Re-validated through the real daemon (dedicated `watchdogvpn` service
   user) - DNS resolution now works, but per-process route differentiation
   (the `direct` app-policy rule) does not reproduce the same result as the
   manual/root run.
10. Diagnosed the daemon-vs-manual discrepancy to sing-box being unable to
    identify the OWNING PROCESS for connections made by users other than the
    daemon's own service account (`router: find process path: ... not
    found`). Added `CAP_SYS_PTRACE` to the daemon's systemd unit as the
    documented fix for this exact sing-box behavior. Verified via a second
    debug-log capture that the capability did **not** resolve it.
11. Immediately after that verification, a **second and more severe
    incident** occurred, requiring a hard power cut (see Incident 2 below).
    Session paused at the user's explicit instruction.

## 4. What worked partially

- **Manual (root, non-daemon) sing-box runs** with the four code fixes
  applied produced a fully correct result for 3 of 4 traffic-matrix cases:
  - `dig` resolved real domains correctly through the tunnel's DNS path.
  - `curl` matched to the `direct` app-policy rule correctly bypassed the
    tunnel and showed the real ISP IP.
  - `wget` with no matching rule correctly fell through to the tunnel and
    showed the VPS exit IP.
  - `apt-get` (rule: `block`) was **not** actually blocked, but this is an
    expected, understood limitation, not a routing bug: `apt-get` itself
    never opens the network socket - it delegates to separate
    `/usr/lib/apt/methods/{http,https,...}` helper binaries, which have a
    different process name than the rule matched against. This is exactly
    the scenario the existing `match_confidence: low` labeling on
    process_name-only rules already exists to warn about.
- The clean, root-run reproduction proves the **generated configuration
  itself**, after the four fixes, is logically correct for this traffic
  matrix. The remaining problem is specific to running under the daemon's
  service-user identity.

## 5. What failed

- The same, fixed configuration run through the real daemon (`watchdogvpn`
  service user) did not reproduce the "direct" vs "default" traffic
  differentiation reliably - in most attempts both flows showed the tunnel's
  exit IP, meaning the `direct` app-policy rule silently failed to match.
- Two full-machine network/stability incidents occurred (see section 6.1),
  each requiring a full reboot / hard power cycle to recover.
- Kill switch behavior (AUD-P12-003) and disconnect/crash cleanup at scale
  (AUD-P12-006) were never reached - the session never got far enough past
  the DNS/routing and process-attribution problems to test them.

## 6. Errors, symptoms and anomalous behavior observed

- `error: "connect failed"` (generic, daemon-side) - root cause: missing
  daemon-reachable sing-box binary (item 3.2 above).
- `curl: (28) Resolving timed out after N milliseconds` - repeated across
  many attempts, root causes were layered (stale daemon code, AdGuardHome
  port conflict, then the four DNS/routing bugs fixed in this session).
- `dig` output: `;; communications error to 192.168.0.1#53: timed out` -
  same root causes as above.
- `sing-box` `FATAL[0000] start service: post-start inbound/tun[...]:
  starting TUN interface: set routes: add route 0: file exists` - occurs
  whenever WatchdogVPN's sing-box tries to start while a different,
  comparable sing-box-based VPN client already installed on this machine is
  connected. Both default to the same internal kernel routing table number
  (`2022`). Sing-box fails fast and cleanly in this case - not a leak, not a
  hang, just a same-machine resource collision between two independent
  sing-box-based clients. Confirmed reproducible and understood; not a
  WatchdogVPN-only bug, but must never be allowed to happen in the field
  (two VPN tunnels active at once is not a supported configuration for any
  sing-box-based client).
- `sing-box` debug log: `router: find process path: process of uid(1000),
  inode(N) not found` followed by `router: found user: <name>` - the
  process-level identity resolves to a *user*, never a *process path*, for
  every connection whose owning process is not the daemon's own service
  account. This is the direct cause of process_name-based app-policy rules
  silently not matching under the daemon. Confirmed present both before and
  after granting `CAP_SYS_PTRACE`.
- Two severe real-machine incidents (full detail below).

### 6.1 Real-machine incidents

**Incident 1** - after the very first successful TUN connect (with
`strict_route`/`auto_redirect` active and no DNS channel configured yet),
the machine lost all internet connectivity completely: router restart,
Wi-Fi toggle, and cable swap did not restore it. A normal reboot did. Kernel/
systemd logs for that boot showed a clean, orderly shutdown sequence (no
kernel oops, no hung processes, `NetworkManager` correctly unmanaging
`wdvpn-tun0` on shutdown) - i.e. no evidence of kernel-level corruption, but
also no direct evidence of what caused the live outage, since the failure
happened during live operation, not at teardown. Root cause was later
narrowed to the missing `bind_interface` on the "direct" outbound (fixed,
section 6.2, fix #1) combined with the DNS-black-hole default policy (fixed,
section 7) - both of which, together, could plausibly explain a
total-capture, no-egress state under `strict_route`.

**Incident 2** - after verifying that `CAP_SYS_PTRACE` did not fix the
process-attribution problem (a short, targeted debug-log capture), the user
attempted to log out; the screen went black and stayed unresponsive through
the login password prompt. A normal restart did not recover it - the machine
required a full power disconnect. This is more severe than Incident 1. A
real, avoidable contributing factor is on record: sing-box's log level had
been left at `debug` for the diagnostic capture and was not reverted before
this attempt. Under `strict_route`+`auto_redirect`, *every* packet from
*every* running application (browser tabs, WhatsApp, Chrome background
services, etc.) is evaluated by the router and produces multiple debug log
lines - this is a plausible source of severe I/O/CPU pressure independent of
any routing bug, and cannot be ruled out as a real contributor. The debug
log level has been reverted to `warning` in the committed code. The exact
mechanism that made the machine unresponsive to the point of requiring a
hard power cut is **not confirmed** and must not be assumed to be "just the
logging" without verification - it is the top open risk carried into
tomorrow's plan.

### 6.2 Confirmed, fixed code bugs (in `drivers/singbox_driver.py` and `dns/singbox.py`)

1. **Missing `bind_interface` on the "direct" outbound.** The profile's own
   outbound always received `bind_interface` (e.g. `enp4s0`), but the
   generated "direct" outbound (used for app-policy `direct` actions and
   for `direct`/`rules` connection modes) never did. Under `strict_route`,
   an outbound with no `bind_interface` has its own egress traffic
   recaptured by the tunnel's own system-wide route redirect, black-holing
   all "direct"-routed and default DNS traffic. Fixed by threading the same
   `_outbound_bind_interface(profile)` value into `_ensure_direct_outbound()`
   at both call sites. Covered by two new regression tests.
2. **FakeIP incorrectly assigned as the main outbound's `domain_resolver`.**
   Whenever a DNS "proxy" channel was configured (the default
   `proxy_resolution_channel` is `"fakeip"`), the *profile's own outbound*
   (the trojan/vless/etc. tunnel connection) was given
   `domain_resolver: "watchdogvpn-fakeip"`. FakeIP addresses are synthetic,
   client-facing placeholders that can never actually be dialed - the
   tunnel then tried to connect to its own fake address and timed out,
   breaking the whole connection, confirmed via sing-box debug logs
   (`dial tcp 198.18.0.2:5222: i/o timeout`). Fixed by never assigning
   FakeIP to the profile's own outbound; it now resolves via a real,
   dialable resolver instead. Covered by an updated existing test.
3. **DNS query loopback when only a "proxy" channel is configured.** Once
   fix #2 was in place, the natural next choice (route the outbound's
   `domain_resolver` to the "final" DNS server) still broke when the only
   configured channel was "proxy" (routed through the tunnel itself):
   resolving the outbound's own hostname required dialing through the
   tunnel, which required resolving the outbound's hostname first - sing-box
   correctly detected and rejected this as a DNS query loopback. Fixed by
   preferring the DNS "direct"/"bootstrap" channel (never proxied) for the
   outbound's own resolver, and only falling back to "final" when it does
   not resolve to the same tag used by the "proxy" channel. Covered by a new
   regression test asserting no `domain_resolver` is assigned when only an
   unsafe (proxy-only) channel exists.
4. **DNS hijack rule scope too narrow for TUN-captured traffic.** The
   existing hijack-DNS route rule only matched traffic arriving at two
   explicit loopback inbounds (`127.0.0.1:53`). But real system DNS queries
   (addressed to the actual LAN resolver, e.g. the router) get captured by
   `strict_route`/`auto_route` and arrive at sing-box via the TUN's own
   inbound with a *different* destination (the TUN's internal peer
   address) - a destination the old rule never matched. These queries
   silently fell through to the catch-all rule and were sent to the VPN
   outbound as if they were ordinary traffic toward a real, routable
   address - which they are not, since that destination only exists inside
   this machine's own TUN. Fixed by adding a `{"action": "sniff"}` step
   followed by a destination-independent `{"protocol": ["dns"], "action":
   "hijack-dns"}` rule (sing-box's documented pattern for protocol-based,
   not inbound-tag-based, DNS interception under a TUN). Covered by two
   updated existing tests.

All four fixes are committed with passing unit tests (690 total,
`bash tests/unit.sh`, `bash tests/syntax.sh`, `compileall`, `git diff
--check` all green) and were confirmed working end-to-end in a manual,
root-run reproduction (section 4). `CAP_SYS_PTRACE` was also added to the
daemon's systemd unit (`AmbientCapabilities`/`CapabilityBoundingSet`) as a
plausible, documented fix for the process-attribution problem below, and is
committed, but it did **not** resolve that specific problem on its own.

## 7. Other real findings (not code bugs in the routing/DNS generator, but real gaps)

- **Daemon code drift**: the installed daemon
  (`/usr/local/lib/watchdogvpn`) can silently run stale code indefinitely.
  `update.sh` refreshes the files on disk but does not always restart an
  already-"healthy" daemon process, and Python does not reload already
  loaded modules. There is currently no guarantee that "files on disk match
  files in memory" after an update. This means every finding validated
  earlier in Phase 12 (12.2/12.3/12.4) was, until this session, only ever
  exercised through unit tests with mocked config directories - never
  through the actual running daemon.
- **`lib/singbox.sh` install detection is daemon-blind.** It accepts
  `$HOME/.local/bin/sing-box` as "already installed", which was true when
  everything ran as the interactive user, but is invisible to the daemon
  (dedicated service user, `ProtectHome=read-only`, restricted `PATH`).
  `install.sh`/`update.sh` need to either treat only system-wide paths as
  sufficient, or copy a user-local install into `/usr/local/bin` themselves.
- **No conflict detection for the DNS hijack port.** `build_dns_hijack_inbounds()`
  hardcodes `listen: 127.0.0.1:53` with no check for an already-occupying
  local resolver. When one exists (found: AdGuardHome), sing-box fails to
  bind and exits immediately, surfaced only as a generic, unhelpful daemon
  `"connect failed"`.
- **Default DNS policy is a black hole under `rules`+app-policy mode.** A
  fresh `DNSPolicy()` (`mode=auto`, zero configured channels,
  `tun_hijack=True`) produces a hijack listener with no real resolver behind
  it. Any operator who enables app-policy in `rules` mode without first
  configuring DNS channels gets total DNS failure with no actionable error.
- **Two sing-box-based VPN clients cannot run simultaneously on this
  machine.** The other comparable sing-box-based client already installed
  here and WatchdogVPN share the same default kernel routing
  table number (`2022`). This is expected/inherent to sing-box, not a
  WatchdogVPN-specific bug, but currently surfaces as an opaque `FATAL`
  crash in the daemon's own log rather than a clear, actionable CLI error.
- **Incident 3 (post-session, after the code fixes were already committed):**
  the other sing-box-based client on this machine crashed on its own
  (`traps: <client>[PID] trap int3 ... in libsentry.so`, its own Sentry
  crash-reporting handler firing) roughly two minutes before a total network
  outage (neither the VPN nor the normal direct connection worked, no IP at
  all) that required a reboot. The user correctly pushed back on treating
  this as an unrelated coincidence: this client had reportedly never crashed
  before, on the same night this session ran sing-box manually dozens of
  times and killed it with `kill` rather than a clean `disconnect()` in many
  of those runs (a known risk already flagged in section 13/[[feedback-live-tun-testing-safety]]).
  At the moment this was investigated, no WatchdogVPN residue was found
  (no sing-box process, no nftables table, no `wdvpn-tun0` interface, daemon
  in standby) - but that only proves the state was clean *by the time it was
  checked*, not that it was clean at the moment of the crash. The working
  hypothesis is that incomplete cleanup from one of tonight's many
  kill-instead-of-disconnect test cycles left transient state in the shared
  routing table (`2022`) that the other client's own process encountered and
  crashed on when it was reconnected afterward - a *residue* collision, not
  only the already-documented *simultaneous-use* collision. `watchdogvpn.service`
  was stopped and disabled (`systemctl stop` + `disable`) as an immediate,
  low-cost precaution for the rest of the night; this needs to be confirmed
  or ruled out properly tomorrow (see the added phase in section 14), not
  left as an assumption in either direction.
- **Legacy v1 AdGuard automation was still live on this real machine**
  despite the repo/master-plan recording PHASE 2.6 as fully closed. This is
  a "repo says done, deployed machine says otherwise" gap - closing a phase
  in the repo does not retroactively fix machines that were never
  re-installed/updated after that phase. Removed this session with explicit
  authorization; not itself a code bug, but worth remembering when auditing
  "is this really gone" claims on any real machine going forward.
- **AdGuardHome** (separate legitimate product, unrelated to the AdGuard VPN
  removal decision) was occupying port 53 on this dev machine and was
  removed this session with explicit authorization once its conflict with
  WatchdogVPN's own DNS hijack was confirmed.

## 8. Current technical hypotheses

- **H1 (leading, for the open blocker).** sing-box's process-attribution
  mechanism (used for `process_name` app-policy matching) needs more than
  `CAP_SYS_PTRACE` to inspect connections owned by users other than the
  daemon's own service account under this unit's full hardening profile
  (`NoNewPrivileges=true`, `ProtectSystem=strict`,
  `SystemCallArchitectures=native`, etc). Untested so far: whether the
  capability is actually being delivered to the sing-box child process at
  all (ambient capabilities can be stripped by `execve()` semantics
  depending on file capability bits and `securebits`); whether an additional
  capability (e.g. `CAP_DAC_READ_SEARCH`) is required; whether Yama's
  `ptrace_scope` (currently `1` on this machine) interacts unexpectedly even
  with the capability present; or whether sing-box's process match is simply
  not designed to work reliably for a non-root, capability-limited daemon
  process at all.
- **H2.** `NoNewPrivileges=true` combined with granted capabilities can be
  self-defeating for some capability-gated code paths on some kernels -
  worth isolating with a minimal test before assuming sing-box itself is the
  only variable.
- **H3 (safety-critical).** `strict_route=true` + `auto_redirect=true`
  together impose a very aggressive, system-wide capture of literally all
  traffic on the machine. This had never been exercised, end-to-end, against
  a real, busy desktop (browser, WhatsApp, Chrome background services,
  Telegram, etc. all generating constant traffic) before this session - all
  earlier Phase 12 validation was unit-test-only. The two severe incidents
  may be a symptom of this specific combination being heavier and more
  fragile under real, sustained, multi-process load than anything tested so
  far, independent of any single one of the four fixed bugs.
- **H4.** Residual, transient kernel-level state from repeated manual
  sing-box invocations (started and `kill`-ed, rather than cleanly
  disconnected) during this session may have contributed to some of the
  inconsistent reproduction seen between attempts, on top of the
  other-client-collision explanation (section 6) that accounts for some
  (but likely not all) of the inconsistency.

### 8.1 Follow-up VM isolation result - 2026-07-04

The ordered Phase 1 isolation was repeated in an Arch VM from a clean
snapshot, without running the full WatchdogVPN `connect()` path and without
remote profiles, DNS hijack, app-policy persistence, or kill-switch state.
The minimal config used only a temporary TUN, one `process_name = curl`
reject rule, and a `direct` fallback.

Results:

- Root-run sing-box identified `/usr/bin/curl` and matched
  `process_name = curl`, proving the minimal config and sing-box
  process-rule mechanism work.
- Running sing-box as the dedicated `watchdogvpn` user with
  `CAP_SYS_PTRACE` only failed the same way as the live daemon:
  `find process path ... not found`, followed by user-only attribution.
- Removing the daemon-like hardening did not fix the failure, so the root
  cause is not `NoNewPrivileges`, seccomp, `ProtectSystem`, `ProtectHome`,
  or namespace hardening by itself.
- Adding `CAP_DAC_READ_SEARCH` alongside `CAP_SYS_PTRACE` allowed sing-box
  running as `watchdogvpn` to resolve `/usr/bin/curl` and match the route
  rule.
- The same `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH` set also worked with the
  daemon-like hardening profile enabled (`NoNewPrivileges=true`, seccomp,
  `ProtectSystem=strict`, `ProtectHome=read-only`,
  `RestrictNamespaces=true`, etc.).

Conclusion: Phase 1 identified a concrete systemd capability gap. The
daemon needs both `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` in its ambient
and bounding sets for sing-box process attribution across users. This
resolves the process-attribution root cause at the isolated capability
level, but it does not close Task 12.5; the full daemon-mediated traffic
matrix, DNS policy behavior, kill switch, and cleanup validation still need
to run in later phases.

### 8.2 Daemon-mediated app-policy confirmation - 2026-07-04

After landing and installing the capability fix, the corrected daemon was
tested in the Arch VM with the real `watchdog connect` path, the real
`watchdogvpn.service`, and a real VLESS profile. This was still a bounded
single-case validation, not the full Task 12.5 matrix.

Setup:

- active mode: `rules`
- app-policy mode: `blacklist`
- app-policy rule: `process_name = curl` -> `block`
- generated sing-box rule confirmed in the live config:
  `{"action": "reject", "process_name": ["curl"]}`
- sing-box log level remained at `warning`; the test avoided debug logging.

Result:

- `watchdog connect` succeeded through the daemon.
- `wdvpn-tun0` came up and daemon status reported `tun_active = true`.
- `curl http://1.1.1.1/cdn-cgi/trace` failed quickly
  (`curl_exit=7`, no remote IP), consistent with the generated reject rule.
- A control request from `python3` to the same URL succeeded with HTTP 200
  and showed the VLESS exit IP, proving the tunnel itself was working and
  the `curl` failure was process-policy-specific rather than general
  connectivity failure.
- Explicit `watchdog disconnect` returned the daemon to standby and cleanup
  left no sing-box process, no `wdvpn-tun0`, no non-default `ip rule`, and
  no WatchdogVPN nftables residue.

Conclusion: the corrected daemon now enforces a real `process_name` app
policy rule in the daemon-mediated TUN path. The next matrix case is an app
forced `direct` while default traffic continues through the VPN.

### 8.3 Daemon-mediated direct-vs-VPN confirmation - 2026-07-04

The next bounded VM validation confirmed the direct-vs-VPN matrix case
through the real daemon path, still without enabling kill switch testing.

Setup:

- active mode: `rules`
- app-policy mode: `blacklist`
- app-policy rule: `process_name = curl` -> `direct`
- default action: `current`
- generated sing-box rule confirmed in the live config:
  `{"action": "route", "outbound": "direct", "process_name": ["curl"]}`
- generated outbounds included both the VLESS profile outbound and `direct`

Result:

- `watchdog connect` succeeded through the daemon.
- `wdvpn-tun0` came up and daemon status reported `tun_active = true`.
- Baseline direct `curl` to `http://1.1.1.1/cdn-cgi/trace` returned the
  same direct behavior as `curl` after connect (`HTTP 301` from
  `remote_ip = 1.1.1.1`), consistent with the app-policy direct route.
- A control request from `python3` to the same endpoint succeeded with
  HTTP 200 and showed the VLESS exit IP, proving default traffic still went
  through the VPN while `curl` was routed direct.
- Explicit `watchdog disconnect` returned the daemon to standby and cleanup
  left no sing-box process, no `wdvpn-tun0`, no non-default `ip rule`, and
  no WatchdogVPN nftables residue.

Conclusion: the corrected daemon now validates both core per-process
directions in the real TUN path: `curl -> block` with unrelated traffic
through the VPN, and `curl -> direct` with unrelated traffic through the
VPN. Remaining Task 12.5 work should continue with DNS-follow-policy,
blocked helper-process behavior, kill switch, and cleanup/crash validation.
Later sections in this same report record the follow-up DNS and helper-process
validation.

### 8.4 DNS-follow-policy audit - 2026-07-04

The next bounded VM validation audited the live daemon-generated DNS and
route config with:

- active mode: `rules`
- app-policy mode: `blacklist`
- app-policy rule: `process_name = curl` -> `direct`
- default action: `current`
- DNS mode: `custom`
- DNS hijack: enabled
- DNS channels intentionally distinguishable:
  - direct: `udp://9.9.9.9`
  - proxy: `https://1.1.1.1/dns-query`
  - final: `tcp://8.8.8.8`
- DNS rules:
  - `example.com` -> direct channel
  - `cloudflare.com` -> proxy channel

Result:

- `watchdog connect` succeeded through the real daemon.
- `wdvpn-tun0` came up and daemon status reported `tun_active = true`.
- The generated outbounds kept the expected hardening:
  - profile outbound `domain_resolver = watchdogvpn-direct-1`
  - profile outbound `bind_interface = enp0s8`
  - `direct` outbound `domain_resolver = watchdogvpn-direct-1`
  - `direct` outbound `bind_interface = enp0s8`
- The generated DNS servers were correctly detoured by channel:
  - direct DNS server detoured through `direct`
  - proxy DNS server detoured through the active VLESS outbound
  - final DNS server detoured through `direct`
  - FakeIP server present for proxy resolution
- DNS rules were present in the generated config:
  - `example.com` -> `watchdogvpn-direct-1`
  - `cloudflare.com` -> `watchdogvpn-proxy-1`
- Smoke DNS lookups for `example.com` and `cloudflare.com` returned A
  records during the connected window.
- Explicit `watchdog disconnect` returned the daemon to standby and cleanup
  left no sing-box process, no `wdvpn-tun0`, no non-default `ip rule`, and
  no WatchdogVPN nftables residue.

Important finding:

The generated route rule order was:

```json
[
  {"action": "sniff"},
  {"action": "hijack-dns", "protocol": ["dns"]},
  {"action": "hijack-dns", "inbound": ["watchdogvpn-dns-udp-in", "watchdogvpn-dns-tcp-in"]},
  {"action": "route", "outbound": "direct", "process_name": ["curl"]},
  {"action": "route", "outbound": "ubuntu_gabo_yahoo_firefox"}
]
```

That order means TUN-captured DNS packets are hijacked before the
`process_name = curl` app-policy rule can route them to `direct`. The DNS
policy's own domain/channel rules can still steer specific domains to direct
or proxy DNS channels, but the current design does **not** prove that DNS
automatically follows a per-process app-policy action. AUD-P12-002 therefore
remains open as a design/implementation question, not a runtime connectivity
failure.

Operational note:

In the Arch VM, the installed daemon socket and shared-state lock files were
owned by the `watchdogvpn` user/group. The unprivileged shell could not
connect to `/run/watchdogvpn/control.sock` or create
`/var/lib/watchdogvpn/*.lock`, so daemon-mediated validation used
`sudo WATCHDOGVPN_CONFIG_DIR=/var/lib/watchdogvpn ./bin/watchdog ...`.
This did not affect the daemon runtime result, but it should be considered
when auditing CLI/group access behavior separately.

### 8.5 App-policy DNS inheritance fix validation - 2026-07-04

After the DNS-follow-policy audit above, the runtime wiring was updated so
that app-policy rules also prepend matching `dns.rules` when DNS hijack is
active:

- app-policy `direct` -> DNS direct channel when configured, otherwise reject
- app-policy `block` -> DNS reject
- app-policy `current` -> proxy/FakeIP channel when configured, otherwise the
  DNS policy final channel

Local validation:

- `WATCHDOGVPN_CONFIG_DIR=$(mktemp -d) python3 -m unittest
  tests.test_singbox_driver` -> 61 tests passed.
- `bash tests/syntax.sh` -> passed.
- `bash tests/unit.sh` -> passed.
- `WATCHDOGVPN_CONFIG_DIR=$(mktemp -d) python3 -m unittest
  tests.test_dns_singbox tests.test_rules_singbox tests.test_core_watchdog
  tests.test_singbox_driver tests.test_app_policy` -> 184 tests passed.
- `WATCHDOGVPN_CONFIG_DIR=$(mktemp -d) python3 -m unittest discover tests`
  -> 692 tests passed, 1 skipped.
- Local `sing-box check` probes confirmed sing-box 1.13.14 accepts
  `process_name`, `process_path`, `process_path_regex`, `user`, and
  `user_id` matchers in `dns.rules` with both `server` and `action: reject`.

Live daemon validation:

- Installed the updated local code with `sudo ./update.sh --yes`.
- Restarted `watchdogvpn.service`.
- Connected through the real daemon with the same bounded VM test profile.
- `wdvpn-tun0` came up and daemon status reported `tun_active = true`.
- Generated `dns.rules` began with app-policy-derived rules before
  domain/channel DNS rules:

```json
[
  {"process_name": ["curl"], "server": "watchdogvpn-direct-1"},
  {"action": "reject", "process_path": ["/usr/bin/phase3c-blocked-helper"]},
  {"domain": ["example.com"], "server": "watchdogvpn-direct-1"},
  {"domain": ["cloudflare.com"], "server": "watchdogvpn-proxy-1"}
]
```

- Generated `route.rules` still included the corresponding traffic rules:

```json
[
  {"action": "route", "outbound": "direct", "process_name": ["curl"]},
  {"action": "reject", "process_path": ["/usr/bin/phase3c-blocked-helper"]}
]
```

- The live assertion reported:
  `ASSERTION_OK: app-policy DNS rules precede domain DNS rules`.
- Smoke DNS lookups for `example.com` and `cloudflare.com` returned A records
  during the connected window.
- Explicit `watchdog disconnect` returned the daemon to standby and cleanup
  left no sing-box process, no `wdvpn-tun0`, no non-default `ip rule`, and
  no WatchdogVPN nftables residue.

Conclusion: AUD-P12-002 is now resolved for generated-config implementation
and bounded daemon validation. The next section records the bounded
helper-process validation; after that, Task 12.5 still needs kill switch
no-leak validation and cleanup/crash validation before the full matrix can
close.

### 8.6 Blocked helper-process behavior validation - 2026-07-04

The next bounded VM validation tested the package-manager-style helper
process pattern without touching the system package manager or running an
upgrade. The goal was to prove the important behavior observed earlier with
`apt-get`: the parent process name may not own the network socket, so the
correct app-policy target is the helper executable that actually opens the
connection.

Setup:

- Ran in the Arch VM from the clean Task 12.5 baseline.
- The external conversation VPN was disconnected before the WatchdogVPN test
  and restored only after cleanup.
- The test imported a temporary VLESS profile into the shared daemon state,
  then restored the previous `profiles.json` at teardown.
- The test backed up and restored `state.toml`, forcing
  `active_mode = "rules"` only for the connected window.
- The test backed up and restored/removes app-policy state at teardown.
- A controlled helper executable was created by copying `/usr/bin/curl` to:
  `/tmp/watchdogvpn-task-12-5-helper-curl`
- A parent launcher process executed that helper. The app-policy rule matched
  the helper path, not the parent:

```json
{
  "id": "task-12-5-helper-block",
  "action": "block",
  "match": {
    "process_path": ["/tmp/watchdogvpn-task-12-5-helper-curl"]
  },
  "enabled": true
}
```

Result:

- `watchdog connect` succeeded through the real daemon.
- `wdvpn-tun0` came up and daemon status reported `tun_active = true`.
- The generated live sing-box config contained the helper route reject rule:
  `ASSERTION_OK: helper route reject rule found in
  /run/watchdogvpn/watchdogvpn-singbox-.../singbox.json dns_reject=not-present`
- `dns_reject=not-present` is expected for this specific helper test because
  the probe intentionally used `http://1.1.1.1/cdn-cgi/trace` to isolate
  process routing without introducing DNS resolution into the assertion.
- A `python3` control request to the same endpoint succeeded during the
  connected window and reported the VPN exit IP, proving default traffic still
  used the tunnel while the helper was blocked.
- The parent-launched helper failed quickly:
  `curl_exit=0 http_code=000 remote_ip=`, `actual_exit=7`,
  `helper_command_exit=7`.
- The test reported:
  `ASSERTION_OK: delegated helper process was blocked by process_path`.
- Explicit `watchdog disconnect` ran at teardown, restored the previous
  profile and state files, removed the temporary app-policy, and cleanup left
  no sing-box process, no `wdvpn-tun0`, no non-default `ip rule`, and no
  WatchdogVPN nftables residue.

Conclusion: package-manager-style helper behavior is validated for the
bounded daemon path. Blocking the parent process is not sufficient when a
package manager or updater delegates network I/O; the reliable rule is to
match the helper executable that owns the socket, preferably with exact
`process_path` for high-confidence matching. The earlier `apt-get` result is
therefore documented as an expected helper-process limitation of
parent-process matching, not a failure of app-policy enforcement.

### 8.7 Kill switch no-leak validation - 2026-07-04

The next bounded VM validation tested AUD-P12-003 with a real daemon-managed
TUN connection, nftables kill switch rules, `strict_route=true`, and
`auto_redirect=true`.

Implementation changes made during this validation:

- The kill switch now carries the active profile's literal endpoint IP when
  available, allowing the VPN transport endpoint while the default policy
  remains drop.
- nftables rules now include counters and counted terminal drops, which made
  the bounded VM diagnosis auditable instead of relying on policy-drop
  silence.
- The kill switch explicitly allows the sing-box TUN internal DNS endpoint
  (`172.19.0.2:53`) before generic DNS/DoT leak blocks. This is required
  because DNS hijack rewrites system DNS to the TUN-side endpoint before the
  WatchdogVPN output chain sees the packet.
- The kill switch explicitly allows loopback destinations (`127.0.0.0/8` and
  `::1/128`) before terminal drops. This is required because auto-redirected
  TCP flows are redirected to a local sing-box listener and may not appear as
  `oifname lo` at the output hook.
- The same endpoint, mark, internal-DNS, and loopback allowances are covered
  in the iptables fallback path.

Bounded real-traffic validation result:

- Daemon connect succeeded in forced `tun` mode with `tun_active=true`.
- Baseline traffic before enabling the kill switch used the VPN exit:
  `baseline_ip=138.124.58.47`.
- With kill switch active, unbound control traffic still used the same VPN
  exit: `vpn_control_ip=138.124.58.47`.
- A request forced to the physical interface using curl was captured by
  `auto_redirect` and still exposed the same VPN exit:
  `direct_trace_ip=138.124.58.47`.
- Direct TCP DNS on port 53 did not connect: `tcp_53_exit=124`.
- TCP 853 may connect under `auto_redirect`; this is not treated as a leak by
  itself because the physical-interface trace already proved the observed
  public egress stayed on the VPN path.
- Cleanup disabled the kill switch, disconnected WatchdogVPN, restored the
  temporary profile/state backup, and showed no leftover non-default `ip rule`
  or WatchdogVPN firewall table.

Local validation after the implementation changes:

- `bash tests/syntax.sh` - pass
- `bash tests/unit.sh` - pass
- `python3 -m py_compile core/kill_switch.py core/watchdog.py
  tests/test_kill_switch.py tests/test_core_watchdog.py` - pass
- `python3 -m unittest discover -s tests` - 700 OK, 1 skipped
- `git diff --check` - pass

Conclusion: AUD-P12-003 is resolved for bounded Arch VM no-leak validation
with the real daemon, real TUN interface, nftables kill switch, and
`strict_route`+`auto_redirect`. The validation proved that normal traffic
continues through the VPN with the kill switch active, a physical-interface
forced request is captured and still exits via the VPN, and direct TCP DNS is
blocked. Task 12.5 remains open for cleanup/crash validation.

### 8.8 Cleanup/crash validation - 2026-07-04

The next bounded VM validation tested normal disconnect cleanup, systemd stop,
systemd restart, and sing-box child crash behavior. Each subtest started from a
clean runtime preflight, imported a temporary profile into shared daemon state,
forced `active_mode = "tun"`, connected through the real daemon, and checked
for leftover sing-box processes, `wdvpn-tun0`, non-default `ip rule` entries,
WatchdogVPN/sing-box nftables tables, and sing-box/proxy listeners.

The first three subtests passed without code changes:

- `watchdog disconnect` after a daemon-managed TUN connection returned the
  daemon to standby and left no runtime residue.
- `systemctl stop watchdogvpn.service` during an active TUN connection cleaned
  the sing-box child, TUN link, sing-box nftables table, auto-redirect rules,
  and listeners; restarting the daemon left it usable.
- `systemctl restart watchdogvpn.service` during an active TUN connection
  stopped the old daemon/child pair, left no sing-box process or kernel
  routing/firewall residue, and the new daemon came back in coherent standby
  state. A follow-up explicit disconnect was idempotent.

The sing-box child crash subtest exposed a real cleanup bug. After forcing
`SIGKILL` on the daemon's sing-box child:

- the TUN link disappeared and daemon status reported standby;
- the sing-box child briefly appeared as a defunct process;
- sing-box auto-redirect `ip rule` entries remained:
  `pref 1`, `9000`, `9001`, `9002`, and `32768`;
- `table inet sing-box` remained in nftables;
- a subsequent explicit `watchdog disconnect` did not clean those kernel
  route/firewall residues because `SingBoxDriver.disconnect()` only cleaned
  its runtime directory when the child process had already exited.

This residue caused the external conversation VPN and direct network path to
fail to recover until the VM was rebooted. The test was stopped at that point;
the failure was treated as a real AUD-P12-006 bug, not retried blindly.

Implementation fix:

- `SingBoxDriver.disconnect()` now records whether the active session expected
  a TUN before resetting in-memory state.
- For TUN sessions, disconnect now performs best-effort cleanup of sing-box
  auto-redirect residue even if the sing-box child has already crashed:
  - `nft delete table inet sing-box`
  - `ip rule del pref 1`
  - `ip rule del pref 9000`
  - `ip rule del pref 9001`
  - `ip rule del pref 9002`
  - `ip rule del pref 32768`
  - `ip route flush table 2022`
  - `ip -6 route flush table 2022`
- The temporary VM validation script's trap was also hardened with emergency
  cleanup for the same sing-box residue, so a failed validation run no longer
  leaves the VM network wedged before the external VPN is restored.

Local validation after the fix:

- `python3 -m unittest tests.test_singbox_driver` - 63 tests passed
- `python3 -m py_compile drivers/singbox_driver.py tests/test_singbox_driver.py`
  - passed
- focused daemon/runtime tests - 142 tests passed
- `bash tests/syntax.sh` - passed
- `bash tests/unit.sh` - passed
- `python3 -m unittest discover -s tests` - 702 tests passed, 1 skipped
- `git diff --check` - passed

Bounded real-traffic revalidation after installing the fix and restarting the
daemon:

- `sudo ./update.sh --yes` completed and preserved `/var/lib/watchdogvpn/`.
- `watchdogvpn.service` was restarted and the daemon smoke test passed.
- The sing-box child crash subtest was repeated once, bounded, in the Arch VM.
- After `SIGKILL` of the sing-box child, the immediate snapshot still showed
  the expected temporary residue while daemon status had moved to standby.
- The follow-up explicit `watchdog disconnect` cleaned the auto-redirect
  `ip rule` entries, `table inet sing-box`, sing-box listeners, and runtime
  state.
- Final verification reported `ASSERTION_OK: clean runtime after final`.
- The external conversation VPN restored successfully afterward, with no VM
  reboot required.

Conclusion: AUD-P12-006 is resolved for bounded Arch VM daemon validation.
Normal disconnect, systemd stop, systemd restart, and sing-box child crash
cleanup now leave no stale routes, nftables state, TUN link, listeners, or
orphan sing-box processes after explicit cleanup.

## 9. What part of the problem may come from treating this as a "normal" app

Most of what was found and fixed this session **is** "normal app" plumbing,
unrelated to the hostile-DPI mission specifically:

- Daemon code drift / stale install (`update.sh` not guaranteeing a
  restart).
- `lib/singbox.sh`'s install-path detection not accounting for the daemon's
  own reachability.
- The DNS hijack port conflict with another local resolver.
- The default-DNS-policy black hole.
- All four fixed sing-box config-generation bugs (`bind_interface`, FakeIP
  misuse, DNS bootstrap loop, DNS hijack rule scope).

These are the kind of bugs any sing-box-based TUN client would need to get
right regardless of threat model - they are not about censorship resistance,
they are about making a TUN-based VPN client function at all. The good news
is all of them are now understood, and four are code-fixed and tested.

## 10. What part of the problem may come from forgetting the hostile-DPI mission

The opposite risk did **not** materialize today. If anything, the session
deliberately built and is now testing the **most aggressive, most
leak-resistant** TUN configuration sing-box supports:
`strict_route`+`auto_redirect`+per-process rules+DNS hijack - specifically
because a resilience product cannot accept a softer routing mode that might
occasionally leak a flow outside the tunnel, the way a "normal" commercial
VPN client might tolerate. Per-process route differentiation itself (the
entire point of App Policy) is a hostile-network-motivated feature that a
"normal" VPN app would not need at all - so the fact that it is proving hard
to get right under a hardened, non-root daemon is new, legitimately
unexplored territory for this project, not a sign of having drifted toward
"normal app" thinking.

The one place this distinction matters most for tomorrow: **the instinct to
make routing "softer" (e.g. drop `auto_redirect`, or `strict_route`) to make
today's incidents go away must be resisted** without first understanding
*why* the aggressive mode is unstable. Weakening the routing model to dodge
today's findings would directly undermine the project's core resilience
promise. The correct response is to diagnose the instability, not to
route around it by making the product leakier.

## 11. Open technical risks

- App Policy's core promise (per-process control) depends on the daemon
  carrying both `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`; the VM
  isolation plus daemon-mediated `curl -> block` and `curl -> direct`
  differential tests proved the core per-process routing behavior. The
  DNS-follow-policy audit then showed that TUN-captured DNS needed explicit
  app-policy-derived DNS rules, and the follow-up fix now prepends those
  rules before domain/channel DNS rules with bounded daemon validation. A
  controlled helper-process validation then proved that a parent-launched
  helper executable can be blocked by exact `process_path` while unrelated
  traffic continues through the VPN. Kill switch no-leak validation then
  proved bounded real daemon traffic stays on the VPN path with the kill
  switch active. Crash cleanup still needs validation before the risk can be
  closed.
- `strict_route`+`auto_redirect` stability under real, sustained, multi-app
  desktop load is unproven and has now caused two severe machine-level
  incidents, the second requiring a hard power cut. The exact failure
  mechanism for Incident 2 is not confirmed.
- Cleanup/crash validation exposed and fixed a real sing-box child-crash
  residue bug. The bounded Arch VM retest now resolves AUD-P12-006 for normal
  disconnect, systemd stop/restart, and sing-box child crash cleanup.

## 12. Open technical debt / uncertainty

- `lib/singbox.sh` needs a daemon-reachability-aware install check (or
  install.sh/update.sh must always place sing-box in a daemon-reachable
  path).
- The daemon needs a mechanism to guarantee "installed code == running
  code" after an update (e.g. `update.sh` always restarts the daemon, or the
  daemon self-checks its own module state against disk on connect and fails
  loudly if stale).
- No pre-flight check/actionable error exists for "the DNS hijack port is
  already occupied by another local resolver".
- No pre-flight check/actionable error exists for "another sing-box-based
  VPN client is already using the same kernel routing table" - currently
  surfaces as an opaque FATAL crash.
- The DNS hijack inbounds' hardcoded `override_address: "1.1.1.1"` design
  (a raw address-override "direct"-type inbound, separate from the new
  sniff+protocol-based hijack rule) may now be partially redundant - worth a
  design review once the process-attribution blocker is resolved, rather
  than carrying two overlapping DNS-hijack mechanisms indefinitely.

## 13. What must NOT be attempted again tomorrow without first validating a hypothesis

- Do **not** re-run a full daemon-mediated `connect()` with
  `mode=rules`+app-policy+TUN active and simply "try again" hoping it works.
  Every blind repeat today cost real machine stability for no new
  information.
- Do **not** assume capability changes beyond the verified
  `CAP_DAC_READ_SEARCH` requirement will fix unrelated routing behavior.
  Future privilege changes must be isolated the same way before they land.
- Do **not** leave `strict_route`+`auto_redirect` active for a long,
  multi-command, unattended live session again. Every future exposure to
  this exact combination must be short, bounded with `timeout`, and
  immediately followed by a forced, verified teardown - never an open-ended
  sequence.
- Do **not** weaken `strict_route`/`auto_redirect` just to make today's
  symptoms disappear without first understanding the real cause (see
  section 10).

## 14. Ordered test plan for tomorrow

**Phase 0 - Safety setup.** `watchdogvpn.service` was stopped and disabled at
the end of this session (Incident 3, section 7) - re-enable it deliberately
(`systemctl enable --now`) when resuming, don't assume it's already running.
Confirm any other sing-box-based VPN client is fully off before touching
sing-box again. Work from a real terminal, not VS Code's integrated one.
Keep `sudo -v` fresh. Every sing-box test invocation must be short, bounded
with `timeout`, and end with a guaranteed kill/teardown - never an
open-ended session. Before resuming any live test, check `ip rule show` and
`sudo nft list tables` for leftover WatchdogVPN state from a *previous*
session, not just confirm the current attempt cleans up after itself - this
is specifically to test the Incident 3 residue hypothesis.

**Phase 1 - Isolate process attribution, without `connect()`.** Build a
minimal, standalone sing-box config with no trojan outbound, no app-policy,
no DNS hijack - just the TUN plus one `process_name` route rule - and run it
two ways: (a) manually as root, (b) under the real `watchdogvpn.service`
unit. While running under the daemon, inspect the sing-box child process's
actual effective capabilities directly (e.g. via `/proc/<pid>/status`
`CapEff`/`CapAmb`, or `getpcaps <pid>`) to confirm whether `CAP_SYS_PTRACE`
is really reaching the process at all. This isolates H1/H2 without touching
app-policy, DNS, or the kill switch.

**Phase 2 - Resolve the process-attribution root cause.** Follow-up VM
testing identified the missing requirement: `CAP_DAC_READ_SEARCH` must be
granted together with `CAP_SYS_PTRACE`. Land the unit-file fix, update the
systemd/doctor contracts, reinstall/restart the daemon, and confirm the
running sing-box child receives both capabilities before re-attempting the
full traffic matrix.

**Phase 3 - Re-attempt the full daemon-mediated traffic matrix once, with
new information.** Only after Phase 1/2 give a clear, understood answer,
repeat the original Task 12.5 matrix (`dig`, `curl` direct, `wget` default,
`apt-get` block) through the real daemon exactly as designed, bounded and
logged. Escalate to repeats only if that single attempt produces new
information. The first daemon-mediated follow-up confirmed `curl -> block`
with a `python3` tunnel control. The second confirmed `curl -> direct` while
the `python3` control continued through the VPN. The DNS policy inheritance
fix and controlled helper-process validation then covered DNS-follow-policy
and package-manager-style helper delegation. Kill switch no-leak validation
then covered AUD-P12-003 for the bounded Arch VM daemon path. Continue with
cleanup/crash validation.

**Phase 4 - Decide on `auto_redirect` before further TUN experiments.**
Independently of Phase 1-3, and before any further live TUN testing,
decide whether `strict_route` alone (without `auto_redirect`) is sufficient
for the resilience guarantee Task 12.3 wants, given two severe incidents
with both flags on. Test the same matrix with `auto_redirect=false` in a
short, bounded, controlled way to compare stability, before committing to
either configuration as the shipped default.

**Phase 5 - Resume the rest of Task 12.5.** Completed in the Arch VM on
2026-07-04. Normal disconnect, systemd stop, systemd restart, and sing-box
child crash cleanup were validated with bounded daemon tests. The child-crash
case exposed a real auto-redirect residue bug, which was fixed and retested.
Kill switch no-leak validation is resolved for the bounded Arch VM daemon path.

---

*This report documents an in-progress task. Task 12.5 is not closed. The
Phase 1 VM follow-up identified `CAP_DAC_READ_SEARCH` plus `CAP_SYS_PTRACE`
as the minimal daemon capability set needed for cross-user process
attribution, and daemon-mediated `curl -> block` / `curl -> direct`
differential tests confirmed the two core real app-policy routing cases.
The DNS-follow-policy audit confirmed generated DNS channel routing and
smoke DNS connectivity, then the app-policy DNS inheritance fix added and
validated process-matched DNS rules before domain/channel DNS rules. AUD-P12-002
is resolved for generated-config implementation and bounded daemon validation.
A controlled parent/child helper-process validation then confirmed that a
delegated helper executable is blocked when the rule targets the helper's exact
`process_path`, while unrelated `python3` traffic continues through the VPN.
Kill switch no-leak validation then confirmed that normal traffic and a
physical-interface-forced probe both exposed the VPN exit while the kill switch
was active, and direct TCP DNS was blocked. Cleanup/crash validation then
confirmed clean teardown for normal disconnect, systemd stop, systemd restart,
and sing-box child crash after fixing auto-redirect residue cleanup.*
