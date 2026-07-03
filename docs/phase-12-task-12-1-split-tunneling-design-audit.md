# Phase 12 Task 12.1 - Linux Split Tunneling Design Audit

Date: 2026-07-03
Scope: audit/design only. No product code changed.

## Objective

Task 12.1 audits whether the current WatchdogVPN v2 routing foundation can be
extended into Linux app/process policy without making false safety claims.

The answer is: the foundation is useful, but not yet sufficient. The current
system can generate native sing-box rules for `process_name` and
`process_path`, and the daemon path now loads persisted rule groups in `rules`
mode. A production app-policy feature still needs a stricter policy model,
clear DNS semantics, real TUN validation, kill-switch alignment, and explicit
documentation of Linux process-matching limits.

## Current Architecture

### Rule model

`rules/models.py` defines the current routing rule schema:

- Conditions: domain, domain suffix/keyword/regex, IP CIDR, port, port range,
  protocol, network, remote/built-in rulesets, `process_name`, `process_path`.
- Actions: `direct`, `current_profile`, `auto_select`, `group:<id>`, `block`.
- Default groups: `recommended`, `direct`, `proxy`, `block`, `custom`, `app`,
  `imported`.
- Validation is strict: unknown condition keys and empty condition values are
  rejected.

The current model does not support `user`, `user_id`, `process_path_regex`,
`invert`, cgroup markers, source IP/port, source interface, or dedicated app
policy mode/default fields.

### RuleStore

`rules/rule_store.py` stores one JSON file per rule group under the resolved
WatchdogVPN config directory, usually `rules/`. It uses the shared persistence
helpers and validates group names as safe slugs.

This is a solid base for rule groups, but app policy should not be modeled only
as ad hoc edits to the existing `app` group. Split tunneling needs explicit
policy state:

- enabled/disabled state;
- whitelist or blacklist mode;
- default action;
- per-rule action and match type;
- schema version;
- controlled disabled/standby behavior when invalid.

### Local rule engine

`rules/rule_engine.py` implements a local evaluator for diagnostics and tests.
Its priority order is:

`block -> custom -> app -> imported -> recommended -> final_policy`

This matches the intended routing priority. It is not the live traffic
enforcement path; sing-box is the production enforcement path.

Important limits:

- `ruleset_remote` and `ruleset_builtin` are marked unevaluable locally.
- `domain_regex` uses Python `re`, while sing-box uses its own matching engine.
- Process matching is literal for `process_name` and `process_path`.

### sing-box route generation

`rules/singbox.py` translates enabled rule groups into sing-box `route.rules`.
`block` becomes native `action: reject`; `direct` targets the `direct` outbound;
`current_profile`, `auto_select`, and `group:<id>` currently target the single
active outbound.

This means app policy can support real `direct`, current-profile VPN, and block
actions now. It cannot honestly claim true node-group or auto-selection routing
per app until WatchdogVPN has multiple simultaneous outbounds/selectors.

`drivers/singbox_driver.py` merges DNS hijack rules before mode route rules so
the unconditional final route does not shadow DNS hijack. That ordering must be
preserved.

### Daemon runtime

`core/watchdog.py` now threads the stored DNS policy and active mode into
driver connections. In `rules` mode it also loads persisted RuleStore groups
and forwards them into the driver path. This applies to manual connect,
startup autoconnect, reconnect, and rotation via the runtime router.

`daemon/runtime_worker.py` serializes connect/disconnect/status/rotate commands
on one worker thread. The daemon is the correct place to own the app-policy
runtime path; app policy must not add a second privileged control plane.

### systemd and capabilities

`systemd/watchdogvpn.service` runs as the dedicated `watchdogvpn` user with:

- `CAP_NET_ADMIN`
- `CAP_NET_BIND_SERVICE`
- `CAP_NET_RAW`
- `/dev/net/tun` access
- strict filesystem and namespace hardening

Those capabilities are appropriate for TUN, route manipulation, DNS hijack on
port 53, and firewall interaction. Task 12 must preserve the daemon privilege
boundary instead of granting capabilities to CLI commands or broad wrappers.

### TUN settings

The current sing-box TUN inbound is:

- tag: `watchdogvpn-tun-in`
- interface: `wdvpn-tun0`
- address: `172.19.0.1/30`
- `auto_route: true`
- stack: `system`

It does not currently set `strict_route`, `auto_redirect`, explicit route
addresses/exclusions, or a route-level `auto_detect_interface`. WatchdogVPN
does bind outbound connections to the detected physical default interface by
setting outbound `bind_interface`, which helps avoid loops, but TUN leak
behavior still needs real validation.

### Kill switch

`core/kill_switch.py` supports nftables first and iptables fallback. It allows
loopback and the configured tunnel interface, rejects DNS ports 53/853 before
established/LAN accepts, optionally allows LAN, and can block IPv6.

Critical audit point: the default app config still names the kill-switch
tunnel interface `tun0`, while sing-box TUN uses `wdvpn-tun0`. Unless the real
installed config is updated before kill-switch enforcement, fail-closed behavior
can reject or allow the wrong interface. Task 12 must align this before claiming
kill-switch-safe split tunneling.

### DNS v2 interaction

DNS v2 can generate sing-box DNS servers/channels, direct/proxy domain
resolvers, FakeIP, static hosts, DNS diversion rules, and local DNS hijack.
System DNS snapshots can be restored on manual disconnect.

However, DNS policy is currently domain/channel-oriented, not app-policy
oriented. A process route rule such as `firefox -> direct` does not by itself
prove that Firefox DNS queries were resolved via the direct DNS channel. If the
browser uses system DNS, DoH, its own cache, or a helper process, DNS may not
follow the route action the user thinks they configured.

For a high-risk resilience tool, app policy must state exactly what is enforced:

- traffic route action;
- DNS query path;
- what happens to encrypted in-app DNS;
- what happens to helper processes and children.

## sing-box Process Matching on Linux

Official sing-box documentation for route rules lists these Linux-relevant
match fields:

- `process_name`
- `process_path`
- `process_path_regex` since sing-box 1.10.0
- `user`
- `user_id`

Documentation references:

- https://sing-box.sagernet.org/configuration/route/rule/
- https://sing-box.sagernet.org/configuration/dns/rule/
- https://sing-box.sagernet.org/configuration/route/
- https://sing-box.sagernet.org/configuration/inbound/tun/

The local binary is `sing-box 1.13.14`. A real `sing-box check` on this machine
accepted route rules containing `process_name`, `process_path_regex`, `user`,
and `user_id`.

Design implication: WatchdogVPN should extend the app-policy schema to support
`process_path_regex`, `user`, and `user_id` in addition to the existing
`process_name` and `process_path`. The UI/CLI should label `process_name` as a
convenience matcher, not a high-assurance identity boundary.

`route.find_process` is not required when process/user rules exist; according
to sing-box docs it enables process lookup for logging when no process, path,
package, user, or user-id rules are present.

## Linux App Policy Limits

These limits must be documented in user-facing text before release:

- Browsers are multi-process. Matching only `firefox` or `chromium` may miss
  crash handlers, sandboxes, WebExtensions, helper binaries, updater helpers,
  external protocol handlers, and browser-launched child processes.
- Browser DNS can bypass expectations through built-in DoH, DNS cache, or
  profile settings. Route policy is not automatically DNS policy.
- Terminal rules are fragile. Matching `gnome-terminal`, `konsole`, `zsh`, or
  `bash` does not necessarily identify the network client. For validation use
  the actual tool process, for example `/usr/bin/curl`, not the terminal
  emulator.
- Package managers spawn helpers and transport methods. For example, a safe
  package-manager-style validation should use controlled download/check
  commands before touching real system upgrades.
- Flatpak, Snap, AppImage and sandboxed apps can use wrapper paths, mounted
  runtime paths, portals, helper daemons, or confined network behavior. Prefer
  exact path plus user/user_id where possible, and test each packaging format
  before documenting support.
- Process names are spoofable by untrusted local code. They are usability
  selectors, not a security identity boundary.
- `process_path` is stronger than `process_name`, but still depends on how the
  process is launched and what executable path sing-box observes.
- `process_path_regex` is useful for packaged apps with versioned paths, but
  broad regexes can accidentally match unrelated binaries.
- `user`/`user_id` can be useful for a stronger compartment model when the user
  runs selected apps under a dedicated Linux user. That is more defensible than
  name-only rules, but it is a workflow requirement, not a transparent app
  picker.
- nftables/cgroup marking may become necessary for high-assurance policy, but
  it should be introduced only if real validation shows sing-box process/user
  matching is insufficient for WatchdogVPN's supported workflows.

## Findings and Risks

Every finding below has an assigned Phase 12 owner task. A future session must
not close the owner task unless its assigned finding is either fixed and
validated, or explicitly reclassified in the master plan with a new owner task.

### AUD-P12-001 - App policy schema does not exist yet

Severity: HIGH

The current `app` rule group is not a complete app-policy model. It cannot
store enabled state, whitelist/blacklist mode, default action, schema version,
or Linux identity strategy.

Recommendation: Task 12.2 should add a separate `AppPolicyStore` or equivalent
first-class model, then generate/merge route rules from that model without
bypassing RuleStore priority semantics.

### AUD-P12-002 - DNS policy can diverge from process route policy

Severity: HIGH

Process route actions do not automatically prove DNS follows the same action.
DNS v2 has route-aware building blocks, but no app-policy DNS contract yet.

Recommendation: Task 12.3 should define DNS semantics per action. The safe
default for VPN-routed apps should be proxy/FakeIP or hijacked DNS. Direct apps
must use direct DNS only when that is explicitly accepted. Blocked apps should
not be able to resolve through WatchdogVPN-managed DNS.

### AUD-P12-003 - Kill-switch tunnel interface mismatch risk

Severity: HIGH

The default kill-switch config uses `tun0`; sing-box TUN uses `wdvpn-tun0`.
If kill switch is active with the wrong interface, fail-closed behavior may be
incorrect.

Recommendation: align the configured kill-switch tunnel interface with the
active driver/interface before enabling app policy with kill switch, then
validate nftables and iptables paths on the real machine.

### AUD-P12-004 - TUN route hardening is incomplete for hostile networks

Severity: HIGH

Current TUN uses `auto_route: true` but not `strict_route` or
`auto_redirect`. Official sing-box docs recommend `auto_redirect` on Linux and
describe `strict_route` effects for unsupported networks and bound-interface
traffic.

Recommendation: Task 12.3 or 12.5 should compare current TUN config against
`strict_route`/`auto_redirect` behavior on this machine before exposing app
policy as leak-safe.

### AUD-P12-005 - `auto_select` and `group:<id>` are not real per-app selectors

Severity: MEDIUM

The current generator maps `auto_select` and `group:<id>` to the single active
outbound. That is acceptable historical deferral, but app policy must not show
these as real per-app node selection until multi-outbound selector generation
exists.

Recommendation: Task 12.2 should either reject these actions in app policy for
now or label them as aliases to current profile until Phase 14 provides real
node-group/auto-selection behavior.

### AUD-P12-006 - Daemon stop does not explicitly disconnect runtime

Severity: MEDIUM

Daemon shutdown stops the IPC server and worker, but does not explicitly call
`runtime.disconnect()`. systemd may kill child processes in the cgroup, but
that is not equivalent to restoring DNS snapshots, firewall state, or
WatchdogVPN runtime files.

Recommendation: Task 12.5 should include systemd stop/restart validation. If
DNS/routes/processes are not restored cleanly, add a Phase 12 subtask before
closure.

### AUD-P12-007 - Route rule syntax uses legacy outbound shorthand

Severity: LOW

The current generated route rules use `outbound` without explicit
`action: route`. sing-box 1.13.14 accepts it, but official docs mark the
shorthand as deprecated since 1.11.0.

Recommendation: schedule a compatibility cleanup to emit explicit
`action: route` for forward-looking configs. This is not required before
starting Task 12.2, but should be considered before release.

## Finding Ownership Matrix

| Finding | Severity | Owner task | Closure requirement |
|---|---:|---|---|
| AUD-P12-001 app-policy schema missing | HIGH | Task 12.2 | Add a first-class app-policy model/store with strict schema validation and fail-closed invalid-policy behavior. |
| AUD-P12-002 DNS can diverge from process route policy | HIGH | Task 12.3 and Task 12.5 | Define per-action DNS semantics in runtime wiring, then prove them with real traffic validation. |
| AUD-P12-003 kill-switch interface mismatch | HIGH | Task 12.3 and Task 12.5 | Align kill-switch tunnel interface handling with the active sing-box TUN interface and validate fail-closed behavior. |
| AUD-P12-004 TUN route hardening incomplete | HIGH | Task 12.3 and Task 12.5 | Decide and implement/decline `strict_route` and `auto_redirect` with real-machine evidence. |
| AUD-P12-005 `auto_select` and `group:<id>` are not real per-app selectors | MEDIUM | Task 12.2 | Reject, hide, or explicitly alias these actions until Phase 14 multi-outbound selectors exist. |
| AUD-P12-006 daemon stop does not explicitly disconnect runtime | MEDIUM | Task 12.5 | Validate `watchdog disconnect`, daemon stop/restart, and sing-box crash cleanup; create a Phase 12 fix subtask if cleanup is not clean. |
| AUD-P12-007 route rule shorthand is deprecated | LOW | Task 12.3 or Task 12.6 | Either migrate generated route rules to explicit `action: route` or record a low-risk compatibility decision before Phase 12 closes. |

## Task 12.2 Resolution Notes

Task 12.2 resolved the model-owned findings:

- AUD-P12-001: added a first-class app-policy model and store in
  `app_policy/`, with schema versioning, strict validation, atomic JSON
  persistence, environment path override, and `load_or_disabled()` for
  fail-closed runtime callers.
- AUD-P12-005: app-policy v1 rejects `auto` and `group:<id>` actions. Only
  `current`, `direct`, and `block` are accepted until Phase 14 provides real
  multi-outbound selectors.
- A related persistence bug pattern was fixed while validating Task 12.2:
  explicit path overrides now bypass shared-state discovery before touching
  `/var/lib/watchdogvpn`.

Task 12.2 deliberately did not wire runtime, DNS, kill switch, TUN hardening, or
daemon cleanup. Those remain owned by Task 12.3 and Task 12.5 in the matrix
above.

## Recommended Design

1. Keep sing-box as the first implementation mechanism.
2. Require TUN mode for system-wide app/process policy validation. Proxy mode
   can support explicit proxy workflows, but should not be marketed as
   transparent split tunneling.
3. Extend app policy matching to include:
   - `process_name`
   - `process_path`
   - `process_path_regex`
   - `user`
   - `user_id`
4. Treat `process_path` and `user_id` as preferred high-confidence matchers.
   Treat `process_name` as convenience-only.
5. Keep block rules highest priority.
6. Merge generated app-policy rules at the existing `app` tier unless a later
   design requires a separate higher-priority tier.
7. Keep `direct`, `current_profile`, and `block` as real actions for Phase 12.
   Keep `auto` and `group` either disabled or transparently mapped to current
   profile until multi-outbound selector support exists.
8. Define a DNS contract for every app-policy action before runtime wiring:
   - VPN/current: DNS through proxy/FakeIP/hijack.
   - Direct: DNS through direct channel only when direct DNS is allowed.
   - Block: DNS and traffic rejected.
   - Auto/group: same as current profile until real selector support exists.
9. Align kill-switch interface selection with the active tunnel driver.
10. Keep cgroup/nftables marking as a later escalation path only if real tests
    prove sing-box process/user matching cannot satisfy the supported workflows.

## Real Validation Plan

Task 12.5 should not rely on generated JSON alone. Use a real daemon-managed
connection, a known profile, and observable public endpoints.

Baseline capture before each scenario:

- `ip route`
- `ip rule`
- `ip link show wdvpn-tun0`
- `nft list ruleset` or iptables equivalents
- `resolvectl status` or active resolver manager state
- `ss -plnut`
- `pgrep -af sing-box`

Required scenarios:

1. App forced through VPN:
   - Rule: exact `/usr/bin/curl` or a dedicated test wrapper path ->
     current-profile/VPN.
   - Validate: `curl` public IP equals VPN egress, route observed through
     sing-box/TUN, DNS query reaches proxy/FakeIP path.

2. App forced direct:
   - Rule: a different exact process path or dedicated Linux test user ->
     direct.
   - Validate: public IP equals ISP/direct egress, not VPN egress; DNS uses
     direct channel only if policy allows direct DNS.

3. App blocked:
   - Rule: controlled process path -> block.
   - Validate: TCP, UDP DNS, and HTTP(S) fail. Failure must not silently fall
     through to final policy.

4. Browser:
   - Test at least one browser with exact observed process names/paths.
   - Disable or explicitly account for in-browser DoH during validation.
   - Document which child/helper processes were observed.

5. Terminal/curl:
   - Match the actual network client process, not the terminal emulator.
   - Validate with both process name and process path.

6. Package-manager-style traffic:
   - Use a safe metadata/download command, not a system-changing upgrade.
   - Identify the actual transport process and helper chain.

7. Kill switch:
   - Enable kill switch with app policy active.
   - Interrupt the VPN route and confirm non-tunnel leaks do not occur.
   - Confirm direct-policy exceptions are either intentionally disabled under
     kill switch or documented as incompatible with fail-closed mode.

8. Disconnect/reset cleanup:
   - `watchdog disconnect`
   - `systemctl stop watchdogvpn`
   - daemon restart while connected
   - crash/kill sing-box while connected
   - Confirm no stale TUN interface, route/rule residue, DNS snapshot, port 53
     listener, or orphan sing-box process remains.

## Subtasks Created By This Audit

These should be folded into Phase 12 tasks, not treated as separate phases:

- Add first-class app-policy schema/store with strict validation.
- Add `process_path_regex`, `user`, and `user_id` support if supported by the
  installed sing-box version.
- Define app-policy DNS semantics before runtime wiring.
- Align kill-switch interface handling with sing-box TUN interface.
- Decide whether Phase 12 app policy permits `auto`/`group` actions before
  Phase 14 multi-outbound selectors.
- Validate `strict_route` and `auto_redirect` on Linux before claiming hostile
  network leak safety.
- Add daemon stop/restart cleanup validation to the real traffic matrix.

## Task 12.1 Decision

Proceed to Task 12.2 only as a model/persistence task. Do not expose app policy
as a user-facing security feature until Task 12.5 proves route action, DNS
behavior, kill switch behavior, and cleanup on the real daemon path.
