# WatchdogVPN QA Audit - Phase 12, Task 12.6 Split Tunneling Closure

> Date: 2026-07-05
> Task: PHASE 12 - Linux Split Tunneling & App Policy, Task 12.6 - Split tunneling audit closure
> Status: OPEN. The audit found no HIGH findings. AUD-P12-008 is resolved; Task 12.6 cannot close while AUD-P12-009 remains open.

---

## 1. Scope

Task 12.6 runs the QA audit protocol over the completed Phase 12 split
tunneling work, focused on routing, daemon runtime, DNS, kill-switch behavior,
and minimal CLI control. Per the Phase 12 plan, any HIGH or MEDIUM audit
finding becomes a Task 12.6 subtask before the phase can close.

This audit is documentation/detection only. It does not change product code.

Primary evidence sources:

- Phase 12 design audit: `docs/phase-12-task-12-1-split-tunneling-design-audit.md`
- Real traffic report: `docs/qa-audit-2026-07-04-phase-12-task-12-5-real-traffic.md`
- App-policy model/store/CLI/runtime code
- sing-box route/DNS/TUN driver code
- kill-switch implementation and tests
- Unit/regression tests already present in the repository

## 2. Coverage Checklist

This section records the audit coverage explicitly so "no finding" is
distinguishable from "not reviewed".

| Surface | Reviewed criteria | Result |
| --- | --- | --- |
| Split tunneling / app policy | Persistent schema, supported actions, whitelist/blacklist default semantics, app-policy rule ordering, real `process_name`/`process_path` behavior, helper-process caveat, CLI operability. | Reviewed. AUD-P12-008 was found and then resolved by adding CLI support for `default_action` plus regression coverage for the default-direct/app-current matrix. |
| Daemon / driver readiness | Daemon passes app-policy/DNS state into sing-box, invalid policy fails closed, child crash/status/startup cleanup from Task 12.5, TUN connect readiness semantics. | Reviewed. MEDIUM AUD-P12-009 found because TUN readiness can report success before the child proves stable after auto-redirect/nftables setup. |
| Routing / TUN cleanup | `strict_route`/`auto_redirect`, direct outbound physical-interface bind, route rule order, explicit route actions, crash cleanup/reconciliation, residual route-table discovery. | Reviewed. LOW AUD-P12-010 carried for hardcoded fallback route-table discovery. No HIGH/MEDIUM routing leak found; Task 12.5 real traffic and cleanup/crash tests covered the dangerous paths. |
| DNS | App-policy-derived DNS rules for `direct`, `current`, and `block`; DNS hijack route order; FakeIP safety for outbound self-resolution; LAN resolver leak behavior under app policy and kill switch. | Reviewed. No new finding. AUD-P12-002 was resolved by generated-config changes and real daemon validation, and Task 12.5 verified DNS-follow-policy/no LAN resolver leak behavior. |
| Kill switch | TUN interface alignment, default-drop behavior, DNS leak block order, loopback/internal TUN DNS allowances, sing-box auto-redirect mark allowances, forced-physical-interface no-leak validation. | Reviewed. No new finding. AUD-P12-003 was resolved and validated in the bounded Arch VM path; unit tests cover nftables/iptables rule ordering and failure rollback. |

## 3. Acceptance Matrix

| Criterion | Audit result | Evidence |
| --- | --- | --- |
| App policy has strict persistent schema validation | PASS | `app_policy/models.py` rejects unknown fields, non-strict booleans/integers, unsupported schema versions, unsupported actions, empty matchers, and invalid rule shape. `core/watchdog.py` turns invalid runtime policy into enabled whitelist/default-block fail-closed behavior. |
| Whitelist and blacklist modes are implemented | PASS | `AppPolicyMode` supports both modes; `rules/singbox.py` emits app-policy rules and a catch-all default in whitelist mode or when blacklist `default_action` is not `current`. |
| `process_name` and `process_path` rules route real traffic as documented | PASS with caveat | Task 12.5 validated real traffic for `process_name` (`curl` direct/block) and exact `process_path` (`python3.14`, Firefox) under the daemon after systemd process-attribution permissions were fixed. The documented caveat remains: helper processes must be matched by the helper executable path, not only the parent command name. |
| Direct/VPN/block actions are validated with real traffic | PASS | Task 12.5 validated `direct`, `current`/VPN, and `block` actions with daemon-managed real traffic. |
| DNS behavior follows the selected route policy without LAN resolver leaks | PASS | AUD-P12-002 was resolved and validated in Task 12.5. App-policy DNS rules are prepended in `drivers/singbox_driver.py`; direct DNS routes to the direct resolver or rejects when no safe direct resolver exists; blocked app DNS is rejected; current/VPN DNS follows proxy/final policy. |
| Kill switch remains fail-closed under app policy | PASS | AUD-P12-003 was resolved and validated in Task 12.5. `core/kill_switch.py` uses `wdvpn-tun0`, blocks DNS leak ports before LAN/established accepts, allows sing-box auto-redirect marks, and allows the internal TUN DNS endpoint. |
| Minimal CLI commands expose enough control for validation | PASS | AUD-P12-008 is resolved. The CLI can enable/disable policy, set mode, set `default_action`, and add/remove rules; regression tests cover configuring the default-direct/app-current matrix through CLI commands instead of direct JSON mutation. |
| No TUI work is added in this phase | PASS | Task 12 stayed in model/runtime/CLI/docs/tests; no TUI work was added. |
| Phase-specific QA audit has no unresolved HIGH or MEDIUM findings | FAIL | MEDIUM finding AUD-P12-009 remains open. |

## 4. Findings

### AUD-P12-008 - CLI could not set app-policy `default_action`

- Layer: 5 - CLI/Operator control
- Severity: MEDIUM
- Status: RESOLVED on 2026-07-05
- Description: The persistent app-policy model supports `default_action =
  current | direct | block`, and the runtime correctly uses it. The CLI exposes
  `app-policy status`, `enable`, `disable`, `mode`, `default-action`, `add`,
  and `remove`.
- Scenario: The required Task 12.5 matrix case "default direct + app-specific
  VPN" needed app-policy enabled in blacklist mode with `default_action:
  direct` and exact `process_path` rules set to `current`. Before this fix, the
  CLI lacked a default-action setter, so the temporary VM validation script had
  to back up and write `/var/lib/watchdogvpn/app-policy.json` directly.
- Impact before the fix: Normal operators could not configure one of the
  validated split-tunnel modes through supported CLI commands. This did not
  indicate a routing leak, but it violated the Task 12.6 acceptance criterion
  that minimal CLI commands expose enough control for validation, and it
  encouraged unsafe hand-editing of daemon state.
- Evidence before the fix:
  - `cli/main.py` app-policy subcommands were limited to status/enable/disable/
    mode/add/remove.
  - `app_policy/models.py` includes and validates `default_action`.
  - Task 12.5 final VM evidence used `default action: direct` for the passing
    default-direct/app-VPN test.
- Resolution:
  - Added `watchdog app-policy default-action {current,direct,block}` with JSON
    output support and persistence through `AppPolicyStore`.
  - Added CLI tests for persistence, invalid value rejection, and configuring
    the default-direct/app-current matrix without direct JSON mutation.
  - Added sing-box generation coverage proving that the resulting policy emits
    the app-current process rule before a direct catch-all.

### AUD-P12-009 - TUN connect success can be reported before the child is stable

- Layer: 2 - Daemon/runtime health
- Severity: MEDIUM
- Status: OPEN
- Description: `SingBoxDriver.connect()` returns success once the local proxy
  port responds and, for TUN mode, `wdvpn-tun0` is briefly active. In the VM
  retry sequence before the kernel/module state was repaired, `watchdog connect`
  printed `Connected`, then the daemon status immediately reconciled to
  `standby` after sing-box failed during `auto_redirect`/nftables setup.
  This is a recurrence of the earlier Layer 2 readiness pattern where
  `connect()` could report success from partial liveness before the service was
  actually usable; the proxy-mode surface was tightened earlier, but the TUN
  surface still has a later readiness boundary.
- Scenario: A system can momentarily create the proxy/TUN surfaces and then
  fail during post-start TUN/auto-redirect setup. The current health check is
  short and structural; it does not add a bounded settle/recheck window or read
  early fatal process exit/log output before reporting success.
- Impact: This is not a confirmed leak: the observed state reconciled to
  standby and cleanup succeeded. It is still a real operator-facing correctness
  issue because `watchdog connect` can report success for a connection that
  fails seconds later, making VM/TUN diagnostics more confusing and making
  automation trust a transient success.
- Evidence:
  - `drivers/singbox_driver.py` TUN health returns `"ok"` as soon as proxy ports
    are responsive and `wdvpn-tun0` is active.
  - Task 12.5 VM retry logs showed `Connected` followed by `Status: standby`
    with sing-box `FATAL ... auto-redirect: setup nftables` before the Arch VM
    kernel/module state was repaired.
- Recommendation: Move the TUN readiness boundary to the correct lifecycle
  point: after sing-box has survived the post-start auto-redirect/nftables setup,
  not merely after local bind/TUN surface creation. At minimum, add a bounded
  post-connect stability check, re-check that the child process is still alive
  after a short settle interval, inspect early fatal log output when it exits,
  and return a failed connect instead of a transient success. Keep the timeout
  bounded so real connects remain fast.

### AUD-P12-010 - TUN residue table discovery is tied to the current address literal

- Layer: 2 - Cleanup/reconciliation
- Severity: LOW
- Status: DEFERRED LOW DEBT
- Description: The fallback TUN residue discovery path identifies WatchdogVPN
  route tables by checking route-table output for `wdvpn-tun0` or the literal
  address prefix `172.19.0.`.
- Scenario: If the TUN address range changes later, fallback cleanup could miss
  some route tables unless the table also references `wdvpn-tun0`.
- Impact: Bounded cleanup hardening debt. Task 12.5 real cleanup/crash
  validation passed, so this does not block Task 12.6 closure by itself.
- Evidence: `_route_table_looks_like_watchdogvpn()` in `drivers/singbox_driver.py`.
- Recommendation: Derive the TUN address prefix from the generated TUN config,
  persist it in runtime cleanup metadata, or avoid address-literal matching in a
  future cleanup hardening pass.

## 5. Resolved Prior Audit Items

The Task 12.6 audit confirms that the original Phase 12 audit items are either
resolved or no longer blocking:

- AUD-P12-001: resolved by first-class strict app-policy model/store and
  fail-closed runtime handling.
- AUD-P12-002: resolved by app-policy-derived DNS rules and real traffic
  validation.
- AUD-P12-003: resolved by kill-switch/TUN alignment and bounded no-leak
  validation.
- AUD-P12-004: resolved by the `strict_route`/`auto_redirect` implementation
  decision plus real VM validation after kernel module prerequisites were fixed.
- AUD-P12-005: resolved for Phase 12 by rejecting unavailable `auto` and
  `group:<id>` app-policy actions.
- AUD-P12-006: resolved by disconnect, systemd stop/restart, crash, status
  reconciliation, and startup reconciliation validation.
- AUD-P12-007: resolved by explicit sing-box route rule syntax.

## 6. Task 12.6 Closure Status

Task 12.6 is not closed.

No HIGH findings are open. AUD-P12-008 is resolved. One MEDIUM finding must be
handled before Phase 12 can close:

1. AUD-P12-009: make TUN connect success wait for bounded child stability.

After AUD-P12-009 is fixed and regression-tested, rerun a focused audit update
and mark the Task 12.6 acceptance matrix closed.
