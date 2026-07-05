# WatchdogVPN QA Audit - Phase 12, Task 12.6 Split Tunneling Closure

> Date: 2026-07-05
> Task: PHASE 12 - Linux Split Tunneling & App Policy, Task 12.6 - Split tunneling audit closure
> Status: OPEN. The audit found no HIGH findings, but Task 12.6 cannot close while the MEDIUM findings below remain open.

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

## 2. Acceptance Matrix

| Criterion | Audit result | Evidence |
| --- | --- | --- |
| App policy has strict persistent schema validation | PASS | `app_policy/models.py` rejects unknown fields, non-strict booleans/integers, unsupported schema versions, unsupported actions, empty matchers, and invalid rule shape. `core/watchdog.py` turns invalid runtime policy into enabled whitelist/default-block fail-closed behavior. |
| Whitelist and blacklist modes are implemented | PASS | `AppPolicyMode` supports both modes; `rules/singbox.py` emits app-policy rules and a catch-all default in whitelist mode or when blacklist `default_action` is not `current`. |
| `process_name` and `process_path` rules route real traffic as documented | PASS with caveat | Task 12.5 validated real traffic for `process_name` (`curl` direct/block) and exact `process_path` (`python3.14`, Firefox) under the daemon after systemd process-attribution permissions were fixed. The documented caveat remains: helper processes must be matched by the helper executable path, not only the parent command name. |
| Direct/VPN/block actions are validated with real traffic | PASS | Task 12.5 validated `direct`, `current`/VPN, and `block` actions with daemon-managed real traffic. |
| DNS behavior follows the selected route policy without LAN resolver leaks | PASS | AUD-P12-002 was resolved and validated in Task 12.5. App-policy DNS rules are prepended in `drivers/singbox_driver.py`; direct DNS routes to the direct resolver or rejects when no safe direct resolver exists; blocked app DNS is rejected; current/VPN DNS follows proxy/final policy. |
| Kill switch remains fail-closed under app policy | PASS | AUD-P12-003 was resolved and validated in Task 12.5. `core/kill_switch.py` uses `wdvpn-tun0`, blocks DNS leak ports before LAN/established accepts, allows sing-box auto-redirect marks, and allows the internal TUN DNS endpoint. |
| Minimal CLI commands expose enough control for validation | FAIL | MEDIUM finding AUD-P12-008. The CLI can enable/disable policy, set mode, and add/remove rules, but cannot set `default_action`. The final default-direct/app-VPN matrix required direct JSON mutation in the temporary VM script. |
| No TUI work is added in this phase | PASS | Task 12 stayed in model/runtime/CLI/docs/tests; no TUI work was added. |
| Phase-specific QA audit has no unresolved HIGH or MEDIUM findings | FAIL | MEDIUM findings AUD-P12-008 and AUD-P12-009 remain open. |

## 3. Findings

### AUD-P12-008 - CLI cannot set app-policy `default_action`

- Layer: 5 - CLI/Operator control
- Severity: MEDIUM
- Status: OPEN
- Description: The persistent app-policy model supports `default_action =
  current | direct | block`, and the runtime correctly uses it. The CLI exposes
  `app-policy status`, `enable`, `disable`, `mode`, `add`, and `remove`, but
  there is no command to set `default_action`.
- Scenario: The required Task 12.5 matrix case "default direct + app-specific
  VPN" needed app-policy enabled in blacklist mode with `default_action:
  direct` and exact `process_path` rules set to `current`. Because the CLI lacks
  a default-action setter, the temporary VM validation script had to back up and
  write `/var/lib/watchdogvpn/app-policy.json` directly.
- Impact: Normal operators cannot configure one of the validated split-tunnel
  modes through supported CLI commands. This does not indicate a routing leak,
  but it violates the Task 12.6 acceptance criterion that minimal CLI commands
  expose enough control for validation, and it encourages unsafe hand-editing of
  daemon state.
- Evidence:
  - `cli/main.py` app-policy subcommands are limited to status/enable/disable/
    mode/add/remove.
  - `app_policy/models.py` includes and validates `default_action`.
  - Task 12.5 final VM evidence used `default action: direct` for the passing
    default-direct/app-VPN test.
- Recommendation: Add a minimal `watchdog app-policy default-action
  {current,direct,block}` command with JSON output support, persistence through
  `AppPolicyStore`, and tests covering valid values and invalid choices.

### AUD-P12-009 - TUN connect success can be reported before the child is stable

- Layer: 2 - Daemon/runtime health
- Severity: MEDIUM
- Status: OPEN
- Description: `SingBoxDriver.connect()` returns success once the local proxy
  port responds and, for TUN mode, `wdvpn-tun0` is briefly active. In the VM
  retry sequence before the kernel/module state was repaired, `watchdog connect`
  printed `Connected`, then the daemon status immediately reconciled to
  `standby` after sing-box failed during `auto_redirect`/nftables setup.
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
- Recommendation: Add a bounded post-connect stability check for TUN mode before
  returning success. At minimum, re-check that the child process is still alive
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

## 4. Resolved Prior Audit Items

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

## 5. Task 12.6 Closure Status

Task 12.6 is not closed.

No HIGH findings are open. Two MEDIUM findings must be handled as Task 12.6
subtasks before Phase 12 can close:

1. AUD-P12-008: add CLI support for app-policy `default_action`.
2. AUD-P12-009: make TUN connect success wait for bounded child stability.

After those are fixed and regression-tested, rerun a focused audit update and
mark the Task 12.6 acceptance matrix closed.
