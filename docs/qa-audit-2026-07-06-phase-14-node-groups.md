# WatchdogVPN QA Audit - Phase 14 Node Groups & Auto-Selection Policy

> Date: 2026-07-06
> Task: PHASE 14 - Node Groups & Auto-Selection Policy, Task 14.9 - Node group audit closure
> Status: COMPLETE. Local audit and VM validation are complete. No unresolved HIGH or MEDIUM findings remain.

## 1. Scope

This audit covers Phase 14 Tasks 14.1 through 14.8:

- autonomous watchdog loop
- scheduled proactive rotation
- persistent node-group model/store/resolver
- auto-selection scoring
- health status and latency persistence
- runtime group integration
- configurable health/latency probe settings
- minimal CLI validation commands

The audit covers code correctness, fail-closed behavior, misleading operator
output, stale health/latency handling, daemon serialization, and the VM/live
paths that require installed systemd service behavior, real TUN/network
mutation, real nodes, and real latency measurements.

## 2. Coverage Checklist

| Surface | Reviewed criteria | Result |
| --- | --- | --- |
| Autonomous watchdog loop | Timer reads bounded config, enqueues only onto `RuntimeWorker`, tolerates corrupt config and stopped worker, starts/stops with daemon. | PASS. VM confirmed loop persistence under the installed service after restart with a 5-second interval. |
| Scheduled rotation loop | Separate timer, disabled-by-default polling, independent gate, serialized worker execution, empty-pool no-op before kill-switch path. | PASS. Local behavior reviewed; VM confirmed `rotation.scheduled_interval_hours off` remained disabled during validation. Scheduled firing was not forced because it was outside the conservative live-test window. |
| Node group model/store | Strict schema, name identity, selection-mode invariants, direct include/exclude contradiction rejection, atomic store mutation. | Reviewed. No open local finding. |
| Candidate resolution | Membership expansion, exclusion precedence, provider/origin/health filtering through `pool_builder.filter_eligible_profiles()`, `resilient_only` fail-closed. | Reviewed. No open local finding. |
| Runtime integration | Group target discovery follows rule/app-policy priority, missing/disabled groups fail closed, manual pins do not fall back, `RotationEngine` remains unchanged. | Reviewed. No open local finding. |
| Scoring and stale latency | `None` is preserved for unmeasured data, latency is fresh-or-stale, latency is only a tie-break, not part of total. | Reviewed. No open local finding. |
| CLI validation commands | Store-only commands avoid daemon dependency, `auto-test` runs through IPC/worker, config setter is Phase-14 allowlisted, output does not overstate degraded nodes after AUD-P14-002. | PASS. AUD-P14-002, AUD-P14-005, and AUD-P14-006 found and resolved. |
| Daemon/IPC serialization | New `node_group_auto_test` command validates payload, returns structured errors, and runs on the same worker thread as connect/disconnect/rotate/timers. | Reviewed. No open local finding. |

## 3. Acceptance Matrix

| Criterion | Audit result | Evidence |
| --- | --- | --- |
| Autonomous watchdog loop runs the existing engine on a bounded interval | PASS | `daemon/watchdog_loop.py`; `tests/test_daemon_watchdog_loop.py`; `RuntimeWorker.submit_tick()` serialization tests. VM evidence: after setting `watchdog.check_interval_seconds = 5` before daemon restart and connecting a real profile, `/var/lib/watchdogvpn/profiles.json` mtime changed from `1783333061` to `1783333276`, proving installed-service loop activity. |
| Scheduled proactive rotation fires through existing rotation machinery | PASS WITH SCHEDULED FIRING NOT FORCED | `daemon/scheduled_rotation_loop.py`; `WatchdogRuntime.scheduled_rotate()`; scheduled rotation tests. VM evidence confirmed `rotation.scheduled_interval_hours off` stayed disabled during validation. Manual rotate and auto-test worker paths were exercised live; long-wait scheduled firing was intentionally not forced in the conservative VM window. |
| Named node groups persist with strict validation | PASS | `node_groups/models.py`, `node_groups/store.py`; `tests/test_node_groups_models.py`, `tests/test_node_groups_store.py`. |
| Auto-selection does not select unavailable/untrusted profiles | PASS | Resolver reuses `filter_eligible_profiles()`; `resilient_only` exhaustion and missing/disabled groups fail closed; VM `auto-test` selected only measured-OK candidates. In a later live run, one candidate measured `degraded` with `latency_ms = null`; the command selected the other measured-OK candidate. |
| Health and latency are persisted end-to-end | PASS | `WatchdogRuntime._record_health_result()` and `_checked_and_recorded()`; end-to-end persistence/ranking tests. VM `auto-test` measured real latency (`293.052 ms`, `224.824 ms`, later `277.493 ms`) and `watchdog profile list` reflected live `ok`/`degraded` health after persistence. |
| Rule/app-policy can target a named group | PASS | `group_target()` is the canonical parser; `WatchdogRuntime._effective_node_group()` scans app-policy and rule groups in traffic-priority order. VM validation configured `app-policy` action `group:phase14-vm`; CLI support was fixed by AUD-P14-006. Known limit remains single active outbound only. |
| Rotation/recovery and group auto-select do not conflict | PASS | The selector feeds `RotationEngine` with a scoped ordered pool; `rotation/rotation_engine.py` is unchanged. VM validation exercised manual connect, manual rotate, auto-test, fail-closed rotation, and watchdog loop through the installed daemon. |
| Operator can inspect why a node was chosen | PASS | VM `watchdog node-group auto-test phase14-vm --json` exposed tested rows, ranked candidates, real latency, selected profile, and later degraded exclusion. |
| Phase-specific QA audit has no unresolved HIGH/MEDIUM findings | PASS | AUD-P14-001 through AUD-P14-006 are resolved. No unresolved HIGH or MEDIUM findings remain. |

## 4. Findings

### AUD-P14-001 - Runtime health status was never persisted

- Layer: 3 - Rotation, recovery and resilience
- Severity: MEDIUM
- Status: RESOLVED on 2026-07-05
- Description: `Profile.health_status`/`last_health_check` existed, and
  `pool_builder._recently_failed()` depended on them, but no real runtime
  health-check path wrote fresh values before Task 14.5.
- Impact before the fix: Recently failed nodes were not cooled down across
  cycles. Live `RotationEngine` checks still prevented accepting a dead node,
  so this was wasted retry/selection work rather than silent unsafe routing.
- Resolution: Task 14.5 added `_record_health_result()` and
  `_checked_and_recorded()` in `core/watchdog.py`, injecting persistence
  through the existing `RotationEngine` health-check callable. Task 14.7
  extended the same path with latency using a separate timestamp.
- Evidence: Phase 14 Task 14.5 validation notes and
  `tests/test_core_watchdog.py` end-to-end cooldown/persistence tests.

### AUD-P14-002 - `node-group auto-test` could report degraded candidates as selected

- Layer: 5 - CLI/Operator diagnostics; Layer 3 - Rotation/resilience
- Severity: MEDIUM
- Status: RESOLVED on 2026-07-06
- Description: The Task 14.8 `node-group auto-test` command measured each
  candidate and then re-resolved/ranked the group from persisted profile
  state. The shared eligibility filter only excludes recent `"down"`
  statuses, not `"degraded"`, because real rotation still performs a live
  deep check before accepting any candidate. For the diagnostic command,
  this meant an all-degraded group could still produce
  `result = "selected"` after the probe.
- Scenario: An operator runs `watchdog node-group auto-test paris` in a
  hostile network where every candidate connects but external reachability
  is degraded. The command could report a selected profile even though that
  same measured run did not produce an `"ok"` candidate.
- Impact before the fix: No confirmed traffic leak or unsafe routing. Real
  rotation would still reject degraded candidates at the live check stage.
  The risk was an operator-facing false claim in a resilience diagnostic:
  the command could imply a usable best node when the just-measured health
  evidence did not support that.
- Evidence before the fix:
  - `WatchdogRuntime.node_group_auto_test()` re-ranked
    `resolve_node_group_candidates()` output after measurement.
  - `pool_builder.filter_eligible_profiles()` only excludes
    `health_status == "down"` inside cooldown.
  - `rotation/rotation_engine.py` accepts only `status == "ok"` as success,
    demonstrating the stricter live-check standard.
- Resolution:
  - `node_group_auto_test()` now tracks which profiles returned `"ok"` in the
    current run and only ranks/reports those as selectable.
  - Measurement persistence still records degraded/down results for all
    tested candidates.
  - The connect-failure path now also checks disconnect success, so a partial
    failed probe cannot be hidden.
  - Added regression tests for all-degraded auto-test output and failed
    disconnect after failed connect.

### AUD-P14-003 - Profile import error paths were not robust for real test URIs

- Layer: 5 - CLI/Operator diagnostics; Layer 2 - Profile parsing
- Severity: MEDIUM
- Status: RESOLVED on 2026-07-06
- Description: VM import exposed two parser/CLI robustness issues: a Trojan
  URI with an unescaped slash inside the password failed host/port parsing,
  and `watchdog profile add --uri ""` reached an internal `AssertionError`
  instead of a clean parse error.
- Scenario: A user imports a real URI generated by a provider that leaves a
  slash unescaped in credentials, or a shell/script accidentally passes an
  empty URI value.
- Impact before the fix: Import could fail with a misleading error or
  traceback. This did not mutate routing, but it blocked legitimate profile
  setup and violated operator-facing resilience standards.
- Resolution: `_normalize_path_authority()` now reconstructs the authority
  for this URI shape and percent-escapes the credential slash before normal
  parsing. `_profile_add()` now treats an explicitly supplied empty `--uri`
  as input to validate, returning a clean parser error instead of an
  unreachable assertion.
- Evidence: VM import failure reproduced before the fix; regression tests
  added in `tests/test_parsers.py` and `tests/test_cli_profile_commands.py`.

### AUD-P14-004 - Installed runtime omitted the `node_groups` package

- Layer: 6 - Install/runtime packaging; Layer 7 - Daemon service
- Severity: HIGH
- Status: RESOLVED on 2026-07-06
- Description: The repository code passed local tests, but the product
  runtime installer did not copy the new `node_groups` package into
  `/usr/local/lib/watchdogvpn`.
- Scenario: After updating the installed runtime and restarting
  `watchdogvpn.service`, the daemon failed to import
  `node_groups.models` from `app_policy.models`.
- Impact before the fix: The installed daemon could not start after update,
  so all daemon-controlled VPN behavior was unavailable until the runtime
  package list was corrected.
- Evidence before the fix: `journalctl -u watchdogvpn` showed
  `ModuleNotFoundError: No module named 'node_groups'`.
- Resolution: Added `node_groups` to `PYTHON_RUNTIME_PACKAGES` in
  `lib/runtime.sh` and pinned it in the install security contract test.
  Re-running the installer placed `/usr/local/lib/watchdogvpn/node_groups`
  and the service restarted successfully.

### AUD-P14-005 - CLI IPC timeout was too short for real sequential auto-test

- Layer: 5 - CLI/IPC; Layer 7 - Live validation
- Severity: MEDIUM
- Status: RESOLVED on 2026-07-06
- Description: `watchdog node-group auto-test <group>` used the default
  5-second IPC timeout even though the daemon command sequentially connects,
  probes, records, and disconnects multiple real candidates.
- Scenario: In the VM, the command timed out while the daemon continued the
  operation and persisted partial health results.
- Impact before the fix: Operators could see a timeout even though daemon
  work was still in progress, making the command unreliable for real node
  validation.
- Resolution: The IPC client now uses a 120-second timeout for
  `node_group_auto_test` only, preserving the short default timeout for
  ordinary requests. Regression coverage confirms the command can outlive
  the default socket timeout.
- Evidence: VM retry after reinstall returned structured JSON for both real
  candidates in approximately 11 seconds.

### AUD-P14-006 - CLI rejected `group:<name>` app-policy actions

- Layer: 5 - CLI/Operator commands
- Severity: MEDIUM
- Status: RESOLVED on 2026-07-06
- Description: The model/runtime already accepted `group:<name>` actions,
  but `watchdog app-policy add --action ...` used argparse choices limited
  to enum actions and rejected group targets before validation.
- Scenario: A user attempts to configure a temporary rule such as
  `--action group:phase14-vm` for VM validation or operational policy.
- Impact before the fix: Named group routing could be configured in code but
  not through the intended CLI command.
- Resolution: Removed the premature argparse enum restriction and lets the
  existing policy validator decide validity. Human output now handles both
  enum actions and string group actions. Regression tests cover JSON and
  human output.

## 5. VM Validation

The VM/live-TUN validation was completed on 2026-07-06 using the installed
`watchdogvpn.service`, real TUN mutation, two temporary real profiles, and a
temporary group named `phase14-vm`. The temporary profiles, app-policy rules,
and node group were removed before closure.

- Installed daemon: `watchdogvpn.service` was enabled, active, restarted
  after runtime updates, and answered `watchdog status --json`.
- Real auto-test: `watchdog node-group auto-test phase14-vm --json`
  sequentially tested both candidates, measured real latency, persisted
  health/latency fields, selected the lowest-latency measured-OK candidate,
  and returned to standby with no active tunnel.
- Degraded exclusion: a later live run measured one candidate as
  `degraded` with `latency_ms = null`; the command selected only the
  measured-OK candidate.
- Group target: VM app-policy accepted `group:phase14-vm`. Manual rotate
  through rules mode used the group-scoped candidate set. The single-outbound
  product limit remains explicit: group targets bias the one active
  connection, not separate per-app outbound tunnels.
- Fail closed: a missing group target produced visible
  `rotation_unavailable` behavior and daemon logs
  `node_group_target_missing name=phase14-missing` and
  `rotation_unavailable reason=pool_empty`; there was no silent fallback to
  the global pool. In the observed VM config the kill switch was off, so the
  flow reported the error and retried according to the existing recovery
  behavior rather than claiming traffic blocking.
- Loops: after configuring a 5-second watchdog interval before service
  restart, the installed daemon updated profile persistence while connected,
  proving the loop was active under systemd. Scheduled rotation remained
  configured off.
- Cleanup: final VM state had no profiles, no node groups, app-policy
  disabled with no rules, status `standby`, and no active TUN.

## 6. Validation

Local commands run for this audit:

```bash
python3 -m unittest tests.test_core_watchdog_node_groups.NodeGroupAutoTestRuntimeTests tests.test_cli_node_group_commands
python3 -m unittest tests.test_core_watchdog_node_groups.NodeGroupAutoTestRuntimeTests tests.test_core_watchdog_node_groups.NodeGroupRuntimeIntegrationTests tests.test_node_groups_scoring tests.test_node_groups_resolver tests.test_daemon_runtime_worker tests.test_daemon_watchdog_loop tests.test_daemon_scheduled_rotation_loop tests.test_cli_node_group_commands
```

Full-suite and standard closure commands are recorded in the Task 14.9
master-plan validation notes.

Results from the final closure run:

- `python3 -m unittest discover -s tests -p 'test_*.py'` -> 946 tests,
  OK, skipped 1.
- `bash tests/unit.sh` passed.
- `bash tests/syntax.sh` passed.
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`
  passed.
- `git diff --check` passed.
- `git diff --stat rotation/rotation_engine.py` was empty.
- No unsafe shell execution flag in files touched by Task 14.9 changes.

## 7. Closure Status

Task 14.9 and Phase 14 are complete.

No unresolved HIGH or MEDIUM findings remain after AUD-P14-001 through
AUD-P14-006. The live VM validation cleaned up all temporary test profiles,
node groups, and app-policy rules before closure.
