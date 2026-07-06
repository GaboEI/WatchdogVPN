# WatchdogVPN QA Audit - Phase 14 Node Groups & Auto-Selection Policy

> Date: 2026-07-06
> Task: PHASE 14 - Node Groups & Auto-Selection Policy, Task 14.9 - Node group audit closure
> Status: LOCAL AUDIT COMPLETE. No unresolved local HIGH or MEDIUM findings remain. VM validation is still required before full Phase 14 closure.

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

The local audit focuses on code correctness, fail-closed behavior,
misleading operator output, stale health/latency handling, daemon
serialization, and claims that can be verified without live TUN/network
mutation. Real daemon/TUN/latency behavior with actual nodes is explicitly
deferred to the VM validation pass.

## 2. Coverage Checklist

| Surface | Reviewed criteria | Result |
| --- | --- | --- |
| Autonomous watchdog loop | Timer reads bounded config, enqueues only onto `RuntimeWorker`, tolerates corrupt config and stopped worker, starts/stops with daemon. | Reviewed. No open local finding. VM must still confirm the loop runs under the installed service. |
| Scheduled rotation loop | Separate timer, disabled-by-default polling, independent gate, serialized worker execution, empty-pool no-op before kill-switch path. | Reviewed. No open local finding. VM must still confirm scheduled firing under the installed service. |
| Node group model/store | Strict schema, name identity, selection-mode invariants, direct include/exclude contradiction rejection, atomic store mutation. | Reviewed. No open local finding. |
| Candidate resolution | Membership expansion, exclusion precedence, provider/origin/health filtering through `pool_builder.filter_eligible_profiles()`, `resilient_only` fail-closed. | Reviewed. No open local finding. |
| Runtime integration | Group target discovery follows rule/app-policy priority, missing/disabled groups fail closed, manual pins do not fall back, `RotationEngine` remains unchanged. | Reviewed. No open local finding. |
| Scoring and stale latency | `None` is preserved for unmeasured data, latency is fresh-or-stale, latency is only a tie-break, not part of total. | Reviewed. No open local finding. |
| CLI validation commands | Store-only commands avoid daemon dependency, `auto-test` runs through IPC/worker, config setter is Phase-14 allowlisted, output does not overstate degraded nodes after AUD-P14-002. | Reviewed. AUD-P14-002 found and resolved locally. |
| Daemon/IPC serialization | New `node_group_auto_test` command validates payload, returns structured errors, and runs on the same worker thread as connect/disconnect/rotate/timers. | Reviewed. No open local finding. |

## 3. Acceptance Matrix

| Criterion | Audit result | Evidence |
| --- | --- | --- |
| Autonomous watchdog loop runs the existing engine on a bounded interval | LOCAL PASS, VM pending | `daemon/watchdog_loop.py`; `tests/test_daemon_watchdog_loop.py`; `RuntimeWorker.submit_tick()` serialization tests. Installed-service behavior still needs VM evidence. |
| Scheduled proactive rotation fires through existing rotation machinery | LOCAL PASS, VM pending | `daemon/scheduled_rotation_loop.py`; `WatchdogRuntime.scheduled_rotate()`; `tests/test_daemon_scheduled_rotation_loop.py`; `tests/test_core_watchdog.py` scheduled-rotation cases. Installed-service timing still needs VM evidence. |
| Named node groups persist with strict validation | PASS | `node_groups/models.py`, `node_groups/store.py`; `tests/test_node_groups_models.py`, `tests/test_node_groups_store.py`. |
| Auto-selection does not select unavailable/untrusted profiles | LOCAL PASS, VM pending | Resolver reuses `filter_eligible_profiles()`; `resilient_only` exhaustion and missing/disabled groups fail closed; `auto-test` now only reports measured-OK profiles as selected. Real node behavior still needs VM evidence. |
| Health and latency are persisted end-to-end | LOCAL PASS, VM pending | `WatchdogRuntime._record_health_result()` and `_checked_and_recorded()`; end-to-end persistence/ranking tests. Real network measurements still need VM evidence. |
| Rule/app-policy can target a named group | LOCAL PASS, VM pending | `group_target()` is the canonical parser; `WatchdogRuntime._effective_node_group()` scans app-policy and rule groups in traffic-priority order; sing-box still maps to the single active outbound as documented. Real routing still needs VM evidence. |
| Rotation/recovery and group auto-select do not conflict | LOCAL PASS, VM pending | The selector feeds `RotationEngine` with a scoped ordered pool; `rotation/rotation_engine.py` is unchanged. Live daemon trigger interaction still needs VM evidence. |
| Operator can inspect why a node was chosen | LOCAL PASS, VM pending | `watchdog node-group auto-test` exposes tested rows and ranked candidate scores; AUD-P14-002 resolved misleading degraded-selection output. Real command output still needs VM evidence. |
| Phase-specific QA audit has no unresolved HIGH/MEDIUM findings | LOCAL PASS | AUD-P14-001 and AUD-P14-002 are resolved. No additional local HIGH/MEDIUM findings were found. Full phase closure remains pending VM validation. |

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

## 5. Deferred VM Validation

The following are not local code debts; they require the real VM/live-TUN
environment and must be completed before full Phase 14 closure:

- installed daemon starts both `WatchdogLoop` and `ScheduledRotationLoop`
- `watchdog node-group auto-test <real-group>` connects candidates
  sequentially, measures real latency, persists profile fields, and
  disconnects cleanly
- a real `group:<name>` rule causes the daemon to connect the best ranked
  profile for that group
- missing, disabled, and exhausted `resilient_only` groups fail closed in
  live daemon behavior
- scheduled rotation, manual `rotate --force`, watchdog ticks, and
  `node-group auto-test` do not overlap or fight in the single worker queue

## 6. Validation

Local commands run for this audit:

```bash
python3 -m unittest tests.test_core_watchdog_node_groups.NodeGroupAutoTestRuntimeTests tests.test_cli_node_group_commands
python3 -m unittest tests.test_core_watchdog_node_groups.NodeGroupAutoTestRuntimeTests tests.test_core_watchdog_node_groups.NodeGroupRuntimeIntegrationTests tests.test_node_groups_scoring tests.test_node_groups_resolver tests.test_daemon_runtime_worker tests.test_daemon_watchdog_loop tests.test_daemon_scheduled_rotation_loop tests.test_cli_node_group_commands
```

Full-suite and standard closure commands are recorded in the Task 14.9
master-plan validation notes.

Results from the local closure run:

- `python3 -m unittest discover -s tests -p 'test_*.py'` -> 941 tests, with
  the same 1 pre-existing unrelated sandbox failure in
  `test_runtime_rules_mode_groups_reach_generated_singbox_config`
  (`subprocess.run(["ip", "rule", "show"])`).
- `bash tests/unit.sh` passed.
- `bash tests/syntax.sh` passed.
- `python3 -m compileall -q .` passed.
- `git diff --check` passed.
- `git diff --stat rotation/rotation_engine.py` was empty.
- No unsafe shell execution flag in files touched by the local Task 14.9
  changes.

## 7. Local Closure Status

Task 14.9 is locally complete for code-audit purposes once the standard
validation commands pass.

No unresolved local HIGH or MEDIUM findings remain. Full Phase 14 closure is
pending VM validation with real network/TUN behavior.
