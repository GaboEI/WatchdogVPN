# WatchdogVPN QA Audit - Phase 15 Task 15.6 Network Services

> Date: 2026-07-06
> Task: PHASE 15 - DNS Policy Refinement, Time Diagnostics & Safe LAN Services,
> Task 15.6 - Network services audit closure
> Status: COMPLETE. AUD-P15-002 was found and resolved. No unresolved HIGH or
> MEDIUM findings remain for Phase 15.

## 1. Scope

This audit closes Phase 15 by reviewing the combined network-service posture
after Tasks 15.1 through 15.5:

- DNS v2 refinement and Phase 10 regression risk
- resolver racing decision
- route/DNS diagnostics
- time/NTP doctor diagnostics
- LAN proxy exposure posture
- cleanup and rollback behavior for DNS and runtime network state

No LAN proxy/gateway implementation, TUI work, or routing/capture model
migration is part of this task.

## 2. Coverage Checklist

| Surface | Reviewed criteria | Result |
| --- | --- | --- |
| DNS v2 runtime contract | DNSPolicy remains threaded into live connect/startup/reconnect/rotation paths; sing-box DNS uses `domain_resolver`; FakeIP is not used for outbound self-resolution; app-policy DNS rules still precede domain/channel rules. | PASS. No regression found from Phase 10/12 guarantees. |
| Resolver racing | Runtime resolver racing is explicitly rejected for v2.0; bounded concurrency remains diagnostic-only in `watchdog dns test`. | PASS. Covered by ADR 0003 and Task 15.2 tests. |
| Route/DNS diagnostic | `watchdog dns diagnose` reports route action/source, DNS channel/path, reason and confidence without claiming live packet observation. | PASS. Covered by `diagnostics.route_dns` and CLI tests. |
| Time/NTP doctor | `doctor.sh` calls a read-only Python diagnostic, reports system time/NTP/skew risk, and does not call time mutation commands. | PASS. Covered by `tests.test_time_check` and doctor contract tests. |
| LAN exposure | Generated SOCKS/HTTP and DNS hijack listeners remain bound to `127.0.0.1`; LAN sharing/gateway is deferred to Phase 20 with branch-only and VM-only gates. | PASS. Covered by ADR 0004 and sing-box/DNS hijack tests. |
| Cleanup and rollback | Runtime config dirs are per-run private dirs with stale-owner cleanup; sing-box TUN residue has best-effort crash cleanup; DNS reset/disconnect restore snapshots when available. | PASS after AUD-P15-002. |

## 3. Finding

### AUD-P15-002 - `dns apply` could mutate DNS before a durable rollback snapshot existed

- Layer: 5 - CLI/Operator control; Layer 7 - DNS/system integration
- Severity: MEDIUM
- Status: RESOLVED on 2026-07-06
- Description: `watchdog dns apply --yes` applied the local DNS entrypoint
  before writing the rollback snapshot to disk. If snapshot persistence failed
  after system resolver mutation, the host could be left pointed at the local
  DNS entrypoint without the normal `watchdog dns reset --yes` rollback state.
  A repeated confirmed apply could also overwrite the original rollback
  snapshot with an already-mutated DNS state.
- Impact before the fix: A storage/permission/write failure at the wrong time
  could turn a recoverable DNS apply into a manual rescue situation. Repeated
  apply could weaken rollback by losing the original resolver state.
- Resolution:
  - `cli/main.py::_dns_apply()` now saves a rollback snapshot before the first
    confirmed DNS mutation.
  - If a snapshot already exists, confirmed apply preserves it instead of
    overwriting the original rollback point.
  - If snapshot persistence fails before the first mutation, apply aborts
    before calling the DNS hijack controller.
  - Added CLI regression tests for pre-mutation snapshot save, failed snapshot
    persistence, and preserving an existing rollback snapshot.
- Residual risk: If the system DNS apply itself fails after a durable snapshot
  exists and automatic immediate restore also fails, the snapshot intentionally
  remains available for `watchdog dns reset --yes` or manual rescue. This is a
  recovery path, not hidden debt.

## 4. Checked Scenarios Without New Findings

- `watchdog dns apply --dry-run` still does not create a snapshot or mutate
  DNS.
- Confirmed `dns apply` still rejects non-53 entrypoint ports before mutation.
- `watchdog dns reset --yes` restores the saved snapshot and removes it after a
  successful restore.
- `WatchdogRuntime.disconnect()` still attempts snapshot restore, removes the
  snapshot after success, and logs restore/load failures without blocking
  disconnect.
- `doctor.sh` reports time/NTP risk and explicitly states that it does not
  change the clock.
- Generated sing-box local proxy inbounds remain loopback-only.
- Generated DNS hijack listeners remain loopback-only.
- Phase 20 remains the owner for any intentional LAN proxy/gateway exposure.
- Phase 19 remains the owner for routing/capture vocabulary and implementation
  migration.
- Phase 21 remains the owner for unified diagnostics beyond the narrow
  route/DNS diagnostic added in Phase 15.

## 5. Validation

Commands run:

```bash
python3 -m unittest tests.test_cli_dns_commands tests.test_dns_state_manager tests.test_dns_hijack tests.test_dns_singbox tests.test_singbox_driver tests.test_time_check tests.test_route_dns_diagnostic
python3 -m unittest discover -s tests -p 'test_*.py'
bash tests/unit.sh
bash tests/syntax.sh
git diff --check
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
```

Results:

- Task-focused validation passed: 139 tests OK.
- Full unit discovery passed: 967 tests OK.
- Unit shell checks passed.
- Syntax checks passed.
- Diff whitespace check passed.
- Compileall passed.

## 6. Closure Status

Phase 15 is closed for HIGH/MEDIUM audit purposes.

No unresolved HIGH or MEDIUM findings remain.
