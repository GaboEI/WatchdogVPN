# Phase 23 R28-01 — Crash-Recoverable Backup Restore

Date: 2026-07-15
Status: CLOSED for R28-001 after source, installed-runtime, and closure re-audit validation.

## Finding

R28-001 showed that restore published configuration files one at a time. A process death between profile and provider publication could leave a profile referring to a provider that was never published.

## Design

Restore now acquires ordered locks for every managed restore target and creates a durable rollback journal before publishing any replacement. The journal contains byte-exact pre-restore snapshots. A normal success removes the journal only after all replacement writes complete. If an ordinary exception, KeyboardInterrupt, or SystemExit occurs, restore rolls back before clearing the journal. If a hard crash prevents cleanup, the next locked store access discovers the journal and restores the prior bytes before returning data.

A residual journal is always rollback-required, never a successful commit.

## Source Evidence

- Focused backup/config/provider/profile CLI suite: 141 tests passed.
- Unit and syntax gates: passed.
- Full Python suite: 1,651 tests passed.
- KeyboardInterrupt regression restores original profile bytes and leaves no journal.
- Persisted-journal profile/provider recovery is automatic on the first ProfileStore read.

## Closure Evidence

R28-001 is closed at dba2a9c507db22a7b66bbc400042be072201cb9d after implementation commit 1ee26a9ebfb17590c4bfe34d88b243515b489d9c. Both code commits are published on phase-23-cli-field-validation; at runtime validation, source, origin, and installed marker aligned at dba2a9c.

Closure review found and corrected one defect in the first candidate: recovery had an overbroad cleanup of unknown JSON files under shared state. Journal schema v2 now prunes only unlisted top-level rule documents, the only files a restore itself can create or remove. Schema-v1 journal recovery uses that same safe rule-only scope. Unmanaged JSON is explicitly preserved.

After the corrective commit, the focused backup suite passed 36 of 36, tests/unit.sh and tests/syntax.sh passed, and the full Python suite passed 1651 of 1651 in 222.158 seconds. The transactional update completed, refreshed the daemon from PID 87528 to 97996, and passed its IPC smoke test.

An isolated installed-runtime proof interrupted profile and provider publication, added an interrupted rule, and retained an unmanaged JSON fixture. The next locked profile read restored the byte-exact profile and provider state, removed only the interrupted rule and journal, and preserved the unmanaged JSON.

doctor.sh confirms the installed runtime matches the source checkout. watchdog status --json confirms daemon reachable, desired state off, clean standby, no runtime artifacts, inactive kill switch, and disabled LAN gateway. The bypass timer remains deliberately disabled and inactive. Doctor warnings are environment observations for unsynchronized NTP and VPN truth DOWN, not failures.

No R28-001 debt is accepted. R28-002 remains pending explicit authorization. Phase 23 and Task 23.4 remain open and unmergeable until all R28 items and the final audit exit gate are complete.
