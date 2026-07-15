# Phase 23 R28-01 — Crash-Recoverable Backup Restore

Date: 2026-07-15
Status: source validated; commit, publication, installed validation, and independent closure pending.

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

## Remaining Closure Work

1. Review, commit, push, and install the exact diff.
2. Run isolated installed journal recovery.
3. Verify source/origin/installed marker alignment and clean standby.
4. Independently review R28-001 before changing its status to CLOSED.
