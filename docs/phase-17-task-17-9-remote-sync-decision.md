# Phase 17 Task 17.9 - Remote Sync Decision

> Date: 2026-07-07
> Status: CLOSED - automatic remote sync deferred.

## Scope

Task 17.9 evaluates whether Phase 17 should implement WebDAV or LAN sync.

## Decision

Automatic WebDAV, LAN and other remote backup sync are deferred. The decision is
recorded in [ADR 0006](decisions/0006-remote-backup-sync.md).

The supported portable workflow for Phase 17 is explicit ZIP export/import.
When the archive leaves the local machine, users should use the encrypted backup
format implemented in Task 17.7.

## Rationale

Phase 17 now has client-side encrypted backup archives, but remote sync also
requires:

- credential storage and revocation;
- conflict handling across devices;
- retry and partial-transfer recovery;
- stale or attacker-replaced archive detection;
- upload/download confirmation UX;
- LAN peer discovery and exposure controls if LAN sync is ever implemented.

Those contracts are not implemented or validated in Phase 17. Shipping sync
without them would risk leaking secrets or overwriting good local state with
stale remote state.

## Boundaries

- No plaintext backup upload is supported.
- No WebDAV credential storage is added.
- No automatic remote upload/download command is added.
- No LAN listener, LAN peer discovery, LAN sync service, LAN proxy or gateway
  behavior is added.
- ADR 0004 and Phase 20 remain the gate for any LAN exposure.

## Future Acceptance Gate

A future remote sync task must define and validate:

- encrypted-only upload unless a stronger reviewed contract exists;
- credential storage;
- conflict handling;
- user confirmation for upload/download/replace;
- partial transfer recovery;
- stale archive detection;
- LAN exposure controls and VM/network validation for any LAN sync behavior.

## Validation

This is a design decision task. Validation consists of documentation and
roadmap consistency checks. No runtime network sync code was added.

Commands run:

- `rg -n "automatic remote sync deferred|ADR 0006|0006-remote-backup-sync|No WebDAV|No LAN listener|portable workflow|WebDAV/LAN sync, later explicitly deferred" docs README.md ROADMAP.md` -> expected references found;
- `python3 -m unittest tests.test_backup_manager tests.test_cli_uninstall_commands` -> 34 tests OK;
- `bash tests/syntax.sh` -> passed;
- `git diff --check` -> passed.
