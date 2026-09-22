# Remote Backup Sync

## Decision

Automatic WebDAV, LAN and other remote backup sync are deferred. The decision is
recorded in [ADR 0006](decisions/0006-remote-backup-sync.md).

The supported portable workflow is explicit ZIP export/import. When the archive
leaves the local machine, users should use the encrypted backup format.

## Rationale

WatchdogVPN has client-side encrypted backup archives, but remote sync also
requires:

- credential storage and revocation;
- conflict handling across devices;
- retry and partial-transfer recovery;
- stale or attacker-replaced archive detection;
- upload/download confirmation UX;
- LAN peer discovery and exposure controls if LAN sync is implemented.

Those contracts are not implemented or validated. Shipping sync without them
would risk leaking secrets or overwriting good local state with stale remote
state.

## Boundaries

- No plaintext backup upload is supported.
- No WebDAV credential storage is added.
- No automatic remote upload/download command is added.
- No LAN listener, LAN peer discovery, LAN sync service, LAN proxy or gateway
  behavior is added.
- LAN proxy/gateway sharing remains governed by
  [ADR 0004](decisions/0004-lan-proxy-sharing.md).

## Requirements for Remote Sync

A future remote sync feature must define and validate:

- encrypted-only upload unless a stronger reviewed contract exists;
- credential storage;
- conflict handling;
- user confirmation for upload/download/replace;
- partial transfer recovery;
- stale archive detection;
- LAN exposure controls and controlled network handling for any LAN sync
  behavior.
