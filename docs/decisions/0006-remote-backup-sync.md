# ADR 0006: Remote Backup Sync

Date: 2026-07-07

## Status

Deferred.

## Context

Phase 17 added versioned backups, restore rollback, partial import/export,
merge policy, provider/selection-state handling, retention policy, sensitive
warnings, encrypted backup archives and uninstall backup flows.

Public comparable VPN/proxy clients commonly offer ZIP backup plus remote
sync targets such as WebDAV, platform cloud storage or LAN sync. WatchdogVPN
should eventually support multi-device portability, but remote sync changes the
trust boundary. A local sensitive archive becomes a network object handled by
credentials, remote servers and conflict resolution behavior.

The encrypted backup format from Phase 17 Task 17.7 removes the biggest blocker
for safe upload: WatchdogVPN no longer needs to upload plaintext backups.
However, encryption alone is not a complete sync product contract.

Remote sync still requires reviewed answers for:

- credential storage and revocation;
- whether credentials live in the OS keyring, root-owned config, user config or
  an external secret helper;
- conflict detection across devices;
- merge, replace or manual conflict UX;
- remote metadata privacy;
- retry/backoff behavior;
- partial upload/download failure recovery;
- whether deletes propagate between devices;
- how to avoid silently importing stale or attacker-replaced archives;
- how LAN sync discovers peers without exposing secrets or opening unauthenticated
  services.

## Decision

Do not implement automatic WebDAV, LAN or other remote backup sync in Phase 17.

The supported portable workflow for Phase 17 is explicit local ZIP export/import,
preferably encrypted with the reviewed encrypted backup format when the archive
will leave the local machine.

Remote sync may be reconsidered in a later dedicated task only if it provides:

- client-side encrypted backups only, unless a stronger reviewed security
  contract is documented;
- explicit credential-storage design;
- explicit conflict handling;
- user-visible upload/download/replace confirmation;
- failure recovery for partial transfers;
- no silent upload of plaintext archives;
- no default LAN exposure;
- VM/network validation for LAN sync behavior.

LAN proxy/gateway sharing remains governed by ADR 0004 and Phase 20. This ADR
does not authorize any LAN listener, peer discovery service or gateway mode.

## Consequences

- WatchdogVPN avoids shipping a sync feature that could silently leak secrets or
  overwrite good local state with stale remote state.
- Users still have a portable flow: export an encrypted backup ZIP and import it
  manually on another device.
- Phase 17 can close backup/sync scope with a clear remote-sync threat-model
  answer.
- Future remote sync work must update or supersede this ADR instead of adding
  upload behavior behind an existing backup command.
