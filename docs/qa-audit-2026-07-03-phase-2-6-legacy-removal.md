# WatchdogVPN QA Audit - Phase 2.6 Legacy Provider and Desktop Widget Removal

> Date: 2026-07-03
> Protocol: `/home/gabodev/Escritorio/temporales/WatchdogVPN_QA_AUDIT_PROTOCOL.md`
> Scope: post-removal audit after Phase 2.6 closure. Detection was documented
> first; product-code hardening closure is recorded below.
> Status: RESOLVED 2026-07-03 - hardening closure completed below.

## Protocol Update

Before auditing the product state, the reusable QA protocol was reviewed and
expanded from five layers to eight layers. The added coverage is:

- Layer 6: daemon, IPC, systemd and privilege boundaries.
- Layer 7: installer, updater, uninstaller and migration safety.
- Layer 8: network leak safety, DNS/routing policy and hostile-environment
  resilience.

This was necessary because Phase 2.6 touched real install/update/uninstall
contracts, shared daemon state, DNS defaults, systemd units, and user-facing
runtime entry points.

## Validation Baseline

- `bash tests/unit.sh` passed.
- `WATCHDOGVPN_CONFIG_DIR=$(mktemp -d) python3 -m unittest discover tests`
  passed: 645 tests.
- Removal grep from Task 2.6.5 remains clean in the pushed repo state.
- No `shell=True`, `os.system()`, or `eval()` execution path was found in the
  audited tracked runtime code.

## Audited Surface

- `daemon/ipc_server.py`
- `daemon/runtime_worker.py`
- `cli/ipc/client.py`
- `cli/main.py`
- `core/watchdog.py`
- `dns/state_manager.py`
- `config/persistence.py`
- `install.sh`
- `update.sh`
- `uninstall.sh`
- `lib/runtime.sh`
- `lib/systemd.sh`
- `systemd/watchdogvpn.service`
- Existing IPC, DNS, install-security and systemd contract tests.

## Findings And Subtasks

### AUD-P26-001 - Bound daemon runtime commands

| Field | Value |
|---|---|
| ID | AUD-P26-001 |
| Layer | Layer 6 - Daemon, IPC, systemd and privilege boundaries |
| Severity | HIGH |
| Status | RESOLVED 2026-07-03 |
| Subtask | Add bounded daemon command execution and regression coverage. |

Description:

The daemon request handler submits runtime commands with `timeout=None`. The
runtime worker itself has a default 30-second timeout, but the IPC server
overrides that default. If a runtime command hangs, the request handler can wait
forever. Because the runtime worker processes commands serially on one worker
thread, a hung connect/rotate/disconnect can also prevent later status or
disconnect requests from being served by the worker.

Evidence:

- `daemon/ipc_server.py` lines 72-77 call
  `self.server.worker.submit(..., timeout=None)`.
- `daemon/runtime_worker.py` lines 72-80 define a 30-second default timeout,
  but it is bypassed by the IPC handler.
- `daemon/runtime_worker.py` lines 90-99 process queued requests on a single
  worker loop.
- `tests/test_cli_ipc_client.py` covers client timeout against a hanging socket,
  but there is no daemon-server regression where a runtime command hangs and a
  later status/disconnect remains usable or fails predictably.

Impact:

For a resilience tool, the control plane must remain predictable while the
network path is degraded. A stuck runtime command can leave the CLI reporting
client-side timeouts while the daemon remains busy or wedged behind the first
request.

Recommendation:

- Restore a bounded IPC-server timeout or make command deadlines explicit by
  command type.
- Ensure status can return a last-known state without waiting behind a long
  connect/rotate operation, or return a structured `busy` response quickly.
- Add a regression test with a runtime command that never returns and verify the
  next status/disconnect behavior is deterministic.

### AUD-P26-002 - Make DNS snapshots atomic and permission-normalized

| Field | Value |
|---|---|
| ID | AUD-P26-002 |
| Layer | Layer 1 / Layer 6 / Layer 8 |
| Severity | MEDIUM |
| Status | RESOLVED 2026-07-03 |
| Subtask | Move DNS snapshot persistence onto the shared persistence helper. |

Description:

The Phase 2.6 permission fix hardened the shared persistent stores through
`config/persistence.py`, including atomic writes, file locks, and explicit
shared-state permissions. DNS snapshot persistence is outside that path:
`cli/main.py` writes `dns-state.json` directly with `Path.write_text()`, and
`dns/state_manager.py::load_snapshot()` reads it directly.

Evidence:

- `cli/main.py` lines 734-739 create the parent directory and call
  `path.write_text(...)` directly.
- `cli/main.py` lines 742-748 load the snapshot directly with
  `path.read_text(...)` and `json.loads(...)`.
- `dns/state_manager.py` lines 34-40 has the same direct read pattern.
- `config/persistence.py` lines 38-55 already provides atomic fsync+replace and
  shared permission normalization.
- Existing tests cover normal snapshot save/reset and corrupt snapshot survival,
  but not partial-write protection, lock behavior, or shared-mode normalization
  for `dns-state.json`.

Impact:

If the process crashes during snapshot write, or if the file is created with
permissions inherited from the wrong umask, DNS rollback can fail later. The
current watchdog disconnect path survives a corrupt snapshot by warning and
leaving the file in place, but that still means DNS restoration may not happen
when the user needs it.

Recommendation:

- Store DNS snapshots through the same persistence primitives used by other
  shared state.
- Add tests for atomic save, corrupt/partial snapshot behavior, and file mode
  normalization under a shared `/var/lib/watchdogvpn` config directory.
- Consider making DNS reset surface a clearer recovery hint when the snapshot is
  unreadable.

### AUD-P26-003 - Add real post-install/update daemon validation

| Field | Value |
|---|---|
| ID | AUD-P26-003 |
| Layer | Layer 7 - Installer, updater, uninstaller and migration safety |
| Severity | MEDIUM |
| Status | RESOLVED 2026-07-03 |
| Subtask | Add a non-destructive daemon/CLI smoke test after install and update. |

Description:

The installer and updater validate repository syntax and systemd unit files, but
the final runtime validation is intentionally skipped. After enabling services,
there is no required smoke test proving that the daemon starts, creates the IPC
socket, accepts an authorized desktop CLI request, and can read the migrated
shared state.

Evidence:

- `install.sh` lines 337-340 explicitly skip automatic runtime validation.
- `install.sh` lines 416-430 installs runtime files, enables services, waits,
  and finishes without a daemon IPC smoke test.
- `update.sh` lines 184-191 replaces runtime files, verifies units, enables
  services, and finishes without a daemon IPC smoke test.
- `lib/runtime.sh` lines 151-163 adds the invoking user to the shared group and
  warns that a new login session is required, but the installer does not then
  distinguish "current shell cannot use IPC yet" from "daemon is broken".

Impact:

The exact class of live failure found during Phase 2.6 was an install/runtime
contract issue. The current test suite guards many of those contracts, but a
real machine can still finish install/update without proving that the newly
installed daemon is reachable and reading the intended state.

Recommendation:

- Add a post-install/update smoke step that checks `systemctl is-active
  watchdogvpn.service`, the socket path, and a read-only daemon status command.
- If the installing user's current session lacks the new group membership,
  report that as an actionable session-refresh state rather than a generic
  failure.
- Keep the smoke test non-destructive: no connect, no rotate, no DNS mutation.

## Scheduled Work Not Counted As Findings

- The TUI still contains provisional v2 bridge logic and older operational
  shape in places, but the project decision is explicit: complete the real v2
  capabilities first, expose them through a full CLI, validate in real CLI
  usage, and only then migrate/redesign the TUI in PHASE 15.5.
- Dependency installation for later protocol drivers remains scheduled in later
  phases. It is not a Phase 2.6 removal defect.
- LOW UX debt already recorded in previous Layer 5 audit remains deferred as
  documented there.

## Checked Scenarios Without Findings

### Shared state permissions

The earlier live bug around `/var/lib/watchdogvpn/.migrated` and group access is
covered by current install/runtime code and tests:

- `lib/runtime.sh` creates the service user, adds the installing user to the
  shared group, prepares systemd-managed state when needed, and repairs shared
  state permissions.
- `systemd/watchdogvpn.service` uses `StateDirectoryMode=2770`.
- `config/persistence.py` normalizes shared directories to `2770` and files to
  `0660`.
- `tests/unit/test_install_security_contracts.sh` and
  `tests/unit/test_watchdogvpn_systemd_contract.sh` assert these contracts.

### Systemd hardening

The daemon service is reasonably constrained for the current architecture:

- Dedicated `User=watchdogvpn` and `Group=watchdogvpn`.
- Managed runtime/state/config directories.
- Capability bounding limited to `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, and
  `CAP_NET_RAW`.
- `/dev/net/tun` explicitly allowed.
- `NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp=true`, and
  related hardening directives are present.

### Command execution style

The audited Python runtime uses list-form subprocess calls. No shell-evaluation
path was found in tracked runtime code during this audit.

### DNS normal apply rollback

`SystemDNSStateManager.apply_local_dns()` saves the current state before
applying local DNS and calls `restore_state(saved)` on apply failure. The open
finding is specifically about snapshot durability and shared permissions after
the snapshot is persisted to disk.

## Priority Order

1. AUD-P26-001 - daemon command deadlines/control-plane availability.
2. AUD-P26-002 - DNS snapshot atomicity and shared-state permissions.
3. AUD-P26-003 - real post-install/update daemon smoke validation.

## Hardening Closure - 2026-07-03

### Implemented fixes

- AUD-P26-001: daemon IPC request handling now uses a bounded server-side
  timeout instead of `timeout=None`. A stuck runtime command returns a
  structured `ok=false` response with `daemon runtime command timed out`, and a
  regression test covers a blocking runtime plus a later status request.
- AUD-P26-002: DNS snapshot save/load now goes through `dns.state_manager`
  helpers backed by `config.persistence` file locks, atomic fsync+replace
  writes, and shared-state permission normalization.
- AUD-P26-003: install/update now run a non-destructive daemon smoke test after
  service enablement. The smoke checks `watchdogvpn.service`, the IPC socket,
  and read-only `watchdog status --json`; if the daemon is healthy but the
  current login session lacks refreshed group membership, it reports an
  actionable session-refresh warning instead of misclassifying the daemon as
  broken.

### Validation completed

- `python3 -m py_compile daemon/ipc_server.py tests/test_cli_ipc_client.py`
  passed.
- `WATCHDOGVPN_CONFIG_DIR=$(mktemp -d) python3 -m unittest
  tests.test_cli_ipc_client tests.test_daemon_runtime_worker` passed: 27 tests.
- `python3 -m py_compile cli/main.py dns/state_manager.py
  tests/test_cli_dns_commands.py` passed.
- `WATCHDOGVPN_CONFIG_DIR=$(mktemp -d) python3 -m unittest
  tests.test_cli_dns_commands tests.test_dns_state_manager
  tests.test_core_watchdog` passed: 82 tests.
- `bash tests/unit/test_install_security_contracts.sh` passed.
- `bash tests/unit/test_install_backend_selection.sh` passed.
- `bash tests/syntax.sh` passed.
- `bash tests/unit.sh` passed.
- `WATCHDOGVPN_CONFIG_DIR=$(mktemp -d) python3 -m unittest discover tests`
  passed: 647 tests.

### Residual risk

- Python cannot safely terminate an arbitrary stuck worker thread. This closure
  makes the daemon IPC boundary deterministic and test-covered, but a deeper
  future daemon architecture could still add last-known-state `busy` responses
  or supervised per-command workers if real-world testing shows a need.
- No destructive live network validation was run during this closure because the
  developer machine had an active tunnel. The new install/update smoke test is
  intentionally read-only and does not connect, disconnect, rotate, or mutate
  DNS.

## Closure Criteria

Phase 2.6 should not be considered audit-closed until:

- [x] Every HIGH/MEDIUM subtask above is fixed or explicitly accepted by the user
  with rationale.
- [x] Regression tests are added for each fixed subtask.
- [x] `bash tests/unit.sh` passes.
- [x] `WATCHDOGVPN_CONFIG_DIR=$(mktemp -d) python3 -m unittest discover tests`
  passes.
- [x] The report is updated with a hardening closure section listing fixes,
  validations, and final residual risk.
