# Phase 22 Task 22.2 - Connection Lifecycle CLI

Date: 2026-07-09
Branch: `phase-22-full-cli-interface`
Status: closed

## Scope

Task 22.2 audits and completes the lifecycle CLI commands:

- `watchdog connect <profile_id> [--json]`
- `watchdog disconnect [--json]`
- `watchdog status [--json]`
- `watchdog rotate [--force] [--json]`

The CLI remains argparse-based. This task does not migrate frameworks and does
not start any TUI work.

## Daemon And Runtime Path

All lifecycle commands use the intended daemon/runtime path:

```text
watchdog CLI -> WatchdogIPCClient -> daemon IPC socket -> RuntimeWorker -> WatchdogRuntime/driver
```

Command mapping:

- `connect` calls `WatchdogIPCClient.connect(profile_id)`;
- `disconnect` calls `WatchdogIPCClient.disconnect()`;
- `status` calls `WatchdogIPCClient.status()`;
- `rotate` calls `WatchdogIPCClient.rotate(force=<bool>)`.

The CLI does not directly instantiate runtime drivers, mutate routes, apply DNS
state, stop processes or bypass `RuntimeWorker` serialization for these
commands.

Manual rotate remains a daemon runtime action. The daemon routes it through
`WatchdogRuntime.rotate_now(force=...)`, so it uses the same runtime safety
policy as the existing rotation path instead of bypassing lifecycle handling in
the CLI.

## Human Output Contract

Successful lifecycle human output includes:

- daemon reachability;
- desired VPN state from persistent state;
- actual runtime state reported by the daemon;
- active profile ID;
- proxy/TUN activity;
- LAN gateway state;
- kill-switch activity;
- whether the state is a cleanly disconnected state;
- whether the state is failure/degraded.

`disconnect` additionally prints cleanup expectations:

- process cleanup belongs to daemon runtime driver disconnect;
- interface cleanup applies where TUN or gateway mode created owned state;
- DNS restore uses the saved runtime snapshot where present;
- owned local proxy listeners are removed by driver disconnect where
  applicable.

On command failures, human output prints the daemon/runtime error and recovery
hints for common cases such as daemon not running, stale socket, permission
errors, daemon timeout, missing profile, connect failure and disconnect failure.

## JSON Output Contract

Lifecycle JSON output remains a daemon response envelope:

```json
{
  "version": 1,
  "type": "response",
  "ok": true,
  "payload": {
    "state": {},
    "lifecycle": {}
  },
  "error": null
}
```

The added `payload.lifecycle` object is stable for automation and includes:

- `command`;
- `daemon_reachable`;
- `desired_state`;
- `actual_runtime_state`;
- `active_profile_id`;
- `runtime_active`;
- `proxy_active`;
- `tun_active`;
- `kill_switch_active`;
- `lan_gateway_status`;
- `profile_available`;
- `runtime_available`;
- `disconnected_cleanly`;
- `failure_or_degraded`;
- `cleanup_expectations`.

Daemon-unreachable JSON is also a response envelope with `ok=false`,
`daemon_reachable=false`, `actual_runtime_state=unknown`, `recovery_hints` and
the mapped CLI exit code.

## State Semantics

The lifecycle summary distinguishes:

- desired state: local persistent `vpn_desired_state`, or `unknown` if the
  state store is invalid/unreadable;
- actual runtime state: daemon-reported `ConnectionState.status`;
- daemon reachability: whether the IPC request reached the daemon;
- profile availability: false for profile-not-found errors;
- runtime availability: false when the daemon reports an unavailable runtime
  class of error;
- disconnected cleanly: daemon reachable, desired state off, no active proxy,
  TUN or gateway runtime state, and standby-like runtime status;
- failure/degraded: daemon/runtime error, known failure status or degraded LAN
  gateway state.

## Cleanup Guarantees

The CLI reports cleanup expectations but does not itself perform runtime
cleanup. Cleanup remains owned by lower layers:

- process cleanup: driver disconnect;
- TUN/interface/route cleanup: driver cleanup for modes that created owned
  state;
- DNS/system state restoration: `WatchdogRuntime.disconnect()` restores a saved
  DNS snapshot where present;
- listener cleanup: driver disconnect removes owned local proxy listeners where
  applicable.

This task validates CLI reporting of those expectations. It does not claim new
installed/runtime cleanup proof.

## Tests

Task 22.2 adds tests for:

- connect human output through IPC client;
- status human and JSON lifecycle output;
- disconnect JSON lifecycle output and human cleanup expectations;
- rotate force flag and JSON lifecycle output;
- daemon error response with recovery hints;
- daemon-unavailable JSON and human output;
- degraded/failure human status output;
- standalone daemon status JSON still round-trips.

## Validation

Task validation:

```text
python3 -m unittest tests.test_cli_connection_commands
OK - 13 tests

python3 -m unittest tests.test_cli_connection_commands tests.test_cli_ipc_client tests.test_cli_node_group_commands tests.test_cli_dns_commands tests.test_cli_rules_commands
OK - 80 tests

bash tests/unit.sh
OK

bash tests/syntax.sh
OK

python3 -m unittest discover -s tests -p 'test_*.py'
OK - 1190 tests, 1 skipped

git diff --check
OK

PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
OK
```

## Runtime Boundary

This task changes CLI output and tests only. It does not change daemon/runtime
behavior, DNS behavior, routes, firewall, forwarding, system proxy, installed
package behavior or driver cleanup logic.

Installed VM/lab validation was not required because connect/disconnect runtime
behavior did not change.
