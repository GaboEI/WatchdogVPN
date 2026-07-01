# WatchdogVPN QA Audit — Layer 2 Driver and Process Management

> Date: 2026-07-02  
> Protocol: `/home/gabodev/Escritorio/temporales/WatchdogVPN_QA_AUDIT_PROTOCOL.md`  
> Scope: detection and documentation only. No fixes were made during this audit.

## Audited Surface

- `drivers/singbox_driver.py`
- `drivers/amneziawg_driver.py`
- `drivers/openvpn_driver.py`
- `drivers/openvpn_cloak_driver.py`
- `drivers/base.py`
- Evidence from:
  - `tests/test_singbox_driver.py`
  - `tests/test_amneziawg_driver.py`
  - `tests/test_openvpn_driver.py`
  - `tests/test_openvpn_cloak_driver.py`

## Findings

### AUD-001

| Field | Value |
|---|---|
| ID | AUD-001 |
| Layer | Layer 2 — Driver and process management |
| Severity | HIGH |
| Description | Temporary runtime config files can remain in `/tmp` with sensitive profile data if the process crashes mid-connect or the host loses power. |
| Scenario | sing-box, AmneziaWG, OpenVPN, or OpenVPN+Cloak writes a temp config under `/tmp`, then WatchdogVPN or the machine crashes before `disconnect()` or cleanup runs. |
| Impact | Server addresses, private keys, proxy passwords, OpenVPN material, or Cloak config can remain on disk. This is a security exposure, especially for `singbox` and plain `openvpn` temp files that are not explicitly chmodded after writing. |
| Status | OPEN |

Evidence:
- `drivers/singbox_driver.py`: `CONFIG_PATH = Path("/tmp/watchdogvpn_singbox.json")`; `_write_config()` writes JSON but does not chmod; cleanup only happens in `disconnect()`.
- `drivers/amneziawg_driver.py`: `CONFIG_PATH = Path("/tmp/watchdogvpn_awg.conf")`; file is chmod `0600`, but still persists after a crash before cleanup.
- `drivers/openvpn_driver.py`: `CONFIG_PATH = Path("/tmp/watchdogvpn_openvpn.conf")`; config is written without explicit chmod and cleanup only happens in `disconnect()`.
- `drivers/openvpn_cloak_driver.py`: `/tmp/watchdogvpn_oc.conf` and `/tmp/watchdogvpn_cloak.json` are chmod `0600`, but still persist after crash before cleanup.

### AUD-002

| Field | Value |
|---|---|
| ID | AUD-002 |
| Layer | Layer 2 — Driver and process management |
| Severity | HIGH |
| Description | Drivers can report a successful connection before real readiness is established. |
| Scenario | `connect()` starts a subprocess and immediately returns `True` because `poll()` is still `None`, before proxy ports, tunnel interfaces, or real traffic are verified. |
| Impact | Manual connect/startup paths can briefly or incorrectly surface `connected` status even when the backend will fail moments later. This is most visible in `SingBoxDriver.connect()` and `OpenVPNDriver.connect()`, and partially applies to `OpenVPNCloakDriver.connect()` after both processes start but before a TUN device exists. |
| Status | OPEN |

Evidence:
- `SingBoxDriver.connect()` returns `True` immediately when the process is alive; readiness is deferred to `health_check()`.
- `SingBoxDriver.status()` reports `status="connected"`, `tun_active=True`, and `proxy_active=True` based only on process liveness.
- `OpenVPNDriver.connect()` returns `True` when the process is alive, before `_vpn_interface_active()` is checked.
- `OpenVPNCloakDriver.connect()` waits for initial `ck-client` survival, then returns `True` when OpenVPN is alive, before `_vpn_interface_active()` confirms the tunnel.
- `WatchdogRuntime.startup()` calls `driver.connect(profile)` and then returns `driver.status()` without a health gate.

### AUD-003

| Field | Value |
|---|---|
| ID | AUD-003 |
| Layer | Layer 2 — Driver and process management |
| Severity | MEDIUM |
| Description | `is_available()` checks binary presence but not version or runtime compatibility. |
| Scenario | A binary exists and is executable, but is too old, incompatible, or the wrong implementation with the expected name. |
| Impact | The driver can be selected as available and fail later during `connect()` or health checks. For OpenVPN+Cloak, `check_version()` only checks OpenVPN; `ck-client` version compatibility is not validated. |
| Status | OPEN |

Evidence:
- `SingBoxDriver.is_available()` returns true when `find_singbox_binary()` finds a path.
- `AmneziaWGDriver.is_available()` checks only quick-tool presence.
- `OpenVPNDriver.is_available()` checks only OpenVPN binary presence.
- `OpenVPNCloakDriver.is_available()` checks OpenVPN and `ck-client` presence, but `check_version()` reads only OpenVPN.

### AUD-004

| Field | Value |
|---|---|
| ID | AUD-004 |
| Layer | Layer 2 — Driver and process management |
| Severity | HIGH |
| Description | A stale `watchdogvpn_awg` interface from a previous crash can be interpreted as a live AmneziaWG connection. |
| Scenario | The host already has `watchdogvpn_awg` up before `AmneziaWGDriver.connect()` is called, or after a previous crash left the interface behind. |
| Impact | `awg-quick up` may fail because the interface already exists, but `status()` still reports `connected` whenever `_interface_exists()` returns true, even with no active profile. A stale interface can create misleading state and recovery decisions. |
| Status | OPEN |

Evidence:
- `AmneziaWGDriver.connect()` does not pre-clean or reconcile an existing `watchdogvpn_awg` interface before running `awg-quick up`.
- `AmneziaWGDriver.status()` returns `status="connected"` whenever `_interface_exists()` is true, regardless of `_active_profile`.
- `AmneziaWGDriver.health_check()` also starts from `_interface_exists()` and then checks handshake/ping on the fixed interface name.

### AUD-005

| Field | Value |
|---|---|
| ID | AUD-005 |
| Layer | Layer 2 — Driver and process management |
| Severity | MEDIUM |
| Description | Forced process cleanup assumes `kill()` followed by `wait(timeout=5)` succeeds. |
| Scenario | A subprocess ignores termination, `kill()` is issued, and the second `wait(timeout=5)` also times out or raises. |
| Impact | `disconnect()` can raise instead of returning a clean failure state, leaving the watchdog/recovery caller to handle an unexpected exception path. |
| Status | OPEN |

Evidence:
- `SingBoxDriver.disconnect()` catches the first `TimeoutExpired`, calls `process.kill()`, then calls `process.wait(timeout=5)` without a second guard.
- `OpenVPNDriver.disconnect()` has the same pattern.
- `OpenVPNCloakDriver._stop_process()` has the same pattern for both OpenVPN and `ck-client`.
- Existing tests cover the successful kill-after-timeout path, but not a second timeout after `kill()`.

### AUD-006

| Field | Value |
|---|---|
| ID | AUD-006 |
| Layer | Layer 2 — Driver and process management |
| Severity | MEDIUM |
| Description | `ck-client` crash after the fixed warmup window is detected later, not during connect readiness. |
| Scenario | `ck-client` survives the 1.5 second warmup, OpenVPN starts, then `ck-client` crashes 1-2 seconds later before OpenVPN has a usable tunnel through it. |
| Impact | `connect()` can return `True` for a connection that is about to become `down` or `degraded`. Later `health_check()` catches dead `ck-client`, but startup/manual status can be temporarily misleading. |
| Status | OPEN |

Evidence:
- `OpenVPNCloakDriver.connect()` waits `_CLOAK_STARTUP_WAIT = 1.5`, checks `ck_process.poll()`, starts OpenVPN, and returns true if OpenVPN is alive.
- `OpenVPNCloakDriver.health_check()` correctly returns `down` if `ck-client` or OpenVPN later dies.
- Tests cover `ck-client` crash during the initial warmup, not a crash immediately after OpenVPN starts.

## Checked Scenarios Without Findings

### Local SOCKS port `2080` already occupied

`SingBoxDriver.health_check()` does not report `ok` merely because port `2080`
or `2081` is open. It first checks for a local port, then performs HTTP and
public IP checks through `curl --socks5-hostname 127.0.0.1:2080`. If the port
belongs to a non-SOCKS service or a broken proxy, the HTTP/public-IP checks
should fail and return `degraded`, not `ok`.

Residual risk: `connect()` can still return `True` before sing-box has failed
from a bind conflict if the process has not exited at the instant of `poll()`.
That broader readiness issue is tracked as AUD-002.

### Binary deleted or moved mid-run

Running subprocesses are held by process handle, so deleting a binary path
mid-run does not by itself kill the active subprocess. Future reconnects or new
connect attempts will fail binary discovery and return `False`/raise from
version checks depending on the driver path.

Residual risk: this is not a current orphan-process finding; it is covered by
normal failed reconnect behavior.

### `sing-box run` crashes immediately

If `sing-box` has already exited by the time `health_check()` runs, the driver
returns `down`. Tests cover dead-process health status. The gap is that
`connect()` can return `True` before the immediate crash is observable; that is
tracked as AUD-002.

### Hung disconnect normal path

sing-box, OpenVPN, and OpenVPN+Cloak all attempt terminate-then-kill behavior,
and tests cover the first timeout followed by successful `kill()` cleanup.
The remaining exception path after a failed `kill()` wait is tracked as
AUD-005.

## Recommended Priority Order

### HIGH

1. AUD-001 — Move sensitive temp configs out of predictable `/tmp` paths or use
   secure per-run temp files with restrictive permissions and startup cleanup.
2. AUD-004 — Reconcile stale `watchdogvpn_awg` interfaces before connect/status
   can report connected.
3. AUD-002 — Make connect/startup readiness truthful, or ensure public status is
   not `connected` until health verification passes.

### MEDIUM

4. AUD-006 — Extend OpenVPN+Cloak readiness checks after OpenVPN starts and
   before reporting connect success.
5. AUD-003 — Add version/compatibility validation to availability checks or
   doctor diagnostics, including `ck-client`.
6. AUD-005 — Harden forced cleanup when `kill()` plus second wait still fails.

## Notes For Future Work

- No code changes were made during this audit.
- The findings should feed a future hardening task before or alongside Phase 10,
  depending on priority. They should not be silently fixed inside Phase 10 DNS
  work unless explicitly scheduled.
