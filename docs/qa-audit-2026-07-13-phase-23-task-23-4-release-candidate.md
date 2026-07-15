# Phase 23 Task 23.4 Release-Candidate Audit

- Date: 2026-07-13
- Branch: phase-23-cli-field-validation
- Audited commit: 24f266b51d12b9c7b1570c64a14f9d3aba16198a
- Protocol: WatchdogVPN_QA_AUDIT_PROTOCOL.md
Outcome: FAIL — Task 23.4 remains OPEN

## Executive summary

The reusable eight-layer QA protocol was executed as a detection-only audit. No product defect was remediated during this work.

The release candidate is not eligible for Phase 23 closure, production declaration, PR, or merge. The audit found 28 open defects:

- 15 HIGH
- 11 MEDIUM
- 2 LOW

The independent release-candidate live matrix is also incomplete. OpenVPN and OpenVPN+Cloak execution was intentionally withheld after the audit proved that imported configurations can preserve executable OpenVPN directives. A bounded live attempt across the remaining historically healthy protocols was aborted when the HTTP/TUN cell captured and terminated the active SSH management session. On reconnection the daemon was still connected with a live TUN and proxy listeners; the auditor performed an explicit disconnect, restored the prior persistent selection, and verified a clean standby state.

Task 23.3.6 and the earlier Task 23.2 field matrix remain useful historical evidence, but they do not replace this independent Task 23.4 result.

## Baseline and environment

The pre-audit baseline was verified without modification:

- source HEAD: 24f266b51d12b9c7b1570c64a14f9d3aba16198a
- true origin branch tip: 24f266b51d12b9c7b1570c64a14f9d3aba16198a
- installed runtime marker: 24f266b51d12b9c7b1570c64a14f9d3aba16198a
- installed_at: 2026-07-13T14:56:29Z
- worktree: clean
- daemon: active, PID 171826
- initial WatchdogVPN state: desired off, clean standby, no product runtime artifacts

An external amn0 interface was observed early in the audit and later disappeared without auditor action. Layer 8 live work began only after a new baseline showed enp0s8 and loopback as the only interfaces, the normal LAN default route, and no external VPN interface.

The installed state and IPC permission contract was correct during inspection:

- /run/watchdogvpn: watchdogvpn:watchdogvpn, mode 0750
- request and event sockets: watchdogvpn:watchdogvpn, mode 0660
- /var/lib/watchdogvpn: watchdogvpn:watchdogvpn, mode 2770
- shared state files: mode 0660
- the desktop user was a member of the watchdogvpn group
- the installed systemd hardening and capability sets matched the source unit

## Prioritized finding index

| ID | Severity | Layer | Summary |
|---|---|---|---|
| AUD-20260713-001 | HIGH | 1 | Persistent rename durability omits parent-directory fsync |
| AUD-20260713-002 | HIGH | 2 | OpenVPN readiness accepts an unrelated TUN/TAP interface |
| AUD-20260713-003 | HIGH | 2 | OpenVPN+Cloak status loses ownership of a live sibling process |
| AUD-20260713-004 | HIGH | 2 | sing-box health can be satisfied by a foreign proxy |
| AUD-20260713-005 | MEDIUM | 2 | OpenVPN+Cloak startup is not transactional |
| AUD-20260713-006 | HIGH | 3 | Lifecycle paths connect after a failed disconnect |
| AUD-20260713-007 | MEDIUM | 3 | Recovery backoff overflows before applying its cap |
| AUD-20260713-008 | HIGH | 4 | Loopback endpoint validation is bypassable and parser-specific |
| AUD-20260713-009 | HIGH | 4 | Manual profile imports are non-atomic |
| AUD-20260713-010 | MEDIUM | 4 | Invalid ports and missing credentials reach runtime generation |
| AUD-20260713-011 | MEDIUM | 4 | Subscription add can leave orphan provider profiles |
| AUD-20260713-012 | MEDIUM | 5 | TUI layout assumes a wide, capable ANSI terminal |
| AUD-20260713-013 | MEDIUM | 5 | TUI text handling permits control-sequence injection and width overflow |
| AUD-20260713-014 | MEDIUM | 5 | Clipboard helpers can block indefinitely |
| AUD-20260713-015 | HIGH | 6 | Daemon restart creates a direct-traffic exposure window |
| AUD-20260713-016 | HIGH | 6 | SIGTERM shutdown omits runtime, DNS, and firewall cleanup |
| AUD-20260713-017 | MEDIUM | 6 | Timed-out IPC mutations continue executing |
| AUD-20260713-018 | LOW | 6 | Command payloads accept unsupported keys |
| AUD-20260713-019 | HIGH | 7 | Interrupted migration can certify truncated state |
| AUD-20260713-020 | HIGH | 7 | Uninstall suppresses teardown failures and removes recovery tools |
| AUD-20260713-021 | MEDIUM | 7 | Runtime replacement and installed-version publication are non-transactional |
| AUD-20260713-022 | HIGH | 8 | Non-sing-box drivers silently ignore DNS and routing policy |
| AUD-20260713-023 | HIGH | 8 | Enabled kill switch is absent during healthy operation and initial failure |
| AUD-20260713-024 | HIGH | 8 | OpenVPN profiles can execute scripts/plugins under daemon capabilities |
| AUD-20260713-025 | HIGH | 8 | TUN health reports success without an egress probe |
| AUD-20260713-026 | MEDIUM | 8 | TUN auto-redirect captured the active SSH management session |
| AUD-20260713-027 | MEDIUM | 8 | Proxy-only health hard-depends on api.ipify.org |
| AUD-20260713-028 | LOW | 8 | Automatic health checks write the raw public IP to a runtime log |

## Detailed findings

### AUD-20260713-001

- ID: AUD-20260713-001
- Layer: Layer 1 — Core logic and state
- Severity: HIGH
- Description: Atomic persistent writes fsync the temporary file but never fsync the parent directory after os.replace.
- Scenario: Power loss or a kernel/storage crash occurs after the rename is visible but before the directory entry is durable.
- Impact: Security-relevant state can revert to the previous inode after reboot, including a desired-state change from on to off or off to on.
- Status: OPEN
- Evidence: config/persistence.py:38-75 calls os.fsync on the file and os.replace, with no parent-directory open/fsync. Focused storage/core tests passed 152 tests but contain no rename-durability failure injection.
- Recommendation: Fsync the containing directory after each atomic replace and add fault-injection tests for the state, profile, provider, policy, and configuration stores.

### AUD-20260713-002

- ID: AUD-20260713-002
- Layer: Layer 2 — Driver and process management
- Severity: HIGH
- Description: OpenVPN and OpenVPN+Cloak can report readiness from an unrelated TUN/TAP interface.
- Scenario: Another VPN already owns tun0 or any TUN/TAP interface while the new OpenVPN process is merely alive.
- Impact: Connect returns success without proof that the selected profile created a usable tunnel.
- Status: OPEN
- Evidence: drivers/openvpn_driver.py:113-131 accepts any TUN/TAP when dev is absent and accepts the configured name without ownership proof; drivers/openvpn_cloak_driver.py:204-218 always accepts any TUN/TAP. A controlled reproduction with only an unrelated tun0 returned true from both readiness paths.
- Recommendation: Bind readiness to process-owned management/status evidence and the exact interface created by the current process generation.

### AUD-20260713-003

- ID: AUD-20260713-003
- Layer: Layer 2 — Driver and process management
- Severity: HIGH
- Description: OpenVPN+Cloak status clears both process references and deletes durable child records when only one child has exited.
- Scenario: The OpenVPN or Cloak child dies while its sibling remains alive.
- Impact: The live sibling becomes unowned and a later disconnect cannot terminate it through the deleted children.json record.
- Status: OPEN
- Evidence: drivers/openvpn_cloak_driver.py:341-360 clears both references and calls configuration cleanup. A real harmless-process reproduction left the sibling alive after status and disconnect; the test process was then explicitly reaped. tests/test_openvpn_cloak_driver.py:377-392 currently encodes the unsafe state transition.
- Recommendation: Preserve ownership of each live child, report a runtime mismatch, and make disconnect reap every retained or recorded sibling before removing evidence.

### AUD-20260713-004

- ID: AUD-20260713-004
- Layer: Layer 2 — Driver and process management
- Severity: HIGH
- Description: sing-box health uses fixed local proxy ports without proving that the listener belongs to the owned sing-box process.
- Scenario: A foreign functional proxy listens on 127.0.0.1:2080 or 2081 while the selected process does not own those listeners.
- Impact: Health reports ok for the wrong process and masks a dead or mismatched VPN runtime.
- Status: OPEN
- Evidence: drivers/singbox_driver.py:1037-1050 and 1099-1158 probe generic ports; health_check at 1382-1405 consumes those results. A controlled foreign-proxy reproduction returned ok while status correctly reported runtime_mismatch from owned PID/socket observation.
- Recommendation: Make health consume the same ownership-qualified listener observation as status and reject foreign listeners.

### AUD-20260713-005

- ID: AUD-20260713-005
- Layer: Layer 2 — Driver and process management
- Severity: MEDIUM
- Description: OpenVPN+Cloak multi-process startup lacks rollback around the second spawn.
- Scenario: Cloak starts successfully and the OpenVPN Popen call then raises, for example because the binary disappears between discovery and execution.
- Impact: The Cloak child and private runtime directory remain after the failed connect request.
- Status: OPEN
- Evidence: drivers/openvpn_cloak_driver.py:242-285 has no transaction or finally block around both Popen calls. Failure injection on the second Popen retained the first process and runtime directory.
- Recommendation: Treat both spawns and their records as one transaction and perform full cleanup on every exception.

### AUD-20260713-006

- ID: AUD-20260713-006
- Layer: Layer 3 — Rotation, recovery and resilience
- Severity: HIGH
- Description: Rotation, reconnect, and driver switching proceed to connect even when disconnect returns false.
- Scenario: A driver cannot terminate its existing process or remove its interface, then rotation or reconnect selects another profile.
- Impact: Two runtimes, routes, DNS paths, or firewall owners can overlap while the operation reports a new selected connection.
- Status: OPEN
- Evidence: rotation/rotation_engine.py:85-98, core/watchdog.py:768-785, and core/watchdog.py:966-975 ignore the disconnect boolean. A controlled rotation returned success and called connect after disconnect returned false.
- Recommendation: Make failed teardown a hard lifecycle barrier and report a structured cleanup failure without starting another driver.

### AUD-20260713-007

- ID: AUD-20260713-007
- Layer: Layer 3 — Rotation, recovery and resilience
- Severity: MEDIUM
- Description: Exponential recovery backoff can overflow before the maximum interval is applied.
- Scenario: The consecutive failure count reaches 1025 with the default base interval.
- Impact: Recovery raises OverflowError instead of producing the capped delay; the worker catches the exception but loses the intended controlled cycle and repeats error handling.
- Status: OPEN
- Evidence: rotation/recovery.py:43-47 calculates the exponential value before min. Attempts 1000 through 1024 returned 300 seconds; attempt 1025 raised OverflowError.
- Recommendation: Cap the exponent before exponentiation or use a threshold comparison that never constructs an unbounded integer/float.

### AUD-20260713-008

- ID: AUD-20260713-008
- Layer: Layer 4 — User input and data validation
- Severity: HIGH
- Description: Loopback endpoint protection is bypassable through alternate IPv4 spellings and is absent from several structured import formats.
- Scenario: An import uses 127.1, 2130706433, 0x7f000001, or a loopback endpoint in sing-box JSON, Clash YAML, Hysteria YAML, or OpenVPN configuration.
- Impact: A remote subscription or imported file can target local services despite the default allow_local=false boundary.
- Status: OPEN
- Evidence: parsers/uri.py:62-78 relies on ipaddress.ip_address. Linux resolved each alternate spelling to 127.0.0.1 while the parser accepted it. parsers/singbox_json.py:59-74 and parsers/clash_yaml.py:150-169 do not apply the same loopback policy.
- Recommendation: Canonicalize endpoints using the platform resolution forms that the runtime will use and enforce one shared local/private endpoint policy across every parser.

### AUD-20260713-009

- ID: AUD-20260713-009
- Layer: Layer 4 — User input and data validation
- Severity: HIGH
- Description: Manual profile imports perform ID selection and per-profile saves without one lock or batch transaction.
- Scenario: Concurrent imports choose the same derived ID, or a later item in a multi-profile import duplicates an existing ID.
- Impact: Two successful callers can silently collapse into one stored profile, and a failed batch can leave earlier profiles committed.
- Status: OPEN
- Evidence: providers/manual_provider.py:77-113 validates and saves sequentially. A barrier-controlled race returned success to both callers but left one profile; a two-item batch raised on the duplicate while retaining the first new profile.
- Recommendation: Lock ID allocation through commit, prevalidate the entire batch, and add an atomic ProfileStore batch operation.

### AUD-20260713-010

- ID: AUD-20260713-010
- Layer: Layer 4 — User input and data validation
- Severity: MEDIUM
- Description: Semantic validation permits impossible ports and missing credentials, and runtime generation substitutes profile IDs as secrets.
- Scenario: Imports contain port 0, port 70000, or empty VLESS/Trojan/Hysteria credentials.
- Impact: Invalid profiles are persisted and either fail much later or authenticate with an unintended display-derived value.
- Status: OPEN
- Evidence: URI import accepted port 0; sing-box JSON accepted 70000; drivers/singbox_driver.py:331-338 does not enforce the port range. URI cases with an empty credential were parsed into host-derived values, and drivers/singbox_driver.py:523-655 falls back to profile.id for several secrets.
- Recommendation: Add protocol-specific semantic schemas before persistence and remove display-ID credential fallbacks.

### AUD-20260713-011

- ID: AUD-20260713-011
- Layer: Layer 4 — User input and data validation
- Severity: MEDIUM
- Description: SubscriptionProvider.add commits profiles before committing the provider record.
- Scenario: ProviderStore.add fails after profile import, including a concurrent provider-limit race or storage error.
- Impact: Orphan profiles remain with a provider_id that does not exist.
- Status: OPEN
- Evidence: providers/subscription_provider.py:59-83 writes the ProfileStore first. An injected ProviderLimitError left the imported provider-owned profile in storage while the provider add failed.
- Recommendation: Commit provider metadata and all owned profiles under one transaction or roll back every inserted profile on provider failure.

### AUD-20260713-012

- ID: AUD-20260713-012
- Layer: Layer 5 — TUI, CLI output and user experience
- Severity: MEDIUM
- Description: The TUI assumes a wide ANSI-capable terminal and does not rerender blocked views on resize.
- Scenario: The TUI runs at 40 columns, under TERM=dumb, or is resized while waiting indefinitely for input.
- Impact: Cursor writes exceed the terminal width, footer controls are unreachable, ANSI/mouse modes are emitted to incapable terminals, and the view remains stale until user input.
- Status: CLOSED by R-25 on 2026-07-15; independent R-28 re-audit remains mandatory.
- Evidence: capability detection now separates redirected, non-ANSI, too-small, compact, and wide terminals before raw/alternate-screen setup. Forty-column dashboards and action selectors use one-column layouts with visible controls; every cursor-addressed write rechecks and clips to the live viewport. A real SIGWINCH wakes blocked input and redraws without keyboard input. Six regressions cover 40/120 columns, `TERM=dumb`, redirected streams, too-small terminals, live SIGWINCH, compact controls, and stale post-resize coordinates; an installed real PTY `TERM=dumb` run emitted no escape bytes.
- Recommendation: Closed. Preserve capability gating, viewport-bounded writes, compact controls, and signal-driven redraw. AUD-013 remains separate for hostile control-string sanitization and Unicode cell-width accounting.

### AUD-20260713-013

- ID: AUD-20260713-013
- Layer: Layer 5 — TUI, CLI output and user experience
- Severity: MEDIUM
- Description: TUI fitting strips only a limited ANSI subset, counts code points instead of display cells, and writes remaining control sequences verbatim.
- Scenario: A status/event/log value contains wide Unicode or an OSC terminal sequence.
- Impact: Text overwrites panel boundaries and untrusted operational text can issue terminal control actions.
- Status: CLOSED by R-26 on 2026-07-15; independent R-28 re-audit remains mandatory.
- Evidence: CLI and TUI now use the shared `terminal_safety` package. The final TUI `write()` boundary strips C0/C1 and complete CSI/OSC/DCS/SOS/PM/APC/unsupported escape sequences, then clips only at complete Unicode display clusters within the live cell budget. Focused regressions pass CJK, combining, flags, emoji modifiers, ZWJ emoji, OSC 52, DCS, CSI and 8-bit C1 payloads through dashboard/event, log, profile, provider, fit and final-write paths. Installed root-runtime and user-TUI imports independently repeated the hostile-string and cell-width assertions.
- Recommendation: Closed. Preserve the shared sanitizer as the final boundary for every untrusted terminal payload and retain cluster-aware geometry for all clipping, padding and centering.

### AUD-20260713-014

- ID: AUD-20260713-014
- Layer: Layer 5 — TUI, CLI output and user experience
- Severity: MEDIUM
- Description: Clipboard import helpers launch external clipboard tools without a timeout.
- Scenario: wl-paste, xclip, xsel, or pbpaste exists but hangs.
- Impact: watchdog profile add --clipboard blocks indefinitely with no bounded recovery.
- Status: CLOSED by R-27 on 2026-07-15, with corrective closure at `cd5dc4e478a1785fc0c1b900c7a03bd669f39f05` after external verification reopened the finding; independent R-28 re-audit remains mandatory.
- Evidence: each supported helper now runs through `Popen(start_new_session=True)` with a two-second communication deadline, group-wide SIGTERM, bounded SIGKILL escalation, and verification that no live process-group member remains before any result is accepted. Linux verification distinguishes a dead zombie awaiting PID-1 collection from an executable survivor, while unreadable or malformed `/proc` observations remain fail-closed. `wl-paste`, `xclip`, `xsel`, and `pbpaste` each have success, nonzero, timeout and real resistant-child cleanup coverage. Missing/unavailable/timeout/cleanup-uncertain paths return actionable human or JSON errors without traceback or helper stderr disclosure. The installed corrected runtime repeated the resistant-child timeout, returned the terminated-group message in 0.748 seconds, and independently proved zombie/live/uncertain classification.
- Recommendation: Closed. Preserve the private-process-group boundary, bounded escalation, cleanup verification and non-disclosure of helper stderr.

### AUD-20260713-015

- ID: AUD-20260713-015
- Layer: Layer 6 — Daemon, IPC, systemd and privilege boundaries
- Severity: HIGH
- Description: A daemon restart with desired state on tears down the active cgroup and waits one watchdog interval before attempting reconnection.
- Scenario: systemctl restart, including the updater restart, occurs while WatchdogVPN is connected and the kill switch is disabled.
- Impact: The default configuration exposes direct host traffic for up to 30 seconds before the first recovery tick.
- Status: OPEN
- Evidence: systemd uses KillMode=control-group; lib/systemd.sh:121-154 performs a real restart. daemon/watchdog_loop.py:56-61 waits before its first tick, and config/app_config.py:29-41 defaults the interval to 30 seconds and kill switch to false. A deterministic loop reproduction recorded first_wait_seconds=[30.0] and zero ticks before the wait.
- Recommendation: Reconcile desired-on state synchronously before READY, preserving a fail-closed path throughout restart.

### AUD-20260713-016

- ID: AUD-20260713-016
- Layer: Layer 6 — Daemon, IPC, systemd and privilege boundaries
- Severity: HIGH
- Description: Graceful daemon shutdown stops threads and sockets but never performs driver, DNS snapshot, or firewall cleanup.
- Scenario: systemd sends SIGTERM while a connection, DNS apply snapshot, LAN gateway, or kill switch is active.
- Impact: Persistent DNS/firewall/routing state can outlive the service, and cleanup depends on incidental cgroup/device behavior rather than the product lifecycle.
- Status: OPEN
- Evidence: daemon/main.py:48-57 stops loops and IPC only; daemon/runtime_worker.py:94-98 stops its thread only; the unit has no ExecStop or ExecStopPost. A patched main invocation returned rc 0 with runtime.disconnect call count zero. core/watchdog.py:408-414 shows that driver teardown, kill-switch handling, and DNS restoration exist only in manual disconnect.
- Recommendation: Add a shutdown-specific cleanup transaction that does not rewrite desired state, and verify SIGTERM plus crash-start reconciliation for every driver and network artifact.

### AUD-20260713-017

- ID: AUD-20260713-017
- Layer: Layer 6 — Daemon, IPC, systemd and privilege boundaries
- Severity: MEDIUM
- Description: An IPC mutation continues on the worker after the request handler has returned a timeout error.
- Scenario: Connect, disconnect, rotate, or node-group auto-test exceeds the server timeout.
- Impact: The user receives failure while the command can later mutate network state, producing an ambiguous and potentially surprising outcome.
- Status: OPEN
- Evidence: daemon/ipc_server.py:80-88 times out only while waiting; daemon/runtime_worker.py:100-108 has no cancellation. A slow connect reproduction timed out for the caller and completed afterward. The client grants node-group auto-test 120 seconds, but the server applies its 30-second request timeout to all commands.
- Recommendation: Use command IDs and explicit cancellation/outcome queries, and align command-specific server and client deadlines.

### AUD-20260713-018

- ID: AUD-20260713-018
- Layer: Layer 6 — Daemon, IPC, systemd and privilege boundaries
- Severity: LOW
- Description: Per-command payload schemas do not reject unsupported fields.
- Scenario: An authorized client sends status or another command with unexpected payload keys.
- Impact: Client/server skew and misspelled fields are silently ignored instead of producing a structured validation error.
- Status: OPEN
- Evidence: The installed daemon accepted status with payload {"unexpected": 1}; top-level unknown envelope fields were correctly rejected. daemon/runtime_worker.py:215-298 validates selected values but does not reject extra payload keys.
- Recommendation: Define and enforce an allowed-key set for every command payload.

### AUD-20260713-019

- ID: AUD-20260713-019
- Layer: Layer 7 — Installer, updater, uninstaller and migration safety
- Severity: HIGH
- Description: Interrupted legacy-state migration can preserve a truncated destination file and still create the completion marker.
- Scenario: cp is interrupted after creating a partial target file, then install/update reruns.
- Impact: The retry refuses to overwrite the existing partial file and marks corrupted shared state as successfully migrated.
- Status: OPEN
- Evidence: lib/runtime.sh:202-209 uses cp -a --update=none followed by touch .migrated. A /tmp reproduction seeded a complete source and truncated target; migration retained "truncated" and created the marker.
- Recommendation: Stage and validate the complete migration under a temporary destination, atomically publish it, and create the marker only after content-level validation.

### AUD-20260713-020

- ID: AUD-20260713-020
- Layer: Layer 7 — Installer, updater, uninstaller and migration safety
- Severity: HIGH
- Description: Uninstall suppresses service-stop and network-rescue failures, then removes the rescue commands and reports completion.
- Scenario: systemd stop, kill-switch deletion, domain-bypass rescue, or DNS rescue fails during uninstall.
- Impact: A live daemon, blocking firewall, stale routes, or broken DNS can remain after the product and its recovery tools are deleted.
- Status: CLOSED by R-24 on 2026-07-14; independent R-28 re-audit remains mandatory.
- Evidence: `uninstall.sh` now aborts before any product-file removal unless daemon inactivity, kill-switch firewall cleanup, domain-bypass route cleanup, and DNS cleanup each return verified success. The strict helpers reject a failed `systemctl`, nftables/iptables, route, or installed DNS cleanup command and emit exact retained-tool recovery instructions. Failure injection covers daemon stop and nftables deletion; ordering regression proves the guards precede product removal. The installed safety library passed the same two injected failure barriers after transactional update.
- Recommendation: Closed. Preserve the fail-closed ordering and strict-helper contract in future uninstall changes.

### AUD-20260713-021

- ID: AUD-20260713-021
- Layer: Layer 7 — Installer, updater, uninstaller and migration safety
- Severity: MEDIUM
- Description: Runtime update deletes the active tree before constructing the replacement and publishes the installed marker before the full install and smoke test complete.
- Scenario: Permission, disk, copy, wrapper, unit, restart, or smoke-test failure occurs after replacement begins.
- Impact: The machine is left with an absent/partial mixed-generation runtime; the marker can claim the new commit before wrappers and services are proven. Recovery is manual from backups.
- Status: OPEN
- Evidence: lib/runtime.sh:127-153 backs up, rm -rf deletes the destination, copies in place, and records the version; install_runtime_files continues with wrappers and units at 76-95. The ERR trap in lib/common.sh:38-63 prints guidance but performs no rollback. A /tmp failure injection removed the old runtime and did not restore it.
- Recommendation: Build a complete staged tree, validate it, atomically switch generations, restart/smoke test, then publish the marker; automatically roll back on any later failure.

### AUD-20260713-022

- ID: AUD-20260713-022
- Layer: Layer 8 — Network leak safety, DNS/routing policy and hostile-environment resilience
- Severity: HIGH
- Description: OpenVPN, OpenVPN+Cloak, and AmneziaWG accept but silently ignore WatchdogVPN DNS, routing, app-policy, chain, LAN, and capture options.
- Scenario: A non-sing-box profile is connected while rule routing, block/direct actions, custom DNS, app policy, chain routing, or LAN sharing is configured.
- Impact: Connect can report success while the user's security policy is not enforced by the live driver.
- Status: OPEN
- Evidence: drivers/base.py:30-36 explicitly states that only sing-box consumes these options. drivers/openvpn_driver.py:133-171, drivers/openvpn_cloak_driver.py:220-286, and drivers/amneziawg_driver.py:572-625 never use them. core/watchdog.py:542-629 passes the options without checking driver compatibility.
- Recommendation: Either implement equivalent policy enforcement per driver or fail closed before connect with an explicit unsupported-policy result.

### AUD-20260713-023

- ID: AUD-20260713-023
- Layer: Layer 8 — Network leak safety, DNS/routing policy and hostile-environment resilience
- Severity: HIGH
- Description: kill_switch.enabled does not install kill-switch rules on successful connect or while the tunnel is healthy.
- Scenario: The tunnel process crashes or its interface disappears before the watchdog exhausts reconnect/rotation.
- Impact: Traffic can fall directly to the normal network during the detection and retry window even though the user enabled the kill switch.
- Status: OPEN
- Evidence: core/watchdog.py:392-402 does not inspect or enable the kill switch. The only enable calls are in all-failed recovery at 985-997 and re-application of an already-active switch at 999-1011. A configured-enabled successful-connect reproduction returned connected=true with zero kill_switch.enable calls.
- Recommendation: Install and verify fail-closed rules as part of the connection transaction, before protected traffic can escape, and keep them coherent through crash/restart.

### AUD-20260713-024

- ID: AUD-20260713-024
- Layer: Layer 8 — Network leak safety, DNS/routing policy and hostile-environment resilience
- Severity: HIGH
- Description: Imported OpenVPN configurations preserve executable script and plugin directives and run them in the capability-bearing daemon.
- Scenario: A local import, backup, or other untrusted OpenVPN source contains script-security 2 with up/down hooks or a plugin path.
- Impact: Code executes as the watchdogvpn service with ambient CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_PTRACE, and CAP_DAC_READ_SEARCH, creating a local capability escalation and network-compromise path.
- Status: OPEN
- Evidence: parsers/openvpn_config.py:63-102 stores the complete raw configuration without a denylist. drivers/openvpn_driver.py:93-104 and drivers/openvpn_cloak_driver.py:142-166 write it unchanged. A safe generation-only reproduction preserved script-security, up, and plugin directives. systemd/watchdogvpn.service:32-33 grants the capability set.
- Recommendation: Parse against a strict supported-directive allowlist, reject all executable/plugin/management/include paths, and run OpenVPN under a narrower separately sandboxed privilege boundary.

### AUD-20260713-025

- ID: AUD-20260713-025
- Layer: Layer 8 — Network leak safety, DNS/routing policy and hostile-environment resilience
- Severity: HIGH
- Description: sing-box TUN health reports ok without proving any remote egress through the selected profile.
- Scenario: sing-box stays alive and creates local ports, TUN, and auto-redirect rules while credentials, endpoint connectivity, or upstream routing is unusable.
- Impact: Connect returns success and health remains ok while protected traffic is blackholed or misrouted; recovery and kill-switch escalation never start.
- Status: OPEN
- Evidence: drivers/singbox_driver.py:1327-1339 gates connect on health_check. In TUN mode, health_check at 1382-1399 returns ok from local artifacts and skips the HTTP/public-IP probes at 1401-1405. A mock reproduction returned tun_health=ok with zero external probe calls.
- Recommendation: Require an ownership-qualified, profile-path egress probe for TUN readiness and ongoing health, with hostile-network-aware multi-endpoint semantics.

### AUD-20260713-026

- ID: AUD-20260713-026
- Layer: Layer 8 — Network leak safety, DNS/routing policy and hostile-environment resilience
- Severity: MEDIUM
- Description: TUN auto-redirect captured and terminated the active LAN SSH management session during the bounded real matrix.
- Scenario: A remote operator connects a TUN profile over an established SSH session without an explicit management-path bypass.
- Impact: The controlling process can be killed before its finally cleanup runs, leaving WatchdogVPN connected and requiring a new session or out-of-band console.
- Status: OPEN
- Evidence: The independent matrix SSH channel ended without buffered output. On immediate reconnection, the daemon was still connected to the HTTP cell with wdvpn-tun0, proxy/DNS listeners, sing-box routing artifacts, and desired state on. Explicit disconnect returned rc 0 and restored clean standby. drivers/singbox_driver.py:253-263 enables strict_route and auto_redirect, while the default final route has no automatic management-session exclusion.
- Recommendation: Add a documented and testable management-path exclusion/preflight for remote operation, or refuse disruptive TUN changes when the control path cannot be preserved.

### AUD-20260713-027

- ID: AUD-20260713-027
- Layer: Layer 8 — Network leak safety, DNS/routing policy and hostile-environment resilience
- Severity: MEDIUM
- Description: Proxy-only health requires a successful response from the single third-party api.ipify.org endpoint.
- Scenario: The VPN works but that service is down, blocked by censorship/DPI, or selectively unreachable.
- Impact: A healthy tunnel is marked degraded and can trigger unnecessary recovery or rotation.
- Status: OPEN
- Evidence: drivers/singbox_driver.py:1128-1158 hardcodes api.ipify.org; health_check at 1401-1405 requires both example.com and a non-empty public-IP response. A mock with working proxy HTTP and unavailable ipify returned degraded.
- Recommendation: Use multiple policy-controlled health targets, distinguish endpoint failure from tunnel failure, and avoid making one third party authoritative.

### AUD-20260713-028

- ID: AUD-20260713-028
- Layer: Layer 8 — Network leak safety, DNS/routing policy and hostile-environment resilience
- Severity: LOW
- Description: Automatic proxy health checks write the raw observed public IP into the private driver log.
- Scenario: A proxy-only health check succeeds.
- Impact: Sensitive network-location data is retained automatically and may be exposed when raw runtime logs are inspected or shared.
- Status: OPEN
- Evidence: drivers/singbox_driver.py:1151-1153 appends public_ip_via_proxy with the raw value. Runtime directories are mode 0700 and support exports redact IPs, which limits but does not remove the privacy exposure.
- Recommendation: Log only success/change metadata or a keyed, non-reversible comparison token; keep raw IP observation opt-in and ephemeral.

## Live matrix status

The shared state contained 127 enabled profiles covering all 12 protocol types. Historical health metadata included at least one ok profile for every protocol:

| Protocol | Profiles | Historical ok |
|---|---:|---:|
| amneziawg | 17 | 2 |
| http | 6 | 3 |
| hysteria2 | 6 | 2 |
| openvpn | 6 | 2 |
| openvpn_cloak | 4 | 2 |
| shadowsocks | 5 | 3 |
| socks | 5 | 3 |
| trojan | 42 | 4 |
| tuic | 5 | 1 |
| vless | 21 | 4 |
| vmess | 4 | 1 |
| wireguard | 6 | 2 |

Task 23.4 did not certify this as a release-candidate matrix:

- OpenVPN and OpenVPN+Cloak: unavailable for execution because AUD-20260713-024 makes running imported raw configurations unsafe. Follow-up owner: WatchdogVPN maintainer through a dedicated remediation task, followed by a clean RC rerun.
- Remaining ten protocols: a bounded independent run was attempted, but the HTTP/TUN cell terminated SSH and invalidated the buffered per-cell evidence. Follow-up owner: WatchdogVPN maintainer after AUD-20260713-025 and AUD-20260713-026 are remediated, using an out-of-band console or a proven management bypass.
- Provider add/update/connect and rotation/recovery RC repetitions: not re-executed after the HIGH blockers because the protocol forbids mixing remediation into the audit and the runtime could not be considered safe for continued disruptive testing. Follow-up owner: WatchdogVPN maintainer in the post-remediation RC audit.
- App-policy no-leak proof: the 2026-07-12 Task 23.2.1 direct/current/block evidence remains valid historical evidence, but no new independent Task 23.4 proof is claimed.

Therefore the acceptance criterion "full matrix executed or explicitly unavailable" is documented, but the unavailable cells remain follow-up work and Task 23.4 cannot close.

## Validation evidence

Focused, non-remediation validation completed during detection:

- Layer 1: 152 Python tests passed; 600 concurrent persistence operations completed without corruption in the tested non-crash path.
- Layer 2: 218 Python tests passed.
- Layer 3: 149 Python tests passed.
- Layer 4: 108 Python tests passed.
- Layer 5: 39 Python tests passed; CLI listing of 500 profiles completed in 0.1242 seconds at 40 columns with valid width and literal markup.
- Layer 6: 108 Python tests passed; systemd, migration, and doctor daemon shell contracts passed.
- Layer 7: 18 Python tests passed; distro, backend selection, install security, mixed-install, layout, update-restart, and migration shell contracts passed. install.sh, update.sh, and uninstall.sh dry-runs each returned rc 0.
- Layer 8: 631 focused Python tests passed in 61.966 seconds.
- All focused suites can be green while the injected and real-system scenarios above still fail; those gaps are the purpose of this audit.

The live-run cleanup was explicitly verified after the SSH interruption:

- watchdog disconnect exit code: 0
- effective state: standby
- TUN active: false
- proxy active: false
- kill switch active: false
- runtime artifacts: empty
- product interfaces: absent
- routes: normal LAN default plus local routes only
- resolver: restored to the pre-run LAN resolver state
- worktree: clean

## Release decision

Task 23.4 remains OPEN and failed its release-candidate gate.

No HIGH or MEDIUM finding may be accepted silently. Each finding requires a separate, authorized remediation task with focused regression coverage, the four mandatory repository gates, installed-runtime validation where applicable, and then a complete rerun of this audit protocol. No PR or merge to main is authorized by this report.

## R-26 / AUD-013 closure (2026-07-15)

Commit `63c1425b40aade084af407907dcf6b8088575f99`
(`fix: harden terminal output rendering`) closes AUD-013 with no accepted
technical debt. A shared, dependency-free `terminal_safety` package now owns
terminal-sequence removal and display-cell geometry for CLI and TUI. It removes
C0/C1 plus complete CSI, OSC, DCS, SOS, PM, APC, and generic unsupported escape
sequences. Its cluster iterator accounts for combining marks, CJK, paired
regional indicators, variation selectors, emoji modifiers, keycaps, and ZWJ
emoji, and no clipping operation splits a display cluster.

The TUI final `write()` primitive sanitizes every text value and clips it to
the current viewport's remaining cells; `fit()`, cell padding, centering and
selection rows use the same contract. Trusted internal style sequences remain
separate from untrusted text. Provider-table sizing in the CLI now also derives
width from sanitized display cells. The package ships in both
`/usr/local/lib/watchdogvpn` and the per-user TUI support directory.

Adversarial tests drive C0/C1, CSI, OSC 52, DCS, CJK, combining, flag, emoji-
modifier and family-ZWJ data through dashboard/event, log, profile, provider,
fit and final-write paths. Mandatory gates passed 1,641 Python tests in 247.611
seconds plus unit, syntax, inventory parity 124/124, and diff. The pushed
functional commit was installed, refreshing daemon PID `18769 -> 32737`;
source, origin and marker aligned at `63c1425`. Installed root and user layouts
both passed direct sanitizer/geometry imports. Doctor returned nested exit zero
with `OK=110 WARN=2 FAIL=0`; status is desired-off clean standby and the bypass
timer remains disabled/inactive. One MEDIUM finding remains (AUD-014). R-27
requires explicit authorization and the independent R-28 gate remains
mandatory; Task 23.4 and Phase 23 remain OPEN and unmergeable.

## R-27 / AUD-014 closure (2026-07-15)

Commit `9b4bd715524d767580eac40f4c673608911bd4a7`
(`fix: bound clipboard helper execution`) closes AUD-014 with no accepted
technical debt. Clipboard readers use a private session/process group and a
two-second communication deadline. Timeout or a leader that leaves descendants
triggers group-wide SIGTERM, a bounded grace period, group-wide SIGKILL, and
verification that the group is absent before any output is accepted. Cleanup
uncertainty fails closed. Helper stderr is retained only internally and never
included in operator errors.

All four supported helpers (`wl-paste`, `xclip`, `xsel`, and `pbpaste`) have
success, empty, nonzero, timeout and actionable-error coverage. In the real
cleanup matrix each helper spawns a child that ignores SIGTERM; every child is
removed by the bounded escalation and the CLI remains responsive. Human and
JSON paths return 65 without traceback for unavailable clipboard services.
Mandatory gates passed 1,647 Python tests in 206.477 seconds plus unit, syntax,
inventory parity 124/124 and diff. The pushed commit was installed, refreshing
daemon PID `34789 -> 47271`; source/origin/marker aligned at `9b4bd71`. The
installed package repeated a resistant-child timeout in 2.513 seconds with no
survivor, and its human/JSON errors passed. Doctor returned nested exit zero
with `OK=110 WARN=2 FAIL=0`; status is desired-off clean standby and the bypass
timer is disabled/inactive. All 28 original findings are remediated. Task 23.4
and Phase 23 remain OPEN and unmergeable until the mandatory independent R-28
re-audit is explicitly authorized, completed, documented and approved.

## R-27 / AUD-014 corrective closure (2026-07-15)

External repetition of the resistant-child regression reopened R-27 after the
initial closure: it failed deterministically when the killed orphan remained a
zombie until PID 1 collected it. `killpg(pgid, 0)` still reports such a process
group, so the first implementation incorrectly treated reaping latency as a
live survivor and returned the cleanup-uncertain error. The test also used a
150 ms startup deadline that could expire before the helper published its
child PID. This was a real portability and verification defect, not a missing
message literal and not a clipboard-helper escape.

Corrective commit `cd5dc4e478a1785fc0c1b900c7a03bd669f39f05`
(`fix: distinguish dead clipboard helper zombies`) defines cleanup success as
the absence of live group members. Linux `/proc/<pid>/stat` inspection treats
only `Z`, `X`, and `x` members as already dead; any unreadable or malformed
observation remains indeterminate and therefore fail-closed. Deterministic
regressions cover zombie-only, live-member, malformed-observation, and real
SIGTERM-resistant descendant cases. The helper startup allowance is 500 ms,
while the complete cleanup assertion remains bounded to three seconds.

The formerly failing test passed 8/8 repetitions. Targeted tests passed 43/43;
mandatory gates passed 1,649 Python tests in 257.050 seconds plus unit, syntax,
inventory parity 124/124 and diff. The commit was pushed and installed, moving
daemon PID `49162 -> 60429`; source, origin and installed marker aligned at
`cd5dc4e`. The installed package proved zombie/live/uncertain classification
and removed a real resistant descendant in 0.748 seconds while returning the
documented terminated-group message. Doctor returned nested exit zero with
`OK=110 WARN=2 FAIL=0`; status remains desired-off clean standby and the domain
bypass timer disabled/inactive. This evidence supersedes the initial R-27
closure evidence above. AUD-014 has no accepted technical debt; all 28 original
findings are remediated, while R-28 remains a mandatory independent gate.
