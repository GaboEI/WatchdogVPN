# WatchdogVPN QA Audit — DNS v2 (Phase 10G / Task 10.14)

> Date: 2026-07-02
> Scope: Phase 10 audit and debt closure. Covers DNS behavior across `auto`,
> `off`, `custom`, `advanced`, kill switch active, failed apply, disconnect,
> and the uninstall/rescue path, plus CLI/TUI output and docs.
> Unlike the reusable `WatchdogVPN_QA_AUDIT_PROTOCOL.md` (detection only),
> Task 10.14 requires HIGH/MEDIUM findings to be fixed before Phase 10 closes.
> Findings below were fixed in this same closure pass.

## Audited Surface

- `dns/models.py`, `dns/presets.py`, `dns/resolver_inventory.py`,
  `dns/resolver_parser.py`, `dns/tester.py`, `dns/state_manager.py`,
  `dns/singbox.py`, `dns/hijack.py`, `dns/capabilities.py`
- `drivers/singbox_driver.py`, `drivers/amneziawg_driver.py`,
  `drivers/openvpn_driver.py`, `drivers/openvpn_cloak_driver.py`,
  `drivers/legacy/adguard_driver.py`, `drivers/base.py`
- `core/watchdog.py`, `rotation/rotation_engine.py`
- `core/kill_switch.py`
- `cli/main.py` (`dns status|test|apply|reset`), `tui/watchdogvpn/dns.py`
- `bin/vpn_dns_rescue`, `uninstall.sh`, `lib/runtime.sh`, `doctor.sh`
- `docs/phase-10-design.md`, `docs/demo.md`, `docs/configuration.md`,
  `docs/threat-model.md`, `CHANGELOG.md`, `docs/v2-validation-log.md`

## Findings

### AUD-DNS-001

| Field | Value |
|---|---|
| ID | AUD-DNS-001 |
| Severity | HIGH |
| Description | The DNS v2 policy (custom/advanced channels, FakeIP, ECS, static IP map, DNS diversion rules) is generated and unit-tested in isolation, but was never passed into a live sing-box connection. |
| Scenario | A user connects a profile through `SingBoxDriver` (directly, via `WatchdogRuntime.connect()`/`startup()`, or via a rotation reconnect), then runs `watchdog dns apply --yes --systemd-link <link>` to redirect system DNS to the local entrypoint (`127.0.0.1:53`) that DNS v2's TUN hijack is supposed to serve. |
| Impact | `SingBoxDriver.connect()` called `generate_singbox_config(profile)` with no `dns_policy` argument, so the running sing-box process never got a `dns` section, hijack inbounds, FakeIP server, static IP "hosts" server, or diversion rules — regardless of what the user configured. Once the system resolver was pointed at `127.0.0.1:53`, nothing in the live sing-box process was listening there for DNS. This is a silent failure that appears as success: CLI/TUI commands succeed, tests pass in isolation, but the actual DNS behavior a user configured never took effect. It explains why `custom`/`advanced` mode, FakeIP, ECS, static IP and diversion rules acceptance boxes stayed unchecked in the master plan despite full unit coverage. |
| Root cause | `drivers/singbox_driver.py` `connect()` hard-coded `dns_policy=None`; no caller in `core/watchdog.py` or `rotation/rotation_engine.py` ever loaded/passed a real `DNSPolicy`. The real Phase 10F workstation validation (Task 10.13) did not catch this because it validated `SystemDNSStateManager` mechanics against an already-active external tunnel, not a WatchdogVPN-managed sing-box connection with an embedded policy. |
| Status | RESOLVED 2026-07-02 |

Resolution:
- `drivers/base.py`: `BaseDriver.connect()` now accepts an optional
  `dns_policy: DNSPolicy | None = None`. All driver implementations
  (`SingBoxDriver`, `AmneziaWGDriver`, `OpenVPNDriver`, `OpenVPNCloakDriver`,
  legacy `AdGuardDriver`) accept the parameter; only `SingBoxDriver` uses it
  (per the Phase 10 design: "sing-box is the primary DNS engine for advanced
  behavior").
- `SingBoxDriver.connect()` now forwards `dns_policy` into
  `generate_singbox_config()`.
- `core/watchdog.py`: `WatchdogRuntime` gained a `dns_policy_store:
  DNSPolicyStore` field (`config/dns_policy_store.py`, same store the CLI
  already uses). `connect()`, `startup()`, and `_try_reconnect()` all load
  the current policy and pass it into `driver.connect()`.
- `rotation/rotation_engine.py`: `RotationEngine.rotate()` (and its internal
  `_try_profile`/`_rollback`/`_single_node_check` helpers) now accept and
  forward `dns_policy`, and `core/watchdog.py`'s `_attempt_rotation()` passes
  the loaded policy through, so rotation reconnects also keep DNS behavior
  live.
- Default policy (`DNSPolicy()`, empty channels) still resolves to no `dns`
  section in the generated config, so this is fully backward compatible for
  any user who has not touched DNS v2.
- Added regression coverage:
  `tests/test_singbox_driver.py::test_connect_forwards_dns_policy_to_generated_config`,
  `tests/test_core_watchdog.py::test_connect_forwards_the_stored_dns_policy_to_the_driver`,
  `tests/test_core_watchdog.py::test_startup_forwards_the_stored_dns_policy_to_the_driver`,
  `tests/test_rotation_engine.py::test_single_node_forwards_dns_policy_to_driver_connect`.

### AUD-DNS-002

| Field | Value |
|---|---|
| ID | AUD-DNS-002 |
| Severity | MEDIUM |
| Description | System DNS state (`SystemDNSStateManager` snapshot applied via `watchdog dns apply`) is never automatically restored on VPN disconnect, only via the explicit `watchdog dns reset --yes` command. |
| Scenario | A user runs `watchdog dns apply --yes` while connected, then disconnects the VPN (`WatchdogRuntime.disconnect()`) without also running `watchdog dns reset --yes`. |
| Impact | System DNS keeps pointing at the local entrypoint (`127.0.0.1:53`) with nothing behind it once the tunnel is gone, breaking name resolution until the user manually runs `watchdog dns reset --yes` or `vpn_dns_rescue auto`. `docs/phase-10-design.md:153` states the design intent as "Restore state on disconnect, VPN-off, uninstall, and failed apply," which this does not fully satisfy for the "disconnect" case. |
| Status | RESOLVED 2026-07-02 |

Resolution:
- Re-assessed after initial "accepted risk" triage: `WatchdogRuntime.disconnect()`
  already exists today and does not require any Phase 11/12 CLI work to reach,
  so deferring this was unnecessarily conservative — it is fixed in this same
  audit pass instead.
- Added `dns/state_manager.py::default_snapshot_path()` and `load_snapshot()`
  (shared, `WATCHDOGVPN_DNS_SNAPSHOT_FILE`-aware helpers around the same
  `DNSStateSnapshot` model the CLI already uses for `dns apply`/`dns reset`).
- `WatchdogRuntime` gained `dns_state_manager: SystemDNSStateManager` and
  `dns_snapshot_path: Path` fields. `disconnect()` now calls
  `_restore_dns_snapshot_if_present()`, which loads the snapshot (if any),
  restores it through `SystemDNSStateManager.restore_state()`, and removes the
  snapshot file — mirroring exactly what `watchdog dns reset --yes` does.
- If no snapshot exists, this is a silent no-op (matches "DNS was never
  applied" / already-reset states). If loading or restoring the snapshot
  raises, `disconnect()` logs a warning and still completes — a broken
  snapshot never blocks disconnect, and `watchdog dns reset --yes` /
  `vpn_dns_rescue auto` remain available as manual fallbacks.
- `cli/main.py`'s own `_dns_snapshot_path`/`_load_dns_snapshot` were left
  untouched (different, intentional semantics: the CLI's `dns reset` command
  should error loudly if asked to restore a snapshot that does not exist,
  while `disconnect()` should silently no-op) — not unified to avoid an
  unrelated behavior change in already-tested CLI code.
- Added regression coverage:
  `tests/test_core_watchdog.py::test_disconnect_restores_dns_snapshot_when_present`,
  `tests/test_core_watchdog.py::test_disconnect_does_nothing_when_no_dns_snapshot`,
  `tests/test_core_watchdog.py::test_disconnect_survives_dns_restore_failure`,
  `tests/test_dns_state_manager.py::DNSSnapshotHelperTests` (4 tests).

### AUD-DNS-003

| Field | Value |
|---|---|
| ID | AUD-DNS-003 |
| Severity | LOW |
| Description | Three docs still described DNS v2 as "planned for Phase 10" after Phase 10 shipped, and `CHANGELOG.md` had no entry for the DNS v2 work. |
| Scenario | A reader consults `docs/demo.md`, `docs/configuration.md`, `docs/threat-model.md`, or `CHANGELOG.md` after Phase 10 closes. |
| Impact | Stale docs undersell/misrepresent shipped functionality; no leak or functional risk. |
| Status | RESOLVED 2026-07-02 |

Resolution:
- `docs/demo.md` DNS example now describes the shipped `watchdog dns`
  commands and modes instead of "planned for Phase 10".
- `docs/configuration.md` clarifies that the legacy `dns.advanced_mode` v1 key
  is unrelated to the DNS v2 policy file, instead of saying DNS v2 is
  "planned".
- `docs/threat-model.md` DNS row now describes the actual apply/reset
  snapshot-restore mitigation instead of "restore behavior is planned".
- `CHANGELOG.md` gained an "Added" entry under Unreleased summarizing the
  DNS v2 feature set and the kill switch DNS/DoT ordering hardening.

## Checked Scenarios Without Findings

### OFF mode makes no system DNS calls

`dns/singbox.py::build_singbox_dns_config` returns `None` immediately when
`policy.mode == DNSMode.OFF` (no `dns` section is added to the sing-box
config), and `dns/hijack.py::DNSHijackController.apply()` returns
`applied=False, reason="dns policy is off"` without calling the state manager
at all. Covered by `tests/test_dns_singbox.py::test_off_policy_returns_none`
and `tests/test_dns_hijack.py::test_apply_noops_when_policy_is_off`.

### Kill switch fail-closed on apply failure

`dns/hijack.py::DNSHijackController.apply()` catches apply exceptions and, if
the kill switch is active, raises `DNSHijackError` explicitly stating traffic
is left fail-closed, rather than silently continuing. Covered by
`tests/test_dns_hijack.py::test_failed_apply_with_active_kill_switch_reports_fail_closed`.

### Failed apply leaves no snapshot

`dns/state_manager.py::SystemDNSStateManager.apply_local_dns()` calls
`restore_state()` and re-raises `DNSStateError` on any exception during
`_apply_for_manager()`, so a failed apply always rolls back rather than
leaving a half-applied, unsnapshotted state. Already validated for real on
the workstation in Task 10.13 (closed local entrypoint case).

### Kill switch DNS/DoT rule order and IPv4/IPv6 parity

`core/kill_switch.py` places DNS/DoT reject rules (UDP/TCP 53, 853) before
`established,related` in both the nftables and iptables/ip6tables paths (fix
from commit `0669c0f`), and IPv6 blocking mirrors the IPv4 rule set when
`block_ipv6` is enabled. Already re-validated for real in Task 10.13.

### `vpn_dns_rescue` availability

`bin/vpn_dns_rescue` is installed to `/usr/local/bin/vpn_dns_rescue` by
`lib/runtime.sh`, invoked by `uninstall.sh` on both dry-run and real
uninstall, checked by `doctor.sh`, and used as the `SystemDNSStateManager`
fallback for an unknown resolver manager. No gap found in wiring; there is no
dedicated end-user guide beyond `--help` output and design/threat-model
mentions, accepted as LOW/cosmetic since the tool is discoverable through
`doctor`/uninstall messaging.

### CLI/TUI DNS controls

`cli/main.py` `dns status|test|apply|reset` and `tui/watchdogvpn/dns.py` map
every control to the real CLI handlers with no stub/placeholder paths found.

## Priority Order

1. AUD-DNS-001 (HIGH) — fixed: wire `DNSPolicy` into the live sing-box
   connect path across direct connect, startup autoconnect, reconnect, and
   rotation.
2. AUD-DNS-002 (MEDIUM) — fixed: restore system DNS state automatically on
   `WatchdogRuntime.disconnect()` when a snapshot exists.
3. AUD-DNS-003 (LOW) — fixed: refresh stale "planned for Phase 10" docs and
   add the missing CHANGELOG entry.

## Closure — 2026-07-02

All HIGH, MEDIUM, and LOW findings from this audit were fixed in this same
pass — no findings remain open or accepted-risk.

Validation:
- `python3 -m unittest discover tests` — PASS, 436 tests.
- `bash tests/unit.sh` — PASS.
- `.venv/bin/pytest tests` — PASS, 452 tests.
- `git diff --check` — PASS.

## Notes For Future Work

- Phase 11/12: once the full connect/disconnect CLI lifecycle lands, evaluate
  whether rotation profile switches should also re-`apply` system DNS state
  (not just re-embed the policy in the new sing-box config), and whether
  `WatchdogRuntime.connect()` should offer an equivalent auto-apply path
  symmetric to the new auto-restore-on-disconnect behavior.
- There is currently no CLI/TUI command to mutate `DNSPolicy.channels`,
  `rules`, `static_ips`, or FakeIP/ECS settings — only `dns-policy.json` is
  hand-edited. This matches Task 10.11's documented scope (status/test/apply/
  reset only) and is not a Task 10.14 finding, but worth flagging for
  whichever future task adds a DNS policy editor command.
