# QA Audit - Phase 19 Routing Mode And Capture Architecture

Date: 2026-07-08
Status: closed

## Scope

This audit closes Phase 19 after Tasks 19.1 through 19.9. It reviewed:

- versioned routing state in `config/state_manager.py`;
- runtime mapping in `core/watchdog.py` and `drivers/singbox_driver.py`;
- route action validation in `rules.models`, `app_policy.models` and backup
  selection-state validation;
- rule-set lifecycle handling in `rules.ruleset_lifecycle`;
- route and DNS diagnostics in `diagnostics.routing` and
  `diagnostics.route_dns`;
- routing/capture CLI output in `cli/main.py`;
- Phase 19 docs, ADRs and roadmap text.

The audit focused on routing/capture confusion, stale mode wording, state
migration safety, route-action preservation, rule-set runtime safety,
system-proxy cleanup, docs accuracy, accidental runtime use of `active_mode`,
and the Phase 21.5 scheduling of proxy-chain and route-chain runtime work.

## Audit Matrix

| Area | Result | Evidence |
| --- | --- | --- |
| Rule/Global as routing policies | PASS | `WatchdogRuntime._connect_options()` reads `routing_policy`; diagnostics report `routing_policy`; docs define Rule/Global as routing policies. |
| Capture modes | PASS after AUD-P19-001 and AUD-P19-002 | `capture_modes` validates local proxy, TUN and system proxy intent; TUN reports local proxy active; equivalent token order canonicalizes. |
| Route actions | PASS | `default_route_action` accepts only `current`, `direct`, `block`; route/app-policy rules keep `direct`, `current_profile`, `block`, `group:<name>` and `auto_select` where supported; `chain:<name>` rejects. |
| Global semantics | PASS | Global ignores rule groups and applies `default_route_action` to captured traffic in diagnostics and runtime mapping. |
| Rule semantics | PASS | Rule loads rule groups, app policy and verified rule-set runtime plan before driver connect. |
| `active_mode` guardrail | PASS | Runtime mapping reads `routing_policy`, `capture_modes` and `default_route_action`; `active_mode` remains compatibility/display-only output. |
| Rule import compatibility | PASS | Import adapters preview, reject unsafe constructs, require explicit partial import and preserve rollback reporting. |
| Rule-set runtime safety | PASS | Runtime uses WatchdogVPN-verified local rule-set cache declarations; missing critical policy fails before driver connect. |
| System proxy cleanup boundary | PASS | System proxy is representable but runtime fail-closed until apply/restore/cleanup/crash-recovery work lands. |
| Proxy-chain/route-chain scheduling | PASS | ADR 0007 and roadmap schedule chains as Phase 21.5 before Full CLI and v2.0.0; validators reject `chain:<name>` meanwhile. |
| Installed-VM validation evidence | PASS | Tasks that changed runtime routing/capture behavior recorded installed VM validation; this closure changed status reporting/state normalization only. |

## Findings

### AUD-P19-001 - TUN capture status hid the local proxy listener

- Layer: Layer 5 - CLI output and user experience; Layer 8 - Network leak
  safety and routing policy.
- Severity: MEDIUM.
- Status: RESOLVED.
- Description: `SingBoxDriver.status()` reported `proxy_active=False` whenever
  the internal driver compatibility mode was `tun`.
- Scenario: A running sing-box session used the Phase 19 `local_proxy,tun`
  capture shape. The generated config still contained loopback SOCKS/HTTP
  inbounds, but status exposed only TUN as active.
- Impact: Operator and daemon status could under-report the active local proxy
  listener and make TUN appear to replace local proxy rather than coexist with
  it.
- Evidence: `drivers/singbox_driver.py::generate_singbox_config()` always
  builds SOCKS/HTTP inbounds and adds TUN as an additional inbound. The old
  `status()` branch derived `proxy_active` from `_active_mode != "tun"`.
- Fix: `SingBoxDriver.status()` now reports `proxy_active=True` for running
  sing-box sessions; the TUN-specific status test now pins local proxy and TUN
  coexistence.

### AUD-P19-002 - Capture mode validation was unnecessarily order-sensitive

- Layer: Layer 4 - User input and data validation; Layer 1 - Core logic and
  state.
- Severity: LOW.
- Status: RESOLVED.
- Description: `capture_modes` validation accepted only canonical token order,
  so equivalent input such as `tun,local_proxy` failed even though
  `local_proxy,tun` was valid.
- Scenario: A user, script or restored state expressed the same capture set in
  a different token order.
- Impact: The error was recoverable, but it made the state shape less robust
  and could confuse operators because capture modes are a set-like concept.
- Evidence: `parse_capture_modes()` compared the raw tuple directly against
  supported tuples.
- Fix: `parse_capture_modes()` now canonicalizes token order as
  `local_proxy,tun,system_proxy`; `StateManager` persists the canonical string;
  CLI JSON reports canonical arrays.

## Checked Scenarios Without New Findings

- No executable runtime path was found making routing decisions from
  `active_mode`; the remaining driver `mode` parameter is an internal
  compatibility adapter output from the versioned routing state.
- `routing_policy=global` does not load rule groups or app policy and uses
  `default_route_action` for captured traffic.
- `routing_policy=rule` loads rule groups, app policy and verified local
  rule-set declarations.
- Critical missing rule-set trust policy fails before driver connect.
- `system_proxy` states remain runtime fail-closed and do not claim active
  capture.
- `chain:<name>` remains rejected for route rules, app-policy rules/defaults
  and persistent `default_route_action`.
- Public roadmap text now states Rule/Global as routing policies rather than
  modes where that wording could be confused.

## Residual Risk

No HIGH or MEDIUM findings remain open for Phase 19.

System proxy apply/restore runtime remains intentionally not enabled. It is
owned by a later dedicated implementation task with installed-VM validation
requirements.

Proxy-chain and route-chain runtime remains scheduled for Phase 21.5 before
Full CLI and v2.0.0. Until then, validators must continue to reject chain
syntax.

LAN proxy sharing and gateway/router mode remain Phase 20 branch-only work and
must not merge to main without strong VM validation.

## Validation

Focused validation:

```bash
python3 -m unittest tests.test_singbox_driver tests.test_config_storage tests.test_cli_config_commands
```

Result: 130 tests OK.

Full closure validation:

```bash
bash tests/unit.sh
bash tests/syntax.sh
python3 -m unittest discover -s tests -p 'test_*.py'
git diff --check
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
```

Results:

- shell unit checks passed;
- syntax checks passed;
- full Python discovery passed: 1082 tests OK;
- diff whitespace check passed;
- compileall passed.

## Not Revalidated

No live installed VM routing/capture test was run for this closure commit
because the fixes do not start sing-box, apply routes, mutate DNS, create TUN
interfaces, change system proxy settings or touch firewall state. Earlier
Phase 19 tasks recorded installed VM validation for runtime-affecting changes.
