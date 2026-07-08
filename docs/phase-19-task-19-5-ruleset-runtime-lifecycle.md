# Phase 19 Task 19.5 - Remote and Built-in Rule-Set Runtime Lifecycle

> Date: 2026-07-08
> Status: CLOSED - runtime lifecycle implemented.

## Scope

Task 19.5 promotes the Phase 13.5 trust model into runtime behavior for
`ruleset_remote` and `ruleset_builtin` rule conditions.

WatchdogVPN now owns the rule-set download/cache lifecycle instead of delegating
remote downloads to sing-box. Runtime uses verified local cache files only.
This keeps integrity checks, stale-cache policy, and bootstrap behavior inside
WatchdogVPN.

## Runtime Lifecycle

The lifecycle is implemented in `rules.ruleset_lifecycle`.

Implemented behavior:

- `RuleSetLifecycleManager.refresh()` refreshes all trusted policies, selected
  IDs, or referenced IDs.
- Remote rule sets are downloaded by WatchdogVPN before sing-box starts.
- Remote downloads require HTTPS and an `expected_sha256` pin from the trust
  registry.
- Built-in rule sets load from explicit local source paths.
- Source JSON rule sets are parsed before replacing cache files.
- Binary `.srs` rule sets are checksum-verified and cached as binary files.
- Existing cache files are not overwritten until the new payload passes source
  validation and integrity checks.
- Failed refreshes can keep a fresh existing cache as `stale`.
- Failed or missing critical rule sets refuse runtime start.
- Non-critical unavailable rule sets are skipped by the route generator.
- Cache eviction removes files not owned by trusted policies while preserving
  currently referenced status cache paths.

## Bootstrap Detour Contract

Rule-set refresh happens before sing-box starts and uses WatchdogVPN's Python
downloader, so profile DNS, profile outbound setup, and sing-box rule-set
download behavior cannot deadlock each other.

Generated sing-box config receives only local rule-set declarations:

- `route.rule_set[].type = "local"`
- `route.rule_set[].path = <verified cache path>`
- `route.rules[].rule_set = <WatchdogVPN-generated tag>`

WatchdogVPN intentionally does not emit sing-box `remote` rule-set objects for
these rules. This avoids relying on sing-box remote cache semantics for
security decisions and avoids deprecated `download_detour` behavior.

## Operator Commands

New commands:

```bash
watchdog ruleset status
watchdog ruleset status --json
watchdog ruleset refresh [RULE_SET_ID ...]
watchdog ruleset refresh --referenced-only
watchdog ruleset refresh --force --json
```

`ruleset refresh --referenced-only` selects rule sets referenced by enabled
rule groups. `--force` refreshes even when the cache is not due. `--no-evict`
keeps unowned cache files for diagnostics.

Trust policies remain explicit JSON in `ruleset-trust.json`; this task does not
add a shortcut command that can create an unpinned remote policy.

## Runtime Integration

When routing policy is `rule`, `WatchdogRuntime._connect_options()` now builds a
rule-set runtime plan before connecting:

- referenced rule sets must have trust policies;
- due rule sets are refreshed before connect;
- critical failures raise before the driver starts;
- verified cache declarations and generated tags are passed to the driver.

`SingBoxDriver.generate_singbox_config()` now adds local rule-set declarations
under `route.rule_set` and emits `route.rules[].rule_set` for rules whose
rule-set IDs have verified runtime tags.

The in-process `RuleEngine` and `watchdog rules explain` remain honest
diagnostics: they still report rule-set matches as runtime-required because
Python does not evaluate sing-box rule-set contents as live traffic proof.

## Failure Policy

Failure behavior is inherited from `RuleSetTrustPolicy`:

- critical rule set: `fail-closed`;
- non-critical rule set: `warn-and-skip`.

Checksum mismatch, malformed source JSON, missing built-in source files, and
download failures are recorded in `RuleSetStatus.error`.

Fresh stale cache is allowed only within `max_stale_seconds`. Once cache is too
old or missing, the configured failure behavior applies.

## Validation

Focused validation passed:

```bash
python3 -m unittest tests.test_ruleset_lifecycle tests.test_ruleset_trust tests.test_rules_singbox tests.test_singbox_driver tests.test_core_watchdog tests.test_cli_rules_commands
git diff --check
```

Coverage includes:

- remote SHA-256 verification;
- checksum mismatch without cache mutation;
- stale-cache fallback;
- malformed source rule-set rejection;
- critical missing-policy runtime refusal;
- built-in rule-set manual refresh through CLI;
- sing-box `route.rule_set` declaration generation;
- verified `route.rules[].rule_set` generation.

Full local validation also passed:

```bash
bash tests/unit.sh
bash tests/syntax.sh
python3 -m unittest discover -s tests -p 'test_*.py'
git diff --check
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
```

The full Python suite reported 1056 tests passed and 1 skipped.

## Installed VM Validation

This task changes runtime config generation and connect preflight behavior, so
installed-VM validation was run immediately.

Results:

- `./update.sh --yes` completed after maintainer-provided sudo validation.
- `./doctor.sh` reported installed/source match at
  `45a0cdc2b85a7b2e25a0a160af86fbb7154dcd36`, daemon IPC reachable, `FAIL=0`.
- Installed `watchdog ruleset status --json` loaded a temporary trust registry.
- Installed `watchdog ruleset refresh --referenced-only --force --json` cached a
  built-in rule set and reported `state=loaded`.
- Installed malformed built-in source refresh reported `state=failed` with a
  specific malformed source error and no cache path.
- Installed runtime preflight refused a rule-set reference with no trust policy
  before calling the driver.
- Installed `SingBoxDriver.generate_singbox_config()` emitted local
  `route.rule_set` declarations and `route.rules[].rule_set`.
- Installed `/usr/local/bin/sing-box check -c <generated config>` passed.
- Passive interface/routing checks after the smokes showed the pre-existing
  `tun0`, unchanged default route via `enp0s8`, and unchanged policy rules.

The installed smokes did not start a WatchdogVPN tunnel or apply live capture.
They intentionally avoided disrupting the pre-existing external `tun0`.
