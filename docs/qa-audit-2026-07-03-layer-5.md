# WatchdogVPN QA Audit - Layer 5 TUI, CLI Output, and User Experience

> Date: 2026-07-03  
> Protocol: `/home/gabodev/Escritorio/temporales/WatchdogVPN_QA_AUDIT_PROTOCOL.md`  
> Scope: detection and documentation only. No fixes were made during this audit.  
> Follow-up: HIGH and MEDIUM findings must be fixed in the Layer 5 hardening
> closure before the repo maintenance pass starts.

## Audited Surface

- `cli/main.py`
- `tui/VPN`
- `tui/watchdogvpn/render.py`
- `tui/watchdogvpn/commands.py`
- `tui/watchdogvpn/formatting.py`
- `tests/test_cli_profile_commands.py`
- `tests/test_cli_provider_commands.py`
- `tests/test_cli_dns_commands.py`
- `tests/unit/test_tui_modules.py`
- `tests/unit/test_tui_install_layout.sh`

## Findings

### AUD-L5-001

| Field | Value |
|---|---|
| ID | AUD-L5-001 |
| Layer | Layer 5 - TUI, CLI output and user experience |
| Severity | MEDIUM |
| Description | CLI commands do not catch persistent validation errors, so malformed persisted data can produce a Python traceback instead of a clean user-facing error. |
| Scenario | A user or old version leaves `profiles.json` with a valid JSON object containing an unsupported profile field, then runs `watchdog profile list` or `watchdog profile list --json`. |
| Impact | The CLI exits non-zero with a traceback. For `--json` automation the output is absent rather than valid JSON, and stderr is not the stable `error: ...` contract used for parser/provider failures. |
| Status | RESOLVED 2026-07-03 |

Evidence:
- `cli/main.py::main()` catches `ParseError`, provider errors,
  `FileNotFoundError`, DNS errors, `OSError`, and `ValueError`, but not
  `PersistentValidationError`.
- Layer 1 hardening intentionally rejects unsupported persisted fields.
  The rejection is controlled at the store/model layer, but the CLI does not
  translate it into a controlled message.
- Reproduction with a temporary `WATCHDOGVPN_PROFILES_FILE` containing one
  unsupported field produced `config.persistence.PersistentValidationError:
  profile contains unsupported fields: failure_count` followed by a traceback.

### AUD-L5-002

| Field | Value |
|---|---|
| ID | AUD-L5-002 |
| Layer | Layer 5 - TUI, CLI output and user experience |
| Severity | LOW |
| Description | Human-readable CLI list output is unbounded TSV, so very long profile or provider names make narrow terminal output hard to read. |
| Scenario | `watchdog profile list` prints a 195-character profile name or provider-owned node name in a 40-column terminal. |
| Impact | The command completes and JSON output remains valid, but the table becomes visually difficult to scan. Users can work around this with `--json`, terminal wrapping, or filtering. |
| Status | DEFERRED LOW UX DEBT |

Evidence:
- `cli/main.py::_profile_list()` and `_provider_list()` print tab-separated
  columns directly without truncation, width detection, or wrapping.
- A temporary 500-profile store completed quickly, but the first text row with
  a long name exceeded 220 visible characters.
- Validation command results:
  - `watchdog profile list`: 501 text lines, about 0.21 seconds.
  - `watchdog profile list --json`: valid JSON, 210828 bytes, about 0.28
    seconds.

### AUD-L5-003

| Field | Value |
|---|---|
| ID | AUD-L5-003 |
| Layer | Layer 5 - TUI, CLI output and user experience |
| Severity | LOW |
| Description | TUI text fitting uses Python character length rather than terminal display width, so wide Unicode glyphs can be mis-sized in narrow panels. |
| Scenario | A dashboard, location row, status message, or future profile/provider view contains emoji, CJK characters, flags, or other double-width glyphs. |
| Impact | The TUI is unlikely to crash because it truncates strings, but visual alignment can drift and narrow panels can show clipped or shifted text. |
| Status | DEFERRED LOW UX DEBT |

Evidence:
- `tui/watchdogvpn/render.py::fit()` uses `len(text)` after stripping ANSI
  codes and replacing newlines.
- The TUI uses Unicode box drawing and flags by default.
- Existing tests cover ASCII truncation (`render.fit("abcdef", 4) == "abc..."`)
  but not display-width-aware truncation.

### AUD-L5-004

| Field | Value |
|---|---|
| ID | AUD-L5-004 |
| Layer | Layer 5 - TUI, CLI output and user experience |
| Severity | LOW |
| Description | The TUI does not automatically disable ANSI color for `TERM=dumb`; no-color behavior depends on persistent TUI preferences. |
| Scenario | A user opens the TUI in an interactive but minimal SSH/session environment where the terminal is technically a TTY but advertises `TERM=dumb`. |
| Impact | The TUI may emit ANSI escape sequences in a terminal that does not render them correctly. Non-interactive output is handled cleanly, and users can configure `tui.theme = no_color` or `tui.color = false`, so this is a degraded-display issue rather than a functional failure. |
| Status | DEFERRED LOW UX DEBT |

Evidence:
- `tui/VPN::main()` exits cleanly when stdin/stdout are not TTYs.
- `tui/VPN::apply_tui_preferences()` disables color only when config selects
  `no_color` or `tui.color = false`.
- `TERM=dumb` with helper imports still left render defaults available; no
  automatic terminal capability check was found.

## Checked Scenarios Without Findings

### Rich markup escaping

No Rich/Textual renderer is used in the current TUI or CLI output path. The TUI
uses raw ANSI rendering through `tui/watchdogvpn/render.py`, and the CLI uses
plain `print()`. A profile name containing `[prod]`, `*`, and `\` printed
literally in `watchdog profile add`, `watchdog profile list`, and valid JSON.

### CLI JSON completeness for normal paths

`profile list --json`, `provider list --json`, `provider stats --json`, and DNS
JSON paths build the JSON string before printing it. For normal success paths,
the output is complete JSON. The separate AUD-L5-001 finding covers the error
path where a traceback occurs before JSON output.

### `watchdog profile list` with 500 profiles

With a temporary valid `profiles.json` containing 500 profiles, text output
completed in about 0.21 seconds and JSON output completed in about 0.28 seconds.
No performance or completion defect was found.

### TUI non-interactive output

When stdout/stdin are not interactive, `tui/VPN` prints
`VPN requiere una terminal interactiva.` and exits. This behavior is covered by
`tests/unit/test_tui_install_layout.sh`.

### TUI resize behavior

Major TUI render loops call `get_size()` inside each iteration before drawing.
This supports terminal resize between render passes. No crash path was found in
the static audit.

### Unknown VPN/auth statuses

`display_vpn_status()` and `display_auth_status()` return fallbacks for unknown
values instead of crashing. Existing tests cover unknown auth reasons and
degraded VPN status.

### Long-running TUI commands

TUI command helpers generally use subprocess timeouts. Interactive actions route
through `run_with_progress()`, which renders progress and kills the process when
the UI timeout is reached. No indefinite command without visible progress was
found in the audited TUI action path.

## User Data Flow Trace

- CLI profile/provider data is loaded from persistent stores, converted to
  model objects, then printed as plain tab-separated text or JSON.
- Parser/provider errors are converted to `error: ...` messages with non-zero
  exit codes, but persistent validation errors currently bypass that CLI
  contract (AUD-L5-001).
- TUI display text flows through `display_*()`, `semantic_style()`, `fit()`,
  and `write()`. Rendering is raw ANSI rather than Rich markup.
- TUI color behavior is driven by persistent settings, not automatic terminal
  capability detection (AUD-L5-004).

## Recommended Priority Order

### MEDIUM

1. AUD-L5-001 - Catch persistent validation errors at the CLI boundary and
   return stable `error: ...` output without traceback, including for `--json`
   commands.

### LOW

2. AUD-L5-002 - Improve human-readable CLI list output for long names, or
   document `--json` as the intended large-output path.
3. AUD-L5-003 - Add display-width-aware fitting for the TUI if wide Unicode
   layout drift becomes visible in real terminal testing.
4. AUD-L5-004 - Consider auto no-color mode for `TERM=dumb` while preserving
   explicit user color preferences.

## Notes For Hardening Closure

- The closure should avoid Phase 11 rule-store work.
- AUD-L5-001 should be fixed before advancing because it is a MEDIUM CLI
  contract issue and can produce traceback output.
- LOW findings can be fixed if small; otherwise they may be documented as
  accepted/deferred UX debt.

## Hardening Closure - 2026-07-03

### Implemented fixes

- AUD-L5-001: CLI commands now catch `PersistentStoreError` at the command
  boundary and return stable `error: ...` stderr output with exit code `70`
  instead of leaking Python tracebacks.
- Added regression coverage for `watchdog profile list --json` when
  `profiles.json` contains an unsupported profile field. The command now keeps
  stdout empty, reports the persistent validation error on stderr, and does not
  print a traceback.

### Deferred LOW findings

- AUD-L5-002 remains deferred as LOW UX debt. The current CLI list output is
  functional and fast, and JSON output is the stable automation path.
- AUD-L5-003 remains deferred as LOW UX debt. Display-width-aware TUI fitting is
  useful polish, but no crash or broken workflow was found.
- AUD-L5-004 remains deferred as LOW UX debt. No-color mode already exists via
  persistent preferences; automatic `TERM=dumb` handling can be revisited in a
  future TUI polish pass.

### Validation

- `python3 -m py_compile cli/main.py tests/test_cli_profile_commands.py` passed.
- `python3 -m unittest tests.test_cli_profile_commands tests.test_cli_provider_commands tests.test_cli_dns_commands` passed: 23 tests.
- Temporary real CLI reproduction passed: `watchdog profile list --json`
  returned exit code `70`, empty stdout, and `error: profile contains
  unsupported fields: failure_count` on stderr with no traceback.
- `python3 -m unittest discover tests` passed: 458 tests.
- `bash tests/unit.sh` passed.
- `.venv/bin/pytest tests` passed: 474 tests.

### Remaining debt

- No HIGH or MEDIUM Layer 5 debt remains open.
- Deferred LOW UX debt is documented above and should not block the
  Pre-Phase 11 repo maintenance pass.
