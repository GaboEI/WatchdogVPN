# Phase 18 Task 18.4 - Shared-State Permissions Re-Audit

Date: 2026-07-07
Scope: re-audit StateDirectory/shared config permissions after the Phase 2.6
bug. CLI, daemon and installer must not create unreadable or unwritable
shared state for normal operator workflows.

## Objective

Re-verify every place that creates or writes shared state (installer,
daemon, CLI) actually produces group-readable/writable output under
`/var/lib/watchdogvpn`, and that the CLI and daemon genuinely operate on the
same directory.

## Method

Used a research agent to map every file/directory creation site under the
shared config dir across `config/`, `dns/`, `rules/`, `app_policy/`,
`node_groups/`, `metrics/`, `daemon/`, `cli/`, and every shell script that
touches `/var/lib/watchdogvpn` or `/etc/watchdogvpn`, then verified each
finding directly (read the actual code, ran real interpreters/tests) rather
than trusting the summary. This surfaced one critical functional bug, one
real (currently-dormant) permission bypass, one latent env-var collision,
and eight instances of redundant/dead code that narrowly missed being a
bypass by luck of call order.

## Findings And Fixes

### 1. CRITICAL: fresh installs never converge the CLI onto shared state

**This is the most severe finding of the whole audit and the reason this
task could not be closed as "just re-confirm the existing hardening."**

`config/paths.py::resolve_config_dir()` only routes a normal (non-service-
user) CLI process to `/var/lib/watchdogvpn` if `/var/lib/watchdogvpn/.migrated`
exists. That marker was only ever created by
`lib/runtime.sh::migrate_watchdogvpn_shared_state()`, and only when a
**non-empty legacy** `$HOME/.config/watchdogvpn` existed to copy from. On
any machine that never had that pre-existing per-user config - which is
every fresh install going forward, not an edge case - the marker never gets
created, so the CLI (`watchdog profile add`, `watchdog rule ...`, etc., all
of which instantiate `ProfileStore`/`RuleStore`/etc. directly, not via IPC)
permanently uses `$HOME/.config/watchdogvpn`, while the daemon (which always
runs as the `watchdogvpn` service user) permanently uses
`/var/lib/watchdogvpn`. **The two processes never share state at all** on a
genuinely fresh install.

This was never caught by any prior QA audit or VM validation because this
development machine's `.migrated` marker was created back in the Phase 2.6
era (`/var/lib/watchdogvpn/.migrated`, dated 2026-07-03) when real legacy
data still existed to migrate - every subsequent phase's local testing on
this machine ran in the already-converged state, masking the gap for
anyone who never re-tested a truly clean machine.

**Fix:** `migrate_watchdogvpn_shared_state()` in `lib/runtime.sh` now
creates the `.migrated` marker once the shared directory is ready
(existing, or created via `prepare_watchdogvpn_state_directory()`),
regardless of whether there was legacy data to copy. The marker means "the
shared state directory is ready for the CLI and daemon to use," not
literally "a migration copy happened." If there is legacy data, it still
gets copied (`cp -a --update=none`, unchanged); if not, the directory is
simply marked ready. `--dry-run` prints a distinct message for the
no-legacy-data case (`mark WatchdogVPN shared state ready ...`) instead of
claiming a migration that isn't happening.

Regression tests added to `tests/unit/test_watchdogvpn_state_migration.sh`:
target directory pre-existing with no legacy source (and with an empty-but-
present legacy source) must still get the marker. Existing scenarios
(non-default path that doesn't exist yet stays unready, real migration,
non-clobber, idempotent re-run, dry-run) were re-verified unchanged.

### 2. Real permission bypass in `config/backup_manager.py`'s restore-rollback path

`_restore_snapshot()` (invoked only from `restore_backup()`'s `except`
branch, when a partial restore fails partway through) used raw
`path.write_bytes(content)` / `path.unlink()`, bypassing
`config/persistence.py` entirely - no `file_lock`, no atomic tmp+rename, no
shared-mode chmod. Under the daemon's real `UMask=0077`
(`systemd/watchdogvpn.service`), a raw write lands as `0600` -
unreadable/unwritable by the `watchdogvpn` group, the exact bug class as
the historical Phase 2.6 incident. Currently dormant in production
(`restore_backup()` isn't wired into any CLI command yet, only exercised by
tests), but fully implemented and one CLI-wiring commit away from being
live.

**Fix:** added `atomic_write_bytes()` to `config/persistence.py` (sibling
to the existing `atomic_write_text()`, same tmp+fsync+atomic-rename+chmod
pattern, for binary content). `_restore_snapshot()` now wraps each
file's restore in `file_lock(path)` and uses `atomic_write_bytes()`/a
locked `unlink()`, matching the locking convention already used everywhere
else in the codebase (e.g. `rules/rule_store.py`'s `remove_group()`).

New tests: `test_atomic_write_bytes_ignores_restrictive_umask` (in
`tests/test_config_storage.py`, mirrors the existing `atomic_write_text`
umask test) and `test_restore_rollback_writes_group_writable_shared_state`
(in `tests/test_backup_manager.py`, patches `SYSTEM_CONFIG_DIR` to the test
dir and asserts a rollback-restored file is `0660`/`2770` even under
`UMask=0077`).

### 3. Latent env-var name collision: `WATCHDOGVPN_CONFIG_DIR`

The shell side (`lib/config.sh`) and the Python side (`config/paths.py`)
both read an environment variable named `WATCHDOGVPN_CONFIG_DIR`, but they
mean different directories with different permission models:
`/etc/watchdogvpn` (installer product config, `0755`/`0644`, root-owned)
on the shell side vs. the shared runtime state directory
(`/var/lib/watchdogvpn` or `~/.config/watchdogvpn`, `2770`/`0660`) on the
Python side. If a user ever exported `WATCHDOGVPN_CONFIG_DIR` in a shell
session (thinking of one meaning) and then ran a Python CLI command in that
same session, Python would silently redirect all shared state to
`/etc/watchdogvpn`, reproducing an unwritable-shared-state failure by a
different path.

**Fix:** renamed the shell-side variable to `WATCHDOGVPN_ETC_CONFIG_DIR`
(`lib/config.sh`, `uninstall.sh`, `lib/version_marker.sh`, and the three
test files that set it for isolation:
`tests/unit/test_config_helpers.sh`, `tests/unit/test_install_backend_selection.sh`,
`tests/unit/test_install_security_contracts.sh`). Added a static regression
assertion that `lib/config.sh` never reintroduces the colliding name.

**Deliberately not fixed:** `WATCHDOGVPN_CONFIG_FILE` has the same
collision shape (shell: `/etc/watchdogvpn/config.toml`; Python:
`config/app_config.py`'s `AppConfig`, an override for
`resolve_config_dir()/"config.toml"`). This one was **not** renamed: unlike
`WATCHDOGVPN_CONFIG_DIR`, it is a live, widely-used test-isolation
mechanism for `bin/watchdogvpn` itself (dozens of call sites across
`test_vpn_backend.sh`, `test_watchdogvpn_cli.sh`, `test_config_helpers.sh`,
`test_install_backend_selection.sh`, plus real end-user muscle memory for
anyone scripting around `bin/watchdogvpn`). Renaming it would be a much
larger, more invasive change for a similarly low-probability edge case
(requires deliberately exporting the variable across a shell-to-Python
process boundary that normal `sudo`-gated flows don't inherit by default).
This is a conscious, documented scope boundary, not an oversight - flagged
here for whoever picks up Task 18.5/18.7 in case the risk calculus should
be revisited later.

### 4. Redundant raw `mkdir` calls removed (dead code, not a live bug)

Eight call sites did `path.parent.mkdir(parents=True, exist_ok=True)` (or
equivalent) immediately before/inside a `dump_json`/`atomic_write_text`
call that already handles directory creation and shared-mode
normalization via `config/persistence.py`'s `_ensure_parent_dir`, and in
every case were already called from within a `with file_lock(self.path):`
block whose entry had *already* run `_ensure_parent_dir` before the raw
mkdir even executed. These were provably redundant, not merely "safe by
luck" - removing them simplifies the code and tightens the invariant that
directory creation only ever happens through the shared helper:
`config/profile_store.py`, `config/provider_store.py`,
`config/dns_policy_store.py`, `config/app_config.py`, `config/state_manager.py`,
`app_policy/store.py`, `node_groups/store.py`, `rules/rule_store.py` (three
call sites), `config/backup_manager.py` (`_write_json_file`,
`_write_rule_groups`).

Not touched: `config/backup_manager.py:158`'s `output_path.parent.mkdir()`
in `create_backup()` - that path is a user-chosen backup ZIP destination
(e.g. `~/watchdogvpn-backup.zip`), not shared state, correctly out of this
audit's scope. `daemon/ipc_server.py`'s socket-directory `mkdir` - targets
`/run/watchdogvpn` (`RuntimeDirectory=`, not `StateDirectory=`), a
different systemd-managed directory with its own explicit
`os.chmod(socket_path, 0o660)` already in place; out of scope.

## Reviewed And Found Correct (no change needed)

- `systemd/watchdogvpn.service`: `User=watchdogvpn`, `Group=watchdogvpn`,
  `StateDirectory=watchdogvpn`/`StateDirectoryMode=2770`,
  `ConfigurationDirectory=watchdogvpn`/`ConfigurationDirectoryMode=0750`,
  `RuntimeDirectory=watchdogvpn`/`RuntimeDirectoryMode=0750`,
  `UMask=0077`. Confirmed this `UMask=0077` is exactly why findings 2 and 4
  mattered (a raw file create under this umask lands at `0600`).
- `lib/runtime.sh::repair_watchdogvpn_shared_state_permissions()` and
  `prepare_watchdogvpn_state_directory()`: correct division of labor
  (systemd creates `/var/lib/watchdogvpn` pre-configured via
  `StateDirectory=` on first daemon start when no migration ran; the
  installer only repairs permissions when it already knows about the
  directory). No ordering/race window exists between install-time repair
  and the daemon's own directory creation.
- `dns/state_manager.py`'s snapshot save/load: confirmed still routed
  through `file_lock`/`dump_json`/`load_json` (the historically-fixed
  AUD-P26-002 path from the Phase 2.6 audit remains fixed).
- `metrics/store.py` (Phase 16): fully compliant, no raw I/O anywhere.
- `daemon/` (`ipc_server.py`, `runtime_worker.py`, `watchdog_loop.py`,
  `main.py`, `event_bus.py`, `scheduled_rotation_loop.py`,
  `systemd_helper.py`): no direct shared-state file writes at all; only the
  Store/Manager classes above touch disk.
- `cli/main.py`: no raw file writes under the config dir; all mutation goes
  through the Store classes.
- `lib/version_marker.sh`'s installed-version marker
  (`/etc/watchdogvpn/installed-version`, root-owned, `0644`): correctly
  world-readable (needed for `doctor.sh` running as a normal user) and
  intentionally outside `repair_watchdogvpn_shared_state_permissions()`'s
  scope, since it's read-only metadata, not shared read/write state.

## Out Of Scope (noted, not fixed here)

- Whether `/etc/watchdogvpn/config.toml`'s `[backend]`/`[custom_vps]`
  section is meaningfully read by any Python runtime code beyond the TUI's
  bridge parsing (`tui/watchdogvpn/state.py`) is a separate architectural
  question about config-file authority, not a permissions bug - nothing
  found is "unreadable/unwritable," it is simply a second, differently-
  purposed `config.toml` (installer/backend selection vs. runtime
  `watchdog`/`kill_switch`/`dns`/`rotation` settings). Left for whoever next
  touches the config architecture; not conflated with this task's
  permissions scope.

## Tests

- `tests/unit/test_watchdogvpn_state_migration.sh`: two new scenarios
  (marker created with no legacy source; marker created with an empty
  legacy source), existing scenarios re-verified unchanged.
- `tests/test_config_storage.py`: new
  `test_atomic_write_bytes_ignores_restrictive_umask`.
- `tests/test_backup_manager.py`: new
  `test_restore_rollback_writes_group_writable_shared_state`.
- `tests/unit/test_install_security_contracts.sh`: new `assert_not_contains`
  helper + regression assertion that `lib/config.sh` never reintroduces the
  colliding `WATCHDOGVPN_CONFIG_DIR:-` default expression.

## Validation

- `bash tests/unit.sh` passed (18 shell test files).
- `bash tests/syntax.sh` passed.
- `python3 -m unittest discover -s tests -p 'test_*.py'` passed: 1028 tests
  (up from 1026 - the two new Python tests above).
- `git diff --check` passed.
- `PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .`
  passed.
- Manually confirmed on this development machine:
  `python3 -c "from config.paths import resolve_config_dir; print(resolve_config_dir())"`
  correctly prints `/var/lib/watchdogvpn` (this machine's marker predates
  the fix, from a real historical migration - the fix is what guarantees
  *future* fresh installs reach the same state, verified via the new shell
  test rather than a real fresh VM).
- No VM was used to prove a truly from-scratch install (no legacy state,
  no prior `.migrated`) converges end-to-end in a live daemon+CLI session;
  this remains Task 18.6's job. The shell-side and Python-side halves of
  the fix are each independently tested (marker gets created; marker is
  honored), and their integration is exactly what
  `tests/test_config_paths.py::test_migration_marker_uses_system_dir_for_regular_user`
  plus the new migration test together prove, but a real end-to-end VM run
  is the strongest possible proof and is intentionally not claimed here.

## Addendum (2026-07-07, same day): a real `update.sh` run found a second, more severe bug

After closing the findings above, the maintainer asked to actually run
`update.sh` for real (no `--dry-run`) on this development machine, since it
doesn't touch VPN/proxy/TUN networking and is therefore safe to validate
live rather than only in isolated tests. This immediately surfaced a real
production-breaking bug that no isolated unit test had caught:

**Bug: `lib/runtime.sh::PYTHON_RUNTIME_PACKAGES` was missing `metrics` and
`diagnostics`.** After the real update replaced
`/usr/local/lib/watchdogvpn`, `watchdogvpn.service` entered a crash loop:

```
File "/usr/local/lib/watchdogvpn/daemon/runtime_worker.py", line 24, in <module>
    from metrics.recorder import MetricsRecorder
ModuleNotFoundError: No module named 'metrics'
```

`metrics/` was added in Phase 16 and `daemon/runtime_worker.py` has imported
from it ever since; `cli/main.py` separately imports
`from diagnostics.route_dns import ...`. Neither top-level package was ever
added to the list of packages `lib/runtime.sh` actually copies into
`/usr/local/lib/watchdogvpn`. This means **every real (non-dry-run)
install/update since Phase 16 shipped would have produced a daemon that
crashes on startup**, and any real invocation of the installed `watchdog`
CLI wrapper would crash at import time before running any command. This had
never been caught because no real (non-dry-run) `install.sh`/`update.sh` had
been run on this machine (or apparently anywhere) since Phase 16 landed -
every validation across Phases 16, 17 and this phase's earlier findings
used `--dry-run`, which never touches the installed package tree or
restarts the daemon. The `daemon smoke test` added to `install.sh`/`update.sh`
back in the Phase 2.6 audit (AUD-P26-003) worked exactly as designed here -
it caught the failure and reported it clearly instead of silently
continuing - it just had never been exercised for real until now.

**Fix:** added `metrics` and `diagnostics` to
`PYTHON_RUNTIME_PACKAGES` in `lib/runtime.sh`.

**Regression coverage, generalized rather than just patched:** new
`tests/unit/test_python_runtime_packages.sh` does not merely assert the two
specific names. It discovers every top-level Python package in the repo,
walks the AST of every `.py` file under each package currently listed in
`PYTHON_RUNTIME_PACKAGES`, finds every cross-package import, and fails if
any imported top-level package is missing from the list - so a future phase
that adds a new top-level package and forgets to list it here fails CI
immediately instead of only failing on someone's next real install. Verified
this test actually catches the regression: temporarily removed
`metrics`/`diagnostics` from the array and confirmed the test fails with
the exact right message, then restored the fix.

**Real-machine validation performed:** ran `sudo ./update.sh --yes` for real
on this development machine (safe - it does not touch VPN/proxy/TUN
networking, only replaces installed files and restarts the daemon service).
The run itself is what surfaced the bug (daemon smoke test correctly
`[FAIL]`ed with `watchdogvpn.service is not active after install/update`);
`journalctl -u watchdogvpn` showed the exact `ModuleNotFoundError` above.
A second real `sudo ./update.sh --yes` run, with the fix applied, ended
with `doctor.sh` reporting `[OK] daemon active: watchdogvpn.service`,
`[OK] installed runtime matches source checkout`, and
`[OK] daemon IPC status smoke test passed` - the pending item this
addendum originally left open is now confirmed.

## Addendum 2 (2026-07-07, same day): the re-run itself caused a real incident with another VPN client

Confirming the fix above (a second real `sudo ./update.sh --yes` run)
triggered a second, unrelated real incident: `update.sh` unconditionally
runs `systemctl enable --now vpn-domain-bypass.timer` as part of
`enable_systemd_units()`, even when the timer was already active. Because
`vpn-domain-bypass.timer` has `OnActiveSec=30s`, that restart reset its
schedule and caused `vpn-domain-bypass.service` to re-apply this
machine's real, already-configured domain-bypass `ip rule`s (and the
catch-all fallback rule into a custom routing table) about 30 seconds
after the update finished - colliding with another VPN client's profile
the maintainer needed for work at that same moment
(`set routes: add route 0: File exists`). Rebooting did not help, because
the timer stayed enabled and simply re-applied the same rules again. The
maintainer manually stopped/disabled the units and flushed the residual
`ip rule`/routing-table state to recover.

This is not a Task 18.4 finding in the strict sense (it is not about
shared config-file permissions), but it surfaced from the same real
validation effort and is recorded here for continuity. Full detail,
contract and fix in `docs/security.md`'s new "Domain Bypass Network
Safety" section and commit `ce69d8d`. Summary:

- `vpn-domain-bypass.timer` removed from the unconditional
  `SYSTEMD_ENABLE_UNITS` enable-on-every-run list.
- New `enable_vpn_domain_bypass_timer_if_safe()`: never restarts an
  already-active timer; only auto-enables it when real domains are
  configured; respects a new `/etc/watchdogvpn/.domain-bypass-disabled`
  marker so a user's manual disable after a conflict is not silently
  undone by a later install/update.
- New `bin/vpn_domain_bypass_rescue`: official recovery command
  (mirrors `vpn_dns_rescue`), now always run by `uninstall.sh` before
  removing files, since disabling the timer alone does not undo
  already-applied kernel routing state.
- New `tests/unit/test_vpn_domain_bypass_safety.sh` covers the enable/
  skip/marker logic with a stubbed `systemctl`.
- The maintainer's own machine had its manual disable protected with the
  new marker file after this fix, so a future install/update on that
  specific machine will not re-enable domain bypass automatically.

## Acceptance

Task 18.4 closes when:

- [x] every shared-state write path is confirmed to go through
  `config/persistence.py`'s atomic-write + shared-mode-normalization
  helpers, or is explicitly and correctly out of scope;
- [x] the one critical bug found (CLI/daemon permanently split state on
  fresh installs) is fixed, not just documented;
- [x] the one real (dormant) permission bypass found
  (`_restore_snapshot`) is fixed with regression coverage;
- [x] the latent env-var collision is closed for the variable where doing
  so was safe and proportionate, and the one left open is explicitly
  justified rather than silently ignored;
- [x] redundant/dead mkdir call sites are cleaned up across every file
  where they were found;
- [x] the real, production-breaking bug found via an actual live
  `update.sh` run (missing `metrics`/`diagnostics` packages) is fixed, with
  a generalized regression test that would catch any future top-level
  package being forgotten, not just these two;
- [x] full local validation (shell + Python test suites, syntax,
  compileall, whitespace) passes;
- [x] a real (non-dry-run) `update.sh` re-run on this machine, with the fix
  applied, ended with the daemon active and the smoke test passing;
- [x] the unrelated real incident surfaced by that same re-run
  (`vpn-domain-bypass.timer` forced restart conflicting with another VPN
  client) is fixed, with a manual-disable marker so the maintainer's own
  recovery action is not silently undone later, and regression coverage;
- [x] real VM validation of a from-scratch install remains explicitly
  owed to Task 18.6, not claimed as done here.
