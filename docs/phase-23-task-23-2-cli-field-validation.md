# Phase 23 Task 23.2 - CLI Field Validation Execution

Date: 2026-07-10
Branch: `phase-23-cli-field-validation`
Status: operator-run prepared, evidence pending

## Scope

Task 23.2 executes the approved Task 23.1 field validation plan through the CLI
only. The TUI is not valid evidence for this phase.

This document and its runner do not prove the matrix by themselves. They define
the operator-run execution path and evidence format. Real validation must be
run by the operator in a disposable VM, lab host or explicitly approved field
machine.

## Runner

The primary operator-run wrapper is:

```text
tests/vm/phase23_run_cli_field_section.sh
```

It validates the private manifest, regenerates the runbook, checks the repo
state and then delegates to the Python runner for one matrix section.

The lower-level operator-run helper is:

```text
tests/vm/phase23_cli_field_validation_runner.py
```

It reads the same local no-secrets manifest as the Task 23.1 runbook generator,
executes one matrix section at a time, and writes command evidence under the
manifest's `evidence_dir`.

The runner:

- refuses to run unless `WATCHDOGVPN_FIELD_VALIDATION=1` is set, except in
  `--dry-run`;
- executes commands with Python subprocess argv lists, never `shell=True`;
- captures command, redacted stdout/stderr, return code and timestamps as JSON;
- redacts the provider URL loaded from `provider.url_file`;
- snapshots routes, policy rules, resolver hash, nftables, listeners and
  relevant processes around mutating sections;
- writes a reboot/manual-off runbook instead of auto-rebooting the machine.

It still performs real runtime actions when not in `--dry-run`. Do not run it
from a session that can be cut by VPN, DNS, route, firewall, daemon or reboot
changes.

## Manifest

Start from:

```text
tests/vm/phase23_cli_field_validation_manifest.example.json
```

Create a private local copy outside the repo, for example:

```text
/tmp/watchdogvpn-phase23-field-manifest.json
```

The manifest must reference local fixture files only. Do not paste provider
URLs, private keys, passwords or profile payloads into chat. Do not commit the
local manifest.

Validate the manifest and generate a readable runbook:

```bash
python3 tests/vm/phase23_cli_field_validation_plan.py \
  --manifest /tmp/watchdogvpn-phase23-field-manifest.json \
  --output /tmp/watchdogvpn-phase23-cli-runbook.md
```

Dry-run the runner without executing commands:

```bash
WATCHDOGVPN_PHASE23_MANIFEST=/tmp/watchdogvpn-phase23-field-manifest.json \
tests/vm/phase23_run_cli_field_section.sh --dry-run all
```

## Operator Sequence

Run the real sections deliberately. Do not run `--section all` first.

### External VPN Absent

Lower any external VPN that could mask WatchdogVPN behavior, then run:

```bash
export WATCHDOGVPN_FIELD_VALIDATION=1
export WATCHDOGVPN_PHASE23_MANIFEST=/tmp/watchdogvpn-phase23-field-manifest.json
export WATCHDOGVPN_EXTERNAL_VPN_STATE=absent

tests/vm/phase23_run_cli_field_section.sh preflight
tests/vm/phase23_run_cli_field_section.sh imports
tests/vm/phase23_run_cli_field_section.sh protocols
tests/vm/phase23_run_cli_field_section.sh provider
tests/vm/phase23_run_cli_field_section.sh app-policy
tests/vm/phase23_run_cli_field_section.sh dns
tests/vm/phase23_run_cli_field_section.sh kill-switch
tests/vm/phase23_run_cli_field_section.sh rotation
tests/vm/phase23_run_cli_field_section.sh manual-off
tests/vm/phase23_run_cli_field_section.sh cleanup
```

### External VPN Present

Raise the external VPN deliberately. Confirm the session is recoverable from
the VM console or snapshot before continuing.

Run the same sections with:

```bash
export WATCHDOGVPN_EXTERNAL_VPN_STATE=present
```

DNS apply/reset while an external VPN is present may be marked unavailable only
if the operator determines it would cut the management session. Record the
reason and owner in `12-findings.md`.

## Reboot Coverage

The runner's `manual-off` section writes:

```text
<evidence_dir>/10-reboot-manual-off/reboot-operator-steps.md
```

Run those reboot steps manually from the VM console/snapshot context. Capture
the outputs under the same evidence directory. Do not ask Codex to run reboot
steps from this chat session.

## Findings

Create or update:

```text
<evidence_dir>/12-findings.md
```

Use the Task 23.1 finding template. Every HIGH or MEDIUM finding must become a
Phase 23 fix subtask before Phase 23 can close.

## Local Validation For This Runner

These checks are local-only and do not execute real field validation:

```bash
python3 tests/vm/phase23_cli_field_validation_plan.py \
  --manifest tests/vm/phase23_cli_field_validation_manifest.example.json \
  --output /tmp/watchdogvpn-phase23-example-runbook.md

python3 tests/vm/phase23_cli_field_validation_runner.py \
  --manifest tests/vm/phase23_cli_field_validation_manifest.example.json \
  --section all \
  --dry-run

tests/vm/phase23_run_cli_field_section.sh \
  --dry-run all

python3 -m py_compile \
  tests/vm/phase23_cli_field_validation_plan.py \
  tests/vm/phase23_cli_field_validation_runner.py

bash tests/syntax.sh
git diff --check
```
