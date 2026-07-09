# Phase 22 Branch Gate - Full CLI Interface

Date: 2026-07-09
Branch: `phase-22-full-cli-interface`
Status: active

## Decision

Phase 22 must be developed on the dedicated branch
`phase-22-full-cli-interface`, not directly on `main`.

The phase may merge back to `main` only after:

- all Phase 22 tasks are complete;
- every CLI command group in scope is implemented or explicitly deferred with
  a written rationale approved by the maintainer;
- JSON contracts for automation-oriented commands are documented and validated;
- human output is reviewed for critical warnings, recovery hints and safe
  wording;
- every mutation validates input and creates backups where the existing product
  contract requires backups;
- no `shell=True` is introduced in the CLI layer;
- no unresolved HIGH or MEDIUM audit findings remain;
- no known bugs or technical debt remain;
- docs, external master plan and external memory are updated;
- final local validation passes;
- installed VM or operator-run validation passes for any task that mutates
  daemon/runtime, DNS, routes, firewall, forwarding, system proxy, installed
  package state or external network behavior;
- the maintainer explicitly approves merge preparation.

The merge back to `main` must use a merge commit. Do not squash Phase 22
history; the architecture audit, command implementations, safety fixes,
validation and audit closure commits are part of the review trail.

## Rationale

Phase 22 turns the CLI into the primary operator and automation surface for the
v2 capability set. It touches command routing, human output, JSON output,
configuration mutation, backups, diagnostics, setup, doctor behavior and
connection lifecycle commands.

Keeping the phase branch-only prevents partially implemented commands,
unstable JSON contracts, incomplete mutation safety or unfinished recovery
wording from landing on `main`.

## Scope Control

Phase 22 may audit CLI architecture and extend the existing CLI. It must not
start a framework rewrite unless Task 22.1 proves a concrete defect that cannot
be solved conservatively and the maintainer approves the migration.

Phase 22 must not start TUI work. The TUI remains sequenced after CLI-backed
field validation.

## Runtime Safety

Tasks that only edit CLI parsing, docs or pure unit-testable command behavior
can be validated locally. Tasks that can affect installed runtime, daemon
state, DNS, routes, firewall, forwarding, system proxy, package installation or
external connectivity need an operator-run VM/lab validation plan before they
are closed.

Do not run network-disruptive validation directly while the operator session
depends on an external VPN. Prepare clear scripts or commands for operator
execution when that kind of validation is required.

## Initial Task

Start with Task 22.1, CLI architecture audit. The default position is to keep
the existing CLI architecture unless the audit identifies a concrete defect
that justifies migration.
