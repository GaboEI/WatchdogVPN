# Phase 23 Branch Gate - CLI-Backed Field Validation

Date: 2026-07-09
Branch: `phase-23-cli-field-validation`
Status: active

## Decision

Phase 23 must be developed on the dedicated branch
`phase-23-cli-field-validation`, not directly on `main`.

No pull request or merge back to `main` may happen until the entire phase is
complete and validated.

The phase may merge back to `main` only after:

- all Phase 23 tasks are complete;
- the real-machine field validation matrix is written and executed, or any
  unavailable item is documented with a concrete reason and follow-up owner;
- every HIGH or MEDIUM field finding is fixed;
- every known bug found during field validation is fixed;
- no known technical debt remains inside Phase 23;
- DNS, routes, firewall, forwarding, system proxy and daemon/runtime cleanup
  are validated where touched;
- docs, external master plan and external memory are updated;
- final local validation passes;
- required VM/lab/operator validation evidence is recorded;
- the phase-specific release-candidate audit has no unresolved HIGH or MEDIUM
  findings;
- the maintainer explicitly approves merge preparation.

The merge back to `main` must use a merge commit. Do not squash Phase 23
history; the field plan, validation evidence, fixes and audit closure commits
are part of the review trail.

## Rationale

Phase 23 intentionally exercises real runtime and network behavior through the
CLI. It can touch VPN profiles, provider updates, daemon behavior, DNS, routes,
firewall rules, kill switch behavior, app policy, recovery and installed-system
cleanup.

Keeping this work branch-only prevents partial validation, incomplete cleanup
proof, unresolved field findings or unsafe runtime changes from landing on
`main`.

## Runtime Safety

Because Phase 23 can affect live network state, commands that may disrupt the
operator session must be prepared as VM/lab/operator-run commands or scripts.
Do not run disruptive validation directly while the current session depends on
an external VPN or mutable system network state.

Local-only documentation, parser, static checks and non-privileged unit tests
may be run directly.

## Initial Task

Start with Task 23.1, the field validation plan. Do not execute real
network/runtime validation before the plan is written, reviewed and explicitly
approved.
