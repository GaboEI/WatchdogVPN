# Documentation TODOs

This file records documentation issues that are too broad for small maintenance
passes.

## Roadmap consolidation

Several historical roadmap documents still describe the v0.x alpha planning
line and should remain available as history, but the public documentation needs
a later consolidation pass so new readers can clearly distinguish:

- current v2.0.0 direction and phase status;
- historical v0.x alpha planning documents;
- future v3.0.0 GUI direction.

Candidate files for a dedicated cleanup pass:

- `docs/roadmap.md`
- `docs/product-roadmap.md`
- `docs/roadmap-post-alpha.md`
- `docs/roadmap-v1.1.0.md`
- release notes that mention legacy "advanced DNS" wording from the old
  pre-DNS-v2 architecture.

Keep this as a separate docs task. Do not rewrite those documents as part of
small repo maintenance passes unless the scope is explicitly approved.

## TUI/CLI UX polish from Pre-Phase 11

QA Audit Layer 5 deferred these LOW UX items. They are intentionally assigned
to the future TUI/UX polish work, not to Phase 11 routing rules:

- AUD-L5-002: improve human-readable CLI list output for very long profile and
  provider names, or define an explicit width/truncation policy while keeping
  `--json` as the automation path.
- AUD-L5-003: make TUI text fitting display-width-aware for wide Unicode glyphs
  such as emoji, CJK characters and flags.
- AUD-L5-004: auto-disable color for `TERM=dumb` or equivalent limited
  terminals while preserving explicit user preferences.

The corresponding master-plan task is Phase 12.5.9.
