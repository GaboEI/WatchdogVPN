# WatchdogVPN Repo Maintenance Pass - 2026-07-03

> Protocol: `/home/gabodev/Escritorio/temporales/WatchdogVPN_REPO_MAINTENANCE_PROTOCOL.md`  
> Scope: Pre-Phase 11 Block 4. Small documentation coherence and repo hygiene
> changes only.

## Checked Areas

- README, ROADMAP and CHANGELOG coherence.
- Removed guided third-party DNS integration references.
- DNS v2 shipped-state documentation.
- Root documentation links.
- Repo hygiene basics: license, gitignore, branch state and sensitive-word
  history scan.

## Changes Made

- Updated README DNS v2 wording so the removed guided third-party DNS
  integration remains outside the product.
- Updated `docs/dns-cli.md` so DNS v2 is described as shipped behavior rather
  than still being under Phase 10 validation.
- Updated `docs/security.md` so DNS v2 guidance no longer says "when Phase 10
  lands".
- Added a compact "Recent v2 Phase Status" section to `ROADMAP.md`, covering
  completed Phases 5.5, 7, 8, 9, 9.5, 10 and Pre-Phase 11 QA Layers 1, 4 and 5.
- Added `docs/todo-docs.md` for larger documentation consolidation work that is
  intentionally out of scope for this small pass.

## Validation

- Local README/ROADMAP/CHANGELOG link check found `0` missing local links.
- `LICENSE`, `.gitignore` and `SECURITY.md` are present.
- Branch list is clean: `main`, `origin`, and `origin/main`.
- Sensitive-word history scan was run with:
  `git log --all -p -- . ':!tests' ':!docs/release-notes-*' | grep -iE 'password|api_key|secret|BEGIN.*PRIVATE' | head -n 80 || true`
- The scan showed code/docs references to field names and examples, not exposed
  real credentials in the reviewed output.

## Deferred Documentation Debt

- Historical v0.x roadmap and release-note wording still uses "advanced DNS" in
  legacy context. This is documented in `docs/todo-docs.md` rather than rewritten
  in this pass.
- Screenshots were not regenerated. Existing screenshot files are present under
  `docs/assets/`; visual refresh can be handled in a dedicated release polish
  task if needed.

## Result

- No HIGH or MEDIUM repo-maintenance debt was left open.
- Remaining documentation debt is LOW historical cleanup and does not block the
  Pre-Phase 11 closure block.
