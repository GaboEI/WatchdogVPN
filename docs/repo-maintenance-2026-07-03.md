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

---

# WatchdogVPN Repo Maintenance Pass - 2026-07-03 v2 Roadmap Refresh

> Protocol: `/home/gabodev/Escritorio/temporales/WatchdogVPN_REPO_MAINTENANCE_PROTOCOL.md`
> Scope: Public repo narrative refresh after PRE-PHASE 12 expanded the v2
> roadmap. Documentation only; no product code changed.

## Checked Areas

- README first impression, product identity and protocol category language.
- Public ROADMAP alignment with the current v2 phase sequence.
- Provider collaboration visibility.
- Security Policy support/version wording.
- GitHub About description, website field, topics and social preview guidance.
- Historical roadmap separation from current roadmap.

## Changes Made

- Rewrote `README.md` as a professional product overview:
  - clearer resilience-layer positioning;
  - current v2 foundation separated from planned v2 phases;
  - resilient vs compatibility protocol categories;
  - install/update/uninstall instructions kept concise;
  - provider and contributor paths made visible.
- Added `docs/providers.md` with accepted profile/subscription families,
  metadata expectations, routing-rule safety and submission guidance.
- Replaced `ROADMAP.md` with a current v2 public roadmap covering completed
  foundations and planned Phases 12-24.
- Replaced `docs/product-roadmap.md` with current product direction instead of
  the older v0.x alpha-line planning.
- Updated `SECURITY.md` so reports are accepted for `main`/v2 development and
  recent alpha lines, and so DNS/routing/app-policy/backup/statistics risks are
  explicitly in scope.
- Updated `docs/github-about.md` with stronger current repository metadata.
- Marked `docs/roadmap.md` as historical so it no longer competes with the
  current root roadmap.
- Updated `CHANGELOG.md` with the documentation refresh.

## Validation

- Local link target check for README referenced docs/files produced no missing
  paths.
- Focused wording scan across touched docs found no new competitor/reference app
  names, placeholder text, stale alpha-status wording, or unsafe shell-execution
  claims in the refreshed public docs.
- Repo changes are documentation-only.

## Deferred Documentation Debt

- Historical release notes and old alpha planning docs intentionally still
  describe the v0.x era. They are not the current roadmap and should not be
  rewritten unless a dedicated historical-doc cleanup task is opened.
- Screenshots were not regenerated because the TUI is intentionally sequenced
  later in the v2 roadmap.

## Result

- The public repo now presents WatchdogVPN as a Linux resilience product with a
  credible v2 roadmap, clear protocol integrity language and visible provider
  collaboration path.
- No HIGH or MEDIUM repo-maintenance debt was identified in the touched public
  surfaces.
