# GitHub Planning

This document tracks the initial GitHub milestones, labels and issues to create
after the public `v0.1.0-alpha` release.

## Milestones

Create these milestones in GitHub:

| Milestone | Purpose |
| --- | --- |
| `v0.1.1` | Post-release hygiene and support readiness |
| `v0.2.0` | Persistent configuration and migration |
| `v0.3.0` | Professional `watchdogvpn` CLI |
| `v1.0.0` | First stable baseline |
| `v1.1.0` | Internationalization and advanced UX |

## Labels

Recommended labels:

| Label | Color | Purpose |
| --- | --- | --- |
| `security` | `#d73a4a` | Security reporting, hardening and trust boundaries |
| `support` | `#0075ca` | User support and issue-reporting improvements |
| `diagnostics` | `#5319e7` | Reports, logs, doctor and troubleshooting |
| `installer` | `#fbca04` | Install, update and uninstall behavior |
| `tui` | `#1d76db` | Terminal UI work |
| `cli` | `#0e8a16` | Product CLI work |
| `configuration` | `#c2e0c6` | Persistent config and migration |
| `distro` | `#bfd4f2` | Distro compatibility and validation |
| `ci` | `#0052cc` | CI, ShellCheck, shfmt and automation |
| `documentation` | `#0075ca` | Docs, examples and release notes |
| `i18n` | `#5319e7` | Internationalization and translations |
| `v0.1.1` | `#ededed` | Work targeted for v0.1.1 |
| `v0.2.0` | `#ededed` | Work targeted for v0.2.0 |
| `v0.3.0` | `#ededed` | Work targeted for v0.3.0 |
| `v1.0.0` | `#ededed` | Work targeted for v1.0.0 |
| `v1.1.0` | `#ededed` | Work targeted for v1.1.0 |

## Initial Issues

### v0.1.1

#### Add v0.1.1 release notes and tag checklist

Labels: `documentation`, `v0.1.1`

Body:

```markdown
Prepare the follow-up release notes for `v0.1.1`.

Scope:
- summarize post-alpha support improvements;
- mention `SECURITY.md`;
- mention issue templates;
- mention `watchdogvpn report`;
- mention Debian and CachyOS validation updates;
- include known limitations that still remain.

Acceptance criteria:
- `CHANGELOG.md` has a `v0.1.1` section;
- release notes exist or are drafted;
- validation commands pass before tagging.
```

#### Review and improve `watchdogvpn report` redaction

Labels: `diagnostics`, `security`, `support`, `v0.1.1`

Body:

```markdown
Review the first `watchdogvpn report` implementation and improve sanitization
where needed.

Current behavior:
- generates a local report only;
- does not upload anything;
- redacts IPv4 addresses, emails, device-code URLs and the home path.

Follow-up checks:
- consider IPv6 redaction;
- consider private hostnames/domains;
- consider route/interface details;
- keep the report useful for debugging.

Acceptance criteria:
- no silent upload behavior;
- report remains readable;
- tests cover redaction examples.
```

#### Verify `watchdogvpn report` on installed Ubuntu, Debian, Arch and CachyOS

Labels: `diagnostics`, `distro`, `support`, `v0.1.1`

Body:

```markdown
Run `watchdogvpn report` on installed systems and confirm it completes without
requiring interactive input.

Targets:
- Ubuntu 24.04;
- Debian;
- Arch Linux;
- CachyOS.

Acceptance criteria:
- report file is generated;
- output reminds user to review before sharing;
- sensitive values are redacted;
- failures from unavailable optional components are captured as diagnostics.
```

#### Create v0.1.1 release

Labels: `documentation`, `v0.1.1`

Body:

```markdown
Cut the `v0.1.1` post-release hygiene release.

Before tagging:
- CI green;
- `bash tests/unit.sh`;
- `bash tests/syntax.sh`;
- `python3 -m compileall -q tui tests/unit/test_tui_modules.py`;
- `git diff --check`;
- changelog updated.

Release contents:
- security policy;
- issue templates;
- reporting guide;
- public clone smoke test;
- Debian validation update;
- CachyOS detection and validation update;
- `watchdogvpn report`.
```

### v0.2.0

#### Add persistent configuration under `/etc/watchdogvpn/`

Labels: `configuration`, `installer`, `v0.2.0`

Body:

```markdown
Introduce persistent product configuration separate from runtime defaults.

Initial direction:
- create `/etc/watchdogvpn/`;
- evaluate `config.toml`;
- preserve timer, DNS and TUI preferences during update;
- define backup and migration behavior.

Acceptance criteria:
- existing users keep preferences across update;
- missing new keys are added safely;
- reset behavior is explicit.
```

#### Add configuration migration tests

Labels: `configuration`, `ci`, `v0.2.0`

Body:

```markdown
Add tests for config creation, migration and preservation.

Acceptance criteria:
- fresh install creates expected config;
- update preserves user-edited values;
- new defaults are added without replacing the whole file;
- malformed config fails safely.
```

### v0.3.0

#### Expand professional `watchdogvpn` CLI

Labels: `cli`, `documentation`, `v0.3.0`

Body:

```markdown
Expand the product CLI beyond the initial report/status/tui commands.

Target shape:
- `watchdogvpn status`;
- `watchdogvpn tui`;
- `watchdogvpn doctor`;
- `watchdogvpn report`;
- `watchdogvpn config get`;
- `watchdogvpn config set`;
- `watchdogvpn logs`;
- `watchdogvpn version`.

Acceptance criteria:
- `watchdogvpn --help` is clear;
- docs exist in `docs/cli.md`;
- existing low-level commands remain available.
```

### v1.0.0

#### Keep TUI command execution out of shell mode

Labels: `security`, `tui`, `v1.0.0`

Body:

```markdown
Continue reducing shell-string execution in the Python TUI.

Acceptance criteria:
- simple subprocess calls use argument-list helpers;
- shell execution is kept only for pipelines that need shell semantics;
- command builders with dynamic input have tests.
```

#### Promote ShellCheck and shfmt from advisory to required

Labels: `ci`, `security`, `v1.0.0`

Body:

```markdown
Turn shell style checks into required CI once the warnings are cleaned up.

Acceptance criteria:
- ShellCheck passes or justified suppressions exist;
- shfmt output is clean;
- CI fails on new shell style regressions.
```

### v1.1.0

#### Plan TUI internationalization

Labels: `i18n`, `tui`, `v1.1.0`

Body:

```markdown
Plan and design TUI internationalization.

Initial languages:
- English;
- Spanish;
- Russian;
- Persian/Farsi;
- Chinese Simplified;
- Arabic;
- French.

Acceptance criteria:
- translation key strategy exists;
- English fallback behavior is defined;
- RTL terminal limitations are documented.
```

#### Add multilingual documentation skeleton

Labels: `documentation`, `i18n`, `v1.1.0`

Body:

```markdown
Create the structure for translated documentation summaries.

Suggested structure:
- `docs/i18n/README.es.md`;
- `docs/i18n/README.ru.md`;
- `docs/i18n/README.fa.md`;
- `docs/i18n/README.zh_CN.md`;
- `docs/i18n/README.ar.md`;
- `docs/i18n/README.fr.md`.

Acceptance criteria:
- main README links translated summaries;
- translated files clearly say they are summaries, not full docs.
```
