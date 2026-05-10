# Roadmap v1.1.0

`v1.1.0` is the international product expansion vision for WatchdogVPN.

This work should happen after the stable `v1.0.0` baseline unless a specific
piece is needed earlier for product safety. Configuration persistence, CLI
structure and reporting are intentionally pulled forward into the post-alpha
roadmap because they are foundational.

## Vision

Move WatchdogVPN from a stable Linux system tool into a more accessible,
international and user-friendly product for people working in censored,
unstable or restrictive network environments.

## Module 11: TUI Internationalization

Goal: make the TUI translatable with English as the default language.

Initial language set:

- English
- Spanish
- Russian
- Persian/Farsi
- Chinese Simplified
- Arabic
- French

Recommended structure:

```text
tui/watchdogvpn/i18n/
├── en.json
├── es.json
├── ru.json
├── fa.json
├── zh_CN.json
├── ar.json
└── fr.json
```

Design rules:

- Use translation keys instead of hard-coded UI text.
- Fall back to English when a key is missing.
- Detect `$LANG` as a suggestion, not a forced choice.
- Let users change language from the TUI and CLI.
- Treat Arabic and Farsi right-to-left terminal layout as experimental.

Example CLI direction:

```sh
watchdogvpn config set language es
watchdogvpn config set language en
watchdogvpn config set language ru
```

## Module 12: Multilingual Documentation

Goal: help non-English users understand what WatchdogVPN does before installing
it.

Recommended scope for `v1.1.0`:

- Short translated README files.
- Basic installation instructions.
- Security warning.
- What the project does and does not do.
- How to change language.
- How to report a problem.

Suggested structure:

```text
docs/i18n/
├── README.es.md
├── README.ru.md
├── README.fa.md
├── README.zh_CN.md
├── README.ar.md
└── README.fr.md
```

The main README should remain in English and link to translated summaries.

## Module 13: Advanced Configuration Persistence

Goal: preserve user preferences across updates.

This is important enough that the first implementation belongs before `v1.1.0`,
likely in `v0.2.0`. `v1.1.0` can extend it.

Target configuration shape:

```toml
[language]
current = "en"
auto_detect = true

[timers]
watchdog_interval = "5min"
rotation_interval = "12h"

[dns]
advanced_mode = false
profile = "quad9-doh"

[tui]
theme = "default"
color = true

[feedback]
enabled = false
```

Rules:

- Clean install uses product defaults.
- Update preserves user values.
- New default keys are added safely.
- Reset requires explicit user confirmation.

## Module 14: Feedback and Local Reports

Goal: let users report problems without adding silent telemetry.

Rules:

- Never send logs automatically.
- Generate local reports only with explicit consent.
- Warn users that reports may include networking information.
- Let users review the file before sharing.

Possible command:

```sh
watchdogvpn report
```

Report content should be sanitized:

- WatchdogVPN version.
- OS and distro.
- systemd unit status.
- timer status.
- `vpn_truth_check` output.
- `vpn_auth_check` output.
- recent logs without credentials.
- config summary without secrets.

GitHub support files:

```text
.github/ISSUE_TEMPLATE/
├── bug_report.yml
├── feature_request.yml
└── config.yml
```

## Module 15: Visual Personalization

Goal: support basic TUI readability preferences.

Initial themes:

- `default`
- `high_contrast`
- `no_color`

Possible commands:

```sh
watchdogvpn config set theme high_contrast
watchdogvpn config set color false
```

This should stay simple. It is less urgent than configuration persistence,
reporting and CLI structure.

## Module 16: Professional CLI

Goal: make `watchdogvpn` the primary product command while keeping `VPN` as a
compatibility launcher.

Target command shape:

```sh
watchdogvpn status
watchdogvpn tui
watchdogvpn doctor
watchdogvpn install
watchdogvpn update
watchdogvpn uninstall
watchdogvpn config get
watchdogvpn config set language es
watchdogvpn config set theme high_contrast
watchdogvpn report
watchdogvpn logs
watchdogvpn version
```

This belongs earlier than full `v1.1.0`, likely in `v0.3.0`, because it affects
documentation, support and product identity.

## Module 17: International GitHub and Community

Goal: prepare the public repository for international contributors and users.

Possible additions:

- README language selector.
- Translation request issue template.
- Language correction issue template.
- `CONTRIBUTING.md`.
- `docs/i18n/translation-guide.md`.
- GitHub labels for `translation`, `i18n`, `documentation`, `good first issue`
  and `help wanted`.
- GitHub Discussions if community activity justifies it.

## Priority Order

Priority 1:

- Persistent configuration.
- Professional CLI.
- Local feedback/report flow.

Priority 2:

- TUI internationalization.
- Multilingual documentation.
- Issue templates.

Priority 3:

- Visual themes.
- Discussions.
- Community translation process.

## Non-Negotiable Product Rule

For a VPN/resilience tool, trust matters more than convenience.

No feature in `v1.1.0` should introduce silent telemetry, hidden uploads or
automatic sharing of networking data.
