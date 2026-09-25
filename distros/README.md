# Distribution Support

WatchdogVPN installs and manages its runtime packages through a per-family
distribution definition. Each definition is the single place for
package-manager-specific product data, so no distribution branch is spread
through the CLI. WatchdogVPN selects the correct definition from the local
system and owns package reconciliation for the families it supports.

For AmneziaWG, a distribution definition may provide reviewed guidance commands:

```bash
DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
  "first reviewed command"
  "second reviewed command"
)
```

Those commands are displayed only after an AmneziaWG profile is imported and the
local runtime is missing. WatchdogVPN never executes them. A definition that
does not provide the array gets official upstream links instead of guessed
commands. To support a new distribution, add or extend its definition and the
resolver mapping; do not add distribution branches to the CLI or duplicate the
guidance in Python.

A definition may also provide an optional `DISTRO_AMNEZIAWG_FALLBACK_COMMANDS`
array. It is shown under the primary commands as a from-source fallback for
releases whose packaged path can fail — for example a brand-new Ubuntu series
the AmneziaWG PPA has not published yet, which returns a 404 for that release.
The Ubuntu and Debian definitions use it to offer a userspace `amneziawg-go`
build that needs no prebuilt package, no kernel headers and no DKMS module, so
it works on any release and kernel. Definitions that cannot fail this way leave
it undefined.

Every definition must also cover the complete runtime package set and Python
cryptography package. The package set covers the atomic nftables backend, legacy
iptables cleanup tooling, OpenVPN, ping, process recovery, NetworkManager,
Polkit and notification/runtime utilities; install and update reconcile it
unconditionally.

## Supported releases

<!-- BEGIN GENERATED: compat-support-table -->
| Distribution | Release | Model | Support | Certification | Freshness | Protocols |
| --- | --- | --- | --- | --- | --- | --- |
| AlmaLinux | AlmaLinux 9 | stable | certified | 2026-09-02 | — | All 12 in-scope protocols |
| Arch Linux | Arch Linux | rolling | certified | 2026-08-15 | current (365 days) | All 12 in-scope protocols |
| CachyOS | CachyOS | rolling | certified | 2026-08-16 | current (365 days) | All 12 in-scope protocols |
| CentOS Stream | CentOS Stream | rolling | certified | 2026-09-20 | current (365 days) | All 12 in-scope protocols |
| Debian | Debian 13.6 | stable | certified | 2026-08-14 | — | All 12 in-scope protocols |
| Fedora | Fedora 44 | stable | certified | 2026-08-19 | — | All 12 in-scope protocols |
| Kali GNU/Linux | Kali GNU/Linux | rolling | certified | 2026-09-14 | current (365 days) | All 12 in-scope protocols |
| Linux Mint | Linux Mint 22.3 | stable | certified | 2026-08-14 | — | All 12 in-scope protocols |
| Manjaro | Manjaro | rolling | certified | 2026-09-18 | current (365 days) | All 12 in-scope protocols |
| Pop!_OS | Pop!_OS 24.04 | stable | certified | 2026-09-16 | — | All 12 in-scope protocols |
| Red Hat Enterprise Linux | Red Hat Enterprise Linux 9 | stable | family_inferred | — | — | — |
| Rocky Linux | Rocky Linux 9 | stable | certified | 2026-08-20 | — | All 12 in-scope protocols |
| Ubuntu | Ubuntu 24.04.4 | stable | certified | 2026-08-14 | — | All 12 in-scope protocols |
| Ubuntu | Ubuntu 26.04 | stable | experimental | — | — | — |
| openSUSE Leap | openSUSE Leap 15.6 | stable | certified | 2026-09-08 | — | All 12 in-scope protocols |
| openSUSE Tumbleweed | openSUSE Tumbleweed | rolling | certified | 2026-09-10 | current (365 days) | All 12 in-scope protocols |

<!-- END GENERATED: compat-support-table -->

A release that is compatible by family shares a package-manager family with a
certified release but has no certification of its own, so it is not claimed as
certified. Unrelated derivatives are never silently promoted to supported.
