# Cross-Distribution Threat and Compatibility Findings

This note records the cross-distribution threat and compatibility findings that
shaped WatchdogVPN's Red Hat-family and openSUSE support paths. It is a technical
case, not a certification: no distribution named here is certified by these
findings. For current per-distribution support status, see the supported
platforms surface and `docs/validation.md`.

## Problem

WatchdogVPN's install and runtime behavior relied on assumptions that held on
some Linux distributions but not on others. Before extending support to the Red
Hat family (Fedora, Red Hat Enterprise Linux, CentOS Stream, Rocky Linux,
AlmaLinux) and openSUSE (Leap, Tumbleweed), the product had to answer three
questions:

- can it detect the distribution and select a package-management path?
- can it install its required dependencies without assuming they are already
  present?
- can it coexist with the distribution's security and firewall posture without
  weakening it?

## Findings And Resolutions

### Detector and package-manager coverage

- **Finding:** future Red Hat-family handling existed in `lib/distro.sh`, but
  openSUSE fell through to generic unsupported; there was no
  `distros/opensuse.sh` and no `zypper` branch in `lib/packages.sh`.
- **Resolution:** a Red Hat-family detector with a `dnf`/RPM package path
  (`distros/fedora.sh`) and an openSUSE detector with a `zypper` package path
  (`distros/opensuse.sh`, `lib/packages.sh`) are implemented. openSUSE detection
  handles both `opensuse-leap` (stable) and `opensuse-tumbleweed` (rolling)
  release models explicitly.

### Dependencies cannot be assumed present

- **Finding:** control baselines on the Red Hat family showed that `git`,
  `openvpn` and `resolvectl` cannot be assumed installed; some Enterprise
  Linux 9-like images additionally lacked `nft`, `iptables`, `ip6tables` and
  `firewall-cmd`. openSUSE images similarly lacked many required commands at
  baseline.
- **Resolution:** package installation uses the distribution's managed
  package-manager path for every required command. Pre-installing required
  packages manually before WatchdogVPN runs is not a supported install path.

### Security posture must not be weakened

- **Finding:** the Red Hat family can run SELinux enforcing with `firewalld`
  active or inactive, and openSUSE uses AppArmor with image-default tooling
  variation. It is easy to make install succeed by relaxing these controls.
- **Resolution:** the adapters must not disable SELinux, AppArmor or
  `firewalld`. Doctor/support output must report the SELinux enforcing state,
  the `firewalld` active/inactive state and the selected firewall backend, and
  must distinguish an image-default absence of tooling from a
  WatchdogVPN-managed installation. Lowering a security control to pass is not
  acceptable.

### Runtime and sandbox coverage

- **Finding:** a dependency-only pass does not prove the real service runs
  correctly under each family's security sandbox.
- **Resolution:** the real `systemd/watchdogvpn.service` sandbox must be
  exercised on each newly supported family, alongside the package-management
  lifecycle, firewall/nftables interaction and SELinux/AppArmor posture.

## Guarantees

- Red Hat-family and openSUSE support each ship a detector, a package-manager
  path, installer/update/doctor/cleanup coverage and explicit detection tests.
- Detection tests pin each family identifier explicitly, so a new image does not
  silently fall through to generic unsupported behavior.
- The product never trades a security control for a successful install.

## Limitations

- Red Hat Enterprise Linux itself requires a credentialed Red Hat
  account/subscription path. Red Hat-compatible distributions such as AlmaLinux
  and Rocky Linux are compatible controls, not RHEL certification.
- Red Hat Enterprise Linux is family-inferred, not certified.
- A virtual-machine boot, a package-manager probe or a unit dry run is not a
  certification result. A certified release is a release the manifest carries a
  current certification for.
