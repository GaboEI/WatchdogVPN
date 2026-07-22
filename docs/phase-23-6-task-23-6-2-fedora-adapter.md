# Phase 23.6 Task 23.6.2 Fedora/Red Hat-Family Adapter

Status: **CLOSED**

Task 23.6.2 implements the Fedora/Red Hat-family distro adapter path derived
from the Task 23.6.1 audit. This is a support-code task, not field
certification. Fedora, RHEL, CentOS, RockyLinux and AlmaLinux detection may
load `distros/fedora.sh` and use WatchdogVPN-managed `dnf` package
reconciliation, but installed certification still belongs to later Phase 23.6
tasks with clean install/update provenance, SELinux/firewalld evidence, real
runtime, real traffic, teardown and doctor state.

## Implementation Criteria

- `lib/distro.sh` resolves explicit Fedora/Red Hat-family IDs to the Fedora
  adapter without relying on broad `ID_LIKE` claims for unknown derivatives.
- `install.sh` and `update.sh` continue to use the shared package contract and
  do not gain ad hoc distro-specific branches.
- `distros/fedora.sh` owns the `dnf` runtime package list for required product
  commands, including firewall tooling, OpenVPN, NetworkManager, Polkit,
  nftables, iptables frontends, process tools and `systemd-resolved`.
- `doctor.sh` remains read-only, reports SELinux/firewalld state for Red
  Hat-family systems, and warns that adapter implementation is not installed
  certification evidence.
- Tests pin Fedora, RHEL, CentOS, RockyLinux and AlmaLinux detection, package
  mapping and non-interactive `dnf` behavior.

## Certification Boundary

No distro is certified by this task. A later Fedora certification green must
prove that every mandatory dependency came from `install.sh`, `update.sh` or an
explicit product-documented path, not from the Workstation baseline or manual
preparation. RHEL-compatible controls remain controls only; actual RHEL remains
credential-gated until the maintainer provides a Red Hat access path.

## Validation

- `bash tests/unit/test_distro_detection.sh`
- `bash tests/unit/test_protocol_dependencies.sh`
- `bash tests/unit.sh`
- `bash tests/syntax.sh`
- `bash -n lib/distro.sh lib/packages.sh distros/fedora.sh doctor.sh install.sh update.sh`
- `git diff --check`
- Fedora 44 VM temporary-copy dry-run: detector loaded `ID=fedora` as
  `supported=1`, `adapter=fedora`, `family=redhat`, and package reconciliation
  printed a non-mutating `sudo dnf install -y ... firewalld systemd-resolved`
  plan.
- Fedora 44 VM `doctor.sh` temporary-copy read-only check reported adapter
  support with the explicit no-certification warning, `resolvectl` present,
  SELinux `Enforcing`, and firewalld `active=active enabled=enabled`.

Python `pytest` was not run on the protected Arch host because neither the
`pytest` command nor the `python -m pytest` module is installed there. No
runtime VPN, DNS, route, firewall, interface or network-service mutation was
performed on the protected Arch host.
