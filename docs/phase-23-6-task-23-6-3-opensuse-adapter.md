# Phase 23.6 Task 23.6.3 openSUSE Adapter

Status: **CLOSED**

Task 23.6.3 implements the openSUSE distro adapter path derived from the Task
23.6.1 audit. This is a support-code task, not field certification. Explicit
openSUSE IDs may load `distros/opensuse.sh` and use WatchdogVPN-managed
`zypper` package reconciliation, but installed certification still belongs to
later Phase 23.6 tasks with clean install/update provenance, AppArmor/firewalld
evidence, real runtime, real traffic, teardown and doctor state.

## Implementation Criteria

- `lib/distro.sh` resolves `ID=opensuse`, `ID=opensuse-leap` and
  `ID=opensuse-tumbleweed` to the openSUSE adapter without relying on broad
  `ID_LIKE` claims for unknown derivatives.
- `install.sh` and `update.sh` continue to use the shared package contract and
  do not gain ad hoc distro-specific branches.
- `distros/opensuse.sh` owns the `zypper` runtime package list for required
  product commands, including AppArmor/firewall tooling, OpenVPN,
  NetworkManager, Polkit, nftables, iptables frontends, process tools and
  `systemd-resolved`.
- `lib/packages.sh` installs openSUSE packages through non-interactive
  `zypper`.
- `doctor.sh` remains read-only, reports AppArmor/firewalld state for openSUSE
  systems, and warns that adapter implementation is not installed certification
  evidence.
- Tests pin openSUSE Leap, Tumbleweed and explicit `ID=opensuse` detection,
  package mapping and non-interactive `zypper` behavior.

## Certification Boundary

No distro is certified by this task. A later openSUSE certification green must
prove that every mandatory dependency came from `install.sh`, `update.sh` or an
explicit product-documented path, not from a prepared VM. The existing Leap
15.6 baseline remains useful because it showed many mandatory commands missing
before WatchdogVPN package reconciliation.

## Validation

- `bash tests/unit/test_distro_detection.sh`
- `bash tests/unit/test_protocol_dependencies.sh`
- `bash tests/unit.sh`
- `bash tests/syntax.sh`
- `bash -n lib/distro.sh lib/packages.sh lib/common.sh distros/opensuse.sh doctor.sh install.sh update.sh`
- `git diff --check`
- openSUSE Leap 15.6 VM temporary-copy dry-run: detector loaded
  `ID=opensuse-leap` as `supported=1`, `adapter=opensuse`, `family=suse`, and
  package reconciliation printed a non-mutating `sudo zypper --non-interactive
  install --no-recommends ... systemd-resolved firewalld apparmor-utils` plan.
- openSUSE Leap 15.6 VM `doctor.sh` temporary-copy read-only check reported
  adapter support with the explicit no-certification warning and retained
  `FAIL` status for missing baseline dependencies such as `git`, `logrotate`,
  `openvpn`, `nmcli`, firewall tooling and `resolvectl`.

Private evidence:

`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-6-3-opensuse-adapter`

The directory must remain `0700`; evidence files must remain `0600`.

This repository document defines the adapter boundary and must not be read as
installed certification evidence.
