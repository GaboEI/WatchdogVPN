# Phase 23.6 Task 23.6.1 Threat/Compatibility Audit

Status: **IN PROGRESS**

Baseline commit: `7441701`

Task 23.6.1 covers Fedora, the wider Red Hat/RHEL-compatible family, and
openSUSE before any new support is claimed. This is an audit and lab-selection
task only: a VM boot, package-manager probe, or unit dry run is not a distro
certification green.

## Evidence

Private evidence is stored outside the repository under:

`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-6-1-threat-compat-audit`

The directory must remain `0700`; evidence files must remain `0600`.

Current evidence files:

- `opensuse_leap_baseline_20260722T0826Z.log`
- `redhat_opensuse_vagrant_lab_20260722T084044Z.log`

## Vagrant Lab Findings

All attempted Vagrant guests used the Phase 23.5/23.6 generic Vagrantfile in
bridge-only mode with `VAGRANT_EXPERIMENTAL=none_communicator`. No guest was
started with a graphical interface. No WatchdogVPN install or runtime support
claim was attempted.

| Target | Box | Result | Certification meaning |
| --- | --- | --- | --- |
| openSUSE Leap 15.6 | `opensuse/Leap-15.6.x86_64` `15.6.13.356` | Booted bridge-only and produced an internal baseline over direct SSH. | Usable as the current openSUSE baseline candidate. |
| openSUSE Tumbleweed | `opensuse/Tumbleweed.x86_64` `1.0.20241025` | Imported and booted bridge-only, but did not expose a reachable SSH/IP path in this lab run. | Not sufficient for internal baseline evidence yet. |
| AlmaLinux 9 official | `almalinux/9` `9.7.20260518` | Imported and booted bridge-only, but did not expose a reachable SSH/IP path in this lab run. | Useful topology check, not sufficient for internal Red Hat-family baseline evidence. |
| RockyLinux 9 | `bento/rockylinux-9` `202510.26.0` | Imported and booted bridge-only, but did not expose a reachable SSH/IP path in this lab run. | Useful topology check, not sufficient for internal Red Hat-family baseline evidence. |
| AlmaLinux 9 bento | `bento/almalinux-9` `202511.24.0` | VirtualBox 7.0.16 rejected the OVF before boot because it contains an NVRAM hardware item with `ResourceType=32768`. | Box/provider incompatibility; not WatchdogVPN evidence. |

Fedora official Vagrant Cloud names such as `fedora/44-cloud-base` were not
available through `vagrant cloud box show` during discovery. Fedora's official
Cloud download page currently lists Fedora Cloud 44 Vagrant VirtualBox media as
beta, so the Fedora certification image still needs an explicitly pinned,
checksum-verified source before Task 23.6.5.

Actual RHEL should not be treated as a free automatic VM target. Red Hat
Developer access can provide RHEL images, but it requires a Red Hat account and
subscription/registration workflow. Until the maintainer provides that
credentialed path, AlmaLinux or RockyLinux are only RHEL-compatible controls,
not RHEL certification.

## openSUSE Leap Baseline

The openSUSE Leap 15.6 baseline shows:

- `/etc/os-release`: `ID=opensuse-leap`, `ID_LIKE="suse opensuse"`.
- Kernel: `6.4.0-150600.23.22-default`.
- PID 1: systemd.
- Network baseline: only `lo` and bridged `eth0`; default policy rules.
- `/dev/net/tun` exists.
- `NetworkManager`, `systemd-resolved`, and `firewalld` are inactive at image
  baseline.
- Present commands include `zypper`, `rpm`, `systemctl`, `systemd-run`,
  `sudo`, `python3`, `curl`, `tar`, `ip`, `ss`, `ping`, and `setpriv`.
- Missing required WatchdogVPN commands include `git`, `logrotate`, `nmcli`,
  `nft`, `iptables`, `ip6tables`, `openvpn`, `modinfo`, `pkaction`,
  `resolvectl`, `firewall-cmd`, `aa-status`, and `getenforce`.

This is a strong dependency-provenance baseline: any future openSUSE green must
come from WatchdogVPN installing or explicitly guiding these requirements, not
from manual pre-installation or a prepared machine.

## Product Gaps Before Implementation

- `lib/distro.sh` has future Red Hat-family handling for Fedora/RHEL/CentOS/
  Rocky/AlmaLinux, but openSUSE currently falls through to generic unsupported.
- `distros/fedora.sh` exists as a future `dnf`/RPM package foundation, but the
  detector deliberately keeps the family unsupported.
- There is no `distros/opensuse.sh`.
- `lib/packages.sh` has no `zypper` install branch.
- Red Hat-family detection tests cover Fedora and RHEL, but should also pin
  CentOS, RockyLinux and AlmaLinux behavior before support work starts.
- openSUSE detection tests should pin both `ID=opensuse-leap` and
  `ID=opensuse-tumbleweed` with `ID_LIKE="suse opensuse"`.
- Fedora/Red Hat-family validation must record SELinux enforcing state,
  firewalld state, nftables/iptables interaction, package-manager lifecycle,
  and the real `systemd/watchdogvpn.service` sandbox.
- openSUSE validation must record AppArmor state, firewalld state when present
  or image-default absence when absent, zypper lifecycle, nftables/iptables
  interaction, and the real `systemd/watchdogvpn.service` sandbox.
- Lowering SELinux/AppArmor/firewalld to get a green is not acceptable.

## Authoritative Source Notes

- Fedora Developer documentation confirms official Fedora Vagrant boxes exist,
  but the Fedora Cloud 44 Vagrant VirtualBox artifact discovered for this audit
  is still listed as beta on Fedora's Cloud download page.
- openSUSE documentation identifies official Vagrant boxes such as
  `opensuse/Tumbleweed.x86_64`; Vagrant Cloud also provides
  `opensuse/Leap-15.6.x86_64`.
- Red Hat Developer documentation requires a Red Hat account/subscription path
  for actual RHEL access. RHEL-compatible clones cannot be represented as RHEL
  certification.
- openSUSE uses `zypper` as its native package-management path.

## Next Gate

Task 23.6.1 should not close until the Red Hat-family lab image path is
observable by direct bridge SSH or an equivalent maintainer-approved console
baseline. After that, implementation can proceed in Task 23.6.2 and Task
23.6.3 without confusing lab-provider limits with WatchdogVPN support.
