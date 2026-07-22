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
- `almalinux9_baseline_20260722T0900Z.log`
- `rockylinux9_baseline_20260722T0901Z.log`
- `bridge_ssh_preflight_update_20260722T0902Z.log`
- `fedora_workstation44_iso_vm_provenance_20260722T0920Z.log`
- `redhat_opensuse_vagrant_lab_20260722T084044Z.log`

## Vagrant Lab Findings

All attempted Vagrant guests used the Phase 23.5/23.6 generic Vagrantfile in
bridge-only mode with `VAGRANT_EXPERIMENTAL=none_communicator`. No guest was
started with a graphical interface. No WatchdogVPN install or runtime support
claim was attempted.

| Target | Box | Result | Certification meaning |
| --- | --- | --- | --- |
| openSUSE Leap 15.6 | `opensuse/Leap-15.6.x86_64` `15.6.13.356` | Booted bridge-only and produced an internal baseline over direct SSH. | Usable as the current openSUSE baseline candidate. |
| openSUSE Tumbleweed | `opensuse/Tumbleweed.x86_64` `1.0.20241025` | Imported and booted bridge-only. MAC/IP discovery found `192.168.0.215`, but SSH on port 22 refused the direct Vagrant key path. | Not sufficient for internal baseline evidence yet. |
| AlmaLinux 9 official | `almalinux/9` `9.7.20260518` | Imported and booted bridge-only. MAC/IP discovery found `192.168.0.176`; direct SSH with the Vagrant key worked and produced an internal baseline. | Usable as a Red Hat/RHEL-compatible control baseline, not RHEL certification. |
| RockyLinux 9 | `bento/rockylinux-9` `202510.26.0` | Imported and booted bridge-only. GuestInfo/MAC discovery found `192.168.0.150`; direct SSH with the Vagrant key worked and produced an internal baseline. | Usable as a second Red Hat/RHEL-compatible control baseline, not RHEL certification. |
| AlmaLinux 9 bento | `bento/almalinux-9` `202511.24.0` | VirtualBox 7.0.16 rejected the OVF before boot because it contains an NVRAM hardware item with `ResourceType=32768`. | Box/provider incompatibility; not WatchdogVPN evidence. |

The repeatable preflight for a usable VM baseline is:

1. Verify `VBoxManage showvminfo` reports `nic1=bridged`, the expected
   `bridgeadapter1`, and `nic2..nic4=none`.
2. Record the VirtualBox adapter MAC.
3. Prefer GuestInfo when present; otherwise do a bounded TCP/SSH sweep from
   `ubuntu-host` and cross-check the resulting ARP entry against that MAC.
4. Attempt direct SSH with the box's documented Vagrant key/user.
5. Only if SSH works, record the internal baseline. If SSH is refused or the MAC
   never produces an IP, the image is lab-incomplete and cannot support a green.

Fedora official Vagrant Cloud names such as `fedora/44-cloud-base` were not
available through `vagrant cloud box show` during discovery. Fedora's official
Cloud download page currently lists Fedora Cloud 44 Vagrant VirtualBox media as
beta, so the Fedora Vagrant path remains unresolved for Task 23.6.5.

Fedora Workstation 44 ISO provenance is now pinned separately from the Vagrant
lab. The official Workstation download page resolves to
`Fedora-Workstation-Live-44-1.7.x86_64.iso`; the official checksum file
`Fedora-Workstation-44-1.7-x86_64-CHECKSUM` verifies the ISO with SHA256
`1620295f6a00c27c3208f0c00b8ece4eab1ec69b9002152d97488bf26a426ddf`. A
separate graphical VirtualBox VM named `Fedora Workstation 44` exists on
`ubuntu-host` with EFI, 2 CPU, 6144 MB RAM, a 64 GB VDI, the verified ISO
mounted, and `nic1=bridged` on `enp4s0` with `nic2=none`. VirtualBox 7.0.16
reports `Unattended installation supported = no` for this Live ISO, so Fedora
still needs an interactive install or another checksum-pinned automation route
before it can produce an internal installed baseline.

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

## Red Hat-Family Control Baselines

AlmaLinux 9.7 official and RockyLinux 9 both provide bridge-only direct SSH
baselines and can be used to audit the current Red Hat-family assumptions before
Fedora/RHEL certification.

AlmaLinux 9.7 baseline:

- `/etc/os-release`: `ID=almalinux`, `ID_LIKE="rhel centos fedora"`.
- Kernel: `5.14.0-611.54.6.el9_7.x86_64`.
- PID 1: systemd.
- Network baseline: only `lo` and bridged `eth0`; default policy rules.
- `/dev/net/tun` exists.
- `NetworkManager` active; `systemd-resolved` and `firewalld` inactive.
- SELinux enabled and enforcing, targeted policy.
- Present commands include `dnf`, `rpm`, `systemctl`, `systemd-run`, `sudo`,
  `python3`, `curl`, `tar`, `ip`, `ss`, `ping`, `setpriv`, `logrotate`,
  `nmcli`, `modinfo`, `pkaction`, `getenforce`, `ausearch`, and `journalctl`.
- Missing required WatchdogVPN commands include `git`, `nft`, `iptables`,
  `ip6tables`, `openvpn`, `resolvectl`, `firewall-cmd`, and `aa-status`.

RockyLinux 9.6 baseline:

- `/etc/os-release`: `ID=rocky`, `ID_LIKE="rhel centos fedora"`.
- Kernel: `5.14.0-570.52.1.el9_6.x86_64`.
- PID 1: systemd.
- Network baseline: only `lo` and bridged `enp0s3`; default policy rules.
- `/dev/net/tun` exists.
- `NetworkManager` active; `systemd-resolved` inactive; `firewalld` active.
- SELinux enabled and enforcing, targeted policy.
- Present commands include `dnf`, `rpm`, `systemctl`, `systemd-run`, `sudo`,
  `python3`, `curl`, `tar`, `ip`, `ss`, `ping`, `setpriv`, `logrotate`,
  `nmcli`, `nft`, `iptables`, `ip6tables`, `modinfo`, `pkaction`,
  `firewall-cmd`, `getenforce`, `ausearch`, and `journalctl`.
- Missing required WatchdogVPN commands include `git`, `openvpn`, and
  `resolvectl`.

AlmaLinux and RockyLinux are intentionally complementary controls. AlmaLinux
proves the installer must not assume firewall tooling is already present on an
EL9-like image. RockyLinux proves the product must coexist with an image where
`firewalld`, `nft` and iptables frontends are already active/present. Both
remain compatible controls only. They do not certify actual RHEL without a
maintainer-provided Red Hat Developer/subscription path.

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

## Implementation Gates For Task 23.6.2 and Task 23.6.3

The next support-code tasks must treat these audit findings as gates:

- Red Hat-family detection must keep Fedora, RHEL, CentOS, RockyLinux and
  AlmaLinux unsupported until the adapter, installer, update, doctor and
  cleanup paths are all implemented and tested. Unit tests should pin each ID
  explicitly.
- Fedora/RHEL-family package installation must use WatchdogVPN-managed `dnf`
  paths for every required command. Current EL9 control baselines prove `git`,
  `openvpn`, and `resolvectl` cannot be assumed present; AlmaLinux additionally
  proves `nft`, `iptables`, `ip6tables` and `firewall-cmd` cannot be assumed
  present.
- The Fedora/RHEL-family adapter must not disable SELinux or firewalld. It must
  report SELinux enforcing state, firewalld active/inactive state, and the
  selected firewall backend clearly through doctor/support evidence.
- Runtime tests on Red Hat-family systems must include one case with firewalld
  inactive/missing tooling and one case with firewalld active and nft/iptables
  frontends present. AlmaLinux 9 and RockyLinux 9 are suitable controls for
  those two postures.
- openSUSE detection must handle `ID=opensuse-leap` and
  `ID=opensuse-tumbleweed` explicitly, including `ID_LIKE="suse opensuse"`.
- openSUSE package installation must add a real `zypper` path in
  `lib/packages.sh`; installing required packages manually before
  WatchdogVPN runs is not valid evidence.
- openSUSE doctor/support evidence must record AppArmor state when tools are
  available and must distinguish image-default absence of firewalld/AppArmor
  tooling from WatchdogVPN-managed installation.
- The real `systemd/watchdogvpn.service` sandbox must be exercised on each new
  family before certification. A dependency-only pass is not enough.

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

Task 23.6.1 should not close until the Fedora Workstation VM is installed or an
equivalent checksum-pinned Fedora automation route produces an internal
installed baseline. Tumbleweed remains optional unless the maintainer chooses it
over Leap for openSUSE certification.
