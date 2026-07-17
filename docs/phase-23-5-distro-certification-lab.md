# Phase 23.5/23.6 Distro Certification Lab

This document formalizes the disposable-VM lab used to certify WatchdogVPN
on Linux distributions. It is preparation and evidence infrastructure, not a
claim that a distribution is supported before the applicable phase closes.

The authoritative lifecycle scope is the current Master Plan on `archvm`.
This repository copy deliberately keeps the phase boundary visible so a VM
image or a successful boot cannot silently turn into a support promise.

## Support boundary

Phase 23.5 certifies only the distributions that `lib/distro.sh` already
claims to support:

| Certification target | Adapter path | Phase | Status before certification |
| --- | --- | --- | --- |
| Arch Linux | `arch` | 23.5 | Field matrix completed on the clean candidate; uninstall/baseline closure still pending |
| CachyOS | `arch` through `ID_LIKE=arch` | 23.5 | Supported fallback, un-certified on a clean VM |
| Debian | `debian` | 23.5 | Supported in code, un-certified on a clean VM |
| Ubuntu | `ubuntu` | 23.5 | Supported in code, un-certified on a clean VM |

Fedora, openSUSE, and a Debian/Ubuntu derivative are intentionally queued for
Phase 23.6. Fedora has no `distros/fedora.sh`; openSUSE has no adapter or
detector branch; and the Debian/Ubuntu `ID_LIKE` fallback has not been
implemented. A VM for one of those systems is useful only as future-lab
preparation until its adapter and threat audit exist.

This lab does not promise support for every Linux distribution or every
kernel. Certification records the distro release and the distribution-default
kernel actually tested. A release is supported only after its evidence is
accepted; an untested kernel is not silently represented as certified.

## Inventory and machine lifecycle

`tests/vm/distro-certification/inventory.json` is the machine inventory.
`tests/vm/distro-certification/Vagrantfile` is a generic, NAT-only
VirtualBox definition. It intentionally requires a maintainer-selected and
verified box rather than hardcoding an unreviewed third-party image.

One host is used sequentially:

1. Select one inventory entry and verify its box/ISO provenance and
   `/etc/os-release` identity.
2. Create one fresh VM with the generic Vagrantfile.
3. Record its baseline before WatchdogVPN is installed.
4. Run the complete certification matrix for that one target.
5. Run clean uninstall, collect evidence, destroy the VM, and only then move
   to the next target.

No profile, provider URL, private key, SSH key, or previously installed
WatchdogVPN state may be baked into an image. Real private fixtures are
injected only at execution time under the existing Phase 23 private-fixture
workflow and are never committed as evidence.

If the selected base image has pending distribution updates, apply the
distribution's normal full update and reboot before installing WatchdogVPN.
Record both the image's initial kernel and the post-update running kernel;
the post-update system, still with no WatchdogVPN state, is the certification
baseline. This is essential for rolling targets such as Arch and CachyOS, and
prevents an old box image from being represented as current distro support.

The existing `tests/vm/vagrant` Ubuntu machine is a diagnostic VM with
retained profiles. It must not be reused as the fresh-install certification
candidate.

### CachyOS physical validation target

A maintainer-owned CachyOS PC is available for a controlled physical-host
validation when the CachyOS slot is reached. It is the preferred additional
compatibility target for CachyOS-specific kernels and hardware behavior.
It does not replace the fresh-install VM evidence: the physical host first
gets a recorded preflight and, if it has pre-existing state, its result is
recorded as a separate physical-host validation. No live networking action is
performed on it until the certification task explicitly authorizes it.

## Generic Vagrant invocation

From `tests/vm/distro-certification`:

```bash
WDVPN_VM_BOX=<verified-box> \
WDVPN_VM_BOX_VERSION=<verified-version> \
WDVPN_VM_NAME=wdvpn-<target> \
vagrant up --provider=virtualbox
```

The default topology is NAT-only. For a maintainer-authorized run that needs
the independently routed path used for real protocol validation, request a
second bridged adapter explicitly:

```bash
WDVPN_VM_BOX=<verified-box> \
WDVPN_VM_BOX_VERSION=<verified-version> \
WDVPN_VM_NAME=wdvpn-<target> \
WDVPN_VM_BRIDGE=<verified-host-interface> \
vagrant up --provider=virtualbox
```

The evidence for that run must state the explicit authorization, host bridge
interface, and both guest interfaces. This opt-in does not change the NAT-only
baseline or authorize bridged networking for later distro runs.

When the authorization requires bridge-only validation, disable adapter 1 and
attach only adapter 2 to the selected host interface:

```bash
WDVPN_VM_BOX=<verified-box> \
WDVPN_VM_BOX_VERSION=<verified-version> \
WDVPN_VM_NAME=wdvpn-<target> \
WDVPN_VM_BRIDGE=<verified-host-interface> \
WDVPN_VM_BRIDGE_ONLY=1 \
vagrant up --provider=virtualbox
```

Bridge-only mode deliberately disables Vagrant's NAT SSH communicator and
shared-folder mount. After the guest receives its bridged DHCP address, use a
direct SSH channel to inject the private fixtures and the exact source tree;
record that address only in private evidence, never in the repository or
redacted evidence. Record that adapter 1 was disabled and adapter 2 was the
only active network path. This mode is per-run and requires its own explicit
maintainer authorization.

The caller must pin and record the exact box name and version, its checksum if
available, provider version, VirtualBox version, guest `/etc/os-release`, and
`uname -r` in the evidence directory. The Vagrantfile performs no package
installation or WatchdogVPN provisioning: `install.sh` is itself the subject
under test.

## Per-target certification evidence

Every target gets an independent evidence subdirectory containing redacted
command output and metadata for:

- clean baseline and image provenance;
- source commit and installed-runtime alignment;
- fresh install and `doctor.sh` (`FAIL=0`);
- all 12 protocol attempts with mode-appropriate real egress proof;
- AmneziaWG's actual backend on that target - the distro-default kernel
  module if present, otherwise the `amneziawg-go` userspace fallback - with
  the backend the daemon actually used recorded explicitly, not assumed
  from the distro's usual case;
- DNS apply/reset, kill-switch enable/controlled-failure/disable, rotation
  where applicable, and clean disconnect;
- clean uninstall and post-uninstall baseline comparison.

For a session with TUN and local proxy capabilities, normal egress, SOCKS
egress, and HTTP-proxy egress are separate required observations. A SOCKS
success alone is never evidence that system/TUN traffic works.

Before WatchdogVPN is installed and connected, use GitHub only for baseline
Internet reachability. After a real WatchdogVPN connection is active,
real-egress observations must use censorship-relevant public destinations:
Facebook, Instagram, and YouTube are the required primary targets. Do not
count GitHub, Cloudflare-hosted endpoints, or Wikipedia as proof of VPN
egress, because they can remain reachable through paths that do not represent
ordinary censored-network traffic.

## Kernel and security posture

Record the running kernel; do not substitute a host kernel label for guest
evidence. The guest's default security posture is part of certification:

- Arch/CachyOS: package/kernel and VirtualBox guest behavior;
- Debian/Ubuntu: AppArmor state where present;
- Fedora (Phase 23.6): SELinux enforcing state and the real systemd unit;
- openSUSE (Phase 23.6): AppArmor and zypper/systemd behavior.

Any failure to create a TUN device, apply nftables, run the daemon sandbox, or
obtain protocol egress is a field finding, not a reason to weaken
`strict_route`, `auto_redirect`, the kill switch, or cleanup requirements.

## Task 23.5.2 partial evidence — Arch AmneziaWG user journey

On 2026-07-18, the clean Arch candidate at installed commit `cb3a0a9` passed a
maintainer-driven AmneziaWG journey from profile import through real egress.
This is accepted evidence for the AmneziaWG row only; it does not close the
remaining Arch 12-protocol matrix or Task 23.5.2.

- A real interactive `watchdog profile add --file` saved the profile before
  checking optional runtime readiness, preserved the rotation choice, detected
  the Arch adapter, and printed the adapter-owned installation commands and
  official upstream links. No dependency was installed silently.
- The maintainer executed the displayed commands manually. Arch installed the
  build prerequisites, the AUR source validations passed, the DKMS module
  built for the running `7.1.3-arch2-1` kernel, and both `awg` and the
  `amneziawg-go` fallback became available.
- `watchdog connect` reached honest `connected` state in `native-policy` mode
  with TUN, local proxies, and the nftables kill switch active. A recent
  AmneziaWG handshake and bidirectional transfer counters were observed.
- Real egress returned HTTP 200 with exit code 0 for Facebook over the normal
  TUN path, Instagram through SOCKS on the product's configured port `2080`,
  and YouTube through HTTP proxy on port `2081`.
- The first proxy probes used incorrect ad-hoc ports `1080`/`8080`; those
  immediate localhost connection failures were operator-instruction error,
  not product failure. Listener inspection identified the configured ports
  before the accepted rerun.
- Explicit disconnect restored standby, the service remained active, the
  source checkout stayed clean, and temporary import/AUR build directories
  were removed. Private profile contents, identifiers, endpoints, and keys are
  excluded from repository evidence.

## Task 23.5.2 partial evidence — Arch field matrix and fail-closed correction

On 2026-07-18, the same Arch candidate completed the 12-protocol field matrix,
provider lifecycle, live DNS apply/reset, rotation, and the kill-switch
controlled-failure cell. The VM used adapter 2 only, bridged to the explicitly
authorized host interface; NAT adapter 1 was disabled. This remains partial
Task 23.5.2 evidence because clean uninstall and comparison with an accepted
pre-install baseline have not yet closed.

- VLESS, Trojan, Hysteria2, OpenVPN+Cloak, and AmneziaWG passed their expected
  real runtime path. AmneziaWG and OpenVPN+Cloak were given a longer bounded
  readiness window because their native/compound startup is slower; neither
  was accepted from a transient local listener alone.
- VMess, TUIC, and SOCKS passed. HTTP proxy operation was demonstrated; one
  destination-specific Instagram timeout was retained as provider/path
  evidence rather than represented as a product-wide failure.
- WireGuard and Shadowsocks were classified unavailable on this network after
  the maintainer's ISP confirmed those traffic types are blocked. Plain
  OpenVPN completed its protocol handshake but did not produce real egress.
  Those compatibility rows remain assigned to the isolated external-provider
  lab; they are not false product passes or distro failures.
- Provider add/update/node-connect/remove passed without deleting or mutating
  the 12 manual profiles. Real provider-node egress passed before removal.
- DNS apply/reset passed on the connected runtime after the CLI was corrected
  to require privilege before any mutation. Rotation passed actual profile
  change, long-command completion, concurrent status availability, and real
  TUN/SOCKS/HTTP egress.
- The first valid kill-switch crash test exposed a real universal defect:
  firewall rules trusted sing-box auto-redirect marks globally, so marked
  physical ICMP could bypass the terminal DROP after the sing-box child died.
  Commit `245a05b` removed mark-based firewall trust from both nftables and
  iptables without removing the marks from bounded residue/collision logic.
  The complete unit suite passed before deployment.
- At `245a05b`, healthy kill-switch operation retained HTTP 200 on the required
  normal-TUN, SOCKS, and HTTP-proxy observations. During an attributed failure
  (daemon frozen and its sole verified sing-box child killed), forced physical
  HTTPS returned no HTTP response, forced physical ICMP failed, and the
  nftables DROP counter increased. The daemon then resumed, disconnect removed
  the firewall table, standby was honest, and direct baseline reachability was
  restored.
- `tests/vm/phase23_kill_switch_controlled_failure.py` now encodes that proof
  for future distro runs. It records the physical interface before connection,
  verifies parent/cgroup ownership across all daemon worker threads, selects a
  public probe address distinct from endpoint allowances, always resumes the
  daemon, and refuses to run without the explicit field-validation guard.

All endpoint addresses, generated profile/provider identifiers, subscription
material, and private fixture contents remain outside repository evidence.
