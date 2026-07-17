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
| Arch Linux | `arch` | 23.5 | Supported in code, un-certified on a clean VM |
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
WDVPN_VM_NAME=wdvpn-<target> \
vagrant up --provider=virtualbox
```

The caller must record the exact box name, box version/checksum if available,
provider version, VirtualBox version, guest `/etc/os-release`, and `uname -r`
in the evidence directory. The Vagrantfile performs no package installation
or WatchdogVPN provisioning: `install.sh` is itself the subject under test.

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
