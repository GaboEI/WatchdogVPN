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
| Arch Linux | `arch` | 23.5 | **CERTIFICATION RE-AUDIT OPEN** — resilient/lifecycle evidence accepted; historical Shadowsocks, plain OpenVPN and HTTP dispositions require review under the superseding WireGuard-only exception |
| CachyOS | `arch` through `ID_LIKE=arch` | 23.5 | **NOT CERTIFIED — OPEN**; lifecycle/security evidence passed, but only 2/12 profiles completed mandatory real egress, including only 1/5 resilient profiles (2026-07-19) |
| Debian | `debian` | 23.5 | Supported in code, un-certified on a clean VM |
| Ubuntu | `ubuntu` | 23.5 | Supported in code, un-certified on a clean VM |

Fedora/Red Hat-family systems, openSUSE, and a Debian/Ubuntu derivative are
intentionally queued for Phase 23.6. Fedora now has a package/`dnf` foundation
in `distros/fedora.sh`, but the detector deliberately keeps Fedora, RHEL,
CentOS, Rocky and AlmaLinux unsupported until SELinux/firewalld, installed
lifecycle and certification close. openSUSE has no adapter or detector branch;
the Debian/Ubuntu `ID_LIKE` fallback has not been implemented. A VM for one of
those systems is useful only as future-lab preparation until its remaining
adapter/threat gates close.

This lab does not promise support for every Linux distribution or arbitrary
custom kernels. Certification records every distro release/kernel pair
actually tested. The distribution-default kernel is the mandatory first
candidate; before a broad Arch-family compatibility claim, the same installed
security, lifecycle and real-egress gates must also pass on a representative
alternate/LTS packaged kernel. An untested kernel is never silently represented
as certified.

## Inventory and machine lifecycle

`tests/vm/distro-certification/inventory.json` is the machine inventory.
`tests/vm/distro-certification/Vagrantfile` is a generic, NAT-only
VirtualBox definition. It intentionally requires a maintainer-selected and
verified box rather than hardcoding an unreviewed third-party image. It also
forces `vagrant-vbguest` auto-update off when that host plugin is installed;
Guest Additions repair can otherwise install compilers, DKMS and headers before
the baseline is captured and falsely make those packages look image-provided.

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

### CachyOS certification environment

The original plan named a maintainer-owned physical CachyOS PC because no
suitable CachyOS Vagrant box was available; physical hardware was an available
replacement environment, not an independent product requirement. When that
PC's disk failed before execution, the maintainer explicitly authorized a
fresh, manually provisioned VirtualBox CachyOS VM as the isolated certification
target. That clean VM provides the required installation, runtime, reboot,
network-policy, uninstall and baseline evidence. A later physical-host run may
add compatibility evidence, but it is not a gate for CachyOS certification or
for starting the next Phase 23.5 target.

## Generic Vagrant invocation

From `tests/vm/distro-certification`:

```bash
WDVPN_VM_BOX=<verified-box> \
WDVPN_VM_BOX_VERSION=<verified-version> \
WDVPN_VM_NAME=wdvpn-<target> \
WDVPN_VM_BRIDGE=<verified-host-interface> \
vagrant up --provider=virtualbox
```

The topology is unconditionally bridge-only. The Vagrantfile refuses to start
without `WDVPN_VM_BRIDGE`, disables VirtualBox adapter 1 so no implicit NAT
path exists, and attaches adapter 2 to the selected host interface. NAT is not
a supported certification or diagnostic baseline: it has already altered
protocol behavior and can route a guest through an unrelated VPN active on the
host, giving false-negative endpoint and egress failures. A previously captured
green remains usable only when its evidence independently proved real traffic
through the selected WatchdogVPN profile rather than mere general reachability.

Bridge-only mode deliberately disables Vagrant's NAT SSH communicator and
shared-folder mount. After the guest receives its bridged DHCP address, use a
direct SSH channel to inject the private fixtures and the exact source tree;
record that address only in private evidence, never in the repository or
redacted evidence. Evidence must record the selected host bridge, prove that
adapter 1/NAT is disabled, and show that the bridge is the guest's only active
network path. This applies to every current and future distro-certification VM.

The caller must pin and record the exact box name and version, its checksum if
available, provider version, VirtualBox version, guest `/etc/os-release`, and
`uname -r` in the evidence directory. The Vagrantfile performs no package
installation, including no `vagrant-vbguest` auto-provisioning, or WatchdogVPN
provisioning: `install.sh` is itself the subject under test.

## Per-target certification evidence

Every target gets an independent evidence subdirectory containing redacted
command output and metadata for:

- clean baseline and image provenance;
- pre-install package/command inventory for every mandatory dependency, so an
  image-provided tool cannot be mistaken for installer provisioning;
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

### Non-negotiable dependency-provenance gate

No distro certification may close merely because the final machine has the
right binaries. Evidence must distinguish what the clean image already
contained from what `install.sh` installed, then prove that `update.sh` repairs
the same missing set. Before the final certification statement, explicitly
ask and answer: did this work from WatchdogVPN's reproducible dependency
contract, or from components a developer/tester installed outside it? Any
mandatory pre-existing tool not guaranteed by install/update invalidates the
green until all supported distro adapters provision it, `doctor.sh` reports it
fail-closed, regression tests pin it, and installed validation is repeated.
This applies even when the current target happens to ship the tool by default
and even after all protocol rows pass. The sole protocol-runtime exception is
AmneziaWG: its distro-specific third-party repository/AUR trust step remains
guided and user-executed, followed by product verification. It may never be
silently generalized into an exception for firewall, DNS, capture, cleanup,
recovery, another protocol runtime, or another feature dependency.

### Non-negotiable protocol-egress gate

Every resilient profile must connect end to end and prove its required real
traffic on every certification target. No resilient red may be deferred,
waived, reclassified as external or assigned to Task 23.6.5a.

Compatibility profiles also require real traffic and must be investigated to
closure when they fail. Task 23.6.5a is a conditional, optional Plan B that
should never run if all compatibility profiles pass; it is not a scheduled
gate, a shortcut, or a destination for ordinary red results. A compatibility
row becomes eligible only after repeated installed reproduction and evidence
have exhaustively excluded product, parser/configuration, driver, fixture,
server, runtime, distro and harness causes, leaving the local ISP/path as the
only sustainable explanation. A first failure, a handshake without egress, a
health classification, an ISP suspicion, or a prior disposition is not enough.
Transfer does not turn the row green: it remains explicitly blocked pending the
external-origin control.

Standard WireGuard is the only reduced-investigation exception because the
maintainer obtained direct confirmation from the local ISP that it is blocked.
WireGuard must still be attempted on every candidate; a failure consistent with
that known block may move to Task 23.6.5a without the same exhaustive local
elimination, but it is never green. No other compatibility profile inherits
this exception. These rules apply to every distro, including prior closure
claims, and survive session or chat changes.

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
Record `/dev/net/tun`, nftables and policy-routing capability before protocol
execution. On Arch-family candidates, record the running kernel package base
and matching headers. The AmneziaWG guide must select
`<running-pkgbase>-headers`, never assume `linux-headers`; test and record
whether the native module or `amneziawg-go` fallback actually carried traffic.

The alternate-kernel row is not a demand to bless arbitrary private kernels.
It is a regression barrier against accidentally equating one VM's kernel with
the whole distribution: at minimum Arch's current default plus its packaged
LTS kernel must pass before the product uses an unqualified Arch compatibility
statement. CachyOS's distribution-default kernel supplies a further
Arch-derived flavor, and any additional flavor explicitly advertised by the
project requires its own installed evidence.

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
- WireGuard was unavailable and is covered by the maintainer's direct ISP
  confirmation for that protocol alone. Shadowsocks was also unavailable, but
  the ISP did not confirm a Shadowsocks block. Plain OpenVPN completed its
  protocol handshake but did not produce real egress. The earlier grouping of
  all three under the external-provider disposition is superseded: WireGuard
  retains the narrow exception, while Shadowsocks and plain OpenVPN require
  renewed diagnosis under the global gate. The partial HTTP row requires the
  same audit and is not a full pass.
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

## Task 23.5.2 closure — Arch Linux clean uninstall and baseline comparison

On 2026-07-18, Task 23.5.2 closed. A second VM (`wdvpn-arch-reference`), built
from the same `generic/arch` 4.3.12 box lineage as the candidate but never
touched by WatchdogVPN, provided the pre-install baseline the candidate could
no longer capture retroactively (it was already carrying WatchdogVPN state
from the rest of the matrix). Arch is rolling, so the reference VM's system
was fully updated (`pacman -Syu`, kernel `6.6.10-arch1-1` to `7.1.3-arch2-2`)
before its state was accepted as the comparison baseline: no WatchdogVPN
commands, runtime, config, state directories, or system account/group, with
GitHub reachable directly.

- The candidate then ran a full purge uninstall
  (`--purge-config --purge-logs --purge-state --confirm-delete DELETE`) after
  completing the rest of the Arch matrix. Product commands, directories,
  systemd units, the nftables kill-switch table, TUN interfaces and
  domain-bypass `ip rule` entries were all confirmed absent afterward, with
  GitHub direct reachability restored.
- Comparing that result against the reference baseline surfaced one real,
  universal gap, not previously documented anywhere in the uninstall
  contract: the `watchdogvpn` system user/group, and the installing user's
  membership in it, were never removed - not even by a full purge. Fixed in
  commit `48e2483`, gated on all three purge flags together (the same
  convention as `dpkg --purge`), so a plain uninstall keeps preserving the
  account exactly like every other path already listed under "Preserved
  unless explicitly purged".
- The fix was live-validated on the same candidate, not only unit-tested:
  the account was confirmed still present after the first (pre-fix) purge
  run, then the fixed `uninstall.sh`/`lib/runtime.sh` were deployed and the
  same real purge command was re-run, after which the user, the group, and
  the installing user's group membership were all confirmed absent.
- Full regression coverage added
  (`tests/unit/test_uninstall_system_account.sh`): a plain uninstall and a
  partial purge must not touch the account; only the full three-flag purge
  may. Complete suite green at closure: `tests/unit.sh`, `tests/syntax.sh`,
  and `python3 -m unittest discover tests` (1736/1736).

Arch Linux retains accepted resilient, provider, DNS, rotation, kill-switch,
clean-uninstall and baseline evidence. Its 2026-07-18 full-certification claim
is reopened only for the compatibility disposition audit above: WireGuard has
the sole reduced-investigation exception; Shadowsocks, plain OpenVPN and the
partial HTTP row do not.

## Task 23.5.2 post-closure hardening — fresh installer and destructive-purge audit

The 2026-07-18 closure was immediately followed by a second, destructive
audit on the rebuilt `wdvpn-arch-certification` candidate. This did not
reopen the already accepted protocol matrix. It challenged the fresh-install,
read-only-preflight and full-purge claims against real protected paths and
seeded non-secret data. Seven additional universal defects were found and
closed before proceeding to another distro:

1. Full purge still created internal recovery backups while deleting config,
   state and logs, leaving unencrypted copies under
   `/var/backups/watchdogvpn` after an explicit encrypted export. `96cabb9`
   suppresses backup creation only for the confirmed three-flag purge and
   removes the fixed internal backup root; an overrideable `BACKUP_ROOT` is
   never a deletion target.
2. A clean install started the daemon and created its socket successfully,
   but the final IPC smoke reported it as not running because the already
   running installer process did not have the newly added `watchdogvpn`
   supplementary group. `695dbaf` runs the probe through
   `setpriv --init-groups` and changes the IPC path preflight from
   `Path.exists()` to `stat()` semantics, preserving permission errors instead
   of misclassifying them as an absent daemon.
3. The first failed transactional install could roll the unit back before
   systemd removed `RuntimeDirectory=`, leaving orphaned numeric ownership in
   `/run/watchdogvpn` and `/run/amneziawg`. `9e852eb` always removes the
   exclusive WatchdogVPN runtime directory and removes the conventional
   AmneziaWG UAPI directory only when it is a real empty directory.
4. The refreshed-group smoke inherited sudo's `HOME=/root` identity on some
   systems. `aad780d` resolves the invoking user's UID, GID and NSS home and
   sets `HOME`, `USER` and `LOGNAME` explicitly before the unprivileged IPC
   request.
5. Shared-state migration intentionally preserves its source at
   `~/.config/watchdogvpn`, but delete-all-data did not remove that duplicate
   or the fixed historical root copy. `84fa0b2` purges the invoking user's
   source, root's known copy, and an NSS-resolved sudo invoker home only under
   the confirmed full-purge gate; it never enumerates unrelated users.
6. The common root-path helper checked existence without privilege. A child
   below a non-traversable parent such as `/root` was therefore printed as
   absent and skipped, including previously documented `/root/.local`
   cleanup. `5b75ded` centralizes privileged existence checks for both backup
   and removal and adds a protected-parent regression seam.
7. `doctor.sh` claimed to be read-only but its capture-mode diagnostic used a
   writer lock and created `~/.config/watchdogvpn/state.toml.lock` on a clean
   machine. `f48acd8` adds a side-effect-free read of atomically published
   state and pins that a missing state file creates no directory, lock or
   recovery journal.

The final accepted live sequence used exact commit `f48acd8`: confirmed empty
baseline; ran `doctor.sh` (`FAIL=0`) and proved both legacy config paths still
absent; ran `install.sh --yes` with exit code 0 and a successful real daemon
IPC smoke; verified the installed marker, active service, socket ownership and
mode; proved a process with cleared supplementary groups receives exit 77 and
the permission-specific error while `setpriv --init-groups` receives a valid
standby response; seeded six harmless probes across user/root config, system
config, state, logs and internal backups; then ran the confirmed full purge.

The final baseline has no WatchdogVPN user/group or group membership, product
paths, legacy user/root config, internal backups, runtime directories, nftables
rules, policy-routing table 880 entries or TUN/WireGuard/AmneziaWG interfaces.
The systemd-resolved stub remained active and direct baseline DNS/reachability
worked. Full local gates passed after every fix; final count is 1737/1737
Python tests plus `tests/unit.sh` and `tests/syntax.sh`. GitHub Actions run
29643194893 passed for `f48acd8`. Raw logs contain no private profile,
provider, endpoint or key material and remain outside the repository.

## Task 23.5.3 field evidence — CachyOS certification remains open

Status: **NOT CERTIFIED — TASK OPEN** on 2026-07-19. Repository commit
`f63a591` incorrectly closed this task by treating external/server dispositions
as sufficient for the resilient-profile gate. This section supersedes that
closure. The accepted candidate was a clean VirtualBox CachyOS x86_64 VM using
the Arch adapter through `ID_LIKE=arch`; the maintainer's clarification that a
physical machine is not a second gate remains valid, but it does not relax the
protocol matrix.

The clean candidate completed fresh installation, protected-path doctor and
runtime checks, profile/provider lifecycle, installed DNS/FakeIP transitions,
rotation, app-policy enforcement, kill-switch failure behavior, manual-off,
panic sleep/wake, disconnected and connected real reboots, and destructive
full-purge comparison. A known-good VLESS profile proved normal TUN, SOCKS
and HTTP-proxy traffic using the required public destinations. Reboot while
connected restored the same desired profile, truthful `UP` state, HTTP 200,
a VPN egress distinct from the physical path, and a consistent kill switch.
The post-routing capture guard accepted managed UDP and recorded zero
physical-path drops. NTP remained unsynchronized during one connected-reboot
window; this stayed visible as the plan-defined environmental warning, not a
false pass, and the final fresh-install doctor later observed synchronized
time.

The mandatory resilient-profile gate failed. The authoritative product split
classifies VLESS, Trojan, Hysteria2, AmneziaWG and OpenVPN+Cloak as resilient;
every resilient profile must connect end to end and prove mode-appropriate real
egress on the certification target. Task 23.6.5a is exclusively a last-resort
external-origin control for a `compatibility` profile after product,
configuration, fixture, server, runtime, distro and harness causes have been
exhaustively excluded and the local ISP/path is the only remaining sustainable
cause. A failed compatibility attempt is not automatically eligible. Task
23.6.5a can never receive, waive or close a resilient result. CachyOS produced
only **1/5 resilient passes**: VLESS passed; Trojan, Hysteria2, AmneziaWG and
OpenVPN+Cloak did not obtain useful real egress. Consequently,
lifecycle/security successes and unproven external explanations cannot certify
CachyOS.

The complete 12-profile result remains explicit:

- resilient: VLESS passed 3/3 required real-egress paths; Trojan, Hysteria2,
  AmneziaWG and OpenVPN+Cloak failed useful egress. AmneziaWG had a real
  interface, route, handshake and receive traffic, which is diagnostic evidence
  but not a pass;
- compatibility: SOCKS passed; HTTP was partial because the mandatory
  Instagram destination timed out; VMess, TUIC, Shadowsocks, WireGuard and
  plain OpenVPN did not obtain useful egress. WireGuard was attempted and may
  use the sole reduced-investigation exception based on the direct ISP
  confirmation, but remains blocked rather than passed. The other five
  incomplete compatibility rows require continued diagnosis and real-traffic
  proof; none is recorded as a local pass;
- the HTTP/SOCKS Instagram-only timeout remained destination/path evidence
  because the other required destinations passed through the same runtime;
- the provider was refreshed successfully with 42 current nodes. The bounded
  maintainer-requested sample tested exactly four owned nodes (two VLESS and
  two Trojan), and all four reached authoritative `connect_failed` outcomes
  after deep health reported zero of two required egress targets with
  `endpoint_censorship_or_network_interference_suspected`. Probes were
  correctly skipped when no connection existed. M3.3 is therefore recorded
  as externally/provider blocked, not green and not a distro/product defect;
  the same installed runtime and machine had already passed the known-good
  manual VLESS path.

Field investigation produced universal fixes rather than machine-specific
exceptions. Commits `27b457d` through `5a77be1` closed backup/preflight,
private-permission, authoritative async-runner, bounded-provider, app-policy,
FakeIP cache invalidation, least-privilege Polkit and kill-switch direct-route
contracts. Later installed findings closed protected-path doctor reporting
(`7db2559`), v2 runtime truth (`e77ccff`), captured UDP post-routing
fail-closed enforcement (`13cfef0`), missing-table uninstall diagnostics
(`4451c1f`) and exact uninstall baseline preservation (`bdbf599`). The UDP
fix accepts sing-box's capture mark only in the output chain and guards it in
a policy-controlled post-routing chain: the packet must finally leave through
the managed TUN or be dropped. DNS leak rejection and the UID-plus-mark
physical direct path remain stricter and unchanged.

The final destructive proof used source and installed commit `bdbf599`.
Fresh `install.sh --yes` returned zero, the marker and installed rescue/
uninstall files matched source, the daemon was enabled and active in clean
`standby/off`, and doctor returned zero with no FAIL. The corrected full purge
then returned zero. Routes, IPv4/IPv6 rules, resolver content and resolver
target matched the captured clean baseline exactly; the normalized firewall
ruleset was identical; direct GitHub returned HTTP 200; and no product
command, unit, path, process, listener, interface, nftables object, table-880
route, system account, group or user membership remained. Private evidence
is mode 0700 with every file mode 0600 and remains outside the repository.

Final source gates after the last product fix: `tests/unit.sh`,
`tests/syntax.sh`, and `python3 -m unittest discover tests` (1756/1756), all
green. These source gates do not substitute for installed real egress. Task
23.5.3 must reproduce and resolve the four failed resilient rows and the five
non-WireGuard incomplete compatibility rows. All five resilient rows must pass
end to end. Every compatibility row must also pass real traffic; only the
already-attempted standard WireGuard row has the maintainer-authorized reduced
ISP-block exception and remains pending Task 23.6.5a rather than green. Task
23.5.4 — Debian certification must not begin before those gates receive a new
explicit closure.

### Reopened protocol revalidation at `23af3a6` (2026-07-19)

The candidate was returned from the accepted purge baseline, installed from
exact source/installed marker `23af3a6`, and received fresh private copies of
all 12 fixtures. All imports passed. SHA-256 comparison performed without
printing hashes or content proved 12/12 byte-identical copies from the
authoritative host source to CachyOS. VLESS again passed connection, state and
all three required TUN/SOCKS/HTTP egress probes. Trojan, Hysteria2, AmneziaWG
and OpenVPN+Cloak again reached authoritative `connect_failed`; each produced
zero of three reachable health targets in both bounded rounds and then returned
to clean standby.

A separate clean Arch control was installed from the same `23af3a6` commit and
received another 12/12 byte-identical copy of the fixtures. Its resilient
matrix reproduced the CachyOS result exactly: VLESS passed 3/3, while Trojan,
Hysteria2, AmneziaWG and OpenVPN+Cloak failed useful egress. This rules out a
CachyOS-specific adapter/runtime cause but does not waive the resilient gate.
A reversible diagnostic then replaced the three certification targets with
GitHub, Cloudflare and IETF; all four failed profiles still obtained zero
usable egress. The original targets and quorum were restored, and CachyOS
remained `desired_state=off` in clean standby.

One initial neutral-control attempt was rejected as invalid evidence because a
new evidence subdirectory lacked the private dynamic profile-ID map and the
runner returned `profile_not_found`; the map was restored privately and the
control was repeated correctly. New evidence initially inherited operator
umask 022, was corrected immediately, and is now directory 0700/files 0600;
all subsequent commands ran under umask 077. No product correction is justified
by the current cross-distro evidence. Task 23.5.3 remains open pending repaired
or renewed controlled fixtures/endpoints that make all five resilient rows
pass on the installed CachyOS candidate.

## Task 23.5.3 final superscriptive closure — CachyOS certified (2026-07-19)

Status: **CERTIFIED; TASK CLOSED**. This section supersedes every earlier
`NOT CERTIFIED`, `2/12`, `1/5 resilient`, current-fixture-control and
compatibility-re-audit status in this document. Those entries remain as the
forensic record of rejected evidence, not as the current result. The clean
VirtualBox CachyOS VM is the accepted candidate; a physical-machine repeat is
not required.

The earlier cross-distro red was reproduced to a defective installed-runtime
path rather than waived. Exact commit `b4d9928` was installed on CachyOS and
the clean Arch control, using the same 12 authoritative private fixtures. The
final protocol disposition is explicit:

- all five resilient profiles passed end to end with real traffic: VLESS,
  Trojan, Hysteria2, AmneziaWG and OpenVPN+Cloak;
- four compatibility profiles proved useful real traffic: VMess, TUIC, SOCKS
  and HTTP. The HTTP upstream passed Facebook and YouTube through TUN, SOCKS
  and HTTP-proxy paths. Instagram failed through all three and also failed in
  a direct control against the upstream proxy without WatchdogVPN; that single
  destination failure is external/upstream attribution, not a false product
  green or a missing traffic proof;
- standard WireGuard, Shadowsocks and plain OpenVPN are **not green**. They are
  the only three maintainer-authorized Task 23.6.5a Plan-B dispositions.
  WireGuard was attempted five times and retains the ISP-confirmed block.
  Shadowsocks intermittently established and moved real HTTP traffic but did
  not produce a stable complete run. Plain OpenVPN established its native
  process and generation TUN, then produced no useful egress; WatchdogVPN
  correctly rejected it at deep health and tore it down fail-closed. A
  non-UUID ad-hoc runner initially called its asynchronous
  `command_in_progress` response a failure; authoritative UUID follow-up and
  live process/interface observation exclude that harness result;
- the result is therefore **9 functionally proven rows plus 3 formally
  blocked Plan-B rows**, never “12/12 green”. Plan B is still optional external
  control, never a shortcut, and cannot receive a resilient profile.

Hysteria2 required bounded retries, consistent with the fixture's independently
observed transient startup behavior; a single early failure was not treated as
authoritative. CachyOS targeted reruns closed Trojan, Hysteria2, AmneziaWG and
OpenVPN+Cloak. The remaining VLESS, VMess, TUIC and SOCKS runs passed, and the
Arch control reproduced the same five resilient plus VMess/TUIC/SOCKS passes;
AmneziaWG passed on its second bounded attempt. The 42-node provider lifecycle
remains operational, while the bounded four-node provider sample remains
formally external/provider-blocked rather than green; it is not substituted
for the authoritative manual-profile matrix.

Two universal traffic defects were fixed rather than hidden:

- `faca677` authorizes sing-box physical `direct` egress under the kill switch
  only when both the managed service UID and managed mark agree. nftables and
  iptables regressions preserve the earlier rule that a mark alone is never a
  firewall credential. Installed M4 then proved `direct` on physical egress,
  `current` on a distinct VPN egress and `block` rejected;
- `b4d9928` makes AmneziaWG trigger bounded tunnel traffic during startup so a
  lazy peer can produce its first handshake before readiness is judged. The
  real profile then passed full traffic after a bounded retry.

Final CachyOS gates on `b4d9928` also passed DNS/FakeIP transitions, rotation
fail-closed behavior, manual-off, panic sleep/wake and the controlled
kill-switch crash (`drop_delta=1`). A real disconnected reboot returned clean
`off`/standby with the resolver unchanged. A real connected VLESS reboot
restored the same profile on the first poll, passed TUN/SOCKS/HTTP traffic and
kill-switch consistency, and disconnected back to the exact clean state.

The first destructive comparison then exposed one final universal lifecycle
defect: `/etc/sysctl.d/99-watchdogvpn.conf` and live
`all/default.src_valid_mark=1` survived full purge. Commit `5408f0a` records a
root-private install baseline (`0700` directory, `0600` manifest), preserves a
real user-preexisting file and live values, migrates pre-journal installations
without adopting their own residue, verifies exact restoration, and refuses an
unprovable real uninstall fail-closed. Source gates passed `tests/unit.sh`,
`tests/syntax.sh`, compileall, `git diff --check`, and 1758/1758 Python tests.

Installed lifecycle validation used exact `5408f0a` from a proven clean
`file absent + 0/0` baseline. The manifest recorded `origin=fresh`,
`file_present=0`, and `0/0`; installed source files, marker and applied `1/1`
matched. Confirmed full purge returned zero and restored `file absent + 0/0`.
IPv4/IPv6 routes and rules, resolver hash/mode/target, links and normalized
firewall matched the prior clean baseline byte-for-byte. Direct GitHub returned
HTTP 200. No product path, command, unit, process, listener, interface,
nftables object, table-880 route, internal backup, account, group or membership
remained. The new private evidence directory is mode 0700 with 24 files at
0600. CachyOS finishes uninstalled, checkout clean and synchronized.

The same final evidence closes the superscriptive compatibility re-audit of
Task 23.5.2: Arch is again **CERTIFIED**, with the same honest 9-functional +
3-Plan-B disposition. Task 23.5.4 — Debian certification is the next distro
task; it was not started during this closure.
