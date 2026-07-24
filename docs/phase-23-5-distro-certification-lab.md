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

| Certification target | Adapter path | Phase | Current certification status |
| --- | --- | --- | --- |
| Arch Linux | `arch` | 23.5 | **CERTIFIED / CLOSED** — default-kernel and packaged-LTS evidence complete; 9 functional rows + the 3 individually authorized Plan-B rows, with 5/5 resilient green |
| CachyOS | `arch` through `ID_LIKE=arch` | 23.5 | **CERTIFIED / CLOSED** — clean install/update provenance and full purge complete; 9 functional rows + the same 3 individually authorized Plan-B rows, with 5/5 resilient green |
| Debian | `debian` | 23.5 | **CERTIFIED / CLOSED** — Debian 13.6 bridge-only VM evidence complete; 9 functional rows + the 3 individually authorized Plan-B/no-egress rows, with 5/5 resilient green |
| Ubuntu | `ubuntu` | 23.5 | **CERTIFIED / CLOSED** — Ubuntu 24.04.4 bridge-only VM evidence complete; 9 functional rows + the 3 individually authorized Plan-B/no-egress rows, with 5/5 resilient green |

openSUSE and a Debian/Ubuntu derivative were intentionally queued for later
Phase 23.6 tasks. **Fedora itself is now field-certified (Task 23.6.5, closure
section below): bridge-only, SELinux enforcing, 9 functional rows plus 3 formal
Plan-B rows with 5/5 resilient green, real traffic, clean teardown.** Task
23.6.2 implemented the Fedora/Red Hat-family `dnf` adapter path shared by
Fedora, RHEL, CentOS, RockyLinux and AlmaLinux; that certification now holds for
Fedora, and Task 23.6.5b (closure section below) additionally certified Rocky
Linux 9 specifically. RHEL, CentOS Stream and AlmaLinux remain
`COMPATIBILIDAD_INFERIDA_POR_FAMILIA` only (they share the same adapter code
path but were never themselves field-tested), so the shared adapter's
certification is partial.
Task 23.6.3 implements the openSUSE package and `zypper` adapter path
for explicit openSUSE IDs, but that likewise is not a certification green:
AppArmor/firewalld, installed lifecycle, real runtime, real traffic and teardown
evidence remain pending. The Debian/Ubuntu `ID_LIKE` fallback is implemented in
Task 23.6.4: derivatives such as Linux Mint (`ID_LIKE="ubuntu debian"`) or a
Debian-based system (`ID_LIKE="debian"`) resolve to the Ubuntu or Debian adapter
respectively, with Ubuntu taking precedence and every unrelated `ID_LIKE` left
unsupported. Linux Mint 22.3 is now physically certified through that Ubuntu
fallback in Task 23.6.7 (closure section below). That certification applies to
Linux Mint 22.3 itself; other Debian/Ubuntu derivatives remain compatibility
inferred by their `ID_LIKE` mapping until they are independently field-tested.
A VM for any remaining derivative is useful only as future-lab preparation until
its own adapter/threat gates close.

Task 23.6.1 audit notes live in
`docs/phase-23-6-task-23-6-1-threat-compatibility-audit.md`. That task is
closed as an audit-only baseline/gate record for Fedora, Red Hat-family
controls and openSUSE. It does not certify any new distro.

This lab does not promise support for every Linux distribution or arbitrary
custom kernels. Certification records every distro release/kernel pair
actually tested. The distribution-default kernel is the mandatory first
candidate; before a broad Arch-family compatibility claim, the same installed
security, lifecycle and real-egress gates must also pass on a representative
alternate/LTS packaged kernel. An untested kernel is never silently represented
as certified.

## Inventory and machine lifecycle

`tests/vm/distro-certification/inventory.json` is the machine inventory.
`tests/vm/distro-certification/Vagrantfile` is a generic, bridge-only
VirtualBox definition that fails closed unless an explicit host bridge and the
no-communicator execution mode are selected. It intentionally requires a
maintainer-selected and verified box rather than hardcoding an unreviewed
third-party image. It also
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
VAGRANT_EXPERIMENTAL=none_communicator \
WDVPN_VM_BOX=<verified-box> \
WDVPN_VM_BOX_VERSION=<verified-version> \
WDVPN_VM_NAME=wdvpn-<target> \
WDVPN_VM_BRIDGE=<verified-host-interface> \
vagrant up --provider=virtualbox
```

The topology is unconditionally bridge-only. The Vagrantfile refuses to start
without `WDVPN_VM_BRIDGE`, converts VirtualBox adapter 1 from Vagrant's
temporary NAT preparation to the selected bridge before boot, and disables
every secondary adapter and Vagrant's implicit SSH NAT redirect. NAT is not a
supported certification or diagnostic baseline: it has already altered
protocol behavior and can route a guest through an unrelated VPN active on the
host, giving false-negative endpoint and egress failures. A previously captured
green remains usable only when its evidence independently proved real traffic
through the selected WatchdogVPN profile rather than mere general reachability.

Bridge-only mode deliberately disables Vagrant's NAT SSH communicator and
shared-folder mount. After the guest receives its bridged DHCP address, use a
direct SSH channel to inject the private fixtures and the exact source tree;
record that address only in private evidence, never in the repository or
redacted evidence. Evidence must record the selected host bridge, prove that
adapter 1 is bridged rather than NAT, prove that secondary adapters are
disabled, and show that the bridge is the guest's only active network path.
This applies to every current and future distro-certification VM.

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

## Task 23.5.2 post-closure dependency and Arch LTS gate (2026-07-19)

Status: **ARCH LTS GATE CERTIFIED; DEPENDENCY PROVENANCE CLOSED**. This
addendum closes the later re-audit without weakening the superscriptive
bridge-only rule or retroactively accepting a negative NAT result.

The disposable Arch candidate ran the packaged `linux-lts` kernel. A real
update and a separate fresh install each began with eleven required distro
packages intentionally absent and each restored the complete supported
runtime set. Doctor ended with no FAIL in both cases. This proves that the
candidate did not pass because a developer had silently prepared its
dependencies. AmneziaWG remains the one explicit trust-boundary exception:
the product detected the running LTS kernel and presented the guided commands;
the reviewed external AUR components and matching `linux-lts-headers` were
installed through that documented flow and are not credited to install/update.

The first 12-profile run used Vagrant's then-implicit NAT path and inherited
the Ubuntu host's unrelated AmneziaVPN policy routing. Nine rows nevertheless
proved real traffic through their selected WatchdogVPN runtime and all required
capture paths: VMess, Trojan, Hysteria2, TUIC, Shadowsocks, WireGuard,
AmneziaWG, plain OpenVPN and SOCKS. Those positive observations remain valid.
Only the three negative rows were rejected and repeated after converting the
candidate to a single bridged adapter with no NAT, forwarded port or shared
folder.

The valid bridge-only repeat produced these authoritative results:

- VLESS connected truthfully and passed normal TUN, local SOCKS and local HTTP
  egress, then disconnected cleanly;
- OpenVPN+Cloak connected truthfully and passed the same three real-egress
  paths, then disconnected cleanly;
- HTTP connected truthfully, passed the normal Facebook observation and the
  local HTTP-proxy YouTube observation, while the local SOCKS Instagram probe
  timed out. A direct control against the exact upstream HTTP proxy, with
  WatchdogVPN disconnected and no managed proxy listener, returned HTTP 200
  for Facebook and YouTube and reproduced only Instagram as curl exit 28 with
  no HTTP response. The Instagram result is therefore an upstream/destination
  limitation rather than a WatchdogVPN failure.

One earlier bridge attempt is explicitly invalid evidence: the new evidence
directory lacked the private dynamic profile-ID map, so all three operations
returned immediate `profile_not_found`. It is preserved as a harness failure
and contributes no protocol result. That run also exposed that the runner
trusted the caller's umask. Commit `4da42f2` now enforces directory mode 0700
and file mode 0600 itself; its regression test runs under umask 022. The
affected evidence was corrected before private material was reused. The final
three private trees contain no directory or file permission violations.

The permanent VM enforcement series is `9e00dc3`, `bd8443f`, `617ded9`,
`72edf92` and `4da42f2`: certification requires an explicit bridge, converts
adapter 1 to that bridge, disables secondary adapters, removes implicit NAT
SSH forwarding and shared folders, and pins private evidence permissions.
Final source gates passed shell unit, syntax, compileall, Ruby/Vagrant
validation, `git diff --check` and 1759/1759 Python tests. The installed
candidate ended at source/marker `4da42f2`, doctor `OK=131 WARN=4 FAIL=0`,
`desired_state=off`, clean standby, no managed TUN or proxy listener, no
runtime artifacts, and an inactive consistent kill switch.

This closes the representative Arch LTS kernel and clean dependency-provenance
gates. It does not substitute for CachyOS's separate clean install/update
provenance revalidation, which remains open.

## Task 23.5.3 post-closure clean provenance revalidation (2026-07-19)

Status: **CLOSED; CACHYOS CERTIFICATION REMAINS VALID**. This section closes
the separate CachyOS gate left open by the Arch LTS addendum. It does not turn
the three authorized Plan-B rows green and does not alter their individual
scope.

The candidate was the same bridge-only CachyOS VM, initially fully purged,
with checkout `74f5ecd`. Ten mandatory packages were deliberately removed:
NetworkManager, logrotate, libnotify, OpenVPN, Polkit, nftables, iptables,
iputils, procps-ng and Python cryptography. A fresh `install.sh --yes`
restored 10/10, completed its real daemon IPC smoke, published the exact
installed marker and ended with doctor `OK=132 WARN=3 FAIL=0`. The same ten
were then removed again; `update.sh --yes` independently restored 10/10,
refreshed the daemon generation, retained marker alignment and completed its
IPC smoke. A separately removed `bind` package was correctly excluded from
the product claim: it is a historical auxiliary adapter declaration with no
current runtime consumer and was restored manually to the machine baseline.
AmneziaWG remained available solely through its previously documented guided
third-party trust boundary, never as installer credit.

All 12 byte-identical private fixtures were imported again. The complete
installed matrix reproduced the accepted honest disposition:

- all five resilient rows passed truthful connection, normal TUN, local SOCKS
  and local HTTP-proxy real traffic, then clean disconnect: VLESS, Trojan,
  Hysteria2, AmneziaWG and OpenVPN+Cloak;
- VMess, TUIC and SOCKS also passed all three real-egress observations;
- HTTP passed Facebook on the normal path and YouTube through the local HTTP
  proxy. Instagram alone timed out over the local SOCKS path. With WDV
  disconnected, a private direct control through the exact upstream HTTP
  proxy returned HTTP 200 for Facebook and YouTube and reproduced Instagram
  alone as curl exit 28 with no HTTP response;
- Shadowsocks connected and carried useful YouTube traffic but its normal and
  Instagram observations timed out; standard WireGuard ended in authoritative
  `connect_failed`; plain OpenVPN was observed with one real OpenVPN process
  and an owned TUN before deep health rejected its null egress and cleaned it
  back to standby. These are exactly the three individually authorized
  Task 23.6.5a rows and remain blocked, not green.

Thus the final CachyOS result remains **9 functionally proven rows + 3 formal
Plan-B rows**, including 5/5 resilient green. No failed resilient result was
waived, and no new compatibility profile was sent to Plan B.

The confirmed full purge returned zero and removed every product command,
unit, path, runtime, account, group and installing-user membership. Exact
process-name checks found no sing-box, OpenVPN, Cloak or daemon process; no
managed link or table-880 route remained. The sysctl file was absent and live
`src_valid_mark` was restored to `0/0`. Raw IPv4/IPv6 routes and rules,
resolver hash/target, links, sorted listeners and normalized firewall matched
the prior clean baseline exactly; direct GitHub returned HTTP 200. Two
standard main-table loopback routes introduced by the deliberate
NetworkManager package reinstall were removed as test-created baseline drift;
the kernel local table was untouched, IPv4/IPv6 loopback remained healthy,
and the raw route comparison then matched.

Two harness observations are excluded explicitly. An accidental invocation on
the protected local Arch host failed before loading a nonexistent manifest and
before any action; it made no local network mutation. During the final audit,
`pgrep -f` counted its own command line as two apparent product processes;
exact-name checks corrected that to zero. One auxiliary tee log initially had
mode 0644 and was corrected to 0600. The final private evidence tree has no
directory or file permission violations: every directory is 0700 and every
file 0600.

This answers the permanent final question affirmatively: CachyOS worked after
a clean install and update because WatchdogVPN provisioned every mandatory
supported dependency. No undeclared developer-installed component is credited;
AmneziaWG is the sole guided external exception. The renewed Arch-family
dependency, alternate-kernel and CachyOS provenance audit is closed. The
following addendum supersedes the earlier "Debian not started" handoff state.

## Task 23.5.4 — Debian certification closure (2026-07-21)

Status: **CERTIFIED/CLOSED**. Debian 13.6 (`bento/debian-13`
`202508.10.0`, kernel `6.12.95+deb13-amd64`) was certified in a fresh
bridge-only VM named `wdvpn-debian-certification`, reachable by direct LAN SSH
at `192.168.0.224`. The VM had exactly one bridged adapter on `enp4s0`, no
NAT adapter, no forwarded SSH port and no shared folder. The protected local
Arch/CachyOS host network stack was not used for VPN, DNS, route, firewall or
interface mutation.

The implementation and installed certification commit for the functional
matrix was `0e82068` (`expose split tunnel cli`). GitHub Actions completed
successfully for that commit. The later documentation-only closure commit does
not change runtime behavior.

The Debian dependency-provenance gate passed. Baseline removals and
post-install/update checks proved that the installer/update path supplies the
supported Debian dependency set through `apt`: NetworkManager/nmcli,
logrotate, OpenVPN, nftables, iptables, Polkit/systemd integration and the
other required runtime tools. Product-managed `sing-box` and `ck-client`
remained under `/usr/local/bin`. AmneziaWG retained the explicit guided
third-party trust-boundary exception; on this Debian kernel the native
AmneziaWG module/tooling path was available and the userspace fallback was not
needed.

The private fixture/protocol gate imported all 12 manual profiles without
printing secrets, endpoints, keys, provider URL or raw profile material. The
external provider refresh imported 42 current nodes. A bounded provider matrix
connected successfully, created the managed TUN/listeners, passed real egress
on the normal TUN-captured path, local SOCKS `127.0.0.1:2080` and local HTTP
proxy `127.0.0.1:2081`, rotated successfully, and passed post-rotation real
egress. A later compact installed regression over `0e82068` reproduced the
same provider/rotation result and ended clean.

Protocol classification is honest, not "12 green":

- HTTP is green on Debian: it connected truthfully, exposed TUN/SOCKS/HTTP
  proxy runtime and passed real traffic through all three channels.
- WireGuard plain ends in authoritative `connect_failed` with
  `endpoint_censorship_or_network_interference_suspected`, then cleans up.
  This matches the maintainer-confirmed ISP/provider block and is a formal
  Plan-B row, not a green row.
- Shadowsocks can create runtime during the attempt but the authoritative
  daemon outcome rejects the session after egress health failure/interference
  and returns to clean standby. This matches the confirmed blocked/no-egress
  behavior and is a formal Plan-B row, not a green row.
- Plain OpenVPN was tested both through WatchdogVPN and directly with
  `/usr/sbin/openvpn`: the native OpenVPN process completed TLS, received
  `PUSH_REPLY`, created a TUN interface and logged `Initialization Sequence
  Completed`, but user traffic through the tunnel timed out. WatchdogVPN
  correctly refused to report a successful connection and ended in
  `connect_failed` after the egress health check, then cleaned up. This is a
  no-egress compatibility limitation, not a product green or teardown bug.

DNS/FakeIP passed on Debian. While connected, `watchdog dns apply --yes
--json` under sudo returned rc 0, traffic remained reachable, and `watchdog
dns reset --yes --json` returned rc 0. Earlier rc 70/rc 2 observations were
excluded as harness errors: one apply was invoked while the local DNS runtime
was intentionally absent in standby, and another command was malformed by
shell quoting before reaching the product.

Split tunneling received both a functional Debian validation and a user-facing
CLI correction. The existing engine had been exposed only as the technical
`app-policy` command. Commit `0e82068` added the visible
`watchdog split-tunnel` interface while keeping `watchdog app-policy` as the
backward-compatible technical name. Debian installed validation proved:

- process/app policy `direct` matched the direct baseline exit path;
- process/app policy `current` used the active WatchdogVPN path and produced a
  distinct VPN exit;
- process/app policy `block` denied traffic with the target IP resolved
  explicitly, so the block was not a DNS-only false positive;
- `watchdog split-tunnel add-domain ejemplo.com --action direct` created a
  real routing rule in the evaluated `custom` group, and `watchdog rules
  explain --domain ejemplo.com --json` returned `route_action=direct` with a
  matched rule. The test rule was removed and the final state stayed clean.

Panic sleep/wake passed according to its true design contract. It is a rescue
button, not a kill-switch mode: `panic sleep` puts WatchdogVPN out of the way
so a user who lost connectivity can recover Internet without uninstalling,
start another VPN if necessary, and later resume WatchdogVPN. Debian observed
the service disabled/inactive, hibernate marker present, WatchdogVPN firewall
rules absent and direct Internet still reachable. That direct reachability is
expected. `panic wake` removed the marker and restored the service. Final
status returned to clean standby.

The reboot gate passed disconnected over the final installed runtime: after
`sudo reboot`, the VM returned by direct SSH, source checkout was `0e82068`,
`watchdog status --json` reported standby with no TUN, proxy, failure or
kill-switch, `watchdog doctor --json` returned `doctor_exit_code=0`, and a
direct HTTPS probe returned HTTP 200.

The destructive purge/reinstall gate passed earlier in the Debian session and
was not repeated after the split-tunnel UX change because the later commit did
not alter uninstall/install teardown semantics. The prior Debian purge removed
product commands, runtime/config/state paths and firewall remnants; the
reinstall/update path then restored the runtime and passed provider, rotation
and DNS smoke. No known Debian teardown debt remains.

The final Debian result is **certified for supported end-user operation** with
formal non-green Plan-B/no-egress classifications for the externally blocked
or limited compatibility protocols above. No resilient-profile failure was
waived, no protocol was marked green without traffic, and no known HIGH/MEDIUM
bug or accepted technical debt remains for Task 23.5.4.

## Task 23.5.5 - Ubuntu certification closure (2026-07-22)

Status: **CERTIFIED/CLOSED**. Ubuntu 24.04.4 LTS was certified in the fresh
bridge-only VirtualBox VM `wdvpn-ubuntu-certification`, running on
`ubuntu-host` with exactly one bridged adapter on `enp4s0`, no NAT adapter and
no shared-folder path. The protected local Arch/CachyOS host network stack was
not used for VPN, DNS, route, firewall or interface mutation. The installed
certification checkout and source marker were `c73b001`.

The Ubuntu dependency-provenance gate passed under the stricter "no helped
machine" rule. OpenVPN was absent before product installation and present
after the WatchdogVPN install/update path. The installer/update path supplied
the supported Ubuntu runtime set through `apt`, including NetworkManager/nmcli,
logrotate, OpenVPN, nftables, iptables, Polkit/systemd integration, curl, git,
jq, Python 3, Python cryptography and the remaining supported runtime tools.
Product-managed `sing-box` and `ck-client` were installed under
`/usr/local/bin`. AmneziaWG remains the documented guided trust-boundary
exception: the Ubuntu candidate followed the product/import-guided PPA flow
(`ppa:amnezia/ppa`) and WatchdogVPN verified the backend before use, but AWG
is not credited to normal silent installer dependency provisioning.

All 12 private protocol fixtures were imported from the authoritative private
set without committing or publishing raw profile material. The honest protocol
result is the same certified disposition as Arch, CachyOS and Debian:

- all five resilient rows passed truthful connection, normal TUN, local SOCKS
  and local HTTP-proxy real traffic, then clean disconnect: VLESS, Trojan,
  Hysteria2, AmneziaWG and OpenVPN+Cloak;
- VMess, TUIC, SOCKS and HTTP provided useful compatibility traffic. SOCKS and
  HTTP reproduced an Instagram-only timeout that also occurred against the
  same upstream proxies with WatchdogVPN disconnected, so that destination
  limitation is not a WatchdogVPN bug;
- WireGuard plain remains the maintainer-confirmed ISP/provider block and is
  not green;
- Shadowsocks standard can create the expected runtime but consistently fails
  useful egress under the known blocked/no-egress pattern. WatchdogVPN rejects
  false green and cleans up;
- plain OpenVPN was tested through WatchdogVPN and directly with
  `/usr/sbin/openvpn`. The native process completed TLS 1.3, received
  `PUSH_REPLY`, opened `tun0`, installed the pushed `def1` routes, initialized
  the AES-256-GCM data channel and logged `Initialization Sequence Completed`,
  but user traffic through the tunnel timed out or failed. WatchdogVPN
  correctly refused a green result and cleaned back to standby. This is a
  no-egress compatibility limitation, not a parser, dependency, permission,
  driver, TUN, route, DNS, firewall, cleanup or health-check bug.

The external provider lifecycle passed after enabling provider rotation
explicitly for the test provider. The provider import/update path found 42
nodes, connected a provider node, passed real Facebook/Instagram/YouTube egress
before rotation, rotated to a different node and passed normal TUN, local SOCKS
and local HTTP-proxy traffic after rotation. The provider was removed after the
gate and the final provider list was empty.

DNS/FakeIP passed on Ubuntu through the documented systemd-resolved link path.
An initial `watchdog dns apply --yes --json` invocation without the required
`--systemd-link` argument returned rc 70 and is recorded as harness misuse, not
a product pass. The corrected command
`watchdog dns apply --yes --json --systemd-link wdvpn-tun0` succeeded while
connected, real traffic stayed reachable, `watchdog dns reset --yes --json`
succeeded, and disconnect returned the VM to standby.

Split tunneling passed with isolated process-path evidence. The test used a
temporary copy of `/usr/bin/curl` at `/tmp/wdvpn-cert-curl` so the policy did
not contaminate WatchdogVPN's own health-check process. `current` produced the
VPN exit IP, `direct` produced the physical bridged exit IP, and `block`
rejected target traffic while the WatchdogVPN connection remained healthy. The
test rule was removed, app policy was disabled and the final state had no TUN,
no non-default rules and only `eth0`.

Panic sleep/wake, reboot and purge/reinstall gates passed. Panic sleep disabled
the WatchdogVPN service, left the hibernate marker present, removed the
WatchdogVPN kill switch and allowed direct GitHub recovery traffic; panic wake
restored the service and removed the marker. Reboot returned to clean standby
with doctor `FAIL=0`. Full uninstall removed product commands, unit files,
runtime/config/state paths and managed network artifacts; reinstall from
`install.sh --yes` restored the runtime and marker. A harness mistake ran one
reinstall as `sudo ./install.sh`, which installed the user TUI wrapper for the
wrong user context; this was corrected and revalidated by running the installer
as `vagrant`, after which `/home/vagrant/.local/bin/VPN` was present and
doctor reported `OK=132 WARN=3 FAIL=0`.

One access-recovery incident is excluded from product credit. After the purge
gate, the VM no longer accepted the prior SSH key. The disk was mounted offline
from `ubuntu-host` to restore only `~vagrant/.ssh/authorized_keys`; no
WatchdogVPN runtime, dependency, profile, route, DNS, firewall or product
configuration was changed through that recovery. It is harness access repair,
not a product dependency or green-path input.

Final private evidence is stored under
`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-5-5-ubuntu-certification`
with zero permission violations: every directory is 0700 and every file is
0600. The final Ubuntu state is standby/off, kill switch inactive, no TUN, only
`eth0`, default `ip rule`, no unexpected product listeners and doctor `FAIL=0`.
Known WARNs are not hidden: NTP was not active in the VM, one Polkit rule is
not verifiable without privilege, and truth state is DOWN because no VPN is
connected at rest.

The final Ubuntu result is **certified for supported end-user operation** with
formal non-green Plan-B/no-egress classifications only for the three externally
blocked or limited compatibility protocols above. No resilient-profile failure
was waived, no protocol was marked green without real traffic, and no known
HIGH/MEDIUM bug or accepted technical debt remains for Task 23.5.5.

## Task 23.5.6 - Phase 23.5 audit closure (2026-07-22)

Status: **CERTIFIED/CLOSED**. Task 23.5.6 audited the complete Phase 23.5
certification record across Arch Linux, CachyOS, Debian and Ubuntu after the
Ubuntu closure commit `935cd8a`. The audit was documentation/read-only with
respect to installed runtime state: the protected local Arch/CachyOS host was
not used for VPN, DNS, route, firewall, interface or network-service mutation.

The audited authority set was this repository document, the external Master
Plan, the project memory directory and the handoff file. The repository,
`origin/main`, `ubuntu-host`, CachyOS checkout and Ubuntu certification VM
checkout were verified at `935cd8a` before this closure documentation was
written. `wdvpn-ubuntu-certification` and `wdvpn-debian-certification` were
verified as bridge-only VirtualBox machines on `enp4s0` with no NAT or
secondary adapters; Debian remained powered off and Ubuntu was inspected over
direct bridged SSH without starting a graphical session.

The final Phase 23.5 distro disposition is consistent across the certification
record:

- Arch Linux is certified/closed for the default kernel and packaged LTS
  evidence path.
- CachyOS is certified/closed through the `ID_LIKE=arch` adapter path.
- Debian 13.6 is certified/closed on a fresh bridge-only VM.
- Ubuntu 24.04.4 LTS is certified/closed on a fresh bridge-only VM.

No distro is recorded as "12 green". The honest result remains 9 functional
rows plus 3 formal non-green compatibility rows for the externally blocked or
limited WireGuard plain, Shadowsocks standard and OpenVPN plain cases, with
5/5 resilient rows green on every certified distro. Plan-B/no-egress
classification is not product success and is not used for any resilient
profile.

The dependency-provenance rule remains closed: supported dependencies credited
to certification came from WatchdogVPN `install.sh`, `update.sh` or another
explicitly documented product route. AmneziaWG remains the guided external
trust-boundary exception and is not credited as a normal silent dependency.
Known harness-only events, including Ubuntu's wrong-user `sudo ./install.sh`
run and SSH key recovery, are documented as excluded from product credit.

Private evidence permissions were rechecked for the Ubuntu evidence tree and
reported zero violations: directories 0700 and files 0600. The prior Arch,
CachyOS and Debian closure entries remain the accepted evidence records for
those tasks. The Ubuntu final installed state was verified as standby/off, kill
switch inactive, no TUN, only `eth0`, default policy rules, no unexpected
product listeners and doctor `FAIL=0`.

The audit found one real handoff contradiction outside the repository: the
CachyOS section still named `c73b001` as its final repo state after the project
had already advanced and synced to `935cd8a`. That stale line was corrected in
the private handoff. No repository runtime bug, unresolved HIGH/MEDIUM finding,
known technical debt or evidence gap was found during Task 23.5.6. Phase 23.5
is closed; Phase 23.6 must still start only after explicit maintainer approval.

## Task 23.6.5 - Fedora field certification closure (2026-07-22)

Status: **CERTIFIED/CLOSED**. Fedora Workstation 44 (`ID=fedora`,
`VERSION_ID=44`, kernel `6.19.10-300.fc44.x86_64`, **SELinux enforcing**,
firewalld and systemd-resolved active) was certified in the bridge-only
VirtualBox VM `Fedora Workstation 44` on `ubuntu-host`, single bridged adapter
on `enp4s0`, no NAT and no secondary adapter, guest IP `192.168.0.151`. The
protected Arch host network stack was not used for VPN/DNS/route/firewall/
interface mutation. The functional matrix ran on installed source `3bf0276`,
which includes the two product fixes found during this task (`4f930da`,
`3bf0276`); CI passed for both.

Dependency-provenance gate: Fedora Workstation ships almost the entire required
runtime set, so provenance was proven by deliberate removal and restore. The
only base package missing on the stock image was `python3-cryptography`, which
`install.sh` provided. Nine required packages (`openvpn`, `nftables`,
`iptables-nft`, `firewalld`, `logrotate`, `procps-ng`, `iputils`, `bind-utils`,
`python3-cryptography`) were removed and restored: after removal the required
commands `nft`/`iptables`/`ip6tables`/`openvpn`/`ping`/`pgrep` and the
cryptography module were absent; `update.sh --yes` restored them and doctor
returned `FAIL=0`. `bind-utils` (`dig`) was correctly not reclaimed by
install/update - it is a historical auxiliary declaration with no current
runtime consumer, restored to the machine baseline manually. Product-managed
`sing-box` and `ck-client` install under `/usr/local/bin`. Accepted limitation
(maintainer sign-off): `libnotify`, `polkit` and `NetworkManager` cannot be
removed on Fedora Workstation because gnome-shell/gnome-settings-daemon
hard-depend on them; they are stock Workstation packages and declared in
`distros/fedora.sh`, installed by the same proven `dnf` path, and no manual
out-of-band install of them was performed.

Protocol matrix - honest disposition, the same as Arch/CachyOS/Debian/Ubuntu:
**9 functional rows plus 3 formal Plan-B rows, 5/5 resilient green**, never
"12 green".

- Resilient (all five passed truthful connection plus real TUN, local SOCKS
  (`127.0.0.1:2080`) and local HTTP-proxy (`127.0.0.1:2081`) egress to the
  required censorship-relevant destinations, then clean disconnect): VLESS,
  Trojan, Hysteria2, OpenVPN+Cloak and AmneziaWG.
- Compatibility with useful real traffic: VMess, TUIC, SOCKS and HTTP. HTTP
  reproduced an Instagram-only timeout that also occurred against the same
  upstream HTTP proxy with WatchdogVPN disconnected, so it is an upstream
  limitation, not a product failure.
- Plan-B/no-egress (not green): standard WireGuard ended in authoritative
  `connect_failed` matching the maintainer-confirmed ISP block; standard
  Shadowsocks raised runtime but the daemon rejected it after egress health
  failure and returned to clean standby; plain OpenVPN raised its native
  process and a TUN interface (transport/TLS/TUN confirmed, so not a bug) but
  produced no egress and the daemon rejected it fail-closed. None is a false
  green.

AmneziaWG required two real product fixes and one operational discovery:

1. **MTU black-hole fix (`4f930da`).** The AmneziaWG driver fell back to plain
   WireGuard's 1420 inner MTU when a profile pinned none. AmneziaWG's
   obfuscation overhead makes 1420 sit at the path black-hole boundary over
   real transports such as Cloudflare WARP: small requests pass while large
   TLS transfers intermittently hang. The driver now defaults to 1280 (IPv6
   minimum MTU), strictly safer than 1420 and cannot black-hole where 1420
   worked, so it only makes AmneziaWG more reliable on every distro. Regression
   test added.
2. **Fedora AmneziaWG guided-setup commands (`3bf0276`).** `distros/fedora.sh`
   carried no `DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS`, so importing an AmneziaWG
   profile printed "No prevalidated command list is available for this distro".
   Fedora has no official AmneziaWG package (the upstream copr ships only
   EPEL/RHEL), so the guided trust-boundary setup builds the userspace stack
   from Amnezia's official source - `amneziawg-tools` plus `amneziawg-go`. The
   userspace path is preferred over the DKMS kernel module because it needs no
   kernel headers and is not blocked by Secure Boot module signing while
   carrying identical real traffic. The guided flow was validated end to end:
   removing the backend and running only the codified commands installed
   `awg`/`awg-quick`/`amneziawg-go`, WatchdogVPN detected the backend, and the
   profile connected with real 3-path egress.
3. **Shared-profile contention (operational, not a product defect).** Early
   AmneziaWG runs were intermittent because the same AmneziaWG profile/key was
   active on several devices at once (the maintainer's iPhone, Arch host and
   native Amnezia app, plus the certification VM), and AmneziaWG/WireGuard bind
   one peer key to a single endpoint at a time, so the devices repeatedly stole
   the tunnel from each other; the assistant's own repeated test connections
   amplified it. With a fresh, dedicated, never-used profile (sourced from the
   CachyOS Amnezia export) the AmneziaWG row was fully green on the first
   contained run over both the kernel module and the userspace backend: 9/9
   3-path egress, VPN exit confirmed by three reflectors with no leak, and a
   complete 1 GB download at ~10 MB/s.

Provider lifecycle passed: the subscription imported 42 nodes, a node connected
with real 3-path egress, and `watchdog rotate --force` rotated to a different
node with real egress after rotation. (Non-forced rotation additionally
requires the app-level `rotation.enabled` config, a deliberate second gate
above per-provider rotation.)

DNS apply/reset passed through systemd-resolved: `watchdog dns apply` correctly
refused without privilege (`rc 70`, actionable message), succeeded under sudo
with `--systemd-link wdvpn-tun0` (resolver moved to `127.0.0.1`, traffic stayed
reachable), and `watchdog dns reset` restored the prior state.

Kill switch controlled-failure passed: the guarded field script reported
`PHASE23_KILL_SWITCH_CONTROLLED_FAILURE_OK backend=nftables drop_delta=1` -
during the attributed failure (daemon frozen, its verified sing-box child
killed) the nftables DROP counter increased and forced physical traffic was
blocked fail-closed, with no leak, before clean disconnect.

Split tunneling passed with isolated process-path evidence (a temporary copy of
`curl`): `current` produced the VPN exit, `direct` produced the physical exit,
and `block` rejected the traffic, while WatchdogVPN's own connection stayed
healthy throughout. sing-box attributes the process correctly under Fedora's
SELinux-enforcing posture; there is no per-process enforcement gap.

Panic sleep/wake passed against its true rescue contract: `panic sleep` disabled
the service, removed the WatchdogVPN firewall, left the hibernate marker, and
restored direct Internet (verified against a non-DNS-filtered site); `panic
wake` restored the service to standby.

Reboot passed both disconnected (returned to standby, doctor `FAIL=0`, direct
Internet reachable) and connected (`desired_state=on` persisted, the same VLESS
profile auto-reconnected on return with real VPN egress).

Uninstall/baseline passed: the confirmed full purge
(`--yes --purge-config --purge-logs --purge-state --confirm-delete DELETE`)
removed every product command, unit, path, the `watchdogvpn` account/group and
the installing user's membership, the sysctl file (`src_valid_mark` restored to
`0/0`), internal backups, nftables tables, TUN interfaces and table-880 routes;
direct baseline reachability and the resolver were restored. `sing-box`,
`ck-client` and the user-installed AmneziaWG backend are intentionally preserved
per the uninstall contract ("remove WatchdogVPN without deleting user-owned
VPN/proxy software").

Network-environment note: the certification LAN blocks major social platforms
at the DNS layer (facebook/instagram resolve to localhost, youtube is
IP/SNI-blocked) while non-social domains resolve normally. This is the exact
censorship WatchdogVPN circumvents: the resilient/compatibility egress rows
reaching Facebook/Instagram/YouTube through the tunnel are therefore stronger
evidence, since those destinations are actively blocked on the direct path.

Private evidence is under
`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-6-5-fedora-certification`
(directory `0700`, all files `0600`). No unresolved HIGH/MEDIUM finding and no
known technical debt remain for Task 23.6.5. Fedora is certified; openSUSE
(Task 23.6.6) and the Debian-derivative (Task 23.6.7) certifications, and the
Task 23.6.8 audit closure, remain.

## Task 23.6.6 - openSUSE field certification closure (2026-07-23)

Status: **CERTIFIED/CLOSED**. openSUSE Leap 15.6 (`ID=opensuse-leap`, kernel
`6.4.0-150600.23.22-default`, `wicked`/`wickedd` managing networking via
`netconfig` - NetworkManager and systemd-resolved both installed but inactive,
AppArmor present) was certified in the bridge-only VirtualBox VM
`wdvpn-opensuse-leap-audit` on `ubuntu-host`, single bridged adapter on
`eth0`/`enp0s3`, no NAT, guest IP `192.168.0.135`. The protected Arch host
network stack was not used for VPN/DNS/route/firewall/interface mutation.

Three real, universal product bugs (not openSUSE-specific in mechanism - each
would affect any distro hitting the same code path) were found and fixed
during this task, each committed, pushed and CI-green before the matrix
continued:

1. **Python interpreter resolver (`9106311`).** openSUSE Leap's default
   `python3` is 3.6.15, too old for the codebase (`from __future__ import
   annotations` needs 3.7+), so `install.sh`'s runtime validation failed
   immediately - this had never been exercised before because every
   previously-certified distro's default `python3` already happened to be
   modern enough. Added `watchdogvpn_python()` to `lib/common.sh`: prefers an
   adapter-declared `DISTRO_PYTHON`, falls back to system `python3` if >= 3.9
   (non-regressive on every already-certified distro), else the newest
   available `python3.9`-`python3.13`. Rewired every direct `python3` call
   site (`lib/runtime.sh`, `lib/packages.sh`, `install.sh`, `update.sh`,
   `doctor.sh`, `lib/amneziawg.sh`, `bin/watchdog`, `bin/watchdogvpn-daemon`,
   `bin/watchdogvpn`, `tests/syntax.sh`) through it; `opensuse.sh` pins
   `DISTRO_PYTHON=python3.11` and ships `python311`/`python311-cryptography`.
2. **`systemd-analyze verify --man=no` (also `9106311`).** `systemd-analyze
   verify` resolves each unit's `Documentation=man:...` reference by
   default, which requires `man`/man-db - not a real WatchdogVPN runtime
   dependency, and openSUSE Leap's minimal image doesn't ship it (unlike
   Fedora/Arch, where it happened to already be present for unrelated
   reasons). `install.sh` failed at "Systemd verification" with
   `Command 'man logrotate(8)' failed with code 1`. Fixed by passing
   `--man=no`, which still validates full unit correctness without depending
   on man-db.
3. **`dns reset` leaving system DNS permanently broken (`ae2fe81`).**
   `dns/state_manager.py::_restore_resolv_conf` only re-pointed the
   `/etc/resolv.conf` symlink back at its original target and skipped
   restoring the captured content whenever a target was recorded. That's
   correct for NetworkManager (its own dispatcher regenerates the target's
   content once `nmcli` restore runs), but wrong for openSUSE's
   `netconfig`/`wicked`, which writes `/run/netconfig/resolv.conf` once and
   never regenerates it: `apply_local_dns`'s `write_text` follows the
   symlink and overwrites that file's content directly, so restore left it
   permanently reading `nameserver 127.0.0.1`. Confirmed live: after
   `watchdog dns apply` -> `dns reset` -> a normal `disconnect`, system DNS
   was completely broken (`getent hosts` failed on everything, nothing left
   listening on `127.0.0.1:53`). Fixed by always writing the captured
   content back after repointing the symlink (harmless no-op wherever
   another resolver stack's own restore already regenerated the same
   bytes). Added a regression test using a real symlink-to-static-file
   `resolv.conf` - no existing test exercised that path; every prior
   `RESOLV_CONF`-category test used a plain, non-symlinked file.

One additional finding was investigated and resolved as **not a bug**:
testing `split-tunnel` current/direct/block by mutating rules while already
connected made each new action look like it silently had no effect. Root
cause: app-policy/split-tunnel rules are baked into the connecting profile's
sing-box config once, at connect time - same as most VPN clients, WatchdogVPN
has no live hot-reload of an active session's routing rules, and `add`/
`remove` only mutate the on-disk policy file with no daemon IPC call to
trigger a live reconfiguration. Re-tested correctly (reconnect after each
rule change): `current` -> tunnel exit `138.124.58.47`, `direct` -> true
physical exit `178.66.128.30` (verified against a captured pre-connect
baseline, not a same-session comparison, which is what caused the first,
incorrect reading), `block` -> `http_code=000`/`exit=6`, all correct.
Since silent no-notice was still a real UX gap, commit `c3a5880` adds an
honest CLI notice ("the active session keeps its current routing rules;
reconnect for this change to take effect") printed - and included as a JSON
`notice` field - whenever a mutation runs while the daemon is connected,
across every app-policy/split-tunnel mutating command.

**AmneziaWG guided-setup added for openSUSE (`b4bb113`).** `opensuse.sh`
carried no `DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS`, the same gap `fedora.sh` had
before `3bf0276`. openSUSE has no official AmneziaWG package either, so the
guided flow builds the userspace stack from Amnezia's official source
(`amneziawg-tools` + `amneziawg-go`), preferring userspace over the DKMS
kernel module for the same reason as Fedora (no kernel headers needed, not
blocked by Secure Boot module signing). Validated end to end: removing the
backend and running only the codified commands (`zypper install go gcc
make`, then the two upstream `git clone` + `make` + `install` steps)
produced working `awg`/`awg-quick`/`amneziawg-go`.

Dependency-provenance gate: 8 required packages (`openvpn`, `nftables`,
`iptables`, `firewalld`, `logrotate`, `procps`, `iputils`,
`python311-cryptography`) were removed via `zypper remove` (a single batch,
whose dependency cascade also swept up `NetworkManager`/`wpa_supplicant`/
`apparmor-utils`/`python3-psutil` - all either separately declared in
`opensuse.sh` and therefore correctly restored, or genuinely unrelated OS
packages that WatchdogVPN never claimed to own). After removal, SSH stayed
reachable (`wicked` - not the removed `NetworkManager` package - manages the
live interface) and every required command/module was confirmed absent.
`update.sh --yes` restored all of them; `bind-utils` (`dig`) was correctly
not reclaimed - same historical auxiliary declaration with no runtime
consumer already documented for Fedora. `sing-box`/`ck-client` install under
`/usr/local/bin` as product-managed files. `doctor.sh` returned `FAIL=0`
after restoration.

Protocol matrix - honest disposition, same as every other certified distro:
**9 functional rows plus 3 formal Plan-B rows, 5/5 resilient green**, never
"12 green".

- Resilient (all five passed truthful connection plus real TUN, local SOCKS
  (`127.0.0.1:2080`) and local HTTP-proxy (`127.0.0.1:2081`) egress to
  Facebook/Instagram/YouTube, then clean disconnect): VLESS, Trojan,
  Hysteria2, OpenVPN+Cloak and AmneziaWG. AmneziaWG used a genuinely fresh,
  never-used child profile (sourced from CachyOS, per the maintainer's
  explicit confirmation it was currently unused) to avoid repeating the
  shared-profile contention saga from Task 23.6.5; it passed 3/3 egress on
  the first try plus a 100 MB sustained download with no MTU black-hole
  regression.
- Compatibility with useful real traffic: VMess, SOCKS, HTTP and TUIC, all
  3/3 green with no upstream anomalies this time.
- Plan-B/no-egress (not green, all fail-closed correctly, each verified with
  live process/interface monitoring plus daemon logs, not just the terminal
  CLI status - the maintainer specifically asked that this be checked rather
  than taken at face value): standard WireGuard never brought up any network
  interface at all during the ~30 s attempt (0.3 s-interval sampling caught
  nothing beyond `lo`/`eth0`) before `connect_failed` - a real connection-level
  failure, consistent with the maintainer's own confirmation from their ISP
  that WireGuard is blocked more aggressively than the other two. Plain
  OpenVPN raised a real native process and two TUN interfaces
  (`tunwdriuwu0sg`, `wdvpn-tun0`) that stayed up for the full attempt - a
  genuine handshake, not a stub - but the egress health check against
  Facebook/Instagram/YouTube found 0/3 reachable on both the initial check
  and one retry ~16 s later (`endpoint_censorship_or_network_interference_
  suspected`), so it unwound to the same `connect_failed` label; the label
  conflates "never connected" with "connected, zero egress" and only the
  driver/interface evidence distinguishes the two here. Standard Shadowsocks
  raised runtime and its *initial* health check actually passed
  (`successful_targets=2`, real user traffic reached at least two of the
  three sites) - the daemon's ongoing background monitoring then caught the
  same 0/3 degradation ~42 s later and correctly failed closed
  (`kill_switch_active`), consistent with the ISP's block acting on an
  established session rather than the handshake itself. None is a false
  green, and none is a WatchdogVPN defect - the app's own classification
  (`endpoint_censorship_or_network_interference_suspected`) already names
  the real cause correctly in both OpenVPN's and Shadowsocks's logs.

Kill switch controlled-failure passed: the guarded field script reported
`PHASE23_KILL_SWITCH_CONTROLLED_FAILURE_OK backend=nftables drop_delta=1` -
forced physical traffic was blocked fail-closed with no leak during the
attributed failure, before clean recovery.

Split tunneling passed (see the finding above): `current`, `direct` and
`block` all produced the correct outcome once tested with a reconnect after
each rule change, with WatchdogVPN's own connection healthy throughout.

DNS apply/reset passed after the fix: `watchdog dns apply --yes` moved
`/etc/resolv.conf` to `127.0.0.1` while real traffic stayed reachable, and
`watchdog dns reset --yes` restored the exact original file content
(including netconfig's comment header) - verified by disconnecting
afterward and confirming `getent hosts` resolved normally again.

Panic sleep/wake passed against its true rescue contract: `panic sleep`
disabled the service, removed the WatchdogVPN firewall, left the hibernate
marker, and restored direct Internet (verified against github.com, a
non-DNS-filtered site); `panic wake` restored the service to standby.

Reboot passed both disconnected (returned to standby, doctor `FAIL=0`,
direct Internet reachable) and connected: the first connected-reboot attempt
correctly revealed that `vpn_autoconnect_enabled` is a separate, off-by-default
opt-in flag (`core/watchdog.py::startup`), not something `connect` sets
implicitly - the daemon fail-closed via the kill switch instead of silently
leaking, exactly as designed, when the flag was off. Not a bug: enabled it
via `watchdog setup --autoconnect enable --yes --acknowledge-backup-warning`,
reconnected, rebooted again, and the same VLESS profile auto-reconnected
correctly with real VPN egress.

Uninstall/baseline passed: the confirmed full purge (`--yes --purge-config
--purge-logs --purge-state --confirm-delete DELETE`) removed every product
command, unit, path, the `watchdogvpn` account/group and the installing
user's membership (`userdel`'s "group not removed" message was expected
mid-sequence noise - the explicit follow-up `groupdel` call in
`remove_watchdogvpn_system_account` completed it, confirmed by `getent group
watchdogvpn` and `id vagrant` afterward), the sysctl file (`src_valid_mark`
restored to `0/0`), nftables tables, `ip rule` entries/table 880, and
restored `/etc/resolv.conf` to the exact pre-install baseline content;
direct Internet stayed reachable throughout. `sing-box`, `ck-client`,
`awg`/`awg-quick` and `amneziawg-go` are intentionally preserved per the
uninstall contract.

Private evidence is under
`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-6-6-opensuse-certification`
(directory `0700`, all files `0600`). No unresolved HIGH/MEDIUM finding and no
known technical debt remain for Task 23.6.6. openSUSE is certified; Task
23.6.5b (Rocky/Alma, mandatory), the Debian-derivative (Task 23.6.7)
certification, and the Task 23.6.8 audit closure, remain.

## Task 23.6.5b - Red Hat-family field certification closure: Rocky Linux 9 (2026-07-23)

Status: **CERTIFIED/CLOSED**. Rocky Linux 9 (`ID=rocky`, `ID_LIKE="rhel
centos fedora"`, SELinux enforcing, NetworkManager the live and only manager
of the guest's single interface) was certified in a bridge-only VM,
`enp0s3`, no NAT. The protected Arch host network stack was not used for
VPN/DNS/route/firewall/interface mutation throughout. Same disposition
pattern as every prior certified distro: **9 functional rows + 3 formal
Plan-B rows, 5/5 resilient green**, never "12 green".

This was the deepest bug-finding task of Phase 23.6: **seven real, universal
product bugs** (none Rocky-specific in mechanism - each would affect any
distro/kernel/network-manager combination hitting the same code path) were
found and fixed, each committed, pushed and CI-green before the matrix
continued:

1. **EPEL missing (`9cdcb2b`)**. RHEL-family derivatives need EPEL enabled
   before several required packages (`nftables`, etc.) can be reconciled by
   `dnf` at all - Fedora proper doesn't need this since its own repos already
   carry them. Added `distro_prepare_package_repos()`, an optional adapter
   hook called from `lib/packages.sh::validate_required_commands()` before
   package installation; no-op on real Fedora, installs `epel-release` on
   RHEL-family. Verified end to end by removing `epel-release` itself via
   `update.sh --yes` and confirming it was correctly reinstalled.
2. **Python floor wrong (`8f0424b`)**. The floor set during the openSUSE task
   (`>= 3.9`, for `from __future__ import annotations`) was insufficient:
   the codebase uses `dataclass(slots=True)` pervasively across dozens of
   files, which needs Python **3.10**, not 3.9. This had never been caught
   because every previously-certified distro's resolved interpreter already
   happened to be 3.10+. Raised `WATCHDOGVPN_MIN_PYTHON_MINOR` to 10 and
   pinned `distros/fedora.sh`'s RHEL-family branch to `python3.11`.
3. **AmneziaWG copr guidance (`8a3babd`)**. Unlike Fedora (no prebuilt
   `amneziawg-tools` package, from-source build required), RHEL-family can
   use the `tigro/amneziawg` copr for a prebuilt `amneziawg-tools`
   (independently verified to actually exist and publish RHEL/EPEL builds,
   as opposed to `amnezia-vpn/amneziawg`, which does not have a copr at
   all) - `amneziawg-go` (userspace) still has no prebuilt anywhere and
   stays a from-source build. Added a RHEL-family-specific
   `DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS` override.
4. **NetworkManager DNS state corruption (`42f9f33`)**. This was the first
   certification to ever exercise the real `NETWORK_MANAGER` resolver branch
   against an active DHCP connection with no manual DNS override (Fedora/
   Ubuntu both run systemd-resolved on top of NetworkManager instead;
   Debian's NetworkManager connection was loopback-only both prior times).
   `_save_network_manager_connections` queried all six DNS-related nmcli
   properties in one comma-joined call and `.strip()`ed the result, which
   silently eats a leading blank line whenever the *first* requested field
   (`ipv4.dns`) is empty - the ordinary case for a plain DHCP connection,
   not an edge case - shifting every later value one position and feeding a
   corrupted value straight into `nmcli con mod ... ipv4.dns no` on
   `dns reset`, which nmcli correctly rejected, leaving a stray
   `nameserver 127.0.0.1` in `/etc/resolv.conf`. Fixed by querying each
   property in its own separate call, so an empty result can never shift a
   neighbor.
5. **NetworkManager TUN-interface persistence (`04ed290`)**. NetworkManager
   auto-adopts a newly-seen interface like `wdvpn-tun0` into its own
   persistent, autoconnect-on connection profile; killing the owning process
   alone does not stop NM from recreating the interface afterward, since
   NM's own stored desired state drives it, not the kernel device's
   existence. Initially logged as a cosmetic, not-worth-chasing observation
   (a normal connect/disconnect cycle still worked correctly end to end),
   but escalated to a real bug once a later daemon restart
   (`watchdog_panic wake`) reported a **critical `runtime_mismatch`**
   against the leftover interface, and the documented recovery step
   (`watchdog disconnect`) could not clear it either, since NM kept
   recreating it faster than the driver's own cleanup could matter.
   `_cleanup_tun_residue()` now also deletes NetworkManager's stored
   connection profile (`nmcli con delete`); this is shared TUN
   infrastructure (native-policy mode's OpenVPN/OpenVPN+Cloak/AmneziaWG
   companion delegate to the same driver instance), so the fix covers every
   protocol, not only sing-box-native ones.
6. **Panic sleep silently failing under sudo (`d1d0e4d`)**. `sudo`'s default
   `secure_path` strips `/usr/local/bin` on Rocky (likely other distros
   too). `watchdog_panic sleep`'s own graceful `watchdog disconnect` step
   resolves `watchdog` by bare name; under `sudo watchdog_panic sleep`, that
   silently failed and skipped the whole disconnect step - including
   clearing `vpn_desired_state` - even though the script had already printed
   as if it succeeded. The daemon's own fail-safe shutdown handler then
   correctly, but very unhelpfully, re-applied the kill switch the command
   exists to remove, leaving the user's Internet blocked after their own
   rescue command. Never caught on Fedora/openSUSE because both of those
   certifications only exercised panic sleep/wake from an already-
   disconnected standby state. Fixed by prepending
   `/usr/local/bin:/usr/local/sbin` to the script's own `PATH` at the top,
   fixing every bare-name lookup in it.
7. **Strict `rp_filter` silently dropping AmneziaWG return traffic (`d0a55ce`,
   `ca2d0e6`, `bb9f86c`)**. The deepest investigation of the task. AmneziaWG
   connected (real process, real interface, kill switch applied) but never
   passed a byte of traffic on three different profiles, including a
   genuinely fresh one - ruling out the profile contention pattern seen
   earlier in Task 23.6.5. Root-caused via direct SSH access to the
   AmneziaWG server: `awg show` showed the peer receiving data with no
   completed handshake, and `ip -s link show` on the client showed TX
   incrementing while RX stayed at 0. `_configure_routes()`'s
   `ip rule ... table main suppress_prefixlength 0` (the standard
   wg-quick/awg-quick default-route trick) makes the physical interface's
   own reverse-path check for the server's address resolve via the tunnel
   instead of itself, so strict `rp_filter` silently drops the server's real
   response packets. Confirmed directly: manually loosening
   `net.ipv4.conf.enp0s3.rp_filter` made RX jump immediately to real data.
   The fix went through three layers as each one revealed the next gap: (a)
   `etc/sysctl.d/99-watchdogvpn.conf` sets `rp_filter` to loose (2) plus a
   driver-level `_ensure_rp_filter()` fail-fast at connect time; (b) found
   deploying (a) live - `conf.default` only templates interfaces *created
   after* the file is applied, and a machine's primary NIC is typically
   created by the kernel driver before `systemd-sysctl.service` ever runs
   (confirmed via journalctl timestamps: sysctl finished four seconds before
   NetworkManager even saw `enp0s3`), so `install_sysctl_defaults()` now
   also detects and directly nudges the live default-route interface on
   every install/update run, with the sysctl baseline manifest extended to
   track and restore that interface's true original value too; (c) found on
   the very next plain reboot after (b) - the install/update-time nudge does
   not survive an ordinary reboot on its own, so a small boot-time systemd
   unit (`watchdogvpn-rp-filter.service` + `bin/vpn_rp_filter_boot`) now
   reapplies it on every boot. Verified end to end after each layer: (a)+(b)
   made connect fail *fast* (safety net firing correctly) instead of the old
   silent ~30s hang, with a one-line manual `sysctl -w` then passing 9/9 real
   egress checks; (c) made AmneziaWG connect and pass 9/9 real egress checks
   automatically after a full reboot with **no manual intervention
   whatsoever**.

Dependency-provenance gate: removed and confirmed restored via
`update.sh --yes`: `openvpn`, `nftables` (cascaded firewalld/iptables-nft/
podman-stack, all intended or harmless), `logrotate`, `procps-ng`,
`python3.11-cryptography`, `epel-release`, `git`. `iputils` required
`sudo rpm -e --nodeps iputils` instead of `dnf remove`, since `dnf`'s
dependency graph makes it a hard dependency of the live, active
NetworkManager on this image (a 63-package cascade including NetworkManager
itself) - removing it the normal way risked losing the SSH session
entirely; `--nodeps` removed only the package files, NetworkManager stayed
active throughout, and `update.sh`'s normal package reconciliation still
correctly restored `ping` afterward. `epel-release`'s absence/restoration is
a direct end-to-end validation of `distro_prepare_package_repos()` (bug 1
above) on a real system, not just the bash unit test mock. `bind-utils`
correctly not reclaimed, same no-current-consumer finding as Fedora.
`doctor.sh` returned `FAIL=0` after every restoration.

Kill switch controlled-failure passed: `drop_delta=1` on the `nftables`
backend - forced physical traffic to `github.com` was blocked fail-closed
(`curl` return code 7, `http_code=000`) with no leak during the attributed
failure, before clean recovery.

AmneziaWG (see bug 7 above) ultimately passed 9/9 real egress checks (TUN,
local SOCKS, local HTTP proxy, each against Facebook/Instagram/YouTube) with
real RX traffic (multi-megabyte), both immediately after the install/update-
time fix and, separately, fully automatically after a reboot once the
boot-time unit closed the last gap. Provider connectivity, DNS apply/reset,
split-tunnel, panic sleep/wake (fixed above), reboot (disconnected and
connected) and full-purge uninstall/baseline all passed against the same
resilient/compatibility/Plan-B disposition pattern used throughout Phase
23.6.

Uninstall/baseline passed with exact restoration confirmed twice: a
full-purge uninstall (`--yes --purge-config --purge-logs --purge-state
--confirm-delete DELETE`) restored `net.ipv4.conf.all.rp_filter=0`,
`net.ipv4.conf.default.rp_filter=1` and `net.ipv4.conf.enp0s3.rp_filter=1` -
an *exact* match to the true pre-WatchdogVPN baseline captured on this VM's
very first clean boot, before any manual diagnostic testing ever touched
it - along with `src_valid_mark`, the sysctl.d file, the baseline manifest,
the boot-time unit and its script, all removed cleanly. A subsequent fresh
`install.sh --yes` (exercising the fresh-capture path rather than the
migration path) reproduced the identical working result, confirming both
install paths apply and capture the fix identically.

Private evidence is under
`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-6-5b-rockyalma-certification`
(directory `0700`, all files `0600`).

### Closure pass (2026-07-23): retrospective audit and evidence hardening

A retrospective technical audit of the certification above found the
evidence real but methodologically inconsistent in places (bare-domain HTTP
checks without following redirects, no explicit physical-IP baseline for the
non-AmneziaWG protocol rows, Plan-B rows accepted on the CLI's own status
alone rather than independent process/interface sampling, no field
re-validation of the NetworkManager TUN-persistence and rp_filter fixes, no
regression pass on the other certified distros). Verdict at that point:
**CERTIFICACION_CONDICIONADA**. A dedicated closure pass then closed every
gap with live evidence (`closure-pass-20260723/` inside the same private
evidence directory) and found and fixed **two additional real bugs** in the
process:

1. **`sudo watchdog_panic sleep` still failed by bare name** (`28efc04`,
   reverted and replaced, see below). The earlier fix only patched the
   script's own internal PATH once sudo had already found and started it;
   sudo's own `secure_path` lookup of the script itself is a separate,
   earlier step that fix never touched. Found while executing the
   documented panic sleep/wake cycle exactly as a user would. First fixed
   with `etc/sudoers.d/99-watchdogvpn-secure-path`, extending `secure_path`
   for every command on the system, not only WatchdogVPN's own. On review
   this was judged too broad a change for the problem: it altered sudo's
   behavior system-wide for every user and command, when a narrower fix
   exists. A command-scoped `Defaults!cmnd_alias secure_path=...` rule was
   tested as an alternative and empirically confirmed *not* to work - sudo
   has to resolve which command is being run, from its bare name, before it
   can even test whether a command-scoped rule applies, so a scoped
   `secure_path` can never help resolve the bare name in the first place.
   The sudoers.d fragment was reverted entirely (no sudoers modification of
   any kind ships now) and replaced with the fix that actually needs no
   privilege-boundary change at all: `docs/security.md`, `bin/watchdog_panic`'s
   own usage text and runtime hints, and `doctor.sh`'s recovery hints all
   consistently instruct invoking the command by its full installed path
   (`sudo /usr/local/bin/watchdog_panic ...`), which needs no `secure_path`
   resolution by sudo to begin with. Verified on Rocky: the full-path form
   works with zero sudoers changes present.
2. **`conf.all`/`conf.default.rp_filter` did not survive a reboot on
   CachyOS** (`819a962`). `systemd-sysctl.service` ran and reported success,
   but something later in boot (NetworkManager starts a few seconds
   afterward on that VM) reset both back to strict, silently defeating the
   boot unit's own per-interface nudge (effective policy = the more
   restrictive of the two). Fixed by having `bin/vpn_rp_filter_boot`
   defensively reassert `conf.all`/`conf.default` directly on every boot,
   not only the detected interface. Verified end to end: rebooted CachyOS
   again after deploying the fix, both values held loose immediately, and
   AmneziaWG connected on the first attempt with real egress.

Gaps closed, each with live evidence: the 8-protocol matrix re-run with
`www.` domains, `-L`, final HTTP code, effective URL, remote IP and an
explicit physical-IP baseline (all 8 passed; the SOCKS/HTTP provider rows
show a reproducible, upstream-attributed Instagram-only TLS-handshake
timeout, documented as a known limitation of that specific provider path,
not a WatchdogVPN defect); a full clean-room AmneziaWG validation (complete
purge including Go module/build caches, guidance captured verbatim, only
the three documented commands executed, real handshake/RX/egress
confirmed); 0.3s-interval process/interface sampling for WireGuard standard
and OpenVPN plain, which **corrected** an earlier overstatement - WireGuard
does raise a real process and a real TUN interface before failing on zero
egress, the same class of failure as OpenVPN plain and Shadowsocks, not a
"never connects" case; real-traffic split-tunnel validation (`current`
reaches the tunnel exit IP, `direct` reaches the exact physical baseline
IP, `block` fails with a real DNS-resolution error); a full field
NetworkManager-TUN-persistence cycle including the panic sleep/wake path
that originally exposed the bug, with no `runtime_mismatch`; and a live
two-NIC default-route-change test for the rp_filter fix, which reproduced
and confirmed the already-documented known limitation (an interface no
longer tracked by the baseline manifest is not restored to its true
original value on uninstall - low severity, since it only ever downgrades
strict to loose, never disables reverse-path filtering).

Targeted regression on the shared components changed: **Fedora** -
update/DNS-apply-reset/connect-disconnect/TUN-cleanup/panic-sleep-wake/
AmneziaWG/reboot all passed, no regressions. **CachyOS** - same checks,
found and fixed the rp_filter reboot bug above, then re-verified clean.
**Ubuntu/Debian** - blocked: no valid SSH credentials for any of the three
candidate VMs on `ubuntu-host` after reasonable attempts; documented as an
open item rather than skipped silently or fabricated.

Final verdict, precise per distribution - only Rocky Linux 9 was ever
physically installed, booted and exercised in this task; AlmaLinux 9,
RHEL and CentOS Stream share the same `distros/fedora.sh` RHEL-family
adapter code path but were never themselves booted or tested here:

```
Rocky Linux 9:            CERTIFICACION_COMPLETA
AlmaLinux 9:               COMPATIBILIDAD_INFERIDA_POR_FAMILIA
RHEL/CentOS Stream:        COMPATIBILIDAD_INFERIDA_POR_FAMILIA
```

with the Ubuntu/Debian regression pass as an explicitly open follow-up, not
a blocker for Rocky Linux 9's own certification. No unresolved HIGH/MEDIUM
finding and no known technical debt remain for Task 23.6.5b beyond that one
documented item and the two flaky-test-fixture failures in
`tests/test_openvpn_cloak_driver.py` (root-caused, fixed and verified - see
below). The Debian-derivative certification (Task 23.6.7) and the Task
23.6.8 audit closure remain.

### Final clarification pass (2026-07-23): test-suite integrity and sudoers scope

Before registering this task's closure, three points raised on review of the
closure pass above were run down to ground truth:

1. **Two failing tests in `tests/test_openvpn_cloak_driver.py`**
   (`test_connect_rolls_back_cloak_when_openvpn_spawn_fails` and
   `test_connect_rolls_back_both_children_when_readiness_fails`) were
   flaky, not a product defect. Both tests' `Mock` child processes use
   hardcoded PIDs (1111, 2222) that get durably recorded to a real runtime
   directory via the real `record_child_process()`; `_teardown_children()`'s
   rollback then calls the real `recorded_children_terminated()`, which
   performs a genuine `/proc`-based liveness check against those PIDs by
   design (it must never assume a child is dead on uncertain evidence). If
   an unrelated real process on the machine running the suite happens to
   hold PID 1111 or 2222 at that moment, the check correctly - by its own
   stricter-than-strictly-necessary design - refuses to confirm the mock
   children are gone, and the test's own rollback assertion fails. Classified
   `test_obsoleto`: a test-fixture defect (asserting through a real `/proc`
   check instead of isolating it), not a bug in `_teardown_children()`'s own
   rollback logic, which behaves correctly and does not block this
   certification. Fixed, not merely documented: both tests now patch
   `drivers.openvpn_cloak_driver.recorded_children_terminated` to always
   return `True`, removing the dependency on the real process table. Full
   suite re-run clean after the fix: `Ran 1778 tests ... OK`.
2. **Distro scope corrected** to the precise per-distribution table above -
   only Rocky Linux 9 was physically certified in this task; AlmaLinux 9,
   RHEL and CentOS Stream are family-inferred compatibility, not independent
   physical certifications, since they were never themselves booted.
3. **`etc/sudoers.d/99-watchdogvpn-secure-path` reverted** (see bug 8 above)
   in favor of a fix with zero sudoers footprint: always invoke
   `watchdog_panic` by its full installed path. No sudoers file ships with
   WatchdogVPN at all as of this closure.

Final verdict: **CERTIFICACION_COMPLETA_ROCKY_LINUX_9**.

## Task 23.6.7 - Linux Mint Debian/Ubuntu-derivative field certification (2026-07-24)

Status: **CERTIFICACION_COMPLETA_LINUX_MINT_22_3**. Linux Mint 22.3 "Zena"
was certified in the fresh bridge-only VirtualBox VM
`wdvpn-linuxmint-23-6-7` on `ubuntu-host`, with exactly one bridged adapter on
`enp4s0`, no NAT adapter, no shared folders, the ISO ejected, and guest IP
`192.168.0.149`. The protected Arch host and the VirtualBox host were not used
for VPN, DNS, route, firewall or interface mutation.

The certification proved the Task 23.6.4 `ID_LIKE` fallback end to end on a
real derivative, not by editing `/etc/os-release`: Linux Mint reports
`ID=linuxmint` and `ID_LIKE="ubuntu debian"`, and WatchdogVPN resolved it to
`DISTRO_ADAPTER_ID=ubuntu`, `DISTRO_FAMILY=ubuntu`, and
`distros/ubuntu.sh`. This is a physical certification for Linux Mint 22.3 only.
Other Debian/Ubuntu derivatives remain compatibility-inferred until independently
field-tested.

Dependency provenance passed through the WatchdogVPN installer/update contract.
The clean Mint image did not ship every required tool; for example `git` was
absent before product installation and present after the WatchdogVPN path. The
Ubuntu adapter reconciled the supported `apt` runtime set, including
NetworkManager/nmcli, logrotate, OpenVPN, nftables, iptables, Polkit/systemd
integration, curl, git, Python 3, Python cryptography and the remaining runtime
commands. Product-managed `sing-box` and `ck-client` were installed under
`/usr/local/bin`. AmneziaWG remains the documented guided trust-boundary
exception: on Linux Mint the Ubuntu adapter's guided PPA sequence
(`ppa:amnezia/ppa`, running-kernel headers and `amneziawg`) was executed and
verified before the AmneziaWG row was counted.

The honest protocol disposition matches the other certified distro families:
**9 functional rows plus 3 formal non-green Plan-B/no-egress rows, with 5/5
resilient rows green**, never "12 green".

- Resilient green with real normal TUN, local SOCKS and local HTTP-proxy egress
  to Facebook, Instagram and YouTube on all three paths: VLESS, Trojan,
  Hysteria2, OpenVPN+Cloak and AmneziaWG. The original AmneziaWG fixture was
  not counted because the maintainer confirmed it may have been disabled; a new
  dedicated profile was generated and then passed all 9 egress probes. The VM
  used the native AmneziaWG kernel backend (`/usr/bin/awg`, `awg-quick`,
  `watchdogvpn_awg`, `wdvpn-tun0`, MTU 1280).
- Compatibility with useful real traffic: VMess and TUIC passed all 9 egress
  probes. SOCKS and HTTP passed Facebook and YouTube on all three paths and
  reproduced the same Instagram-only timeout pattern already documented on
  other distros; this is useful compatibility traffic with a target/upstream
  limitation, not a WatchdogVPN green for Instagram.
- Formal Plan-B/no-egress, not green: standard WireGuard, standard Shadowsocks
  and plain OpenVPN. WireGuard and plain OpenVPN ended in the known no-egress
  pattern with no useful target traffic. Shadowsocks raised a connected runtime
  but produced 0/3 useful probes on direct, SOCKS and HTTP paths in the final
  evidence and returned to standby.

DNS apply/reset passed through systemd-resolved using the connected
`wdvpn-tun0` link: the first non-sudo apply attempt is recorded as harness
misuse and not credited; the corrected `sudo watchdog dns apply --yes --json
--systemd-link wdvpn-tun0` returned `status=applied`, real Facebook egress
remained HTTP 200, and `sudo watchdog dns reset --yes --json` returned
`status=restored`.

Split tunneling passed with an isolated curl copy: `current` reached the VPN
exit IP, `direct` reached the physical bridged exit IP, and `block` rejected
the request while the WatchdogVPN connection stayed healthy. Panic sleep/wake
passed using the full `/usr/local/bin/watchdog_panic` path: sleep stopped the
service and left direct GitHub recovery traffic working, wake restored the
service, and doctor returned `FAIL=0`. Reboot returned to the same bridge-only
VM, `ID_LIKE` mapping intact, standby/off state, no TUN/proxy/kill switch and
doctor `FAIL=0`.

Full purge/reinstall passed after correcting a harness mistake. A first
noninteractive uninstall attempt could not obtain sudo and is recorded as
invalid. The corrected sudo uninstaller removed product commands, units, config,
state and logs; a TTY reinstall as `gabodev` restored the runtime, installed the
TUI wrapper under `/home/gabodev`, and after a fresh login session doctor
reported `OK=136 WARN=2 FAIL=0` with `watchdog status` in standby.

Private evidence is stored under
`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-6-7-linuxmint-certification`
with zero permission violations after final sync: directories `0700`, files
`0600`. The final VM state is running, bridge-only, standby/off, kill switch
inactive, no runtime artifacts, and installed source/marker aligned at
`7be1cc3cea67b93e2b0e940ebf3c128b6c801dc4`.

Final verdict: **CERTIFICACION_COMPLETA_LINUX_MINT_22_3**. No resilient profile
was waived, no protocol was marked green without real traffic, and no known
HIGH/MEDIUM bug or accepted technical debt remains for Task 23.6.7. Task 23.6.8
audit closure remains the next Phase 23.6 gate.
