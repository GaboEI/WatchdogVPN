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
| Arch Linux | `arch` | 23.5 | **CERTIFIED** — full matrix, DNS, rotation, kill switch, and clean uninstall/baseline comparison complete (2026-07-18) |
| CachyOS | `arch` through `ID_LIKE=arch` | 23.5 | **CERTIFIED** — clean VirtualBox VM, full matrix/dispositions, real reboots and exact purge/baseline comparison complete (2026-07-19) |
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

Arch Linux (Task 23.5.2) is now fully certified: protocol matrix, provider
lifecycle, DNS apply/reset, rotation, kill-switch controlled failure, and
clean uninstall with post-uninstall baseline comparison all have accepted
real-machine evidence.

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

## Task 23.5.3 closure — CachyOS certification

Status: **CLOSED — CACHYOS CERTIFIED** on 2026-07-19. The accepted candidate
was a clean VirtualBox CachyOS x86_64 VM using the Arch adapter through
`ID_LIKE=arch`. The maintainer explicitly clarified that the earlier physical
target existed only because Vagrant did not offer a suitable CachyOS image;
it was never a second certification gate. The manual VirtualBox candidate
therefore supersedes that unavailable environment and closes Task 23.5.3.

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

No historical red was converted into a synthetic protocol pass:

- all 12 private fixtures imported, but Trojan, Hysteria2, AmneziaWG,
  OpenVPN+Cloak, VMess and TUIC retained their demonstrated server/fixture or
  selected-egress failures; AmneziaWG had a real interface, route, handshake
  and receive traffic without useful egress;
- WireGuard, Shadowsocks and plain OpenVPN retain the already planned
  external-origin disposition in Task 23.6.5a and are neither CachyOS
  failures nor local passes;
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
green. Task 23.5.4 — Debian certification is the next task in Phase 23.5. The
accepted CachyOS matrix need not be repeated unless a later product change or
new defect materially affects its evidence.
