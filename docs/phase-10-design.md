# Phase 10 Design - DNS v2 System

> Status: Design accepted for implementation planning.  
> Date: 2026-07-02  
> Implementation status: Not started.  
> Inspiration: comparable DNS and DNS-server models, adapted to WatchdogVPN's
> Linux CLI/TUI, kill switch, sing-box, native tunnel, and system resolver
> constraints.

## Goal

Build a WatchdogVPN-owned DNS v2 system that is safe by default, explicit for
advanced users, and powerful enough to support per-channel DNS behavior,
FakeIP, ECS, static IP mappings, DNS diversion rules, TTL/cache policy, DNS
testing, and clean system restore.

Phase 10 must not recreate the removed guided third-party DNS integration.

## References

- ADR-0001: guided third-party DNS integration removal decision.
- Phase 9 kill switch validation: `docs/v2-validation-log.md`

The useful product idea is not a single global DNS setting. DNS behavior is
separated by resolution channel, with multiple resolvers per channel,
auto-configure, reset, TTL, FakeIP, static IPs, and
enable DNS diversion rules. WatchdogVPN should adopt that product model while
respecting Linux system resolver safety.

## Current DNS Surface

Current repository state before Phase 10 implementation:

- `core/kill_switch.py` already blocks DNS/DoT outside the tunnel when kill
  switch is active.
- `bin/vpn_dns_rescue` remains as a safety helper for resolver recovery.
- `config/app_config.py` has a minimal `dns.mode = "auto"` placeholder.
- `docs/configuration.md` documents DNS keys as read-only until runtime DNS
  apply flows exist.
- No removed guided third-party DNS integration remains.
- No DNS v2 engine exists yet.

## Product Model

### User Modes

Phase 10 DNS v2 supports these modes:

- `auto`: recommended default. WatchdogVPN chooses a safe DNS policy based on
  the active driver and resolver manager.
- `off`: WatchdogVPN does not manage DNS, except DNS rescue remains available
  for recovery.
- `custom`: user selects resolvers from presets or custom URLs.
- `advanced`: user controls DNS channels, FakeIP, ECS, static IPs, rules, TTL,
  and test domain.

Installer must not ask non-technical users to choose a DNS provider. The normal
install path should work with `auto`.

### DNS Channels

WatchdogVPN DNS v2 uses channel-specific resolver sets:

- `bootstrap_dns`: resolves DNS server hostnames and proxy server hostnames
  before encrypted DNS/proxy DNS is usable.
- `dns_server`: resolver used by other DNS servers when a DNS endpoint itself
  needs name resolution.
- `proxy_server`: resolver used to resolve proxy/VPN server hostnames.
- `direct`: resolver for traffic that will go direct.
- `proxy`: resolver for traffic that will go through proxy/VPN.
- `final`: resolver used when no more specific DNS rule matches.

Each channel can select up to 4 resolvers. The DNS tester can race selected
resolvers and choose the fastest healthy result for channels where concurrent
resolution is safe.

### Resolver Types

Supported resolver URI forms:

- `local`
- `dhcp://auto`
- `udp://IP`
- `tcp://IP`
- `tls://host-or-ip`
- `https://host-or-ip/path`
- IPv6 literal variants where the transport supports them

Preset resolvers should include neutral public options. Presets are data, not
dependencies.

### Advanced Features

Phase 10 includes design and implementation for:

- TUN DNS hijack: capture system/application DNS and route it through DNS v2.
- Resolve inbound domain names: resolve inbound domain names before routing
  decisions when needed.
- Static IP map: domain-to-IP mappings similar to a hosts file.
- Test domain: default `gstatic.com`, configurable.
- TTL/cache policy: default cache duration with advanced override.
- DNS diversion rules: map domains/rule groups to DNS channels.
- ECS for direct traffic: optional and off by default for privacy.
- FakeIP for proxy traffic: supported for proxy-channel resolution.

These features must be real behavior before any TUI control is exposed. No TUI
placeholder screens.

### ECS Privacy Boundary

ECS sends an EDNS Client Subnet hint with DNS queries. This can improve CDN or
regional answers for direct traffic, but it also shares an approximate network
location with the resolver and sometimes the upstream authoritative path.
WatchdogVPN therefore keeps ECS disabled by default and only allows it on the
direct DNS channel with an explicit subnet. ECS must never be sent through
proxy, final, FakeIP, bootstrap, or system resolver paths unless a later phase
adds and validates a narrower policy.

### Static IP Map Boundary

Static IP mappings behave like a small WatchdogVPN-owned hosts file. They are
disabled by default and, when enabled, are emitted before upstream DNS routing
so an exact configured domain resolves to the configured IP address first. In
sing-box-backed DNS this uses a `hosts` DNS server with `predefined` records and
a first-position DNS rule for the mapped domains. Static mappings do not mutate
`/etc/hosts` or the host system resolver state.

### DNS Diversion Rule Boundary

DNS diversion rules route DNS decisions to DNS channels; they are not Phase 11
traffic routing rules. They are disabled by default and, when enabled, are
emitted after static IP mappings but before the base direct/proxy DNS rules.
Supported match patterns are explicit and portable: exact domain, domain
suffix, keyword, regex, geosite, and sing-box rule-set. A rule that points to a
channel without a configured resolver must fail during config generation rather
than silently falling back to another channel.

## Linux Resolver Strategy

DNS v2 must detect the active system resolver manager:

- `systemd-resolved`
- NetworkManager DNS
- classic `/etc/resolv.conf`
- unknown/unsupported

Default strategy:

- Prefer non-invasive integration with the active resolver manager.
- Save state before mutation.
- Restore state on disconnect, VPN-off, uninstall, and failed apply.
- Use `vpn_dns_rescue` as fallback recovery, not as the primary DNS manager.
- Fail closed when kill switch is active and DNS cannot be made leak-safe.

System resolver mutation should be limited to the local DNS entry point needed
for hijack/apply. Channel routing and advanced DNS policy should live in the
WatchdogVPN DNS engine and sing-box config where possible.

## Driver Strategy

### sing-box-backed Profiles

sing-box is the primary DNS engine for advanced behavior:

- channel-specific DNS servers
- FakeIP
- DNS rules/diversion
- cache/TTL options where supported
- proxy-channel DNS resolution

The sing-box config generator must receive DNS policy as structured data rather
than string fragments.

### Native Tunnel Profiles

AmneziaWG, OpenVPN, and OpenVPN+Cloak do not provide the same built-in DNS
engine as sing-box. For these, DNS v2 needs a WatchdogVPN-managed local DNS
entry point.

Implementation options to decide during Task 10.1:

- run a lightweight local DNS proxy/forwarder owned by WatchdogVPN;
- use sing-box DNS-only mode as a local resolver;
- use system resolver manager configuration for simpler modes and restrict
  advanced FakeIP/rules to sing-box-backed profiles until a local DNS engine is
  available.

Phase 10 must not silently claim FakeIP/rules support for native tunnel drivers
unless the local DNS engine path is implemented and validated.

## Kill Switch Interaction

Phase 9 already validated DNS/DoT blocking outside the tunnel:

- UDP/TCP `53`
- UDP/TCP `853`

Phase 10 must preserve this ordering:

1. allow tunnel interface
2. block DNS/DoT outside tunnel
3. allow LAN if configured

DNS v2 acceptance requires:

- DNS queries do not escape to LAN router resolvers while kill switch is active.
- DNS configured as direct is blocked or rerouted if direct DNS would leak.
- DNS cleanup leaves no WatchdogVPN firewall or resolver residue.
- DNS rescue remains available after failed apply/uninstall paths.

## Configuration Shape

Initial TOML shape, subject to implementation details:

```toml
[dns]
mode = "auto"                 # auto | off | custom | advanced
test_domain = "gstatic.com"
ttl = "12h"
tun_hijack = true
resolve_inbound_domains = false
static_ip_enabled = false
rules_enabled = false
ecs_direct_enabled = false
proxy_resolution_channel = "fakeip"  # fakeip | proxy | direct | final

[dns.channels.bootstrap]
servers = ["local", "dhcp://auto"]

[dns.channels.dns_server]
servers = ["local", "dhcp://auto"]

[dns.channels.proxy_server]
servers = ["local", "dhcp://auto"]

[dns.channels.direct]
servers = ["local", "dhcp://auto"]

[dns.channels.proxy]
servers = ["https://1.1.1.1/dns-query"]

[dns.channels.final]
servers = ["https://1.1.1.1/dns-query"]
```

Static IP and rules should live in separate files or structured config sections
if they grow beyond a small list.

## Phase 10 Subphases

Phase 10 is intentionally split into subphases. Each subphase must be
implemented, validated, committed, pushed, and recorded before starting the
next one. This keeps DNS v2 powerful without turning it into one oversized
unreviewable change.

### Phase 10A - DNS foundation and inventory

Goal: define the DNS v2 data model and detect the host resolver environment
without mutating the system.

Tasks:
- Task 10.1 - DNS inventory and schema.
- Task 10.2 - Resolver parser and presets.

Exit criteria:
- DNS policy objects exist.
- Resolver URI parsing is validated.
- Resolver manager detection is read-only.
- No system DNS changes are made.
- Unit tests cover valid/invalid resolver forms and resolver manager detection.

### Phase 10B - DNS testing and system state safety

Goal: test resolvers and implement backup/restore before any advanced DNS
behavior is allowed.

Tasks:
- Task 10.3 - DNS tester and auto setup.
- Task 10.4 - System DNS state manager.

Exit criteria:
- Resolver testing/ranking works.
- Existing system DNS state can be saved and restored.
- Failed apply paths restore previous DNS state.
- `vpn_dns_rescue` remains available as fallback.
- Real local validation confirms restore behavior on the workstation.

### Phase 10C - sing-box DNS policy generation

Goal: generate channel-based DNS policy for sing-box-backed profiles.

Tasks:
- Task 10.5 - sing-box DNS generation.

Exit criteria:
- sing-box config generation supports DNS channels.
- Existing protocol outbound generation is preserved.
- Direct/proxy/final channel config is covered by tests.
- No TUN hijack, FakeIP, ECS or rules are enabled yet unless explicitly covered
  by this subphase tests.

### Phase 10D - TUN hijack and kill-switch-safe apply

Goal: route system/application DNS into DNS v2 without leaks.

Tasks:
- Task 10.6 - TUN DNS hijack.

Exit criteria:
- TUN hijackDNS works or fails closed.
- Kill switch DNS/DoT blocking remains ordered correctly.
- DNS does not leak to LAN router resolvers while kill switch is active.
- Cleanup leaves no resolver or firewall residue.
- Real local validation is recorded.

### Phase 10E - Advanced DNS features

Goal: implement advanced channel-based behavior after the DNS foundation
is safe.

Tasks:
- Task 10.7 - FakeIP support.
- Task 10.8 - ECS support.
- Task 10.9 - Static IP map.
- Task 10.10 - DNS diversion rules.

Exit criteria:
- FakeIP works for supported paths and is clearly disabled where unsupported.
- ECS is off by default and only used for direct traffic when enabled.
- Static IP mappings resolve before upstream DNS.
- DNS diversion rules route DNS decisions to the selected channel.
- Driver support boundaries are explicit and tested.

### Phase 10F - User controls and final validation

Goal: expose DNS v2 after behavior is real and validated.

Tasks:
- Task 10.11 - CLI controls.
- Task 10.12 - TUI controls.
- Task 10.13 - Real validation.

Exit criteria:
- CLI exposes status/test/apply/reset with JSON where appropriate.
- TUI exposes no placeholders; every control maps to real behavior.
- Full regression passes.
- Real workstation validation is recorded in `docs/v2-validation-log.md`.

### Phase 10G - DNS v2 audit and debt closure

Goal: audit all Phase 10 subphases before Phase 10 is considered closed.

Tasks:
- Task 10.14 - Phase 10 audit and debt closure.

Exit criteria:
- DNS v2 audit report exists.
- Kill switch DNS/DoT leak behavior is re-audited.
- Resolver restore and failed-apply cleanup are re-audited.
- TUI/CLI DNS controls are re-audited for placeholder-free behavior.
- Docs are re-audited for stale third-party DNS integration or legacy DNS claims.
- No HIGH or MEDIUM findings remain open.
- Any LOW findings are either fixed or explicitly accepted with rationale.
- Full regression passes.
- Real validation log is up to date.

## Phase 10 Task Details

### Task 10.1 - DNS inventory and schema

- Add `dns/` package skeleton.
- Define DNS dataclasses/models:
  - resolver
  - resolver channel
  - DNS policy
  - static IP entry
  - DNS rule
- Parse and validate DNS config.
- Detect active system resolver manager.
- No system mutation yet.

### Task 10.2 - Resolver parser and presets

- Parse resolver URIs.
- Validate transports and IPv4/IPv6 hosts.
- Add preset resolver catalog.
- Include neutral public DNS presets only.
- Unit-test invalid resolver forms.

### Task 10.3 - DNS tester and auto setup

- Test resolver availability and latency.
- Race up to 4 selected resolvers per channel where safe.
- Implement auto setup recommendations based on test domain.
- Default test domain: `gstatic.com`.

### Task 10.4 - System DNS state manager

- Save current resolver state.
- Apply local DNS entry point through the detected manager.
- Restore previous state.
- Integrate with `vpn_dns_rescue` for fallback.
- Validate `systemd-resolved`, NetworkManager, and classic `resolv.conf`
  behavior through unit/mocked tests before real machine tests.

### Task 10.5 - sing-box DNS generation

- Generate sing-box DNS config from DNS policy.
- Add channel mappings for direct, proxy, final, proxy server, and DNS server.
- Support TTL/cache settings where sing-box supports them.
- Preserve existing profile protocol config behavior.

### Task 10.6 - TUN DNS hijack

- Route system/application DNS to the DNS v2 local entry point.
- Ensure hijack is compatible with kill switch DNS blocking.
- Provide rollback on failed apply.

### Task 10.7 - FakeIP support

- Implement FakeIP range/config for proxy traffic.
- Ensure FakeIP does not leak to direct traffic or system resolver state.
- Define clear fallback when FakeIP is unsupported for the active driver.

### Task 10.8 - ECS support

- Implement ECS for direct traffic only.
- Default off unless user enables it.
- Document privacy tradeoff.
- Validate that ECS settings are not sent through unintended channels.

### Task 10.9 - Static IP map

- Add static IP mapping support.
- Validate domain and IP syntax.
- Apply mappings before upstream resolver queries.

### Task 10.10 - DNS diversion rules

- Add rule model mapping domain/rule groups to DNS channels.
- Keep routing rules and DNS rules separate but compatible.
- Decide handoff points with Phase 11 routing rules.

### Task 10.11 - CLI controls

- Add read-only status first.
- Add explicit apply/reset/test commands after engine behavior is complete.
- Commands must support `--json` where appropriate.

### Task 10.12 - TUI controls

- Add TUI DNS controls only after CLI behavior is real.
- No placeholders.
- Include:
  - mode
  - test domain
  - TTL
  - server/channel summary
  - static IP status
  - rules status
  - FakeIP/ECS status

### Task 10.13 - Real validation

- Validate on the local workstation with actual resolver manager.
- Validate with kill switch active.
- Validate DNS by tunnel interface.
- Validate restore on disconnect.
- Validate cleanup after failed apply.
- Record results in `docs/v2-validation-log.md`.

### Task 10.14 - Phase 10 audit and debt closure

- Run a DNS-focused QA audit after all Phase 10 implementation subphases.
- Check DNS behavior across:
  - `auto`
  - `off`
  - `custom`
  - `advanced`
  - kill switch active
  - failed apply
  - disconnect
  - uninstall/rescue path
- Check CLI/TUI output and controls.
- Check docs and examples.
- Fix all HIGH/MEDIUM findings before Phase 10 is closed.

## Acceptance Criteria

- [ ] `auto` mode works without asking user for DNS knowledge.
- [ ] `off` mode does not mutate DNS.
- [ ] `custom` mode supports validated custom resolvers.
- [ ] `advanced` mode supports channel-specific DNS policy.
- [ ] Up to 4 resolvers per channel can be selected and tested.
- [ ] DNS tester ranks working resolvers.
- [ ] System DNS state is backed up and restored.
- [ ] Kill switch active state has no DNS/DoT leak outside the tunnel.
- [ ] TUN hijackDNS works or fails closed with clear status.
- [ ] FakeIP behavior works for supported paths and is clearly disabled where
  unsupported.
- [ ] ECS is off by default and only sent for direct traffic when enabled.
- [ ] Static IP entries resolve before upstream DNS.
- [ ] DNS diversion rules route DNS decisions to the selected channel.
- [ ] TUI exposes no DNS control until the underlying behavior exists.
- [ ] `vpn_dns_rescue` remains available for recovery.
- [ ] Real validation is added to `docs/v2-validation-log.md`.
- [ ] Phase 10G audit completed with no open HIGH/MEDIUM findings.

## Open Questions Before Implementation

- Should native tunnel drivers use sing-box DNS-only mode as the local DNS
  engine, or should Phase 10 introduce a smaller dedicated DNS proxy?
- What FakeIP range should WatchdogVPN reserve by default?
- Should ECS be allowed only in `advanced` mode, or also as a single custom
  toggle in `custom` mode?
- Should DNS diversion rules use the same rule files as Phase 11 routing, or a
  separate DNS-specific rule store?
- Should `local` and `dhcp://auto` remain enabled by default for direct traffic
  when kill switch is active, or should active kill switch force proxy/final DNS?

## Non-Goals

- Reintroducing the removed guided third-party DNS integration.
- Installing third-party DNS services during WatchdogVPN install.
- Exposing TUI placeholders before engine behavior exists.
- Claiming FakeIP/ECS/rules support for drivers where it is not actually wired
  and validated.
