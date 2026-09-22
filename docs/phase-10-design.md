# DNS System Design

WatchdogVPN owns a DNS system that is safe by default, explicit for advanced
users, and powerful enough to support per-channel DNS behavior, FakeIP, ECS,
static IP mappings, DNS diversion rules, TTL/cache policy, DNS testing, and
clean system restore.

DNS behavior is not a single global setting. It is separated by resolution
channel, with multiple resolvers per channel, auto-configuration, reset, TTL,
FakeIP, static IPs, and optional DNS diversion rules. The system must respect
Linux system resolver safety.

The DNS system does not recreate the removed guided third-party DNS
integration (see [ADR-0001](decisions/0001-remove-guided-third-party-dns-integration.md)).

## Design Goals

- Safe defaults: the normal install path works without DNS knowledge.
- Explicit advanced control: channels, FakeIP, ECS, static IPs, rules, and TTL
  are available to users who want them.
- Clean lifecycle: system resolver state is saved before mutation and restored
  on disconnect, VPN-off, uninstall, and failed apply.
- Fail closed: DNS must not leak when the kill switch is active and DNS cannot
  be made leak-safe.
- No third-party DNS installation: presets are data, not dependencies.

## User Modes

- `auto`: recommended default. WatchdogVPN chooses a safe DNS policy based on
  the active driver and resolver manager.
- `off`: WatchdogVPN does not manage DNS, except DNS rescue remains available
  for recovery.
- `custom`: the user selects resolvers from presets or custom URLs.
- `advanced`: the user controls channels, FakeIP, ECS, static IPs, rules, TTL,
  and the test domain.

The installer must not ask non-technical users to choose a DNS provider.

## DNS Channels

Channel-specific resolver sets:

- `bootstrap_dns`: resolves DNS server hostnames and proxy server hostnames
  before encrypted DNS or proxy DNS is usable.
- `dns_server`: resolver used by other DNS servers when a DNS endpoint itself
  needs name resolution.
- `proxy_server`: resolver used to resolve proxy/VPN server hostnames.
- `direct`: resolver for traffic that will go direct.
- `proxy`: resolver for traffic that will go through the proxy or VPN.
- `final`: resolver used when no more specific DNS rule matches.

Each channel can select up to 4 resolvers. The DNS tester can race selected
resolvers and choose the fastest healthy result for channels where concurrent
resolution is safe.

## Resolver Types

Supported resolver URI forms:

- `local`
- `dhcp://auto`
- `udp://IP`
- `tcp://IP`
- `tls://host-or-ip`
- `https://host-or-ip/path`
- IPv6 literal variants where the transport supports them

Preset resolvers include neutral public options. Presets are data, not
dependencies.

## Advanced Features

- TUN DNS hijack: capture system/application DNS and route it through the DNS
  engine.
- Resolve inbound domain names before routing decisions when needed.
- Static IP map: domain-to-IP mappings similar to a hosts file.
- Test domain: default `gstatic.com`, configurable.
- TTL/cache policy: default cache duration with advanced override.
- DNS diversion rules: map domains or rule groups to DNS channels.
- ECS for direct traffic: optional and off by default for privacy.
- FakeIP for proxy traffic: supported for proxy-channel resolution.

These features must be real behavior before any TUI control is exposed. No TUI
placeholder screens.

## Boundaries

### ECS Privacy

ECS sends an EDNS Client Subnet hint with DNS queries. It can improve CDN or
regional answers for direct traffic, but it also shares an approximate network
location with the resolver and sometimes the upstream authoritative path.
WatchdogVPN therefore keeps ECS disabled by default and only allows it on the
direct channel with an explicit subnet. ECS must never be sent through proxy,
final, FakeIP, bootstrap, or system resolver paths unless a narrower policy is
later added and validated.

### Static IP Map

Static IP mappings behave like a small WatchdogVPN-owned hosts file. They are
disabled by default and, when enabled, are emitted before upstream DNS routing
so an exact configured domain resolves to the configured IP address first. In
sing-box-backed DNS this uses a `hosts` DNS server with `predefined` records and
a first-position DNS rule for the mapped domains. Static mappings do not mutate
`/etc/hosts` or the host system resolver state.

### DNS Diversion Rules

DNS diversion rules route DNS decisions to DNS channels; they are not traffic
routing rules. They are disabled by default and, when enabled, are emitted after
static IP mappings but before the base direct/proxy DNS rules. Supported match
patterns are explicit and portable: exact domain, domain suffix, keyword, regex,
geosite, and sing-box rule-set. A rule that points to a channel without a
configured resolver must fail during config generation rather than silently
falling back to another channel.

## System Resolver Strategy

The DNS system detects the active system resolver manager:

- `systemd-resolved`
- NetworkManager DNS
- classic `/etc/resolv.conf`
- unknown/unsupported

Default strategy:

- Prefer non-invasive integration with the active resolver manager.
- Save state before mutation.
- Restore state on disconnect, VPN-off, uninstall, and failed apply.
- Use `vpn_dns_rescue` as fallback recovery, not as the primary DNS manager.
- Fail closed when the kill switch is active and DNS cannot be made leak-safe.

System resolver mutation is limited to the local DNS entry point needed for
hijack/apply. Channel routing and advanced DNS policy live in the WatchdogVPN
DNS engine and sing-box config where possible.

## Driver Strategy

### sing-box-backed Profiles

sing-box is the primary DNS engine for advanced behavior:

- channel-specific DNS servers
- FakeIP
- DNS rules/diversion
- cache/TTL options where supported
- proxy-channel DNS resolution

The sing-box config generator receives DNS policy as structured data rather
than string fragments.

### Native Tunnel Profiles

AmneziaWG, OpenVPN, and OpenVPN+Cloak do not provide the same built-in DNS
engine as sing-box. For these, DNS needs a WatchdogVPN-managed local DNS entry
point. Implementation options:

- run a lightweight local DNS proxy/forwarder owned by WatchdogVPN;
- use sing-box DNS-only mode as a local resolver;
- use system resolver manager configuration for simpler modes and restrict
  advanced FakeIP/rules to sing-box-backed profiles until a local DNS engine is
  available.

WatchdogVPN must not claim FakeIP or rule support for native tunnel drivers
unless the local DNS engine path is implemented and validated.

## Kill Switch Interaction

The kill switch blocks DNS/DoT outside the tunnel on UDP/TCP `53` and UDP/TCP
`853`. The DNS system preserves this ordering:

1. allow tunnel interface
2. block DNS/DoT outside tunnel
3. allow LAN if configured

Guarantees:

- DNS queries do not escape to LAN router resolvers while the kill switch is
  active.
- DNS configured as direct is blocked or rerouted if direct DNS would leak.
- DNS cleanup leaves no WatchdogVPN firewall or resolver residue.
- DNS rescue remains available after failed apply/uninstall paths.

## Configuration Shape

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

Static IP and rules live in separate files or structured config sections if
they grow beyond a small list.

## Limitations and Open Boundaries

- FakeIP, ECS, and rules support is not claimed for drivers where it is not
  actually wired and validated.
- ECS remains off by default and direct-only; there is no proxy/FakeIP ECS path.
- Static IP mappings never mutate `/etc/hosts` or the host system resolver.
- A DNS diversion rule pointing to a channel with no configured resolver is a
  config-generation error, not a fallback.
- The default FakeIP range is not fixed.
- Whether `local`/`dhcp://auto` stay enabled for direct traffic while the kill
  switch is active, or active kill switch forces proxy/final DNS, is an open
  policy question.
- Whether DNS diversion rules share rule files with traffic routing or use a
  separate DNS-specific rule store is open.

## Non-Goals

- Reintroducing the removed guided third-party DNS integration.
- Installing third-party DNS services during WatchdogVPN install.
- Exposing TUI placeholders before engine behavior exists.
- Claiming FakeIP/ECS/rules support for drivers where it is not wired and
  validated.
