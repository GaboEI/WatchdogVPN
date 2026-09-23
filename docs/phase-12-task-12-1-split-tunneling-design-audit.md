# Linux split tunneling: design and limits

WatchdogVPN can generate native sing-box rules for `process_name` and
`process_path`, and the daemon loads persisted rule groups in `rules` mode.
This note describes the architecture behind Linux app/process policy, the parts
that are already usable, and the limits that must be stated before app policy
is presented as a safety feature.

## Architecture

### Rule model

`rules/models.py` defines the routing rule schema:

- Conditions: domain, domain suffix/keyword/regex, IP CIDR, port, port range,
  protocol, network, remote/built-in rulesets, `process_name`, `process_path`.
- Actions: `direct`, `current_profile`, `auto_select`, `group:<id>`, `block`.
- Default groups: `recommended`, `direct`, `proxy`, `block`, `custom`, `app`,
  `imported`.
- Validation is strict: unknown condition keys and empty condition values are
  rejected.

The model does not support `user`, `user_id`, `process_path_regex`, `invert`,
cgroup markers, source IP/port, source interface, or a dedicated app-policy
mode/default.

### RuleStore

`rules/rule_store.py` stores one JSON file per rule group under the resolved
WatchdogVPN config directory, usually `rules/`. It uses the shared persistence
helpers and validates group names as safe slugs.

This is a solid base for rule groups, but app policy should not be modeled only
as ad hoc edits to the `app` group. Split tunneling needs explicit policy
state:

- enabled/disabled state;
- whitelist or blacklist mode;
- default action;
- per-rule action and match type;
- schema version;
- controlled disabled/standby behavior when the policy is invalid.

### Local rule engine

`rules/rule_engine.py` is a local evaluator for diagnostics and tests. Its
priority order is:

`block -> custom -> app -> imported -> recommended -> final_policy`

This matches the intended routing priority. It is not the live traffic
enforcement path; sing-box is the production enforcement path.

Limits:

- `ruleset_remote` and `ruleset_builtin` are unevaluable locally.
- `domain_regex` uses Python `re`, while sing-box uses its own matching engine.
- Process matching is literal for `process_name` and `process_path`.

### sing-box route generation

`rules/singbox.py` translates enabled rule groups into sing-box `route.rules`.
`block` becomes native `action: reject`; `direct` targets the `direct`
outbound; `current_profile`, `auto_select`, and `group:<id>` currently target
the single active outbound.

App policy can therefore enforce real `direct`, current-profile VPN, and block
actions. It cannot honestly claim true node-group or auto-selection routing per
app until WatchdogVPN has multiple simultaneous outbounds/selectors. Generated
rules target sing-box route actions; the explicit `action: route` form is the
forward-looking one, since the older `outbound` shorthand is deprecated in
recent sing-box releases.

`drivers/singbox_driver.py` merges DNS hijack rules before mode route rules so
the unconditional final route does not shadow DNS hijack. That ordering must be
preserved.

### Daemon runtime

`core/watchdog.py` threads the stored DNS policy and active mode into driver
connections, and in `rules` mode loads persisted RuleStore groups into the
driver path for manual connect, startup autoconnect, reconnect, and rotation.
`daemon/runtime_worker.py` serializes connect/disconnect/status/rotate commands
on one worker thread. The daemon owns the app-policy runtime path; app policy
must not add a second privileged control plane.

Daemon shutdown stops the IPC server and worker but does not explicitly call
`runtime.disconnect()`. systemd may kill child processes in the cgroup, but
that is not equivalent to restoring DNS snapshots, firewall state, or runtime
files.

### systemd and capabilities

`systemd/watchdogvpn.service` runs as the dedicated `watchdogvpn` user with
`CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`,
`CAP_DAC_READ_SEARCH`, `/dev/net/tun` access, and strict filesystem/namespace
hardening. Those capabilities cover TUN, route manipulation, DNS hijack on port
53, firewall interaction, and sing-box process attribution under the service
user. The daemon privilege boundary must be preserved instead of granting
capabilities to CLI commands or broad wrappers.

### TUN settings

The sing-box TUN inbound uses tag `watchdogvpn-tun-in`, interface
`wdvpn-tun0`, a private `/30` tunnel address, `auto_route: true`, and stack
`system`.
It does not set `strict_route`, `auto_redirect`, explicit route
addresses/exclusions, or a route-level `auto_detect_interface`. WatchdogVPN
binds outbound connections to the detected physical default interface with
outbound `bind_interface`, which helps avoid loops, but TUN leak behavior is not
yet validated for hostile networks.

### Kill switch

`core/kill_switch.py` supports nftables first and iptables fallback. It allows
loopback and the configured tunnel interface, rejects DNS ports 53/853 before
established/LAN accepts, optionally allows LAN, and can block IPv6.

The default app config names the kill-switch tunnel interface `tun0`, while
sing-box TUN uses `wdvpn-tun0`. Unless the installed config is updated before
kill-switch enforcement, fail-closed behavior can reject or allow the wrong
interface. The configured kill-switch tunnel interface must be aligned with the
active driver/interface before split tunneling is described as kill-switch
safe.

### DNS interaction

DNS v2 can generate sing-box DNS servers/channels, direct/proxy domain
resolvers, FakeIP, static hosts, DNS diversion rules, and local DNS hijack.
System DNS snapshots can be restored on manual disconnect.

DNS policy is domain/channel-oriented, not app-policy oriented. A process route
rule such as `firefox -> direct` does not by itself prove that Firefox DNS
queries were resolved via the direct DNS channel. If the browser uses system
DNS, DoH, its own cache, or a helper process, DNS may not follow the route
action the user configured.

For each app-policy action, the enforced DNS path must be stated exactly:

- traffic route action;
- DNS query path;
- what happens to encrypted in-app DNS;
- what happens to helper processes and children.

## sing-box process matching on Linux

sing-box route rules support these Linux-relevant match fields:

- `process_name`
- `process_path`
- `process_path_regex` since sing-box 1.10.0
- `user`
- `user_id`

Documentation: [route rule](https://sing-box.sagernet.org/configuration/route/rule/),
[DNS rule](https://sing-box.sagernet.org/configuration/dns/rule/),
[route](https://sing-box.sagernet.org/configuration/route/),
[TUN inbound](https://sing-box.sagernet.org/configuration/inbound/tun/).

App policy should therefore extend its schema to support `process_path_regex`,
`user`, and `user_id` alongside `process_name` and `process_path`. The UI/CLI
should label `process_name` as a convenience matcher, not a high-assurance
identity boundary.

`route.find_process` is not required when process/user rules exist; it enables
process lookup for logging when no process, path, package, user, or user-id
rules are present.

## Linux app-policy limits

- Browsers are multi-process. Matching only `firefox` or `chromium` may miss
  crash handlers, sandboxes, WebExtensions, helper binaries, updater helpers,
  external protocol handlers, and browser-launched child processes.
- Browser DNS can bypass expectations through built-in DoH, DNS cache, or
  profile settings. Route policy is not automatically DNS policy.
- Terminal rules are fragile. Matching `gnome-terminal`, `konsole`, `zsh`, or
  `bash` does not necessarily identify the network client. Match the actual
  tool process, for example `/usr/bin/curl`, not the terminal emulator.
- Package managers spawn helpers and transport methods. Use controlled download/check commands before
  touching system upgrades.
- Flatpak, Snap, AppImage and sandboxed apps can use wrapper paths, mounted
  runtime paths, portals, helper daemons, or confined network behavior. Prefer
  exact path plus user/user_id where possible.
- Process names are spoofable by untrusted local code. They are usability
  selectors, not a security identity boundary.
- `process_path` is stronger than `process_name`, but depends on how the
  process is launched and what executable path sing-box observes.
- `process_path_regex` is useful for packaged apps with versioned paths, but
  broad regexes can accidentally match unrelated binaries.
- `user`/`user_id` support a stronger compartment model when selected apps run
  under a dedicated Linux user. That is a workflow requirement, not a
  transparent app picker.
- nftables/cgroup marking may be needed for high-assurance policy, but only if
  sing-box process/user matching proves insufficient for supported workflows.

## Recommended design

1. Keep sing-box as the first implementation mechanism.
2. Require TUN mode for system-wide app/process policy. Proxy mode can support
   explicit proxy workflows, but is not transparent split tunneling.
3. Extend app-policy matching to `process_name`, `process_path`,
   `process_path_regex`, `user`, and `user_id`.
4. Treat `process_path` and `user_id` as preferred high-confidence matchers and
   `process_name` as convenience-only.
5. Keep block rules highest priority.
6. Merge generated app-policy rules at the existing `app` tier unless a later
   design requires a separate higher-priority tier.
7. Keep `direct`, `current_profile`, and `block` as real actions. Keep `auto`
   and `group` disabled or transparently mapped to the current profile until
   multi-outbound selector support exists.
8. Define a DNS contract for every app-policy action:
   - VPN/current: DNS through proxy/FakeIP/hijack.
   - Direct: DNS through the direct channel only when direct DNS is allowed.
   - Block: DNS and traffic rejected.
   - Auto/group: same as current profile until real selector support exists.
9. Align kill-switch interface selection with the active tunnel driver.
10. Keep cgroup/nftables marking as a later escalation path only if sing-box
    process/user matching cannot satisfy supported workflows.
