# WatchdogVPN v2 - Validation Log

> Real-hardware validation by phase. These notes record actual behavior against
> the Paris VPS (`138.124.58.47`) and the local workstation where explicitly
> observed. Unit tests are listed only when they were part of the same closure
> evidence.

## Evidence Source

- Retrospective log created on 2026-07-02 from the local v2 master plan and
  phase closure notes.
- This file does not claim a new real-hardware validation run on 2026-07-02.
- Missing command transcripts are marked as not recorded rather than inferred.

## Phase 4 - sing-box Driver

- **Date:** 2026-06-29
- **Target:** Paris VPS `138.124.58.47`
- **Protocols validated:**
  - VLESS+Reality on TCP `443`: PASS.
  - Trojan TLS on TCP `5222`: PASS.
  - Hysteria2 on UDP `44333`: PASS.
- **Observed result:**
  - `connect: True`
  - `health: ok`
  - proxy public IP matched the VPS
  - clean disconnect
  - `health_after: down`
- **VLESS+Reality extra observation:**
  - Health check logged `public_ip_via_proxy=138.124.58.47`.
  - No orphan `sing-box` process was observed after disconnect.
- **Validation command evidence:**
  - Exact command transcript not recorded.
  - The planned verification method was a SOCKS request through
    `127.0.0.1:2080`.
- **Issues found and fixed during validation:**
  - VLESS+Reality initially failed while another VPN tunnel routed the VPS IP
    through `tun0`.
  - sing-box outbound now binds to the detected physical default interface by
    default, preventing remote-control traffic from going through a stale or
    unrelated VPN tunnel.
  - Trojan `trojan:///password@host` parsing preserves leading-slash secrets.
  - Hysteria2 parsing preserves `user:pass` auth and supports
    `obfs-password`, optional bandwidth, ALPN, and insecure flags.
- **Scope note:**
  - Standard WireGuard was not validated against a real VPS profile in Phase 4.
    It was treated as compatibility coverage only and covered with synthetic
    import/outbound-generation tests.

## Phase 5 - AmneziaWG Driver

- **Date:** 2026-06-29
- **Target:** Paris VPS `138.124.58.47:30919`
- **Protocol validated:**
  - Native AmneziaWG over UDP `30919`: PASS.
- **Observed result:**
  - `connect=True`
  - `health=ok` after 3 second warmup
  - `handshake_age=3s`
  - `ping=True`
  - `disconnect=True`
  - `health_after=down`
- **Validation command evidence:**
  - Exact command transcript not recorded.
  - Validation depended on WireGuard/AmneziaWG interface state, handshake state,
    and ping through the interface.
- **Runtime dependencies observed:**
  - `awg` is the AmneziaWG configuration tool used by the daemon.
  - `amneziawg-dkms` provides the kernel module when it builds for the running
    kernel.
  - `amneziawg-go` is the userspace runtime fallback when the kernel module is
    unavailable.
  - `amneziawg-tools` is required for AmneziaWG userspace tools.
  - On Ubuntu these were installed from `ppa:amnezia/ppa`.
- **Issues found and fixed during validation:**
  - Driver detection was corrected during earlier validation. Phase 23 field
    validation later removed quick-script runtime dependency from the daemon
    path because quick scripts attempt internal `sudo` outside root, and
    removed the old `wg-quick` fallback because plain WireGuard tooling cannot
    run real AmneziaWG exports with obfuscation keys.
  - Empty exported keys such as `I2 = ` and `I3 = ` are stripped before writing
    the runtime config because `awg setconf` rejects them.
  - Parser detection was expanded for real profile keys including `S3`, `S4`,
    `H3`, and `H4`; `I1` through `I5` are preserved.
- **Operational note:**
  - Immediate health can be `degraded` right after connect because the
    WireGuard handshake needs about 2-3 seconds. Later rotation/recovery logic
    must allow warmup before judging health.

## Phase 5.5 - OpenVPN+Cloak/OverCloud Driver

- **Date:** 2026-06-30
- **Target:** Paris VPS `138.124.58.47`
- **Server/container:** `amnezia-openvpn-cloak`
- **Protocol validated:**
  - OpenVPN wrapped by Cloak/OverCloud-style transport: PASS.
- **Endpoint details:**
  - Cloak server port: TCP `8443`.
  - TCP `443` was already used by native Xray and was intentionally not
    changed.
  - `ck-server v2.8.0` plus OpenVPN TCP `1194` inside the container.
  - OpenVPN connects locally to `127.0.0.1:1194`.
  - Cloak client connects to `138.124.58.47:8443`.
- **Observed result:**
  - `connect=True`
  - `health=ok`
  - `tun=True`
  - `disconnect=True`
- **Validation command evidence:**
  - Exact command transcript not recorded.
- **Automated validation at closure:**
  - 31 driver tests passed.
  - 20 parser tests passed.
  - 189 total tests passed.
- **Issues and lessons found during validation:**
  - `ServerName` is mandatory in `cloak_config`; without it, `ck-client` exits
    immediately with `ServerName cannot be empty`.
  - Port assignment must check existing services first; `443` was already in
    use and `8443` was chosen to avoid touching existing Xray services.
  - `ck-client` needs about 1 second of warmup before OpenVPN connects to it.
    The driver used a 1.5 second startup wait at this stage.
  - Root-owned log files can remain after sudo test runs; drivers must handle
    log open failures and fall back safely.
  - AmneziaVPN `vpn://` export stores JSON inside a base64url/zlib payload and
    includes both Cloak and OpenVPN config material.

## Phase 9 - Kill Switch

- **Date:** 2026-07-01
- **Local environment:** workstation with `tun0` active during validation.
- **Firewall backend observed:** nftables.
- **Observed result before final fix:**
  - Real nftables validation confirmed the dedicated `inet watchdogvpn` table
    and output chain with default drop policy.
  - Cleanup validation confirmed `disable()` removed the nftables table.
  - Cleanup validation also confirmed no leftover `WATCHDOGVPN-OUTPUT`
    iptables/ip6tables chains.
  - A DNS leak gap was found when `allow_lan = true`: LAN CIDRs were allowed
    before DNS-specific deny rules, and the workstation resolver included
    `192.168.0.1`.
- **Fix validated:**
  - DNS/DoT block rules for UDP/TCP ports `53` and `853` are emitted after the
    tunnel-interface allow rule and before LAN CIDR allow rules.
  - Tunnel DNS remains allowed because traffic through the tunnel interface is
    accepted first.
  - LAN access remains allowed after the DNS-specific block rules.
- **Manual validation after fix:**
  - `sudo nft list table inet watchdogvpn` confirmed rule order:
    tunnel-interface allow, DNS/DoT reject for UDP/TCP `53` and `853`, then LAN
    allow.
  - `resolvectl query example.com` resolved through `link: tun0`.
  - `resolvectl query openai.com` resolved through `link: tun0`.
  - `resolvectl query github.com` resolved through `link: tun0`.
  - Python `socket.getaddrinfo()` resolved the same hostnames while the kill
    switch was active.
  - Cleanup removed the `inet watchdogvpn` table.
  - Cleanup left no `WATCHDOGVPN-OUTPUT` chains in iptables/ip6tables.
- **Automated validation at closure:**
  - `python3 -m unittest tests.test_kill_switch` passed: 18 tests.
  - `python3 -m unittest discover -s tests -p 'test_*.py'` passed: 341 tests.
  - `python3 -m py_compile core/kill_switch.py tests/test_kill_switch.py`
    passed.
  - `git diff --check` passed.
  - `shell=True` audit in touched files passed.
- **Known observation:**
  - HTTPS `curl` still returned connection reset during the protected window.
    This was treated as connectivity/provider behavior, not a Phase 9 blocker,
    because DNS resolution was explicitly observed via `tun0` and no DNS leak
    was observed.

## Phase 10F - DNS v2 Real Workstation Validation

- **Date:** 2026-07-02
- **Local environment:** workstation with `tun0` active during validation.
- **Resolver manager observed:** `systemd-resolved`.
- **Firewall backend observed:** nftables.
- **Initial DNS policy:** default DNS v2 `auto` policy.
- **Observed resolver state before apply:**
  - `watchdog dns status --json` reported `systemd-resolved`.
  - `/etc/resolv.conf` inventory included `192.168.0.1`.
  - `tun0` existed and was up.
- **DNS tester validation:**
  - `watchdog dns test --json` ran against real resolvers.
  - Local/DHCP candidates passed for bootstrap, DNS server, proxy server and
    direct channels.
  - Public proxy/final candidates passed for Cloudflare DoH, Cloudflare TLS and
    Quad9 TLS.
  - Quad9 DoH returned HTTP 505 in this environment and was not selected.
- **Apply dry-run validation:**
  - `watchdog dns apply --dry-run --json` produced a rollback plan.
  - Planned entrypoint was `127.0.0.1:53`.
  - Planned snapshot path was
    `/home/gabodev/.config/watchdogvpn/dns-state.json`.
  - No snapshot was created during dry-run.
- **Real apply/reset validation:**
  - `watchdog dns apply --yes --systemd-link tun0` applied DNS state.
  - A rollback snapshot was created at
    `/home/gabodev/.config/watchdogvpn/dns-state.json`.
  - `resolvectl query example.com` succeeded after apply.
  - `resolvectl query openai.com` succeeded after apply.
  - `resolvectl query github.com` succeeded after apply.
  - `watchdog dns reset --yes` restored DNS state.
  - The rollback snapshot was removed after reset.
- **Failed apply validation:**
  - `watchdog dns apply --yes --entrypoint-address 127.0.0.1
    --entrypoint-port 9 --entrypoint-timeout 0.2` failed before mutation.
  - Error observed: local DNS entrypoint was not reachable.
  - No rollback snapshot was created.
- **Kill switch validation before hardening fix:**
  - First Phase 10F kill switch validation found an important leak risk:
    `openai.com` resolved with `link: enp4s0` while kill switch was active.
  - Root cause was rule ordering: `ct state established,related accept` was
    before DNS/DoT reject rules, so an already established DNS conntrack flow
    could bypass later DNS blocks.
- **Fix validated:**
  - Commit `0669c0f` moved DNS/DoT reject rules before
    `established,related` while keeping loopback and tunnel-interface allow
    rules first.
  - The validated nftables order after the fix was:
    `lo` allow, `tun0` allow, UDP/TCP `53` reject, UDP/TCP `853` reject,
    `established,related` allow, LAN CIDR allow.
  - `resolvectl flush-caches` was run before protected DNS queries.
  - `resolvectl query example.com` resolved through `link: tun0`.
  - `resolvectl query openai.com` resolved through `link: tun0`.
  - `resolvectl query github.com` resolved through `link: tun0`.
  - Cleanup removed the `inet watchdogvpn` nftables table.
  - Cleanup left no `WATCHDOGVPN-OUTPUT` chains in iptables/ip6tables.
- **Automated validation at closure:**
  - `python3 -m py_compile core/kill_switch.py tests/test_kill_switch.py`
    passed.
  - `python3 -m unittest tests.test_kill_switch` passed: 20 tests.
  - `python3 -m unittest discover tests` passed: 425 tests after the
    hardening fix.
  - `bash tests/unit.sh` passed.
  - `.venv/bin/pytest tests` passed: 441 tests after the hardening fix.
  - `git diff --check` passed.
- **Conclusion:**
  - DNS v2 CLI/TUI controls are backed by real behavior.
  - DNS apply/reset snapshot behavior was validated on the workstation.
  - Kill switch DNS/DoT leak behavior was revalidated after the conntrack
    ordering fix.
  - Cleanup left no firewall residue.

## Phase 10G - DNS v2 Audit and Debt Closure (Task 10.14)

- **Date:** 2026-07-02
- **Audit report:** `docs/qa-audit-2026-07-02-dns-v2.md`
- **HIGH finding fixed (AUD-DNS-001):** the DNS v2 policy was never passed
  into a live `SingBoxDriver.connect()` call, so `custom`/`advanced` mode,
  FakeIP, ECS, static IP mapping and DNS diversion rules never actually
  reached a running sing-box process, even though each was fully unit-tested
  in isolation. Fixed by threading `dns_policy` through `BaseDriver.connect()`,
  every driver implementation, `WatchdogRuntime` (`connect`, `startup`,
  `_try_reconnect`, rotation), and `RotationEngine.rotate()`.
- **MEDIUM finding fixed (AUD-DNS-002):** system DNS state was not
  automatically restored on VPN disconnect, only via `watchdog dns reset
  --yes` or `vpn_dns_rescue`. Initially triaged as "accepted risk, needs
  Phase 11/12", then re-assessed as fixable now since
  `WatchdogRuntime.disconnect()` already exists. Fixed by adding
  `dns/state_manager.py::default_snapshot_path()`/`load_snapshot()` and
  wiring `WatchdogRuntime._restore_dns_snapshot_if_present()` into
  `disconnect()`: restores and removes the snapshot if one exists, no-ops if
  none exists, and logs a warning without raising if restore fails.
- **LOW findings fixed (AUD-DNS-003):** refreshed stale "planned for Phase
  10" language in `docs/demo.md`, `docs/configuration.md`,
  `docs/threat-model.md`, and added the missing `CHANGELOG.md` entry for the
  DNS v2 feature set.
- **Automated validation:**
  - `python3 -m unittest discover tests` passed: 436 tests.
  - `bash tests/unit.sh` passed.
  - `.venv/bin/pytest tests` passed: 452 tests.
  - `git diff --check` passed.
- **Real workstation re-validation (AUD-DNS-001):** ran `SingBoxDriver.generate_singbox_config()`
  directly with a real VLESS+Reality profile (same VPS/profile validated in
  Phase 4, Task 4.5) and a real `custom`-mode `DNSPolicy` (direct channel:
  `udp://1.1.1.1`, `tun_hijack=True`). Result: `dns section present: True`,
  with the generated `dns.servers`/`dns.rules`/`dns.final` block and hijack
  inbound tags `watchdogvpn-dns-udp-in`/`watchdogvpn-dns-tcp-in` present in
  the exact config `SingBoxDriver.connect()` would write and hand to the
  running sing-box process. Before the AUD-DNS-001 fix, this same call
  path always received `dns_policy=None` regardless of the configured
  policy, so `dns section present` would have been `False`.
- **Real workstation re-validation (AUD-DNS-004):** full `driver.connect(profile, dns_policy=policy)` with the same VLESS+Reality profile and a `custom`-mode `DNSPolicy` (`tun_hijack=False`, direct channel: `udp://1.1.1.1`, proxy channel: `https://1.1.1.1/dns-query`, final: `udp://9.9.9.9`) against Paris VPS `138.124.58.47`. Before the AUD-DNS-004 fix, this call caused sing-box 1.13.14 to exit immediately with `FATAL: outbound DNS rule item is deprecated`. After the fix:
  - sing-box log inspection confirmed: no FATAL exit, config loaded cleanly, only expected inbound/outbound startup messages.
  - `connect: True`, `health: ok`.
  - Generated config confirmed: `dns.rules` contains no `outbound` matcher; proxy outbound carries `"domain_resolver": "watchdogvpn-fakeip"`; a `{"type": "direct", "tag": "direct", "domain_resolver": "watchdogvpn-direct-1"}` outbound is present.

## Validation Gaps To Keep Honest

- No full real-hardware validation log exists yet for every compatibility
  protocol in the parser/provider matrix.
- Phase 4 standard WireGuard had synthetic compatibility coverage but no real
  VPS profile.
- Exact terminal transcripts for Phase 4, Phase 5, and Phase 5.5 manual
  commands were not preserved.
- Local pytest validation is now reproducible through `requirements-dev.txt`
  and `pytest.ini`; both `pytest tests` and `python -m pytest tests` passed with
  408 tests after creating a local `.venv`.
- Phase 10F real validation did not run a full interactive TUI session; TUI DNS
  controls were covered by unit tests and command mapping smoke checks.
- Phase 10G's AUD-DNS-001 fix was confirmed against a real VLESS+Reality
  profile at the config-generation level (real `dns` section and hijack
  inbounds produced for a real `custom`-mode policy). The subsequent full
  `connect()` + `health_check()` attempt against the same profile reported
  `health: down` in this session; this was not chased further since it is
  unrelated to the DNS wiring fix and the same profile previously validated
  as working in Task 4.5. A full live end-to-end DNS hijack test (real
  `resolvectl`/`dig` query answered through the sing-box hijack listener) is
  still outstanding.
