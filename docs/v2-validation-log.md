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
  - `awg-quick` and `awg` are the real binary names.
  - `amneziawg-dkms` is required for the kernel module.
  - `amneziawg-tools` is required for userspace tools.
  - On Ubuntu these were installed from `ppa:amnezia/ppa`.
- **Issues found and fixed during validation:**
  - Driver detection was corrected to prefer `awg-quick`, then
    `amneziawg-quick`, then `wg-quick`.
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
