# Phase 23 R28 Exit-Gate Installed Field Re-audit

Date: 2026-07-15
Target: archvm:/home/gabodev/WatchdogVPN
Candidate: phase-23-cli-field-validation at 7157df396c6f86d382b9b1bb24358804a8800869
Verdict: FAIL - not ready for PR, merge, Task 23.4 closure, or Phase 23 closure.

## Executed installed evidence

The independent re-audit used private Phase 23 fixtures only on the approved VM. No fixture content, provider URL, or credential was printed. The real external-VPN-absent state was used; external-VPN-present and provider subscription rows were not fabricated and remain incomplete.

Preflight passed with source/origin/installed-marker alignment and doctor OK=110, WARN=2, FAIL=0.

- VLESS, VMess, Trojan, Hysteria2, and TUIC passed connect, normal/SOCKS/HTTP egress, disconnect, and post-state snapshots.
- Shadowsocks, SOCKS, and HTTP had working local proxies. Their normal-egress timeout is documented compatibility/proxy-only behavior.
- WireGuard returned 70 with generic "connect failed", then restored state. It remains unclassified compatibility evidence, not a confirmed defect here.
- AmneziaWG, OpenVPN, and OpenVPN+Cloak returned 70 before runtime mutation because of R28-006.

Kill switch passed: enable, VLESS connect, all egress, disconnect, disable, and restoration. Rotation passed, including forced and all-candidates-failed behavior. Manual-off passed: daemon stop/start plus panic sleep/status/wake. DNS diagnose and dry-run passed; real apply returned 70 after an interactive Polkit systemd-resolved authorization condition in the noninteractive runner. Reset, disconnect, and post-state snapshot passed.

## R28-006 - HIGH - Default secure policy makes native drivers unusable

Installed state is routing_policy=rule, capture_modes=local_proxy,tun, default_route_action=current. Watchdog therefore requires capture, dns, and routing enforcement. SingBoxDriver declares all capabilities; AmneziaWGDriver, OpenVPNDriver, and OpenVPNCloakDriver declare none.

A real AmneziaWG fixture returned before runtime mutation:

    driver AmneziaWGDriver cannot enforce requested WatchdogVPN policy: capture, dns, routing

OpenVPN and OpenVPN+Cloak have the same deterministic rejection. Fail-closed behavior is security-correct, but the default installed policy makes these importable native protocol families unusable, including the real AmneziaWG field fixture. This is a HIGH functional release blocker, not an endpoint failure. It was introduced by the native-policy contract in 8bbbd38.

Do not weaken the default or silently ignore policy. Required design: support complete enforcement for native drivers, or offer a clearly disclosed weaker mode only through explicit user consent. Add installed regressions for AmneziaWG, OpenVPN, and OpenVPN+Cloak under default and every supported alternate state.

## Restoration proof

The temporary test profile was removed; the original count returned to 132. Final status is desired-off clean standby with no active profile, TUN, proxy, runtime artifact, or kill switch. Rules, IPv4/IPv6 routes, resolver checksum, and owned processes matched baseline. nftables matched after counter normalization; no WatchdogVPN rule remained. A new loopback listener belonged to independent warp, not WatchdogVPN, and was not touched.

R28-001 through R28-005 remain closed. R28-006 is open and blocks release. No product behavior was changed by this re-audit.
