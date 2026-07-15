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

## Remediation revalidation - 2026-07-15

Candidate 520fe32 was installed before this pass. The official installed
preflight completed with zero failures in both external-VPN-absent and
external-VPN-present states. The external VPN was independently connected on
tun0; its routes remained present while WatchdogVPN ran each protocol and after
WatchdogVPN returned to standby.

The twelve real stored fixtures were exercised without re-importing them:

- VLESS, VMess, Trojan, Hysteria2, TUIC, AmneziaWG, OpenVPN and OpenVPN+Cloak
  connected, completed applicable normal/SOCKS/HTTP egress checks, disconnected
  and produced post-state snapshots in both external states.
- SOCKS and HTTP connected and their local proxy egress passed. Their normal
  TUN egress timed out in both states, matching proxy-only compatibility
  behavior.
- Shadowsocks connected but normal, SOCKS and HTTP egress all failed in both
  states. This row is not approved.
- WireGuard returned connect rc=70 with clean fail-closed rollback in both
  states. This row is not approved.

Provider validation is complete: refresh returned zero changes, a real owned
Trojan node connected, normal, SOCKS and HTTP egress passed, and disconnect
restored clean standby. Provider-node rotation was exercised and restored to
its original enabled state.

DNS apply/reset under an active tunnel, kill-switch enable/connect/egress/
disable, app-policy direct/current/block probes, forced rotation and
all-candidates-failed handling, and daemon manual-off plus panic sleep/wake all
passed. The runner writes, but intentionally does not execute, reboot steps.

The final cleanup returned desired-off standby with no WatchdogVPN TUN, proxy,
kill switch, or owned runtime artifacts; the independent external tun0
remained UP. This is not a release closure: Shadowsocks and WireGuard require
diagnosis or explicit compatibility classification before the installed exit
gate can be declared green.

## Final independent field validation — installed field-gate point 1 (2026-07-15)

Point 1 is GREEN and complete. An independent tester in Spain cloned and
installed WatchdogVPN, created WireGuard and Shadowsocks profiles, and reported
both protocols connected with stable real traffic. The validation included
Facebook, YouTube, a stable 4K video stream, and approximately 200 Mb/s in
each direction as reported by the tester.

This independent evidence supersedes the local environment's protocol-specific
transport observations. WireGuard and Shadowsocks are validated for
WatchdogVPN: neither is an R28 finding, release blocker, GitHub issue,
technical-debt item, or code-change request. No profile recreation is needed.

The raw local matrix remains retained as historical execution evidence, but its
WireGuard and Shadowsocks rows are now fully green by maintainer disposition
and independent real-traffic confirmation.

## Fresh detection-only R28 re-audit — installed field-gate point 2 (2026-07-15)

Point 2 is GREEN and complete. This pass reviewed the R28 recovery, bounded
archive, network-observation, DNS acyclicity, aggregate-metrics, native-policy
and provider-reconciliation invariants directly, then re-ran the source gates.
bash tests/syntax.sh, bash tests/unit.sh, compileall and diff-check passed;
the complete source suite passed 1673/1673 in 218.946 seconds.

The installed runtime was initially behind the audited candidate. The managed
transactional update completed successfully, refreshed the daemon, and aligned
the marker and each audited critical module with 4d9821a. Root systemd
verification passed during that transaction; no systemd unit is failed.

A controlled AmneziaWG connect/disconnect after the update proved the default
native-policy path with TUN, proxy and nftables kill switch, then restored
desired-off standby with no runtime artifacts or retained failure record.
Doctor reports 110 OK, 2 WARN, 0 FAIL; the warnings are the intentional
disconnected truth state and NTP synchronization without measured skew.

No new R28 finding, release blocker, technical debt, or code change resulted
from this re-audit. The only remaining R28 exit-gate item is formal Task 23.4 /
Phase 23 closure and its final documentation/PR decision.
