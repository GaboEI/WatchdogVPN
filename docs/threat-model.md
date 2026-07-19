# Threat Model

This document describes the practical threats WatchdogVPN is designed to handle,
the mitigations currently implemented and the risks that remain open for future
hardening.

## Assets

- User network connectivity.
- Correct VPN tunnel and route state.
- DNS resolution.
- provider profiles, account state and local configuration.
- User configuration files.
- Product logs and diagnostics.
- System integrity around privileged scripts and systemd units.

## Trust Boundaries

- The local machine is trusted enough to run administrative scripts.
- The underlying provider runtime is trusted only as an integration, not as the
  source of truth.
- `systemd`, NetworkManager, shell utilities and Python are trusted platform
  components.
- Remote network endpoints are not trusted to remain stable.
- Provider CLI text status is not treated as authoritative.
- User input in the TUI must be treated carefully before reaching shell commands.

## Main Threats and Mitigations

| Threat | Impact | Current mitigation |
| --- | --- | --- |
| Provider CLI reports a misleading state | User thinks VPN is working when route/tunnel is degraded | `vpn_truth_check` combines daemon lifecycle with mode-aware interface, routing/listener and egress evidence |
| A managed TUN disappears | Traffic may leave through the default route | daemon/runtime health plus an independently observed managed interface make `vpn_truth_check` report `DEGRADED` |
| A managed TUN exists but capture/routing evidence is incomplete | Degraded protection | `vpn_truth_check` requires the v2 lifecycle and managed routing artifacts to agree before reporting `UP` |
| The kill switch sees sing-box UDP/ICMP before the marked route replaces a stale physical output interface | Healthy captured traffic is dropped, while accepting the mark alone could instead create a physical-egress bypass | nftables pairs the output mark allow with an atomic postrouting guard that drops the mark unless the final interface is the exact managed TUN; DNS leak rejects remain earlier, and the physical outbound mark separately requires the daemon UID |
| Legacy static `tun0` configuration disagrees with the active v2 runtime | A healthy `wdvpn-tun0` connection is falsely reported `DOWN` | reachable daemon lifecycle takes precedence; custom-vps remains a bounded fallback only when v2 truth is unavailable |
| Public IP lookup fails | State can be unknown or degraded | multiple IP providers are attempted; degraded state is explicit |
| Provider/profile configuration is invalid | Recovery loops cannot fix setup | stores and runtime commands fail closed with explicit errors |
| Bad VPN endpoint | Rotation may land on unusable node | the v2 rotation/runtime path validates state before accepting a connection |
| DNS profile breaks resolution | User may lose name resolution | DNS v2 `apply`/`reset` snapshot the prior resolver state and restore it on request; `vpn_dns_rescue` remains available as a manual fallback |
| Observability becomes browsing history | Local metrics or support exports may reveal destinations, process activity or provider choices | Phase 16 defaults to aggregate local counters; raw destination/process history is not silently enabled and must be opt-in, retention-bounded, purgeable and excluded from normal diagnostics exports |
| Network context becomes location history | SSID, BSSID, interface names, gateway details or route changes may reveal home/work/travel context | Phase 21 classifies network facts before implementation: raw SSID/BSSID/interface identifiers are sensitive local context, default persistence is rejected, and normal support exports must redact local network identifiers |
| Chain routing silently uses a weaker path | A multi-hop route may collapse to current, direct or a shorter path while the operator believes all hops are active | Phase 21.5 defines `chain:<id>` as a first-class route action only after validation/runtime mapping; v2.0 chains use explicit profile/group hops, reject nested chains, own DNS by default and fail closed when unresolved |
| Local proxy service is reachable from LAN unintentionally | Other devices may use the host as an unintended proxy | LAN sharing remains disabled by default. Local SOCKS/HTTP and DNS hijack inbounds stay loopback-only unless the operator explicitly enables authenticated LAN proxy mode or bounded gateway mode. Gateway mode is IPv4/manual/VM-validated, requires TUN capture, owns reversible firewall/NAT state and must clean up forwarding/firewall state on teardown. |
| Uninstall breaks DNS | Host may remain offline after removal | `vpn_dns_rescue` restores fallback DNS behavior |
| Repeated timer executions overlap | Race conditions and route churn | rotation uses `flock`; timers are one-shot services |
| User-specific bypass domains leak into new installs | New users inherit irrelevant routing policy | default bypass example starts empty |
| Privileged scripts are modified or misused | System integrity risk | scripts are installed root-owned with restrictive permissions |
| Shell command injection through TUI input | Privileged command execution risk | current quoting mitigates some paths; full command-layer hardening is planned |
| External installer download is compromised or changes | Remote code execution risk | risk is documented; manual install and future checksum/signature validation are planned |

## Risk Classification

### Accepted for v0.1.0-alpha

- The provider CLI is not trusted as the source of truth.
- The product requires sudo for system-level actions.
- Some TUI helpers still use shell command strings.
- Automatic CLI installer verification is not yet cryptographically pinned.
- GitHub Actions currently performs baseline validation, not full integration
  simulation.
- LAN proxy/gateway sharing is accepted only because Phase 20 completed
  VM-only validation, authentication, explicit bind/firewall controls,
  kill-switch validation, DNS leak validation and teardown validation. It must
  remain disabled by default.

### Must Not Happen

- `doctor.sh` must not modify the system.
- `update.sh` must not overwrite user configuration without backup.
- `uninstall.sh` must not remove the underlying provider installation.
- `uninstall.sh` must not remove account/license state.
- New users must not inherit machine-specific domain exclusions.
- Observability must not silently store raw browsing or request history.
- Network-aware automation must not silently store raw location-identifying
  network context or perform automatic connect/disconnect actions without an
  explicit opt-in or confirmation path.
- Chain route actions must not silently collapse to current, direct, group,
  auto-select or a shorter chain when a hop, DNS path, health state or runtime
  mapping is unavailable.

### Future Hardening

- Add mocked integration tests for `vpn_truth_check`, daemon IPC and runtime
  rotation paths.
- Split the TUI into command, parser, state and render modules.
- Keep Python subprocess usage out of shell mode.
- Add verified/manual installation documentation for supported provider paths.
- Promote `shellcheck` and `shfmt` from advisory CI checks to required checks
  after cleanup.
- Add release-specific known limitations.

## Interview Notes

Important design answers:

- Provider CLI status is not the source of truth because a provider CLI can
  report a stale or incomplete state.
- `vpn_truth_check` exists to validate observable network reality: tunnel, route
  and public IP.
- Bash is used for privileged runtime scripts because system administration
  tasks integrate naturally with systemd, NetworkManager, iproute2 and logrotate.
- Python is used for the TUI because terminal layout, parsing and interactive
  navigation are easier to maintain there than in shell.
- The most fragile area today is not the core watchdog idea; it is the boundary
  between interactive TUI commands, shell execution and privileged helpers.
