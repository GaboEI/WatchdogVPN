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
| Provider CLI reports a misleading state | User thinks VPN is working when route/tunnel is degraded | `vpn_truth_check` checks tunnel, route and public IP |
| `tun0` disappears | Traffic leaves through the default route | daemon/runtime health checks and truth checks expose the degraded state |
| `tun0` exists but route is not through tunnel | Degraded protection | `vpn_truth_check` reports `DEGRADED`; dashboard exposes route |
| Public IP lookup fails | State can be unknown or degraded | multiple IP providers are attempted; degraded state is explicit |
| Provider/profile configuration is invalid | Recovery loops cannot fix setup | stores and runtime commands fail closed with explicit errors |
| Bad VPN endpoint | Rotation may land on unusable node | the v2 rotation/runtime path validates state before accepting a connection |
| DNS profile breaks resolution | User may lose name resolution | DNS v2 `apply`/`reset` snapshot the prior resolver state and restore it on request; `vpn_dns_rescue` remains available as a manual fallback |
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

### Must Not Happen

- `doctor.sh` must not modify the system.
- `update.sh` must not overwrite user configuration without backup.
- `uninstall.sh` must not remove the underlying provider installation.
- `uninstall.sh` must not remove account/license state.
- New users must not inherit machine-specific domain exclusions.

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
