# Problem Context

WatchdogVPN was created to solve a practical connectivity problem: a VPN connection can appear active while the real route, tunnel or public IP state is degraded.

In unstable network environments, endpoints can fail, routes can change, public IP validation can become unreliable and a provider CLI may not expose enough operational detail for quick recovery. The goal of this project is to make that state visible and recoverable.

The project starts from the assumption that the connection will eventually fail. That matters for users who cannot treat connectivity as a convenience: journalists, researchers, developers, students, remote workers and people living under network censorship or unreliable routing. WatchdogVPN does not promise a perfect or fastest VPN; it provides an operating layer that can detect failure, recover when possible and keep the user informed without requiring constant terminal work.

The first supported backend is AdGuard VPN CLI. The long-term operating model is broader: the same truth-check, watchdog, DNS safety, logging and TUI concepts should be reusable for future backends such as WireGuard-based private tunnels.

## Goals

- Keep VPN state observable from a terminal interface.
- Detect whether the tunnel and route are actually working.
- Recover automatically from common failure states.
- Avoid endless recovery loops when authentication is the real problem.
- Keep logs readable and parseable.
- Preserve user configuration during installation and updates.
- Make the product usable for a normal Linux user, not only for the developer who built it.

## Non-Goals

- Replace the official AdGuard VPN client.
- Provide VPN credentials.
- Circumvent licensing.
- Hide malicious or illegal traffic.
- Force advanced DNS or desktop integrations on the user.

## Engineering Focus

The project prioritizes operational resilience over unnecessary complexity. Its main engineering value is the coordination of:

- state checks
- systemd timers
- safe rotation
- watchdog recovery
- DNS rollback
- domain exclusions
- terminal UX
- traceable logs

The result is a Linux operations tool that can be inspected, tested and extended.
