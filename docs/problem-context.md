# Problem Context

WatchdogVPN was created to solve a practical connectivity problem: a VPN connection can appear active while the real route, tunnel or public IP state is degraded.

In unstable network environments, endpoints can fail, routes can change, public IP validation can become unreliable and a provider CLI may not expose enough operational detail for quick recovery. The goal of this project is to make that state visible and recoverable.

## Goals

- Keep VPN state observable from a terminal interface.
- Detect whether the tunnel and route are actually working.
- Recover automatically from common failure states.
- Avoid endless recovery loops when authentication is the real problem.
- Keep logs readable and parseable.
- Preserve user configuration during installation and updates.

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
- domain bypass
- terminal UX
- traceable logs

The result is a Linux operations tool that can be inspected, tested and extended.
