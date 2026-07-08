# ADR 0004: LAN Proxy Sharing

Date: 2026-07-06

## Status

Accepted and implemented after Phase 20 validation.

## Context

WatchdogVPN currently generates local SOCKS and HTTP sing-box inbounds for the
host user interface and health checks. Those inbounds listen on `127.0.0.1`
only. Phase 15 asked whether WatchdogVPN should also expose SOCKS/HTTP service
to LAN devices.

LAN sharing changes the trust boundary. A localhost helper becomes a network
service reachable by other machines on the local network. Accepting it safely
would require, at minimum:

- disabled-by-default behavior;
- an explicit non-loopback bind address;
- authentication, or a documented reason if authentication cannot be supported;
- firewall and port warnings;
- kill-switch validation for traffic entering from LAN clients;
- DNS leak validation for LAN-client resolution paths;
- live validation that teardown closes the LAN listener and leaves no broad bind.

The current v2.0 runtime is built and tested around local machine protection,
but LAN sharing is a high-value product capability for operators who manage
networks, servers and multi-device environments. It should be built as a
first-class feature, not as an incidental bind-address toggle.

## Decision

Do not expose WatchdogVPN SOCKS or HTTP proxy service to LAN devices by
default.

The default sing-box SOCKS and HTTP inbounds must remain loopback-only. DNS
hijack listeners also remain loopback-only. No `0.0.0.0`, `::`, implicit LAN
interface or wildcard listener is part of the default supported v2.0
configuration.

LAN proxy sharing and full LAN gateway/router mode were promoted to the
dedicated Phase 20 track, before the final Full CLI phase. That work was
developed on a separate branch, validated in VM network scenarios only, and
merged back to `main` only after the branch proved the feature correct, secure
and fully validated.

Phase 20 Task 20.1 opened that track with
`docs/phase-20-task-20-1-lan-sharing-threat-model.md`. Task 20.3 implemented
authenticated LAN SOCKS/HTTP proxy inbounds. Task 20.5 accepted
gateway/router mode under
`docs/phase-20-task-20-5-gateway-router-design-gate.md`, with
disabled-by-default IPv4 forwarding/NAT, explicit interface selection, manual
client setup, DNS and kill-switch contracts, reversible firewall ownership and
VM-only validation. Task 20.7 closed the final VM matrix and security audit in
`docs/qa-audit-2026-07-08-phase-20-lan-sharing-gateway.md`. The accepted
implementation does not authorize wildcard binds, automatic DHCP/router
mutation, IPv6 forwarding or persistent forwarding changes.

## Consequences

- No default LAN exposure is introduced.
- WatchdogVPN avoids creating an accidental unauthenticated LAN proxy path.
- LAN sharing is a validated core capability, but remains disabled by default.
- Task 20.3 satisfies the initial authenticated proxy-listener requirement,
  and Task 20.5 decided that gateway/router remained in Phase 20 instead of
  being split again.
- Gateway/router implementation must stay disabled by default, explicit,
  reversible and VM-validated.
- Future work that adds LAN sharing must update this decision instead of
  weakening the existing localhost-only inbounds silently.
