# ADR 0004: LAN Proxy Sharing

Date: 2026-07-06

## Status

Rejected for v2.0.

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

The current v2.0 runtime is built and tested around local machine protection.
It does not include an authenticated LAN service contract or LAN-client leak
test harness.

## Decision

Do not expose WatchdogVPN SOCKS or HTTP proxy service to LAN devices in v2.0.

The sing-box SOCKS and HTTP inbounds must remain loopback-only. DNS hijack
listeners also remain loopback-only. No `0.0.0.0`, `::`, LAN interface, or
wildcard listener is part of the supported v2.0 configuration.

## Consequences

- No default LAN exposure is introduced.
- WatchdogVPN avoids creating an unauthenticated LAN proxy path.
- LAN-device sharing remains out of scope until a later phase defines an
  authenticated service contract, firewall UX, and VM/live leak validation.
- Future work that adds LAN sharing must update this decision instead of
  weakening the existing localhost-only inbounds silently.
