# ADR 0004: LAN Proxy Sharing

Date: 2026-07-06

## Status

Deferred to a dedicated future phase.

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

Do not expose WatchdogVPN SOCKS or HTTP proxy service to LAN devices from the
current v2.0 mainline runtime.

The sing-box SOCKS and HTTP inbounds must remain loopback-only. DNS hijack
listeners also remain loopback-only. No `0.0.0.0`, `::`, LAN interface, or
wildcard listener is part of the supported v2.0 configuration.

LAN proxy sharing and full LAN gateway/router mode are promoted to the
dedicated Phase 19 track, before the final Full CLI phase. That work must be
developed on a separate branch, validated in VM network scenarios only, and
merged back to `main` only after the branch proves the feature is correct,
secure and fully validated.

## Consequences

- No default LAN exposure is introduced.
- WatchdogVPN avoids creating an accidental unauthenticated LAN proxy path.
- LAN sharing remains a planned core capability, but only through the dedicated
  design and validation phase before Full CLI.
- The future phase must define authentication or an explicit reason if a
  protocol path cannot support it, explicit bind addresses, firewall UX,
  kill-switch behavior for LAN-originated traffic, DNS leak validation,
  NAT/gateway behavior where applicable, and teardown checks that prove no
  listener or forwarding state remains.
- Future work that adds LAN sharing must update this decision instead of
  weakening the existing localhost-only inbounds silently.
