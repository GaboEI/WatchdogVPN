# 0004 - LAN proxy sharing

## Status

Accepted

## Context

WatchdogVPN generates local SOCKS and HTTP sing-box inbounds for the host user
interface and health checks. Those inbounds listen on `127.0.0.1` only. LAN
sharing asks whether WatchdogVPN should also expose SOCKS/HTTP service to LAN
devices.

LAN sharing changes the trust boundary. A localhost helper becomes a network
service reachable by other machines on the local network. Accepting it safely
requires, at minimum:

- disabled-by-default behavior;
- an explicit non-loopback bind address;
- authentication, or a documented reason if authentication cannot be supported;
- firewall and port warnings;
- kill-switch validation for traffic entering from LAN clients;
- DNS leak validation for LAN-client resolution paths;
- live validation that teardown closes the LAN listener and leaves no broad
  bind.

LAN sharing is a high-value capability for operators who manage networks,
servers and multi-device environments, so it is built as a first-class, opt-in
feature rather than an incidental bind-address toggle.

## Decision

Do not expose WatchdogVPN SOCKS or HTTP proxy service to LAN devices by default.

The default sing-box SOCKS and HTTP inbounds remain loopback-only. DNS hijack
listeners also remain loopback-only. No `0.0.0.0`, `::`, implicit LAN interface
or wildcard listener is part of the default supported configuration.

LAN proxy sharing and full LAN gateway/router mode are supported as an explicit
opt-in track with these contracts:

- authenticated LAN SOCKS/HTTP proxy inbounds;
- gateway/router mode disabled by default;
- explicit interface selection;
- manual client setup;
- DNS and kill-switch contracts;
- reversible firewall ownership;
- no wildcard binds, no automatic DHCP/router mutation, no IPv6 forwarding, and
  no persistent forwarding changes.

## Consequences

- No default LAN exposure is introduced.
- WatchdogVPN avoids creating an accidental unauthenticated LAN proxy path.
- LAN sharing is available as a first-class capability but remains disabled by
  default.
- Gateway/router implementation must stay disabled by default, explicit and
  reversible.
- Gateway/router support is scoped to controlled network scenarios; it is not
  supported for physical LAN deployments.
- Future work that adds LAN sharing must update this decision instead of
  weakening the existing localhost-only inbounds silently.
