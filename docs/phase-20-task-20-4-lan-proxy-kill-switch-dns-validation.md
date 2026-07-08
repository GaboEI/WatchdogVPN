# Phase 20 Task 20.4 - LAN Proxy Kill-Switch And DNS Validation

Date: 2026-07-08
Status: closed

## Scope

Task 20.4 validates the LAN proxy runtime added in Task 20.3. It adds a
reproducible VM validation helper and records the installed-VM result.

This task does not add gateway/router mode, NAT, IP forwarding, LAN DNS
listener exposure, managed firewall mutation or new routing behavior.

## Validation Helper

The VM-only helper is:

```bash
WATCHDOGVPN_VM_SMOKE=1 \
PYTHONPATH=/usr/local/lib/watchdogvpn \
python3 tests/vm/phase20_4_lan_proxy_validation.py \
  --bind-address <vm-lan-ip> \
  --watchdog-bin /usr/local/bin/watchdog
```

The helper refuses to run unless `WATCHDOGVPN_VM_SMOKE=1` is set.

It uses temporary config, state and runtime directories and does not mutate the
host's persistent WatchdogVPN state.

## What It Proves

The helper validates:

- LAN sharing can be enabled through the installed CLI with an explicit VM LAN
  bind address.
- Generated credentials remain hidden in normal JSON output and available only
  through the explicit `--show-secret` path.
- The generated sing-box config passes `sing-box check`.
- A closed upstream causes authenticated LAN HTTP/SOCKS requests to fail
  closed instead of succeeding through a direct fallback.
- Proxy DNS is preserved for SOCKS and HTTP LAN proxy traffic: the controlled
  upstream SOCKS server receives domain-form connect requests (`ATYP=3`) for
  both client paths.
- Disabling LAN sharing and reconnecting with a non-LAN config leaves only the
  loopback proxy listeners.
- `ip route` and `ip rule` are unchanged by the validation.

The fake upstream design avoids Internet dependency. It distinguishes "proxy
sent the hostname to the upstream" from "WatchdogVPN resolved through the local
LAN/router resolver first."

## Installed VM Result

Installed VM validation on `archvm` passed with:

- VM LAN address: `192.168.0.228`;
- installed runtime match: `58606ed3f19e10f2f187a05c088188d68e95929c`;
- `FAIL_CLOSED_NO_DIRECT_FALLBACK_OK`;
- `PROXY_DNS_DOMAIN_FORWARDING_OK`;
- `DISABLED_CONFIG_HAS_NO_LAN_LISTENERS_OK`;
- `ROUTE_RULE_UNCHANGED_OK`;
- `PHASE20_4_LAN_PROXY_VM_VALIDATION_OK`.

The installed smoke used `/usr/local/bin/watchdog` and
`/usr/local/lib/watchdogvpn`.

## Remaining Phase 20 Work

Task 20.4 validates LAN proxy DNS/fail-closed behavior for the supported
authenticated proxy mode. It does not implement or validate:

- gateway/router mode;
- NAT or IP forwarding;
- managed firewall apply/teardown;
- LAN DNS listener exposure;
- separate-client VM topology beyond host-reachable LAN bind proof.

Gateway/router mode remains gated by Task 20.5.
