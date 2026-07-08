# Phase 20 Task 20.3 - Authenticated LAN Proxy Mode

Date: 2026-07-08
Status: closed

## Scope

Task 20.3 implements the first runtime LAN proxy path on the dedicated
`phase-20-lan-sharing-gateway` branch.

This task does not merge Phase 20 to `main`. It does not implement gateway
routing, NAT, IP forwarding, DNS listener exposure or managed firewall rules.
Those remain later Phase 20 work.

## Runtime Behavior

When `lan_sharing.enabled = true` and the runtime uses the sing-box driver,
WatchdogVPN keeps the existing loopback inbounds:

- `watchdogvpn-socks-in` on `127.0.0.1:2080`;
- `watchdogvpn-http-in` on `127.0.0.1:2081`.

It then adds authenticated LAN inbounds:

- `watchdogvpn-lan-socks-in` on `lan_sharing.bind_address:socks_port`;
- `watchdogvpn-lan-http-in` on `lan_sharing.bind_address:http_port`.

The runtime refuses to apply LAN sharing if `bind_address` is not assigned to a
local interface according to `ip -j addr show`.

## Authentication

LAN SOCKS and HTTP inbounds use sing-box `users` authentication. This matches
the upstream sing-box SOCKS and HTTP inbound schema, where an empty `users`
array means no authentication. WatchdogVPN never emits an empty users list for
LAN inbounds.

Credentials are generated with `secrets.token_urlsafe(32)` and stored in
`lan-sharing-credentials.json` next to `config.toml` with `0600` permissions.
The username is `watchdogvpn`.

Normal CLI JSON does not print the password. The only explicit secret-output
path is:

```sh
watchdog config lan-sharing-credentials --show-secret
```

Without `--show-secret`, the command reports only whether a password is
available.

## Operator Warning

`watchdog config set lan_sharing.enabled true` returns an operator-visible
warning that LAN sharing will expose authenticated SOCKS/HTTP listeners on the
configured bind address and that Task 20.3 does not apply firewall rules
automatically.

## Security Boundaries

Task 20.3 preserves these boundaries:

- LAN sharing remains disabled by default.
- Wildcard binds remain rejected by persistent config validation.
- Loopback local proxy inbounds remain unchanged.
- LAN inbounds are authenticated.
- Runtime apply fails before sing-box start if the configured LAN bind address
  is not assigned to the host.
- No firewall, DNS, forwarding, gateway or route behavior is added.
- `active_mode` remains compatibility/display-only and does not enable LAN
  sharing.

## Validation

Focused local validation:

```bash
python3 -m unittest tests.test_lan_sharing_config tests.test_singbox_driver tests.test_core_watchdog tests.test_cli_config_commands tests.test_config_storage tests.test_driver_base tests.test_daemon_runtime_worker
```

Full local validation:

```bash
bash tests/unit.sh
bash tests/syntax.sh
python3 -m unittest discover -s tests -p 'test_*.py'
git diff --check
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
```

Installed VM validation is required before this task closes because the task
adds runtime LAN listeners. The VM validation must prove at minimum:

- branch installed from `phase-20-lan-sharing-gateway`;
- configured bind address belongs to the VM;
- loopback SOCKS/HTTP inbounds still exist;
- LAN SOCKS/HTTP inbounds bind to the explicit LAN address only;
- LAN inbounds require authentication;
- `watchdog config lan-sharing-credentials` hides the password unless
  `--show-secret` is used;
- disabling LAN sharing and reconnecting removes LAN listeners;
- no gateway forwarding, route table, policy rule, DNS listener or firewall
  state is introduced by Task 20.3.

Task 20.4 adds the reusable VM helper that validates LAN proxy fail-closed and
proxy-DNS behavior for this runtime path.
