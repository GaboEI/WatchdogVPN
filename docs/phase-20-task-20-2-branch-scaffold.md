# Phase 20 Task 20.2 - Branch-Only Implementation Scaffold

Date: 2026-07-08
Status: closed

## Scope

Task 20.2 adds the disabled-by-default LAN sharing configuration scaffold on the
dedicated `phase-20-lan-sharing-gateway` branch.

This task does not enable a LAN listener, change sing-box inbound binds, mutate
firewall state, enable forwarding, change DNS behavior, start gateway routing or
merge Phase 20 work into `main`.

## Config Shape

`config.toml` now has a `lan_sharing` section with these defaults:

```toml
[lan_sharing]
enabled = false
mode = "disabled"
bind_address = ""
socks_port = 2080
http_port = 2081
authentication_required = true
firewall_managed = false
```

The section is intentionally state-only at this point. Later Phase 20 tasks must
wire runtime apply, warning, teardown, DNS and kill-switch behavior before this
configuration can expose a LAN service.

## Validation Contract

The persistent config validator enforces:

- `enabled`, `authentication_required` and `firewall_managed` are strict
  booleans;
- `mode` is `disabled` or `proxy`;
- `bind_address` is empty or a concrete IP address;
- wildcard binds (`0.0.0.0`, `::`) are rejected unless an explicit test fixture
  sets `WATCHDOGVPN_TEST_ALLOW_WILDCARD_LAN_BIND=1`;
- multicast binds are rejected;
- `socks_port` and `http_port` are in `1..65535`;
- `socks_port` and `http_port` must differ;
- enabling LAN sharing requires `mode = proxy`;
- enabling LAN sharing requires an explicit non-loopback bind address;
- enabling LAN sharing requires `authentication_required = true`.

This keeps accidental broad exposure invalid before runtime code exists.

## CLI Scaffold

`watchdog config set` accepts the following scaffold keys:

```sh
watchdog config set lan_sharing.enabled <true|false>
watchdog config set lan_sharing.mode <disabled|proxy>
watchdog config set lan_sharing.bind_address <ip-address>
watchdog config set lan_sharing.socks_port <port>
watchdog config set lan_sharing.http_port <port>
watchdog config set lan_sharing.authentication_required <true|false>
watchdog config set lan_sharing.firewall_managed <true|false>
```

Boolean keys are parsed as JSON booleans for `--json` output, not strings.
Final value acceptance still goes through the same persistent config validator.

## Runtime Boundary

Task 20.2 does not alter runtime routing/capture decisions. It does not:

- read `lan_sharing` from daemon connect paths;
- alter generated sing-box inbound bind addresses;
- open any port on a LAN interface;
- add firewall rules;
- enable NAT or IP forwarding;
- change DNS listeners or resolver ownership;
- affect `active_mode`, `routing_policy`, `capture_modes` or
  `default_route_action`.

## Validation

Focused validation:

```bash
python3 -m unittest tests.test_config_storage tests.test_cli_config_commands
```

Full task validation:

```bash
bash tests/unit.sh
bash tests/syntax.sh
python3 -m unittest discover -s tests -p 'test_*.py'
git diff --check
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
```

Installed VM network validation is not required for this task because no
runtime network, DNS, route, firewall, forwarding, daemon or listener behavior
changes.
