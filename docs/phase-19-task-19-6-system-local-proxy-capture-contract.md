# Phase 19 Task 19.6 - System Proxy and Local Proxy Capture Contract

> Date: 2026-07-08
> Status: CLOSED - contract defined, unsafe silent system-proxy use blocked.

## Scope

Task 19.6 defines the Linux capture contract for WatchdogVPN's local proxy and
future system proxy integration before the final CLI exposes capture controls.

This task does not implement system proxy mutation. It deliberately blocks
runtime use of `system_proxy` until apply, cleanup, crash recovery, uninstall
and environment detection are implemented and validated.

## Local Proxy Contract

WatchdogVPN's local proxy is a loopback-only sing-box inbound pair:

- SOCKS: `127.0.0.1:2080`
- HTTP: `127.0.0.1:2081`

Local proxy capture means an application explicitly sends traffic to one of
these local proxy endpoints. It does not capture arbitrary process traffic by
itself.

Security and ownership rules:

- Bind address must remain loopback-only.
- Wildcard binds are not allowed in Phase 19.
- LAN exposure belongs to Phase 20 and must not be added here.
- Ports `2080` and `2081` are owned by the active WatchdogVPN sing-box runtime
  while connected.
- Port conflicts must fail the connection rather than silently switching to an
  undocumented port.
- Local proxy authentication is not required while the listener is loopback-only.
- If future work permits non-loopback bind addresses, authentication or a
  written protocol-specific exception becomes mandatory before merge.

Cleanup:

- Disconnect stops the sing-box process and removes runtime files.
- No OS proxy settings are changed for local-proxy-only capture.
- Uninstall removes product files and service units; it must not assume local
  proxy listeners are LAN services.

Limitations:

- Apps that are not configured to use the local proxy bypass this capture path.
- UDP/ICMP are not captured by HTTP/SOCKS unless an application or protocol
  explicitly tunnels them through the proxy.
- DNS behavior depends on the application and configured DNS policy; local
  proxy alone is not proof of full-system DNS capture.

## System Proxy Contract

System proxy capture means WatchdogVPN changes supported desktop/session proxy
settings so proxy-aware applications use the local SOCKS/HTTP listener.

System proxy is incomplete capture:

- applications may ignore system proxy settings;
- UDP/ICMP may bypass it;
- command-line tools may ignore desktop settings;
- browsers or runtimes can have their own proxy configuration;
- DNS may still use the system resolver unless TUN/DNS hijack or app behavior
  routes DNS through WatchdogVPN.

Because system proxy changes user/session state outside the sing-box process,
WatchdogVPN must not enable it without reliable apply and cleanup semantics.

### Supported Mechanisms For Future Implementation

Future implementation may support only explicitly detected mechanisms:

- GNOME/GSettings in a user session with `gsettings` available;
- KDE Plasma/KConfig when a reliable read/write/reset path is implemented;
- environment-variable export only for child processes launched by WatchdogVPN,
  not as a global system proxy claim.

### Unsupported Environments

The final CLI must warn honestly and refuse apply when detection is unsupported:

- headless sessions without a desktop proxy settings backend;
- SSH/non-graphical shells without a managed user session;
- root/system service contexts where user proxy settings are ambiguous;
- unknown desktop environments;
- locked-down desktops where settings cannot be read back;
- NetworkManager proxy gaps that do not cover application-level proxy use.

## Runtime Guardrail

`capture_modes = "local_proxy,system_proxy"` remains a valid persisted shape so
future configuration can represent the intended capture state. However,
runtime connect currently fails closed with:

```text
system_proxy capture is not implemented yet; use local_proxy or tun
```

This prevents a dangerous false claim where WatchdogVPN would say system proxy
is active while only the loopback local proxy exists.

## Cleanup And Recovery Requirements Before Enablement

Before `system_proxy` can be enabled, implementation must provide:

- snapshot of previous proxy settings before mutation;
- idempotent apply;
- disconnect cleanup that restores the snapshot;
- crash recovery on daemon startup;
- uninstall cleanup or explicit restoration guidance;
- detection that the active session is the one being modified;
- proof that cleanup happens when connect fails after applying settings;
- tests for missing backend, readback mismatch, partial apply and restore
  failure.

If cleanup cannot prove ownership of a setting, WatchdogVPN must not erase it.
It should report manual recovery instructions instead.

## Coexistence Rules

- `local_proxy` may run alone.
- `local_proxy` may coexist with `tun`.
- `system_proxy` requires `local_proxy`; system proxy points applications at the
  local proxy listener.
- `system_proxy` may coexist with `tun`, but TUN remains the stronger capture
  path for traffic that ignores proxy settings.
- `direct` is never a capture mode; it remains a route action.
- No capture mode is an error for sing-box runtime paths.
- LAN proxy sharing and LAN gateway/router mode remain out of scope until
  Phase 20.

## Validation

Local validation:

```bash
python3 -m unittest tests.test_config_storage tests.test_core_watchdog tests.test_singbox_driver
git diff --check
```

Coverage includes:

- persisted `system_proxy` is valid only when paired with `local_proxy`;
- runtime refuses unimplemented system-proxy capture before calling the driver;
- local SOCKS/HTTP proxy inbounds remain loopback-only;
- local proxy remains present alongside TUN.

Installed VM validation is required before final closure because this task
changes runtime connect behavior for `system_proxy` states. The validation does
not need to apply live system proxy settings because this task explicitly keeps
system proxy disabled until a future implementation.
