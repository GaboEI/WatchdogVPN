# QA Audit - Phase 20 LAN Sharing And Gateway

Date: 2026-07-08
Status: closed

## Scope

This audit closes Phase 20 after Tasks 20.1 through 20.7 on the dedicated
`phase-20-lan-sharing-gateway` branch. It reviewed:

- LAN sharing threat model and ADR 0004;
- disabled-by-default `lan_sharing` configuration validation;
- authenticated explicit-bind LAN SOCKS/HTTP proxy runtime;
- LAN proxy fail-closed and proxy-DNS validation helpers;
- gateway/router design gate and bounded IPv4 gateway implementation;
- WatchdogVPN-owned nftables gateway table behavior;
- temporary `net.ipv4.ip_forward` snapshot/rollback;
- LAN gateway connection-state diagnostics;
- VM-only installed validation evidence and teardown results.

This audit does not merge Phase 20 to `main`.

## Audit Matrix

| Area | Result | Evidence |
| --- | --- | --- |
| Branch gate | PASS | All Phase 20 implementation commits are on `phase-20-lan-sharing-gateway`; `main` was not modified. |
| Disabled by default | PASS | `lan_sharing.enabled = false` and `mode = "disabled"` remain config defaults; tests pin defaults. |
| Explicit LAN proxy bind | PASS | Enabled proxy mode requires an explicit non-loopback bind assigned to the host; wildcard binds reject outside an explicit test fixture. |
| LAN proxy authentication | PASS | SOCKS/HTTP LAN inbounds use generated credentials; normal CLI output hides secrets; credential file permissions are pinned by tests. |
| Firewall/port warning | PASS | Enabling LAN sharing prints an operator warning; gateway mode warns about forwarding/firewall impact. |
| No direct fallback | PASS | VM helper proved LAN proxy requests fail closed when the upstream is dead. |
| Proxy DNS path | PASS | VM helper proved SOCKS and HTTP proxy target hostnames reach the upstream in domain form rather than being resolved by the LAN/router path. |
| Gateway TUN requirement | PASS | Runtime refuses gateway mode unless `capture_modes` includes `tun`; unit tests pin the fail-closed path. |
| Gateway unsafe config rejection | PASS | Persistent validation rejects missing interface/CIDR, unmanaged firewall, non-manual DNS mode, IPv6/wildcard/loopback/multicast CIDRs and unsafe interface names. |
| Gateway firewall ownership | PASS | Runtime uses only `inet watchdogvpn_lan_gateway` for product-owned gateway state and removes it on cleanup. |
| Gateway default-drop forwarding | PASS | Local tests and VM helper confirm the forward hook uses `policy drop`. |
| Gateway allowed flows | PASS | Rules explicitly allow established/related and configured LAN-interface/CIDR to TUN flow, reject other LAN-interface forwarding and masquerade only the configured client CIDR. |
| Forwarding rollback | PASS | VM matrix observed pre/post `net.ipv4.ip_forward = 0`; helper validates snapshot restore. |
| Firewall residue | PASS | VM matrix confirmed the gateway nftables table is absent after cleanup. |
| Route/rule residue | PASS | VM matrix confirmed `ip rule` and `ip route` were unchanged after proxy and gateway validation. |
| DNS residue | PASS | VM matrix hashes `/etc/resolv.conf` before/after and reported no DNS drift. |
| Stale listener cleanup | PASS | VM matrix confirmed LAN proxy validation ports were closed after teardown. |
| Gateway DNS honesty | PASS | Gateway supports and reports manual DNS mode only; no automatic LAN DNS protection is claimed. |
| Gateway diagnostics | PASS | Connection state distinguishes `disabled`, `configured`, `applied` and `degraded`. |
| Separate LAN-client simulation | PASS | Phase 20.7 namespace lab creates a temporary client namespace and veth pair, applies gateway state against a lab tunnel interface, then proves namespace/link/firewall/forwarding cleanup. |
| LAN router boundary | PASS | The design and implementation do not rely on the LAN router as the access-control boundary; access control is explicit bind/auth plus WatchdogVPN-owned gateway firewall state. |

## Findings

### AUD-P20-001 - Gateway forward chain default policy was accept

- Layer: Layer 8 - Network leak safety, DNS/routing policy and
  hostile-environment resilience.
- Severity: HIGH.
- Status: RESOLVED before audit closure.
- Description: The initial gateway nftables forward chain used default policy
  `accept`.
- Impact: The explicit LAN-to-TUN rules still constrained the intended path,
  but the default-accept chain did not satisfy the gateway design gate because
  unmodeled forwarded traffic should be dropped by default.
- Fix: The gateway forward chain now uses `policy drop` and only permits
  established/related plus configured LAN-to-TUN traffic.
- Evidence: Corrective VM validation and the Phase 20.7 installed matrix both
  checked `hook forward` and `policy drop`.

### AUD-P20-002 - Gateway diagnostics were binary instead of stateful

- Layer: Layer 1 - Core logic and state; Layer 5 - CLI output and user
  experience.
- Severity: MEDIUM.
- Status: RESOLVED before audit closure.
- Description: Gateway diagnostics initially exposed only
  `lan_gateway_active`.
- Impact: Operators could not distinguish disabled, configured-but-not-applied,
  applied and degraded gateway states.
- Fix: Connection state now reports `lan_gateway_status` as `disabled`,
  `configured`, `applied` or `degraded`, while retaining the boolean field for
  compatibility.
- Evidence: Focused core/model tests cover all four states.

### AUD-P20-003 - Namespace gateway lab assumed forwarding before gateway apply

- Layer: Layer 8 - Network leak safety; validation infrastructure.
- Severity: LOW.
- Status: RESOLVED.
- Description: The first Phase 20.7 namespace helper used a pre-apply
  forwarding route query with an input interface, which can fail while
  `net.ipv4.ip_forward = 0`.
- Impact: The helper could fail before testing the gateway runtime even though
  the lab namespace and host route setup were valid.
- Fix: The helper now validates the client namespace route to the gateway host,
  client-to-gateway reachability and the host route to the lab tunnel before
  applying gateway state.
- Evidence: The final installed VM matrix passed at
  `c01623983b013374cddc233ac9618e957c7fd515`.

## VM Matrix Evidence

Installed VM matrix command:

```bash
WATCHDOGVPN_LAN_BIND_ADDRESS=192.168.0.228 \
WATCHDOGVPN_LAN_INTERFACE=enp0s8 \
WATCHDOGVPN_CLIENT_CIDR=192.168.0.0/24 \
WATCHDOGVPN_TUN_INTERFACE=wdvpn-tun0 \
WATCHDOGVPN_LAN_PROXY_SOCKS_PORT=32080 \
WATCHDOGVPN_LAN_PROXY_HTTP_PORT=32081 \
tests/vm/phase20_7_run_installed_matrix.sh
```

Final installed/source match:

- checkout and installed runtime:
  `c01623983b013374cddc233ac9618e957c7fd515`;
- `./doctor.sh`: `FAIL=0`, `Result: WARN`;
- warnings were environmental: external VPN/truth state down during the
  isolated validation window, unsynchronized NTP risk, and optional protocol
  tooling not fully installed.

Observed baseline and cleanup:

- pre/post `net.ipv4.ip_forward = 0`;
- pre/post policy rules: local/main/default only;
- pre/post routes unchanged;
- gateway nftables table absent before and after validation;
- `/etc/resolv.conf` hash unchanged;
- LAN proxy validation ports closed after teardown.

Required markers passed:

- `FAIL_CLOSED_NO_DIRECT_FALLBACK_OK`;
- `PROXY_DNS_DOMAIN_FORWARDING_OK`;
- `DISABLED_CONFIG_HAS_NO_LAN_LISTENERS_OK`;
- `ROUTE_RULE_UNCHANGED_OK`;
- `PHASE20_4_LAN_PROXY_VM_VALIDATION_OK`;
- `PHASE20_6_GATEWAY_APPLY_OK`;
- `PHASE20_6_GATEWAY_CLEANUP_OK`;
- `PHASE20_6_LAN_GATEWAY_VM_VALIDATION_OK`;
- `PHASE20_7_GATEWAY_NAMESPACE_APPLY_OK`;
- `PHASE20_7_GATEWAY_NAMESPACE_CLEANUP_OK`;
- `PHASE20_7_GATEWAY_NAMESPACE_VM_VALIDATION_OK`;
- `PHASE20_7_NO_STALE_PORTS_OK`;
- `PHASE20_7_NO_ROUTE_RULE_DNS_DRIFT_OK`;
- `PHASE20_7_NO_FORWARDING_FIREWALL_RESIDUE_OK`;
- `PHASE20_7_INSTALLED_MATRIX_OK`.

## Residual Risk

No HIGH or MEDIUM findings remain open for Phase 20.

Manual gateway DNS mode is intentionally supported and honest: WatchdogVPN does
not claim automatic LAN-client DNS protection in gateway mode. A future
automatic LAN DNS path would require its own design, teardown and leak
validation.

IPv6 forwarding, automatic DHCP/router mutation, router advertisements,
automatic client route mutation and persistent forwarding changes remain
rejected by the Phase 20 contract.

Merge to `main` is still a separate maintainer-approved step. This audit only
clears the Phase 20 branch gate.

## Validation

Focused local validation:

```bash
python3 -m unittest tests.test_lan_sharing_config tests.test_config_storage tests.test_cli_config_commands tests.test_singbox_driver tests.test_core_watchdog tests.test_models
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m py_compile tests/vm/phase20_7_gateway_namespace_validation.py
bash -n tests/vm/phase20_7_run_installed_matrix.sh
```

Results:

- focused LAN/gateway suite passed: 250 tests OK;
- VM helper compile passed;
- VM runner shell syntax passed.

Full closure validation:

```bash
bash tests/unit.sh
bash tests/syntax.sh
python3 -m unittest discover -s tests -p 'test_*.py'
git diff --check
PYTHONPYCACHEPREFIX=/tmp/watchdogvpn-pycache python3 -m compileall -q .
```

Final closure results:

- shell unit checks passed;
- syntax checks passed;
- full Python discovery passed: 1114 tests OK, 1 skipped;
- diff whitespace check passed;
- compileall passed.
