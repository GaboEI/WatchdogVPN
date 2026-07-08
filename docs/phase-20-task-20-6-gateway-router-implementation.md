# Phase 20 Task 20.6 - Gateway/Router Mode Implementation

Date: 2026-07-08
Status: closed

## Scope

Task 20.6 implements the bounded gateway/router contract accepted by Task
20.5. It adds disabled-by-default IPv4 LAN gateway runtime support on the
dedicated Phase 20 branch.

This task does not merge gateway/router behavior to `main`, does not enable it
by default, does not implement IPv6 forwarding, does not mutate DHCP/router
advertisement/client network managers and does not expose an automatic LAN DNS
listener.

## Configuration

Gateway mode is configured through the existing `lan_sharing` section:

```toml
[lan_sharing]
enabled = true
mode = "gateway"
firewall_managed = true
gateway_interface = "enp0s8"
gateway_client_cidr = "192.168.50.0/24"
gateway_dns_mode = "manual"
```

Validation requires:

- `mode = "gateway"`;
- `firewall_managed = true`;
- a concrete non-loopback `gateway_interface`;
- an IPv4 `gateway_client_cidr` that is not `0.0.0.0/0`, loopback or
  multicast;
- `gateway_dns_mode = "manual"`.

Runtime additionally requires the configured gateway interface to exist on the
host and have an IPv4 address.

## Runtime Behavior

Gateway mode requires TUN capture. Runtime connect fails closed unless
`capture_modes` includes `tun`.

When sing-box has started and the TUN path is healthy, the driver applies
WatchdogVPN-owned nftables state:

- table: `inet watchdogvpn_lan_gateway`;
- filter hook: `forward`;
- NAT hook: `postrouting`;
- accepts established/related forwarding;
- accepts LAN client traffic only from the configured LAN interface and CIDR
  toward `wdvpn-tun0`;
- rejects other forwarded traffic arriving from the configured LAN interface;
- masquerades only the configured LAN client CIDR toward `wdvpn-tun0`.

Only after those rules are installed does WatchdogVPN write
`net.ipv4.ip_forward = 1`. The previous value is snapshotted and restored on
disconnect or failed apply.

## DNS Contract

Task 20.6 implements manual LAN-client DNS mode only. WatchdogVPN reports this
as `gateway_dns_mode = "manual"` and does not claim to protect LAN-client DNS
automatically. LAN clients must be configured explicitly by the operator.

Automatic LAN DNS listener exposure remains out of scope for this task.

## Teardown

Disconnect and failed gateway apply remove the product-owned nftables table and
restore the previous `net.ipv4.ip_forward` value. Existing LAN proxy inbounds
and local loopback inbounds remain unchanged.

## Diagnostics

Connection state now includes:

- `lan_gateway_active`;
- `lan_gateway_interface`;
- `lan_gateway_client_cidr`;
- `lan_gateway_dns_mode`.

Plain `watchdog status` prints LAN gateway state when active.

## Validation

Local unit coverage pins:

- gateway config defaults and validation;
- CLI setters and gateway warning;
- core runtime forwarding of `LANGatewayRuntimeConfig`;
- refusal when gateway mode is enabled without TUN capture;
- nftables gateway rules before forwarding is enabled;
- forwarding snapshot restore on cleanup;
- connection state reporting active gateway details.

Installed VM validation was required because this task mutates real forwarding
and firewall state.

The focused VM helper is:

```bash
sudo env WATCHDOGVPN_VM_SMOKE=1 \
PYTHONPATH=/usr/local/lib/watchdogvpn \
python3 tests/vm/phase20_6_lan_gateway_validation.py \
  --lan-interface <vm-lan-interface> \
  --client-cidr <lab-client-cidr> \
  --tun-interface wdvpn-tun0
```

The helper refuses to run without `WATCHDOGVPN_VM_SMOKE=1` and root privileges.
It applies the installed gateway nftables/ip-forwarding runtime directly,
checks that the table contains the interface, client CIDR, TUN interface,
masquerade and reject rules, then verifies cleanup removes the table and
restores the prior `net.ipv4.ip_forward` value.

Installed VM validation on `archvm` passed with installed/source match at
`e36e4c6a9a2284c1f6757799ef9c50806975d178`.

Observed result:

- `./doctor.sh`: `FAIL=0`, `Result: WARN` only for known environment warnings;
- pre-state `net.ipv4.ip_forward = 0`;
- pre-state gateway nftables table absent;
- pre-state policy rules: local/main/default only;
- helper markers:
  - `PHASE20_6_GATEWAY_APPLY_OK`;
  - `PHASE20_6_GATEWAY_CLEANUP_OK`;
  - `PHASE20_6_LAN_GATEWAY_VM_VALIDATION_OK`;
- post-state `net.ipv4.ip_forward = 0`;
- post-state gateway nftables table absent;
- post-state policy rules and routes unchanged.
