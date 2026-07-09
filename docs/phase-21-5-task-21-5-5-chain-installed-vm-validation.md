# Phase 21.5 Task 21.5.5 - Chain Installed VM Validation

Date: 2026-07-09
Status: closed

## Scope

Task 21.5.5 adds the installed-VM validation harness for chain runtime behavior.
The harness is intentionally operator-run because VM validation may interact
with real network state, installed binaries, daemon logs and the operator's
external VPN session.

This task does not merge Phase 21.5 back to `main`. It does not change normal
runtime behavior. It adds validation scripts and records the exact evidence the
operator must collect before Phase 21.5 audit closure.

## Validation Harness

The installed runner is:

```text
tests/vm/phase21_5_run_installed_chain_validation.sh
```

It performs the standard installed-VM flow:

- checks out and fast-forwards the Phase 21.5 branch;
- runs `./update.sh --yes`;
- runs `./doctor.sh` and requires `FAIL=0`;
- snapshots policy rules, IPv4 routes, IPv6 routes, addresses, TCP listeners,
  resolver checksum, sing-box processes and nftables ruleset;
- keeps raw nftables ruleset evidence while comparing a counter-normalized
  ruleset so packet/byte counter increments do not masquerade as firewall drift;
- runs the Python chain proof with the installed package path;
- tails daemon logs into the evidence directory;
- snapshots post-state and fails on route, rule, DNS, firewall or listener drift.

The Python proof is:

```text
tests/vm/phase21_5_chain_installed_validation.py
```

It creates a local, deterministic lab inside the VM:

- one local HTTP proof target;
- two local SOCKS5 bridge hops with connection recording;
- a sing-box rules-mode config whose selected route action is
  `chain:vm-chain-proof`;
- deterministic chain hop outbounds:
  `watchdogvpn-chain-vm-chain-proof-hop-1` and
  `watchdogvpn-chain-vm-chain-proof-hop-2`;
- hop 2 detouring through hop 1;
- a separate global-chain config proving proxy DNS detours through the final
  chain hop;
- a local bootstrap resolver for sing-box outbound-domain resolver
  compatibility, without changing the chain-owned proxy DNS path under test;
- blocked-chain failure injection that must emit native reject rules;
- a real curl request through the local sing-box SOCKS inbound.

The traffic proof requires:

- hop 1 receives a CONNECT request for hop 2;
- hop 2 receives a CONNECT request for the final destination domain;
- the HTTP proof target receives exactly the expected request;
- the local sing-box SOCKS and HTTP listeners are gone after disconnect.

## What This Proves

The VM harness proves the installed package and installed sing-box binary can
execute a resolved chain plan without silently falling back to direct, current,
group or a shorter chain. It also proves:

- sing-box accepts the generated chain config via `sing-box check`;
- route rules target the final chain hop;
- hop order is preserved as hop 1, then hop 2, then final destination;
- final-hop DNS detour is present in generated global-chain config;
- DNS-unavailable or blocked plans fail closed to reject;
- local proxy listeners clean up after disconnect;
- route, rule, resolver and nftables state do not drift for this local-proxy
  validation path;
- daemon logs are captured for audit evidence.

## Operator Command

Run this from the VM after lowering any external VPN that could interfere with
local proof traffic:

```bash
WATCHDOGVPN_REPO_DIR="$HOME/WatchdogVPN" \
WATCHDOGVPN_BRANCH="phase-21-5-proxy-route-chain-runtime" \
WATCHDOGVPN_EVIDENCE_DIR="/tmp/watchdogvpn-phase21-5-chain-evidence" \
bash tests/vm/phase21_5_run_installed_chain_validation.sh
```

The command should finish with:

```text
PHASE21_5_CHAIN_INSTALLED_VM_VALIDATION_OK
PHASE21_5_NO_ROUTE_RULE_DNS_FIREWALL_DRIFT_OK
PHASE21_5_NO_STALE_PROXY_LISTENERS_OK
PHASE21_5_CHAIN_INSTALLED_VALIDATION_SCRIPT_OK
```

Evidence is written to:

```text
/tmp/watchdogvpn-phase21-5-chain-evidence/phase21_5_chain_installed_validation.json
/tmp/watchdogvpn-phase21-5-chain-evidence/watchdogvpn-daemon-tail.log
```

## Installed VM Result

The maintainer-run installed VM validation passed on 2026-07-09 at commit:

```text
84d8d6c1ab9c27b2cd75eacf13f1ac5afd58ae0e
```

Installed/source status:

- branch `phase-21-5-proxy-route-chain-runtime`;
- installed runtime matched source checkout at `84d8d6c1ab9c27b2cd75eacf13f1ac5afd58ae0e`;
- `doctor` completed with `FAIL=0`;
- expected warnings remained: VPN truth state was `DOWN` while the external VPN
  was lowered, NTP was unsynchronized, and optional AmneziaWG tooling was not
  installed.

Validation markers:

```text
PHASE21_5_SINGBOX_CHECK_OK
PHASE21_5_GLOBAL_CHAIN_DNS_DETOUR_OK
PHASE21_5_FAIL_CLOSED_CONFIG_OK
PHASE21_5_SINGBOX_RUNTIME_STARTED_OK
PHASE21_5_CHAIN_TRAFFIC_PROOF_OK
PHASE21_5_CHAIN_TEARDOWN_OK
PHASE21_5_CHAIN_INSTALLED_VM_VALIDATION_OK
PHASE21_5_NO_ROUTE_RULE_DNS_FIREWALL_DRIFT_OK
PHASE21_5_NO_STALE_PROXY_LISTENERS_OK
PHASE21_5_CHAIN_INSTALLED_VALIDATION_SCRIPT_OK
```

Observed system state:

- pre/post policy rules stayed at local/main/default only;
- pre/post IPv4 route table stayed unchanged;
- resolver checksum did not drift;
- counter-normalized nftables ruleset did not drift;
- local sing-box proxy listeners were removed after teardown;
- evidence was written to
  `/tmp/watchdogvpn-phase21-5-chain-evidence/phase21_5_chain_installed_validation.json`.

## Limits

This harness intentionally avoids changing TUN, forwarding, LAN gateway mode,
system proxy state or real DNS resolver state. It validates chain behavior
through the installed sing-box local proxy path with synthetic local hops. It
does not prove a third-party provider endpoint, a paid account, external
Internet egress IP, or an operator-specific provider topology.

Those limits are deliberate: the chain contract requires no pasted credentials,
no support-export leakage, no unsafe chat-handled secrets and no validation
that can cut the operator's active session. Phase 21.5 audit closure must use
the harness output as VM evidence and keep the limits explicit.

## Runtime Boundary

No product runtime behavior changed in this task. The only new executable paths
are VM validation helpers under `tests/vm`.
