# Phase 23 Task 23.1 - CLI Field Validation Plan

Date: 2026-07-10
Branch: `phase-23-cli-field-validation`
Status: approved for Task 23.2 execution after maintainer review

## Scope

Task 23.1 defines the exact real-machine CLI validation matrix for Phase 23.
It does not execute real VPN, DNS, firewall, route, daemon, forwarding, system
proxy or reboot validation.

Task 23.2 must execute this plan through the CLI only. The TUI is not valid
evidence for Phase 23.

## Carried-Forward Evidence Not Re-Litigated

LAN proxy, LAN gateway and route-chain runtime behavior are intentionally not
separate rows in the Phase 23 matrix. They already closed with their own
dedicated VM/lab validation and audit gates:

- LAN proxy/gateway behavior closed in Phase 20, including Task 20.7's
  installed VM matrix and namespace LAN-client gateway lab. That evidence
  covered authenticated LAN proxy fail-closed/proxy-DNS behavior, gateway
  apply/cleanup, pre/post `ip_forward=0`, unchanged rules/routes/resolver hash,
  no stale listener ports and no residual gateway nftables table.
- Route chains closed in Phase 21.5, including Task 21.5.5's installed VM
  chain validation. That evidence covered chain config generation, hop order,
  final-hop route targeting, global-chain DNS detour, fail-closed reject
  generation, local traffic proof, teardown, and no route/rule/DNS/firewall or
  listener drift.

Phase 23 may still record a new finding against LAN or route-chain behavior if
Task 23.2 exposes a regression through normal CLI lifecycle/status/cleanup
coverage, but the Phase 23 matrix does not re-run those already-closed
specialized matrices by default.

## Safety Gate

All validation that can affect the operator session must be run only by the
operator in a disposable VM, lab host or explicitly approved field machine.
Do not run the disruptive parts from an active remote session that depends on
mutable VPN, DNS, route, firewall or daemon state.

Before any Task 23.2 execution, the operator must have:

- a VM snapshot or equivalent rollback point;
- local copies of real or representative profile fixtures, not pasted into
  chat;
- a local provider subscription URL stored only on the operator machine;
- the external VPN state deliberately set to the planned case: present or
  absent;
- `doctor` output captured before mutation;
- baseline snapshots for routes, policy rules, resolver state, nftables,
  listeners, processes and daemon state;
- explicit cleanup commands available before starting.

Passwords, provider tokens, private keys, endpoint secrets and raw profile
payloads must never be pasted into chat, committed to the repo or copied into
normal evidence. Evidence may include redacted CLI JSON and local file paths
only.

## Operator Manifest

The operator must prepare a local JSON manifest outside the repo, for example:

```text
/tmp/watchdogvpn-phase23-field-manifest.json
```

The checked-in example schema is:

```text
tests/vm/phase23_cli_field_validation_manifest.example.json
```

The manifest records local fixture paths and expected IDs. It must cover every
required protocol exactly once or more:

- `vless`
- `vmess`
- `trojan`
- `hysteria2`
- `tuic`
- `shadowsocks`
- `wireguard`
- `amneziawg`
- `openvpn`
- `openvpn_cloak`
- `socks`
- `http`

The helper:

```bash
python3 tests/vm/phase23_cli_field_validation_plan.py \
  --manifest /tmp/watchdogvpn-phase23-field-manifest.json \
  --output /tmp/watchdogvpn-phase23-cli-runbook.md
```

validates manifest completeness and writes a redacted command runbook for Task
23.2. It does not connect, disconnect, update providers, apply DNS, change
app policy, change routes, edit firewall state, start or stop services, or
contact the network.

## Evidence Directory

Task 23.2 evidence must be written under an operator-local directory:

```text
/tmp/watchdogvpn-phase23-field-evidence/
```

Minimum evidence files:

- `00-environment.txt`
- `01-doctor-before.json`
- `02-baseline-state/`
- `03-profile-imports/`
- `04-protocol-connectivity/`
- `05-provider/`
- `06-app-policy/`
- `07-dns/`
- `08-kill-switch/`
- `09-rotation/`
- `10-reboot-manual-off/`
- `11-cleanup-state/`
- `12-findings.md`

Raw fixture files, raw subscription URLs, private keys and unredacted provider
metadata must not be copied into the evidence directory.

## Matrix

### M0 - Preflight And Cleanup Baseline

| ID | External VPN | CLI commands | Required proof |
| --- | --- | --- | --- |
| M0.1 | absent | `git status --short --branch`; `git rev-parse HEAD origin/phase-23-cli-field-validation`; `./update.sh --yes`; `watchdog doctor --json`; `watchdog status --json`; `watchdog profile list --json`; `watchdog provider list --json`; `watchdog dns status --json`; `watchdog app-policy status --json` | Installed source matches the Phase 23 branch, doctor is acceptable for the VM, daemon is reachable or documented, and starting state is recorded. |
| M0.2 | present | Same commands after the operator deliberately raises the external VPN | WatchdogVPN reports state without clobbering the external VPN; any environment warning is recorded. |
| M0.3 | both | `ip rule`; `ip route`; `ip -6 route`; `ss -H -ltnup`; `sha256sum /etc/resolv.conf`; `sudo nft list ruleset`; `pgrep -a 'sing-box|openvpn|ck-client|awg|wireguard|watchdog'` | Baseline route, resolver, firewall, listener and process state captured before mutation. |

### M1 - Profile Import And Labeling

| ID | Protocol | Required category | Import command | Required proof |
| --- | --- | --- | --- | --- |
| M1.1 | VLESS | resilient | `watchdog profile add --file <vless_fixture> --json` | `watchdog profile list --json` includes the expected ID, protocol `vless`, `resilience_category=resilient`, `config_included=false`. |
| M1.2 | VMess | compatibility | `watchdog profile add --file <vmess_fixture> --json` | Same proof with `protocol=vmess`, `resilience_category=compatibility`. |
| M1.3 | Trojan | resilient | `watchdog profile add --file <trojan_fixture> --json` | Same proof with `protocol=trojan`, `resilience_category=resilient`. |
| M1.4 | Hysteria2 | resilient | `watchdog profile add --file <hysteria2_fixture> --json` | Same proof with `protocol=hysteria2`, `resilience_category=resilient`. |
| M1.5 | TUIC | compatibility | `watchdog profile add --file <tuic_fixture> --json` | Same proof with `protocol=tuic`, `resilience_category=compatibility`. |
| M1.6 | Shadowsocks | compatibility | `watchdog profile add --file <shadowsocks_fixture> --json` | Same proof with `protocol=shadowsocks`, `resilience_category=compatibility`. |
| M1.7 | WireGuard | compatibility | `watchdog profile add --file <wireguard_fixture> --json` | Same proof with `protocol=wireguard`, `resilience_category=compatibility`. |
| M1.8 | AmneziaWG | resilient | `watchdog profile add --file <amneziawg_fixture> --json` | Same proof with `protocol=amneziawg`, `resilience_category=resilient`. |
| M1.9 | OpenVPN | compatibility | `watchdog profile add --file <openvpn_fixture> --json` | Same proof with `protocol=openvpn`, `resilience_category=compatibility`. |
| M1.10 | OpenVPN+Cloak | resilient | `watchdog profile add --file <openvpn_cloak_fixture> --json` | Same proof with `protocol=openvpn_cloak`, `resilience_category=resilient`. |
| M1.11 | SOCKS | compatibility | `watchdog profile add --file <socks_fixture> --json` | Same proof with `protocol=socks`, `resilience_category=compatibility`. |
| M1.12 | HTTP | compatibility | `watchdog profile add --file <http_fixture> --json` | Same proof with `protocol=http`, `resilience_category=compatibility`. |

### M2 - Per-Protocol CLI Connectivity

Each imported profile must run through the same lifecycle sequence in both
external-VPN states where the VM can safely provide that state.

| ID | Protocols | External VPN | CLI commands | Required proof |
| --- | --- | --- | --- | --- |
| M2.1 | all 12 protocols | absent | `watchdog connect <profile_id> --json`; `watchdog status --json`; operator egress probes through normal routing, `--socks5-hostname 127.0.0.1:2080` and `--proxy http://127.0.0.1:2081`; `watchdog disconnect --json`; `watchdog status --json` | Connect succeeds or records a concrete field finding; status reports the expected active profile; at least the mode-appropriate egress probe uses the WatchdogVPN path; no unexpected direct fallback occurs; disconnect reports cleanup expectations and standby state. |
| M2.2 | all 12 protocols | present | Same sequence | WatchdogVPN does not corrupt the pre-existing external VPN session; differences from absent mode are documented. |
| M2.3 | all 12 protocols | both | Repeat post-disconnect snapshots from M0.3 | No unexpected route, DNS, nftables, listener or process residue remains after each protocol case. |

If a protocol cannot be validated with a real endpoint during Task 23.2, the
cell must be marked unavailable with a concrete reason, follow-up owner and
replacement representative proof. HIGH or MEDIUM product findings still block
Phase 23 closure.

### M3 - Provider URL Import, Update And Provider Node Connection

| ID | External VPN | CLI commands | Required proof |
| --- | --- | --- | --- |
| M3.1 | absent | `watchdog provider add <local-provider-url> --name <name> --json`; `watchdog provider list --json`; `watchdog provider stats <provider_id> --json` | Provider URL is redacted in JSON and human output; provider-owned nodes import; raw metadata is not printed. |
| M3.2 | absent | `watchdog provider update <provider_id> --json`; `watchdog provider stats <provider_id> --json` | Update succeeds or records a concrete provider finding; node count/protocol summary is recorded. |
| M3.3 | absent | `watchdog connect <provider_node_id> --json`; `watchdog status --json`; normal, SOCKS and HTTP egress probes; `watchdog disconnect --json` | At least one provider-imported node connects through the daemon path and cleans up. |
| M3.4 | present | Repeat M3.2-M3.3 | Provider update/connect does not break the pre-existing external VPN session. |

### M4 - App Policy Direct, VPN And Block

The app-policy CLI names the VPN/current route action as `current`. In this
matrix, "VPN" means `current`.

| ID | Policy case | CLI commands | Required proof |
| --- | --- | --- | --- |
| M4.1 | direct | create local curl-wrapper paths; `watchdog app-policy enable --json`; `watchdog app-policy mode blacklist --json`; `watchdog app-policy add --process-path <direct_probe_path> --action direct --id phase23-direct --json`; run direct probe; `watchdog app-policy status --json` | Probe is attributed to direct route where observable; no raw process path history is emitted in normal output. |
| M4.2 | VPN/current | `watchdog app-policy add --process-path <vpn_probe_path> --action current --id phase23-vpn --json`; run VPN probe while connected | Probe uses the active WatchdogVPN path where observable. |
| M4.3 | block | `watchdog app-policy add --process-path <block_probe_path> --action block --id phase23-block --json`; run block probe | Probe cannot reach the target; failure is not a DNS-only false positive. |
| M4.4 | cleanup | `watchdog app-policy remove phase23-direct --json`; `watchdog app-policy remove phase23-vpn --json`; `watchdog app-policy remove phase23-block --json`; `watchdog app-policy disable --json` | Policy returns to the recorded starting state or a backup/restore path is recorded. |

### M5 - DNS Apply And Reset

| ID | External VPN | CLI commands | Required proof |
| --- | --- | --- | --- |
| M5.1 | absent | `watchdog dns status --json`; `watchdog dns diagnose --domain <probe_domain> --json`; `watchdog dns apply --dry-run --json` | Dry run is non-mutating and reports the planned resolver path. |
| M5.2 | absent | `watchdog dns apply --yes --json`; resolver probe; `watchdog dns status --json`; `watchdog dns reset --yes --json` | Apply saves or uses rollback metadata; resolver probe works as expected; reset restores pre-apply resolver checksum or records a concrete finding. |
| M5.3 | present | Repeat M5.1-M5.2 only if the operator confirms it will not cut the session | DNS apply/reset does not strand the external VPN session; otherwise cell is unavailable with reason and owner. |

### M6 - Kill Switch Enable And Disable

| ID | Case | CLI commands | Required proof |
| --- | --- | --- | --- |
| M6.1 | enable | `watchdog setup --yes --acknowledge-backup-warning --kill-switch enable --json`; `watchdog connect <profile_id> --json`; controlled drop/failure; blocked egress probe; `watchdog status --json` | Kill switch is active when expected and prevents direct leak during controlled failure. |
| M6.2 | disable | `watchdog disconnect --json`; `watchdog setup --yes --acknowledge-backup-warning --kill-switch disable --json`; `watchdog status --json`; direct egress probe | Kill switch disables cleanly and no stale firewall rules remain. |
| M6.3 | cleanup | Repeat M0.3 snapshots | No unexpected firewall, route, DNS or listener residue remains. |

### M7 - Rotation And All-Failed Behavior

| ID | Case | CLI commands | Required proof |
| --- | --- | --- | --- |
| M7.1 | rotation pool | `watchdog profile rotation <profile_a> --enable --json`; `watchdog profile rotation <profile_b> --enable --json`; `watchdog profile list --pool --json`; `watchdog connect <profile_a> --json`; `watchdog rotate --force --json`; `watchdog status --json` | Rotation moves through the daemon path and selects an eligible profile without direct fallback. |
| M7.2 | provider rotation | `watchdog provider rotation <provider_id> --enable --json`; `watchdog provider node <provider_id> <provider_node_id> --rotation --enable --json`; `watchdog rotate --force --json` | Provider node participates in rotation and output remains redacted. |
| M7.3 | all-failed | Disable or isolate every rotation candidate in the VM; `watchdog rotate --force --json`; `watchdog status --json`; egress probe | Runtime fails closed or stays on a safe state; no silent direct fallback occurs. |
| M7.4 | cleanup | Re-enable original candidates or restore backup; `watchdog disconnect --json`; repeat M0.3 snapshots | Original rotation state is restored and no route/DNS/firewall residue remains. |

Do not edit `rotation/rotation_engine.py` during Task 23.1.

### M8 - Reboot And Manual-Off Behavior

| ID | Case | Operator sequence | Required proof |
| --- | --- | --- | --- |
| M8.1 | reboot while disconnected | `watchdog disconnect --json`; snapshot; reboot VM; `watchdog doctor --json`; `watchdog status --json`; snapshots | VM boots cleanly, daemon/runtime state is coherent, no stale DNS/routes/firewall/listeners/processes remain. |
| M8.2 | reboot while connected | `watchdog connect <profile_id> --json`; snapshot; reboot VM; `watchdog doctor --json`; `watchdog status --json`; egress probe; cleanup | Autostart/autoconnect behavior matches configured policy; no stale partial runtime state remains. |
| M8.3 | manual daemon off | `sudo systemctl stop watchdogvpn.service`; `watchdog status --json`; snapshots; `sudo systemctl start watchdogvpn.service`; `watchdog status --json`; cleanup | Manual service stop does not leave DNS/routes/firewall/listeners/processes wedged; restart reconciles state. |
| M8.4 | panic manual-off path | `watchdog panic sleep`; snapshots; `watchdog panic status`; `watchdog panic wake`; `watchdog status --json`; snapshots | Panic path disables runtime safely and wake restores service eligibility without stale residue. |

## Cleanup Requirements

Every matrix block must end with:

```bash
watchdog disconnect --json
watchdog dns reset --yes --json
watchdog app-policy disable --json
watchdog panic wake
watchdog status --json
watchdog doctor --json
ip rule
ip route
ip -6 route
ss -H -ltnup
sha256sum /etc/resolv.conf
sudo nft list ruleset
pgrep -a 'sing-box|openvpn|ck-client|awg|wireguard|watchdog' || true
```

If cleanup fails, the failure is a Phase 23 field finding. HIGH or MEDIUM
cleanup findings must be fixed before Phase 23 can close.

## Finding Rules

Record findings in `12-findings.md` using:

```text
ID:
Severity: HIGH|MEDIUM|LOW|INFO
Status: open|fixed|accepted
Matrix cell:
External VPN state:
Command:
Observed:
Expected:
Evidence:
Owner:
Fix commit:
Retest:
```

Severity guidance:

- HIGH: traffic leaks direct when policy says VPN/block, kill switch fails,
  DNS/route/firewall cleanup strands connectivity, raw secrets leak in normal
  output, or a required protocol/provider path silently falls back.
- MEDIUM: daemon/runtime state is wrong or unrecoverable without manual repair,
  rotation selects an ineligible node, provider update corrupts local state, or
  reboot/manual-off behavior leaves stale managed state.
- LOW: confusing but recoverable operator output, missing non-sensitive
  evidence detail, or incomplete diagnostic wording.
- INFO: documented environmental limitation with no product behavior defect.

All HIGH and MEDIUM findings must be fixed and retested before Phase 23
release-candidate audit. Known bugs and known Phase 23 technical debt may not
remain at phase close.

## Task 23.1 Validation

Task 23.1 validation is local-only:

```bash
python3 tests/vm/phase23_cli_field_validation_plan.py \
  --manifest tests/vm/phase23_cli_field_validation_manifest.example.json \
  --output /tmp/watchdogvpn-phase23-example-runbook.md
bash tests/syntax.sh
git diff --check
```

These commands do not execute real VPN/provider/DNS/firewall/route validation.
