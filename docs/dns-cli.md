# WatchdogVPN DNS v2 CLI

The DNS v2 CLI is exposed through the canonical product command:

```sh
watchdog dns --help
```

From a source checkout you can also run `./bin/watchdog dns --help`. It is
intentionally separate from the historical `watchdogvpn` runtime wrapper.
Phase 10 shipped the DNS v2 command set with real status, test, apply and reset
behavior.

## Status

`status` is read-only. It loads the DNS policy, detects the current resolver
manager and reports whether a rollback snapshot exists.

```sh
watchdog dns status
watchdog dns status --json
```

Useful lab/test path overrides (temporary files and fixtures; not required for
normal operator use):

```sh
watchdog dns status --policy-file ./dns-policy.json
watchdog dns status --resolv-conf-path /tmp/watchdogvpn-resolv.conf --json
```

## Test

`test` probes configured resolver channels. If no channels are configured, or
`--auto` is passed, it tests the default auto-setup candidates.
Resolver probes are bounded diagnostic checks only; live DNS resolution keeps
the deterministic resolver order recorded in the policy and does not race
runtime answers.

```sh
watchdog dns test
watchdog dns test --json
watchdog dns test --auto --domain gstatic.com --timeout 3
```

## Diagnose

`diagnose` is read-only. It combines configured routing rules, app policy and
DNS policy to explain how hypothetical traffic would be routed and which DNS
channel would resolve its domain. It does not observe live packets or perform a
DNS lookup.

```sh
watchdog dns diagnose --domain example.com
watchdog dns diagnose --domain example.com --process-name curl --json
```

Route calculation uses the same Phase 19 diagnostic contract as
`watchdog rules explain`: `routing_policy=global` ignores route rules and uses
the default route action, while `routing_policy=rule` evaluates rule groups and
falls back to `default_route_action` on no match. The legacy `active_mode`
field is reported only as a compatibility mirror and is not used as the route
decision source.

The output includes a confidence value. `definitive` means the configured
static policy was enough to answer. `partial`, `runtime-required` or `unknown`
mean the command could not honestly prove the full runtime decision from the
provided inputs.

JSON output includes `route_diagnostic`, which contains the route source,
route-action status, rule-evaluation status and rule-set diagnostics used
before DNS channel selection. Use `--ruleset-trust-file` to inspect an
alternate rule-set trust registry during tests or support workflows.

## Apply

`apply` can mutate host DNS, so it is guarded. Use `--dry-run` first.

```sh
watchdog dns apply --dry-run
watchdog dns apply --dry-run --json
```

Real apply requires explicit confirmation and a reachable local DNS entrypoint.
The command saves a snapshot before changing DNS so `reset` can restore the
previous resolver state. Confirmed host-DNS mutation requires root privileges;
the CLI rejects an unprivileged apply before it saves a snapshot or calls the
resolver manager.

```sh
sudo watchdog dns apply --yes --systemd-link tun0
```

The local entrypoint defaults to `127.0.0.1:53`:

```sh
sudo watchdog dns apply --yes --entrypoint-address 127.0.0.1 --entrypoint-port 53
```

Real apply requires port `53`. System resolver managers such as
`systemd-resolved`, NetworkManager and plain `resolv.conf` are configured by
nameserver address; they do not preserve an arbitrary per-nameserver port.
`--entrypoint-port` is still useful in `--dry-run` output and in the
reachability check, but confirmed mutation rejects non-53 ports instead of
leaving the host pointed at an address where DNS will not answer on the
standard port.

`--skip-entrypoint-check` exists for controlled validation paths such as tests
against temporary files. It should not be used for normal workstation apply.

## Reset

`reset` restores the saved DNS snapshot and removes the snapshot file after a
successful restore.

Confirmed apply preserves an existing rollback snapshot instead of overwriting
the original resolver state during repeated apply attempts.

```sh
sudo watchdog dns reset --yes
sudo watchdog dns reset --yes --json
```

`reset` remains an unprivileged clean no-op when no snapshot exists. If a
snapshot is present, it requires root before attempting any resolver restore
and leaves the snapshot intact when that privilege precondition is not met.

## Files

Default files follow the standard WatchdogVPN config directory:

```text
~/.config/watchdogvpn/dns-policy.json
~/.config/watchdogvpn/dns-state.json
```

Overrides:

```sh
WATCHDOGVPN_DNS_POLICY_FILE=/path/to/dns-policy.json watchdog dns status
sudo env WATCHDOGVPN_DNS_SNAPSHOT_FILE=/path/to/dns-state.json watchdog dns reset --yes
WATCHDOGVPN_CONFIG_DIR=/tmp/watchdogvpn watchdog dns status
```
