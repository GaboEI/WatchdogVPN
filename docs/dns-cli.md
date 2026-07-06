# WatchdogVPN DNS v2 CLI

The DNS v2 CLI is exposed through the v2 core command:

```sh
./bin/watchdog dns --help
```

It is intentionally separate from the historical `watchdogvpn` runtime wrapper.
Phase 10 shipped the DNS v2 command set with real status, test, apply and reset
behavior.

## Status

`status` is read-only. It loads the DNS policy, detects the current resolver
manager and reports whether a rollback snapshot exists.

```sh
./bin/watchdog dns status
./bin/watchdog dns status --json
```

Useful test overrides:

```sh
./bin/watchdog dns status --policy-file ./dns-policy.json
./bin/watchdog dns status --resolv-conf-path /tmp/watchdogvpn-resolv.conf --json
```

## Test

`test` probes configured resolver channels. If no channels are configured, or
`--auto` is passed, it tests the default auto-setup candidates.

```sh
./bin/watchdog dns test
./bin/watchdog dns test --json
./bin/watchdog dns test --auto --domain gstatic.com --timeout 3
```

## Apply

`apply` can mutate host DNS, so it is guarded. Use `--dry-run` first.

```sh
./bin/watchdog dns apply --dry-run
./bin/watchdog dns apply --dry-run --json
```

Real apply requires explicit confirmation and a reachable local DNS entrypoint.
The command saves a snapshot before changing DNS so `reset` can restore the
previous resolver state.

```sh
./bin/watchdog dns apply --yes --systemd-link tun0
```

The local entrypoint defaults to `127.0.0.1:53`:

```sh
./bin/watchdog dns apply --yes --entrypoint-address 127.0.0.1 --entrypoint-port 53
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

```sh
./bin/watchdog dns reset --yes
./bin/watchdog dns reset --yes --json
```

## Files

Default files follow the standard WatchdogVPN config directory:

```text
~/.config/watchdogvpn/dns-policy.json
~/.config/watchdogvpn/dns-state.json
```

Overrides:

```sh
WATCHDOGVPN_DNS_POLICY_FILE=/path/to/dns-policy.json ./bin/watchdog dns status
WATCHDOGVPN_DNS_SNAPSHOT_FILE=/path/to/dns-state.json ./bin/watchdog dns reset --yes
WATCHDOGVPN_CONFIG_DIR=/tmp/watchdogvpn ./bin/watchdog dns status
```
