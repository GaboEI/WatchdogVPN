# Observability Data Classification

## Decision

WatchdogVPN observability defaults to aggregate, local-only, bounded data. It
must not silently become a destination history, process activity log, or support
bundle of secrets.

Default posture:

- aggregate counters may be stored locally by default once a metrics store
  exists;
- full request/destination history is not implemented by default;
- detailed history, if ever accepted, must be explicitly enabled, clearly
  labeled sensitive, retention-bounded, purgeable, and excluded from normal
  diagnostics exports;
- all metrics storage has a single emergency purge path;
- diagnostic exports redact or omit observability data unless the user
  explicitly requests a private full export.

## Data Classification

### Allowed by Default: Aggregate and Low-Sensitivity

These fields may be stored by default in aggregate form:

- total bytes in/out;
- counters by route action (`direct`, `current`, `block`, group/auto);
- counters by rule group id/name;
- counters by profile id or node group id;
- counts of reconnects, rotations, recovery outcomes, health-check outcomes
  and failure categories;
- coarse last-updated timestamps for aggregate buckets;
- metrics policy fields such as enabled state, retention days and redaction
  mode.

Constraints:

- no raw destination domain/IP is stored in default aggregate mode;
- no raw process path is stored in default aggregate mode;
- no raw provider URL, token, private key or subscription secret is stored;
- profile and group identifiers are local identifiers and are still treated as
  user configuration, not anonymous telemetry.

### Allowed Only With Explicit Sensitive Mode

These fields are sensitive and may be stored only under a clearly labeled
opt-in mode:

- raw destination domains;
- raw destination IP addresses;
- per-flow or per-request timestamps;
- process names;
- process executable paths;
- full rule-match traces for individual requests;
- provider/profile ids attached to individual destinations;
- DNS query history;
- public exit IP history.

Required controls before this can exist:

- default-off;
- explicit CLI warning before enabling;
- retention days with a low maximum;
- bounded file/database size;
- emergency purge;
- excluded from normal `watchdogvpn report` and support exports;
- private full export requires explicit user action and warning.

### Forbidden in Metrics Storage

These fields must not be stored in metrics:

- private keys;
- passwords;
- provider tokens;
- subscription URLs with credentials;
- raw provider import payloads;
- LAN proxy credentials;
- raw packet payloads;
- browser URLs beyond the host/domain classification explicitly accepted by a
  sensitive mode;
- unredacted diagnostic report contents.

## Retention and Purge

The metrics store must support:

- disabled/off state;
- aggregate mode;
- detailed mode only if explicitly accepted;
- retention days;
- atomic writes;
- bounded on-disk size;
- emergency purge that removes all metrics data, including detailed history if
  it exists;
- exclusion from backup/export by default.

Recommended defaults:

- mode: `aggregate`;
- detailed history: disabled / unsupported unless explicitly enabled later;
- retention: short and bounded;
- export: exclude metrics from normal diagnostics unless summarized and
  redacted.

## Diagnostics and Support Export Rules

Normal diagnostics may report:

- metrics enabled state;
- retention days;
- redaction mode;
- aggregate totals;
- top-level failure categories.

Normal diagnostics must not include:

- raw destination history;
- per-request timestamps;
- process paths;
- provider URLs/tokens;
- private keys;
- LAN credentials;
- raw metric store files.

If a private full export is implemented, it must require a separate explicit
flag and display a sensitive-data warning before writing the bundle.

## Existing Surfaces

- `watchdogvpn report` writes a local report only and applies basic
  sanitization.
- `watchdogvpn logs` reads local logs only and sanitizes obvious sensitive
  values. `bin/watchdogvpn::sanitize_stream()` redacts common compressed and
  uncompressed IPv6 literals as well as IPv4.
- Daemon event payloads expose runtime state such as status, active profile id,
  mode, TUN/proxy flags and kill-switch state; they do not include destination
  history.
- Driver runtime logs are per-run local files under private runtime directories
  and are cleaned with runtime cleanup; sing-box log level remains `warning` by
  default.
