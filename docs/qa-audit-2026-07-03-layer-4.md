# WatchdogVPN QA Audit - Layer 4 User Input and Data Validation

> Date: 2026-07-03  
> Protocol: `/home/gabodev/Escritorio/temporales/WatchdogVPN_QA_AUDIT_PROTOCOL.md`  
> Scope: detection and documentation only. No fixes were made during this audit.
> Follow-up: HIGH and MEDIUM findings must be fixed in the Layer 4 hardening
> closure before Phase 11 starts.

## Audited Surface

- `parsers/uri.py`
- `parsers/subscription.py`
- `parsers/wg_config.py`
- `parsers/singbox_json.py`
- `parsers/clash_yaml.py`
- `parsers/openvpn_config.py`
- `parsers/amneziavpn_format.py`
- `providers/manual_provider.py`
- `providers/subscription_provider.py`
- `cli/main.py` profile/provider command paths
- Evidence from:
  - `tests/test_parsers.py`
  - `tests/test_manual_provider.py`
  - `tests/test_subscription_provider.py`
  - `tests/test_cli_profile_commands.py`
  - `tests/test_cli_provider_commands.py`

## Findings

### AUD-L4-001

| Field | Value |
|---|---|
| ID | AUD-L4-001 |
| Layer | Layer 4 - User input and data validation |
| Severity | MEDIUM |
| Description | URI parser port errors can escape as raw `ValueError` instead of the parser contract's `ParseError`. |
| Scenario | A user imports `vless://uuid@example.com:99999` or `vless://uuid@example.com:notaport`, and the parser accesses `parsed.port`. |
| Impact | CLI catches `ValueError` as a generic internal error path, and non-CLI callers see an unexpected exception type. This violates the parser contract that malformed user inputs should fail as clear `ParseError` messages. |
| Status | OPEN |

Evidence:
- `parsers/uri.py` reads `parsed.port` directly in VLESS, Trojan, Hysteria2,
  TUIC, WireGuard, and `_build_profile()`.
- `urllib.parse.ParseResult.port` raises `ValueError` for non-numeric or
  out-of-range ports.
- Existing invalid URI tests cover missing host/port and bad base64, but not
  invalid numeric port shapes.

### AUD-L4-002

| Field | Value |
|---|---|
| ID | AUD-L4-002 |
| Layer | Layer 4 - User input and data validation |
| Severity | MEDIUM |
| Description | Remote proxy/VPN URI imports accept loopback and localhost endpoints silently. |
| Scenario | A manual profile or provider subscription contains `vless://uuid@127.0.0.1:443`, `trojan://secret@localhost:443`, or equivalent loopback hostnames. |
| Impact | WatchdogVPN can store and later attempt to connect to a local endpoint as if it were a normal remote node. That can create confusing failures, provider-fed dead nodes, or accidental traffic to local services. If local endpoints are ever intentionally allowed, the profile should be explicit rather than silently accepted. |
| Status | OPEN |

Evidence:
- `parsers/uri.py` validates that host and port exist, but does not classify or
  reject loopback hosts for remote URI protocols.
- The same parser is used by manual imports and subscription provider imports.
- No test covers `127.0.0.1` or `localhost` URI imports.

### AUD-L4-003

| Field | Value |
|---|---|
| ID | AUD-L4-003 |
| Layer | Layer 4 - User input and data validation |
| Severity | MEDIUM |
| Description | Subscription responses that are HTML/captive portal pages are not detected explicitly, producing misleading parser errors. |
| Scenario | A provider URL returns HTTP 200 with an HTML login page or captive portal body instead of a VPN subscription. |
| Impact | The parser may route the body through YAML detection because HTML often contains colons, then report `YAML missing proxies section` or a generic unsupported format. The error is recoverable, but it is not actionable for users trying to add a provider. |
| Status | OPEN |

Evidence:
- `parsers/subscription.py::_looks_like_yaml()` returns true for the first
  non-comment line containing `:`.
- HTML bodies containing links or attributes can be misclassified as YAML.
- Existing provider CLI tests cover invalid URL syntax, but not HTTP 200 HTML
  responses.

### AUD-L4-004

| Field | Value |
|---|---|
| ID | AUD-L4-004 |
| Layer | Layer 4 - User input and data validation |
| Severity | MEDIUM |
| Description | Valid base64 subscription bodies with zero parseable profile URIs produce a generic unsupported-format error instead of a clean no-nodes result. |
| Scenario | A subscription endpoint returns base64 text that decodes successfully, but every decoded line is unsupported, blank after filtering, or not a profile URI. |
| Impact | Users and provider integrations cannot distinguish "the URL is not a subscription format" from "the subscription is valid but currently contains no supported nodes." This weakens provider debugging and onboarding. |
| Status | OPEN |

Evidence:
- `fetch_and_parse()` catches any `ParseError` from base64 line parsing and
  falls through to JSON/YAML heuristics before raising `unsupported
  subscription format`.
- `SubscriptionProvider._fetch_profiles()` has a clean
  `subscription contains no supported profiles` path, but it is only reached
  if the fetcher returns an empty list.

### AUD-L4-005

| Field | Value |
|---|---|
| ID | AUD-L4-005 |
| Layer | Layer 4 - User input and data validation |
| Severity | LOW |
| Description | sing-box JSON and Clash YAML parsers silently ignore unsupported outbound/proxy entries and may return an empty list without context. |
| Scenario | A user imports a syntactically valid sing-box or Clash config whose entries are all unsupported by WatchdogVPN. |
| Impact | ManualProvider and SubscriptionProvider wrap empty results into clearer errors, so the common user path is recoverable. Direct parser callers still receive `[]` with no reason, which can hide why a config imported no profiles. |
| Status | OPEN |

Evidence:
- `parse_singbox_json()` appends only supported outbound types and returns the
  resulting list, even when empty.
- `parse_clash_yaml()` appends only supported proxy types and returns the
  resulting list, even when empty.
- Provider/manual wrappers call `_require_profiles()` or `_fetch_profiles()`,
  but direct parser contract is less explicit.

### AUD-L4-006

| Field | Value |
|---|---|
| ID | AUD-L4-006 |
| Layer | Layer 4 - User input and data validation |
| Severity | LOW |
| Description | WireGuard private-key reuse is not detectable at import time and is not documented as a deferred runtime validation. |
| Scenario | A user imports a syntactically valid WireGuard `.conf` whose private key is already active in another local interface. |
| Impact | The parser cannot reliably detect this without querying live system state. The eventual driver/runtime path must surface the conflict clearly, but the import layer currently has no note or validation boundary documenting that limitation. |
| Status | DEFERRED |

Evidence:
- `parse_wg_config()` parses static config text only and has no system
  interface query dependency.
- Standard WireGuard is handled through sing-box compatibility generation in
  current code; native interface conflicts belong to driver/runtime validation,
  not pure parsing.

## Checked Scenarios Without Findings

### Non-ASCII profile names

URI fragments are URL-decoded and stored as Python strings. Existing behavior
supports non-ASCII names at the model/store layer because JSON writes use
UTF-8 and Python's `json.dumps` handles escaping. Layer 5 will still need to
audit terminal display width and Rich escaping.

### Duplicate manual profile IDs

`ManualProvider._unique_profile_id()` checks the store before each save. This
covers URI, text, file, clipboard, and multi-profile imports because each
profile is saved before the next profile's ID is chosen.

### Duplicate subscription node IDs within one provider fetch

`SubscriptionProvider._unique_node_id()` tracks `used_ids` during normalization
and suffixes duplicate nodes in the same provider fetch. Provider updates
intentionally reuse stable provider-owned IDs so existing local state can be
merged.

### Unknown protocol values in `profiles.json`

Layer 1 hardening now makes `Profile.from_dict()` reject unsupported
`ProtocolType` values through a controlled persistent validation path. No
silent corruption was found after that closure.

### Provider URL that is not syntactically valid

`fetch_and_parse()` catches `ValueError` from `urllib.request.Request` and
raises `ParseError("invalid subscription URL: ...")`. CLI provider tests
confirm invalid URL input fails without traceback.

## User Data Flow Trace

- Manual URI/file/text input enters `ManualProvider`, is parsed into `Profile`,
  normalized as `source = manual`, optionally marked for rotation, then saved
  through `ProfileStore`.
- Subscription URL input enters `SubscriptionProvider`, fetches through
  `fetch_and_parse()`, normalizes profiles as provider-owned nodes, then saves
  both provider and profile data.
- Parser errors generally flow to CLI as `ParseError` and return clean exit
  codes, but invalid URI ports still escape as raw `ValueError` (AUD-L4-001).
- Provider subscription data reaches persistent storage, but HTML/captive
  portal and zero-node base64 bodies do not currently produce sufficiently
  specific diagnostics (AUD-L4-003, AUD-L4-004).

## Recommended Priority Order

### MEDIUM

1. AUD-L4-001 - Wrap invalid URI port access in `ParseError` for every URI
   scheme.
2. AUD-L4-002 - Decide and enforce the local/loopback endpoint policy for
   remote URI protocols.
3. AUD-L4-003 - Add explicit HTML/captive-portal detection for subscription
   responses.
4. AUD-L4-004 - Return or raise a clean "no supported profiles" result for
   base64 subscriptions with zero parseable URIs.

### LOW

5. AUD-L4-005 - Make direct JSON/YAML parser empty results more explicit.
6. AUD-L4-006 - Document WireGuard private-key reuse as runtime validation
   rather than parser validation.

## Notes For Hardening Closure

- The closure should avoid Phase 11 rule-store work.
- Regression tests must cover invalid URI ports, loopback URI endpoints,
  HTML subscription responses, and base64 subscriptions with zero supported
  nodes.
- The closure should update this audit report with resolution notes after fixes
  land.
