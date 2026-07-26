# Phase 23.7.5 — Distribution Compatibility Contract (design)

**Status:** DESIGN — approved and frozen. Task 23.7.5.1 `diseño_y_contrato`: CLOSED. This
document records the *contract* the implementation tasks of Phase 23.7.5 will follow. It is a
design record, **not** a compatibility claim: it does not assert that any distribution or
version is supported. Public support/compatibility statements are generated from the
compatibility manifest, and only when the evidence and criteria of this phase justify
them (Task 23.7.5.12). The detailed design-and-execution plan is maintained by the
maintainer outside this repository and is the authoritative source for task breakdown.

## Why this phase exists

Certifying a specific distribution image does not prove a whole family. During
**Task 23.6.5a** the application was exercised on an untested Ubuntu release (26.04
"resolute"); the AmneziaWG guided path relied on the AmneziaWG PPA, which has no series
for that release and returns a 404, so the packaged install could not proceed. The
protocol was technically compatible, but the procedure was not automatic, reproducible or
universal within the family. This phase removes that class of gap structurally: detection,
version awareness, capability contracts, verified provisioning with fallbacks, honest
support classification, and a single source of truth — instead of per-version manual
exceptions.

## Three orthogonal classifications

Compatibility is not one dimension. The contract keeps three separate classifications,
each with its own source of truth, that never silently promote or demote one another.

- **`support_classification`** — a *policy* statement about a distribution **release**,
  computed **only** from policy, the manifest, CI and certifications. Never from a probe
  of one machine.
- **`host_readiness`** — whether **this concrete machine** has every required core
  capability, computed from runtime probes.
- **`protocol_readiness`** — per protocol, whether it is operable **on this host**.

A protocol being absent on a machine affects only that protocol; it does not change the
host's readiness for other protocols, nor the release's `support_classification`.

## `support_classification` — five states (only)

- `certified` — a release physically field-tested end to end (real install, all in-scope
  protocols with real traffic, full lifecycle, clean teardown, `doctor` with no FAIL,
  private evidence).
- `supported` — a release **expressly admitted** by policy, vendor-maintained, with green
  per-release CI, whose declared capability contract is resolvable in CI, and whose family
  is anchored by certified releases.
- `family_inferred` — resolves to a family adapter via `ID`/`ID_LIKE`, shares the family
  contract, was never itself field-tested, and the technical family has a current
  qualifying certification anchor.
- `experimental` — recognized by lineage but **future or not yet evaluated** (a release
  neither admitted nor expressly excluded, e.g. newer than the admitted set), or a rolling
  distribution whose evidence expired. Not a guarantee.
- `unsupported` — **no adapter**, or the release is **expressly excluded** by policy,
  **EOL/withdrawn** from support, or **below the technical capability floor**. The product
  stops early with a clear reason.

Support is **admitted-release + policy** based, not a continuous "minimum-to-maximum"
range. A numerically intermediate release is not automatically `supported`.

**Deterministic precedence (non-overlapping).** The generic phrase "not admitted" never
yields both states:

- Known family, **future or not-yet-evaluated** release (neither admitted nor excluded) →
  `experimental`.
- Rolling with **expired** evidence → `experimental`.
- Release **expressly excluded** by policy → `unsupported`.
- **EOL** release withdrawn from support → `unsupported`.
- Release **below the technical floor** → `unsupported`.
- Family **without an adapter** → `unsupported`.
- **Admitted** release on an **incomplete machine** → keeps its `support_classification`;
  the host becomes `needs_preparation`.

## Host and protocol states

- `host_readiness`: `ready`, `needs_preparation`, `preparation_failed`, `incompatible`.
- `protocol_readiness`: `operable`, `provisionable`, `absent`, `unsupported_here`.

An exhausted provisioning chain on an in-contract distribution ends in `preparation_failed`
(a host state) — not in `unsupported`. The release stays classified by policy.

## Capabilities: core vs protocol

- **Core host capabilities** gate `host_readiness` (init/systemd, network manager, DNS
  backend, TUN, firewall backend, policy routing, kernel, architecture, Python floor,
  package manager, sudo, polkit, persistence, rollback, diagnostic surface; SELinux/
  AppArmor reported and never lowered).
- **Protocol capabilities** gate only their own `protocol_readiness` (sing-box; openvpn;
  openvpn + ck-client; awg tools + kernel module or amneziawg-go). A missing protocol
  runtime never makes the whole host not-ready.
- **Firewall backend (current contract):** `nftables` is required for the atomic kill
  switch (this reflects existing behavior — `doctor.sh` fails when `nft` is absent);
  `iptables` is diagnostic/legacy-cleanup only. Promoting iptables to an alternative
  backend, or retiring it, is an explicit future decision, out of scope here.

## Provisioning: version-aware, strict chain, transactional

For a missing capability, methods are tried in this strict order (no packages built for a
different release used as a generic fallback):

1. Official package for the exact version.
2. External repository explicitly compatible with the exact version.
3. Official compatible artifact, pinned and integrity-verified.
4. Reproducible build from a pinned version/commit.
5. Otherwise `preparation_failed` with a comprehensible reason.

Provisioning is product-managed and transactional (plan → provenance → authorization →
execute → verify postcondition → safe fallback → rollback → record → uninstall). A plain
profile import performs **no** silent system mutation. Source builds must pin
version/commit, verify integrity, record installed files, and support rollback and
uninstall. Uninstall removes only what WatchdogVPN itself provisioned and recorded; it
never removes user-owned software.

## Single source of truth

A declarative JSON compatibility manifest is the one source that feeds the installer,
`doctor`, the CLI, the tests, the CI matrix and the generated public documentation. Public
claims are generated from or verified against the manifest, so documentation cannot promise
more than the installer and runtime can guarantee. The manifest is read through a small
bootstrap that works even before the definitive Python runtime is provisioned.

## Stable vs rolling

Discrete-version families (Ubuntu, Debian, Fedora, Rocky, AlmaLinux, openSUSE Leap) use
admitted-release + version policy. Rolling distributions (Arch, CachyOS, Kali Rolling,
openSUSE Tumbleweed) use a capability-and-freshness policy with a last-validated date and
an evidence-expiry rule, not a numeric minimum. Derivatives are mapped by exact evidence
(e.g. an Ubuntu codename), never by approximate equivalence; a rolling derivative uses its
own rolling policy and evidence, never a borrowed stable version.

## Realization

Task 23.7.5.2 implements the pure domain of this contract in `compat/support_model.py`
(package `compat/`), with L1 tests in `tests/test_compat_support_model.py`. The module is
OS-independent, deterministic and policy-parametrized, and hardcodes no distribution or
release. It defines the frozen state strings above, the deterministic non-overlapping
precedence (disqualifiers first, then strongest evidence), the separate stable and rolling
policies, evidence freshness with an injected clock and a data-supplied expiry, and the
domain invariants — with an explicit `DomainError` on impossible input combinations rather
than a silently-chosen state. The manifest, detection, `doctor`, the CLI and the
provisioner integrate with this model in later frozen tasks; none of that integration
exists yet.

A first review round hardened this realization:

- Stable `supported` now also requires an explicit `family_has_certified_anchor` fact
  (per this contract's "whose family is anchored by certified releases" clause), so
  admitted + vendor-maintained + CI-green alone is not enough; without a certified family
  anchor the honest state is `experimental`, and a derivative never inherits the anchor.
- `check_stable_invariants`/`check_rolling_invariants` no longer assert a hand-picked
  subset of rules: they recompute the single precedence-determined classification for the
  given facts and reject any `(facts, result)` pair that does not match it exactly,
  including a wrongly-typed `result`. This makes them exhaustive against the whole
  precedence, not just the four cases named in the design's examples.
- Rolling temporal evidence (`expiry`, `now`, `last_validated`) is now validated
  unconditionally, before any branch is evaluated, so invalid temporal data is rejected
  even when a disqualifier, a certification, or a derivative-inferred fact would otherwise
  decide the result first. The model adopts an explicit timezone policy: every datetime
  must be naive; an aware datetime, a non-positive `expiry`, or a wrong type is a
  `DomainError`, never a `TypeError`. `has_valid_field_certification` is documented as a
  fact whose currency was already evaluated externally (by the field-certification
  process) — it is intentionally not re-derived from rolling freshness.
- `classify_host_readiness` now rejects an empty core-capability sequence as a
  `DomainError`: an empty contract means no core capabilities were declared, not that the
  host is ready.
- Serialization round-trip and frozen-string coverage now include every public enum
  (`ReleaseModel`, `CoreCapabilityStatus`, `ProtocolRuntimeStatus`), plus a rejection test
  for an unauthorized `enum_cls` passed to `parse`.

## Manifest Realization

Task 23.7.5.3 realizes the manifest layer without integrating it into detection,
install/update, `doctor`, the CLI, provisioning or public documentation. The product
manifest lives at `compat/compatibility.json`; the documentation schema lives at
`compat/compatibility.schema.json`; the bootstrap reader and strict validator live at
`tools/compat_read.py`; L1 tests live at `tests/test_compat_manifest.py`.

The manifest is JSON with top-level `schema_version` and the separated collections frozen
by the external design: `technical_families`, `distributions`, `releases`,
`derivatives`, `capabilities`, `provisioning_methods`, `protocols`, `certifications` and
`validation_metadata`, plus optional bootstrap `metadata`. It stores primitive policy
facts and evidence references only. It deliberately does not store calculated
`support_classification`, `host_readiness`, `protocol_readiness` or hand-authored
`stable_facts` values; those remain derived by the bootstrap reader, the support model and
future evaluators. The bootstrap validator rejects any such calculated-state key if it
appears anywhere in the manifest.

Bootstrap constraints are explicit:

- Minimum supported bootstrap Python syntax target: 3.6.
- Python 3.6 syntax compatibility: verified by parsing `tools/compat_read.py` with the
  Python 3.6 AST grammar.
- Python 3.6 runtime execution: not yet independently verified on this host because no
  `python3.6` interpreter is available.
- Runtime dependencies: Python stdlib only (`json`, `argparse`, `os`, `re`, `datetime`).
- No import of the `compat` package or `compat/support_model.py`.
- No network, privileges, shell evaluation, `eval`, `source`, command generation or system
  mutation.
- Unknown schema major, corrupt JSON, duplicate keys, invalid UTF-8, non-finite numbers,
  top-level non-object, oversized files and product-path symlinks are rejected before any
  query is served.

Types are checked at the manifest boundary before any future model facts are built:
booleans must be real JSON `true`/`false`; strings such as `"true"` and numbers such as
`0`/`1` are rejected; integer fields reject booleans despite Python's `bool` subclassing
`int`; IDs must be non-empty and match the stable manifest identifier grammar. Timestamps
are stored as RFC 3339 UTC with a trailing `Z`; the reader normalizes them explicitly to
naive UTC strings when emitting rolling facts for the pure support model. Rolling expiry is
represented as positive integer seconds.

The validator enforces referential integrity across families, distributions, releases,
derivatives, capabilities, provisioning methods, protocols, certifications and validation
metadata. Stable distributions enumerate admitted/pending/excluded releases instead of
encoding support as a numeric range. Rolling distributions have freshness metadata and no
numeric minimum. Stable derivatives use exact codename mappings; rolling derivatives keep
lineage/adapter sharing but disable borrowed stable-version gating.

Validation is phased inside the bootstrap reader: local structure, required fields and
strict primitive types are checked first for distributions, releases, protocols and
certifications; cross-section metadata and derived semantic invariants run only after that
structure is known valid. Any structural miss that would otherwise surface as `KeyError`,
`TypeError` or `IndexError` is converted to `ManifestError`, so the CLI fails as invalid
manifest data rather than exposing an internal traceback.

The manifest keeps semantic sources in a strict hierarchy:

- Distribution policy lists and release `policy_state` are primitive policy inputs and
  must be equivalent.
- Release booleans (`meets_technical_floor`, `vendor_maintained`, `eol_or_withdrawn`),
  distribution `lineage` (`is_derivative`, `has_own_evidence`,
  `family_inference_allowed`), certifications and future per-release CI records are
  primitive inputs.
- `StableReleaseFacts` and `RollingFacts` are derived on demand by `compat_read.py`; the
  reader refuses to emit facts from a manifest whose primitive sections contradict each
  other.
- `certification_qualifies_for_support` in `tools/compat_read.py` is the single
  certification predicate used for `has_valid_field_certification`, family anchors,
  rolling current evidence and `certified` promotion.
- `repository_ci` records general repository CI only. `per_release_ci` is explicitly
  separate and remains `not_run` until Task 23.7.5.9 creates release-specific L1/L2
  evidence. Manual field-certification success is represented by certification records,
  not by CI fields.

For the current `physical_field_certification` scope, a certification qualifies only when
it is `current=true`, references exactly one stable release or rolling snapshot coherent
with its distribution, has non-empty global evidence, contains exactly every protocol in
the manifest, has evidence on every protocol result, records `green` for all
`resilient`/`compatibility` protocols and records `formal_non_green` for the exact
protocols whose category is `formal_non_green`. `failed`, `not_run` and `not_applicable`
never qualify under this scope. Other scopes are not accepted in schema version 1. The
target must also remain policy-eligible: a stable release must be admitted, listed in
`admitted_releases`, above the technical floor, not EOL/withdrawn and vendor-maintained;
a rolling distribution must be above the technical floor, not expressly excluded and not
EOL/withdrawn. A historical or current-looking certification for an ineligible target
cannot produce a certified fact or a family anchor.

Initial manifest content is conservative and sourced from the Phase 23.5/23.6/23.7.5
record: the eight physically certified distributions/releases/snapshots are represented
with certification records; AlmaLinux, RHEL, CentOS Stream, openSUSE Tumbleweed, Kali and
non-certified derivative cases carry absent or inferred evidence rather than promoted
support; Ubuntu 26.04 is represented as pending/not-yet-admitted evidence, not as a field
certification. The protocol list records required runtimes and evidence policy, including
the permanent distinction between functional rows and the three formal non-green Plan-B /
no-egress rows; it does not claim that all twelve protocols are green across a family.
Each certification stores per-protocol results with dispositions `green`,
`formal_non_green`, `failed`, `not_run` or `not_applicable`, so listing twelve protocol IDs
cannot be interpreted as twelve green results.

The bootstrap interface is intentionally small and deterministic:

```text
python3 tools/compat_read.py validate
python3 tools/compat_read.py get <dotted.path>
python3 tools/compat_read.py list <dotted.object.path>
python3 tools/compat_read.py resolve-reference <section> <id>
python3 tools/compat_read.py facts stable-release <release-id>
python3 tools/compat_read.py facts rolling-distribution <distribution-id>
```

Successful commands emit stable JSON on stdout. Manifest-invalid failures return exit code
2 with an error on stderr; missing queries return exit code 3; usage errors return exit
code 1.

## Detection And Capability Realization

Task 23.7.5.4 adds an internal, read-only detection layer without wiring it into
install/update, `doctor`, public CLI flows, provisioning or generated public claims. The
implementation lives in `compat/detection.py`; the internal JSON tool lives at
`tools/compat_probe.py`; L1 tests live at `tests/test_compat_detection.py`.

The detector preserves raw and normalized host identity separately in `DistroFacts`:
`id_raw`, `id_normalized`, ordered `id_like_ordered`, `version_id`,
`version_codename`, `ubuntu_codename`, `pretty_name`, resolved distribution/release,
technical family, adapter, package manager, derivative/lineage evidence, kernel,
architecture, os-release source, mapped base release evidence, identity evidence,
identity conflicts and a resolution status. Support classification is not stored in these
facts; it is derived by feeding manifest-derived stable/rolling facts into
`compat/support_model.py`.

`os-release` parsing is stdlib-only and deliberately does not source shell data. It
prefers `/etc/os-release`, falls back to `/usr/lib/os-release`, accepts only the normal
symlink from the former to the latter, opens the resolved target through a validated file
descriptor with `O_NOFOLLOW` when available, verifies the descriptor with `fstat`, reads
at most `MAX_OS_RELEASE_BYTES + 1` bytes, requires a regular UTF-8 file, rejects duplicate
keys and malformed lines, and supports only explicit quoting and escape forms. `$VAR`,
`${VAR}`, `$(...)` and backticks are data errors, not executable syntax.

Distribution resolution uses manifest data only: exact `ID`/manifest `os_release_ids`,
exact derivative mappings such as Linux Mint `UBUNTU_CODENAME`, rolling lineage without
borrowed stable versions, and ordered `ID_LIKE` only to identify a family/adaptor when the
distribution itself is not known. Unknown releases are not approximated to a nearby
release; known but unenumerated stable releases remain experimental through the support
model unless an explicit exclusion or floor/EOL policy says unsupported. Stable release
identity is consensus-based: every present anchor (`VERSION_ID`, `VERSION_CODENAME`,
`UBUNTU_CODENAME` and exact derivative mapping where applicable) is resolved
independently, and contradictory anchors produce `release_identity_conflict`, which never
promotes to certified, supported or family-inferred.

Every external observation goes through `SafeCommandRunner`, which accepts only argv lists,
uses `shell=False`, an explicit timeout, a controlled environment/locale, separated stdout
and stderr, bounded output and normalized error kinds. The runner starts a separate
process session, sends stdin from `DEVNULL`, drains stdout/stderr incrementally through
pipes while retaining at most `output_limit` bytes per stream, discards excess bytes while
continuing to drain, marks truncation explicitly, and terminates the process group on
timeout with TERM then KILL if needed. Tests use `FakeCommandRunner`; fixture environments
set `allow_host_fallback=false`, so a missing fixture path cannot be read from the real
host and a missing fixture `existing_paths` entry is absent. The optional host smoke
command is non-authoritative. Probes are read-only and never create interfaces, edit
firewall/routing/DNS state, start services, install packages or execute manifest data.

Core host capability results and protocol runtime capability results are separate
`CapabilityResult` records with `capability_id`, observed status, domain status, evidence,
probe method, reason and error kind. `evaluate()` first validates that the received core
capability IDs match exactly the `core_capabilities` declared by the detected technical
family, and that protocol capability IDs match exactly the manifest's protocol capability
set. Empty, missing, duplicate, unknown, wrongly-typed or invalid-status results are
`DetectionError`; a missing probe result is never silently converted to an absent runtime.
Only core capabilities whose manifest `type` is `required` or `provisionable` participate
in `host_readiness`; `optional` and `diagnostic_only` are reported without lowering the
host state. Schema version 1 does not model alternative groups, so product capabilities
that previously looked like alternatives are required until a later task adds explicit
alternative-group semantics, and an unexpected `alternative` type is rejected by
`evaluate()`.

Evidence that cannot prove a capability without a mutation is conservative: a visible
`/dev/net/tun`, `nft --version`, `sudo -V`, `pkaction --version`, package-manager version
output, `ip rule show`, a kernel release string, persistence and rollback surfaces are
partial/unknown/provisionable unless a read-only check proves the actual contract.
`permission_denied` is also treated as unverified/provisionable evidence in this read-only
task, while preserving `error_kind=permission_denied` for later preparation logic. Missing
protocol runtimes affect only their protocols, so a certified and otherwise-ready host can
report VLESS operable while AmneziaWG remains provisionable.

Architecture support policy is data, not detector code. The manifest's
`cap_architecture.supported_values` declares the admitted normalized architectures; the
detector keeps only universal normalization aliases such as `amd64 -> x86_64` and
`arm64 -> aarch64`.

The internal tool is:

```text
python3 tools/compat_probe.py detect
python3 tools/compat_probe.py capabilities
python3 tools/compat_probe.py evaluate
python3 tools/compat_probe.py report
```

It emits deterministic JSON, writes controlled errors to stderr, returns exit code 2 for
manifest/detection errors, supports explicit fixture paths and a deterministic fixture-host
mode for tests, and is not a public WatchdogVPN CLI.
