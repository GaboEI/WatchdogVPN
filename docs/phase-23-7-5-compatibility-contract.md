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
  AppArmor and firewalld reported where family-relevant and never lowered).
- **Protocol capabilities** gate only their own `protocol_readiness` (sing-box; openvpn;
  openvpn + ck-client; awg tools + kernel module or amneziawg-go). A missing protocol
  runtime never makes the whole host not-ready.
- **Firewall backend (current contract):** `nftables` is required for the atomic kill
  switch (this reflects existing behavior — `doctor.sh` fails when `nft` is absent);
  `iptables` is diagnostic/legacy-cleanup only. Promoting iptables to an alternative
  backend, or retiring it, is an explicit future decision, out of scope here.
- **Family diagnostics:** `cap_firewalld` is emitted for Red Hat/DNF and SUSE/Zypper
  families; `cap_apparmor` is emitted for Debian/APT, Ubuntu/APT and SUSE/Zypper. These
  `diagnostic_only` results report normalized observations in
  `EvaluationReport.core_capabilities` but do not participate in `host_readiness`.
  SELinux accepts only `getenforce` states `enforcing`, `permissive` and `disabled`.
  AppArmor accepts only `/sys/module/apparmor/parameters/enabled` values `Y` -> `active`
  and `N` -> `inactive`; an absent or unreadable file is `unknown`, not the same as
  demonstrated `inactive`. firewalld accepts `firewall-cmd --state` `running` -> `active`
  and `not running` on stdout or stderr -> `inactive`; a missing `firewall-cmd` is treated
  as observed `inactive` with `error_kind=command_missing`. Empty, truncated or unexpected
  diagnostic output is `unknown` with `error_kind=malformed_output`; permission, timeout
  and runner failures preserve the runner error kind.

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
exact stable release `os_release_version_ids`, exact derivative mappings such as Linux
Mint's `UBUNTU_CODENAME`, rolling lineage without borrowed stable versions, and ordered
`ID_LIKE` only to identify a family/adaptor when the distribution itself is not known.
Unknown releases are not approximated to a nearby release; known but unenumerated stable
releases remain experimental through the support model unless an explicit exclusion or
floor/EOL policy says unsupported. Stable release identity is consensus-based: every
present anchor is resolved independently. `VERSION_ID` is matched only against declared
`os_release_version_ids`; `VERSION_CODENAME` is the distribution's own codename; and a
stable derivative's base mapping declares its source explicitly, e.g.
`mapping_source=ubuntu_codename` for Linux Mint. For Linux Mint 22.3, `VERSION_CODENAME`
is `zena`, while `UBUNTU_CODENAME=noble` maps to `ubuntu_24_04`. Contradictory anchors
produce `release_identity_conflict`, which never promotes to certified, supported or
family-inferred. Release codenames are strict strings with manifest ID format and are
unique within their distribution; the same codename may appear in another distribution
only when that distribution has its own non-conflicting release identity.

Every external observation goes through `SafeCommandRunner`, which accepts only argv lists,
uses `shell=False`, an explicit timeout, a controlled environment/locale, separated stdout
and stderr, bounded output and normalized error kinds. The runner starts a separate
process session, records `pgid=process.pid` immediately, sends stdin from `DEVNULL`, drains
stdout/stderr incrementally through pipes while retaining at most `output_limit` bytes per
stream, keeps the timeout deadline active until both the process has exited and streams
are closed, discards excess bytes while continuing to drain, marks truncation explicitly,
and terminates the process group on timeout with TERM then KILL even if the leader already
exited. Tests use `FakeCommandRunner`; fixture environments set `allow_host_fallback=false`,
so a missing fixture path cannot be read from the real host and a missing fixture
`existing_paths` entry is absent. The optional host smoke command is non-authoritative.
Probes are read-only and never create interfaces, edit firewall/routing/DNS state, start
services, install packages or execute manifest data.

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
`evaluate()`. For diagnostic-only capabilities, `domain_status=present` means the
diagnostic was observed and parsed successfully, including inactive/disabled framework
states; `domain_status=provisionable` means the diagnostic is indeterminate. Neither
status changes `host_readiness`.

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

## Dependency Resolution Realization

Task 23.7.5.5 adds a pure internal dependency-method resolver without wiring it into
install/update, `doctor`, public CLI flows, provisioning, AmneziaWG migration, rollback,
uninstall or generated public claims. The declarative catalog lives in the new manifest
section `dependency_requirements`; the domain and selection engine live in
`compat/dependency_resolution.py`; the internal JSON tool lives at
`tools/compat_resolve.py`; focused L1 tests live in
`tests/test_compat_dependency_resolution.py`; a provider-backed L1 matrix lives in
`tests/test_compat_dependency_matrix.py`; and the real focused L2 harness lives in
`tests/test_compat_dependency_l2_real.py`.

The manifest catalog maps a `dependency_requirement` to exactly one capability and an
explicit `method_chain`. The initial catalog covers the dependency surface used by the
current installer/runtime inventory: base runtime commands/packages, final Python,
Python `cryptography`, polkit, DNS helper packages, NetworkManager, nftables,
OpenVPN, sing-box, Cloak `ck-client`, and AmneziaWG runtime. It also records evidence from
`lib/packages.sh`, `lib/singbox.sh`, `lib/cloak.sh`, `lib/amneziawg.sh` and the legacy
`distros/debian.sh` AmneziaWG guidance, but those files are not modified or called by this
task.

Each method candidate is structured data, never an executable shell recipe. Schema
version 1 accepts these method kinds:

- `official_package_exact` — package manager, exact target scope, package names,
  architectures, evidence and postcondition.
- `external_repo_exact` — provider, repository identity, exact `compatible_targets`,
  package names, architectures, evidence and postcondition.
- `official_artifact_pinned` — official provenance, pinned version, per-architecture
  asset metadata, integrity metadata and expected files. The current sing-box data is
  pinned to `1.13.14` with assets
  `sing-box-1.13.14-linux-amd64-glibc.tar.gz` and
  `sing-box-1.13.14-linux-arm64.tar.gz`; Cloak is pinned to `2.12.0` with assets
  `ck-client-linux-amd64-v2.12.0` and `ck-client-linux-arm64-v2.12.0`. The SHA-256
  values are validated against the legacy constants in `lib/singbox.sh` and
  `lib/cloak.sh`; placeholder hashes are rejected.
- `pinned_source_build` — official provenance, revision type, revision, build
  dependencies and expected outputs. AmneziaWG is modeled as exactly two components,
  `amneziawg_tools` (`awg`, `awg-quick`) and `amneziawg_transport` (`amneziawg-go` or a
  future admitted module transport), each with its own repository, immutable commit field,
  build dependencies and internal postcondition. The aggregate source build has no
  top-level revision; unresolved component revisions keep the method at
  `pin_metadata_incomplete` and the provider is not consulted.

`tools/compat_read.py` validates the new section while remaining Python-3.6 syntax-target,
stdlib-only and independent from the modern resolver module. It rejects empty chains,
duplicate priorities, unknown method kinds, unknown capabilities, unknown method refs,
unknown releases/distributions/families, package managers that diverge from the targeted
family, architectures outside `cap_architecture.supported_values`, missing kind-specific
security fields, target identity/scope mismatches, duplicate global candidate IDs,
unsafe package names, non-HTTPS or credentialed URLs, malformed SHA-256 hashes, mapped-base
targets not authorized by derivative mappings, stable rules applied to rolling targets,
rolling rules applied to stable targets, and arbitrary command-looking evidence.

The final Python runtime is target-specific data rather than a hardcoded probe:
Ubuntu/Debian/Mint/Kali use `python3` with `python3-cryptography`; Fedora 44 uses
`python3` with `python3-cryptography`; Rocky/Alma/RHEL/CentOS Stream 9 use `python3.11`
with `python3.11-cryptography`; openSUSE Leap/Tumbleweed use `python3.11` from package
`python311` with `python311-cryptography`; Arch/CachyOS use `python` with
`python-cryptography`. Detection probes `cap_python310` and `cap_python_cryptography`
against that selected interpreter only and records the executable and observed versions.
If no exact policy matches, or if policies overlap, the probes return conservative
`provisionable` results with `runtime_python_policy_missing` or
`runtime_python_policy_ambiguous`; they do not fall back to `python3` or any incidental
interpreter.

DNS helper readiness is conditional on an observed backend and manifest policy, not a
universal package gap. The manifest declares `dns_backend_policy` for
`cap_dns_runtime_package`: `systemd_resolved` and `networkmanager` satisfy the helper
requirement through the backend, `static_resolv_conf` makes the helper optional, and
`unknown` remains provisionable with `dns_backend_unknown`. The detector reports the
separate backend evidence through `cap_dns_backend` and only marks the helper capability
present when the backend policy allows it.

The resolver consumes:

```text
manifest + DistroFacts + support_classification + observed CapabilityResult records
```

and returns `ResolutionDecision` records inside a `ResolutionReport`. It preserves the
target distribution/release/family, support classification, observed capability status,
ordered candidate chain, selected method, execution readiness, rejected candidates,
evidence, reason and controlled error kind. The stable JSON interface is:

```text
python3 tools/compat_resolve.py dependency <dependency-id>
python3 tools/compat_resolve.py all
python3 tools/compat_resolve.py explain <dependency-id>
python3 tools/compat_resolve.py matrix
```

All commands accept the same explicit fixture boundary as `compat_probe.py`. Normal
execution uses the unknown-only availability provider and never fabricates package,
artifact or repository availability. `--availability available` and
`--missing-capability` are accepted only together with `--fixture-host`. The tool emits
JSON with provider metadata (`type` and `authoritative`), writes controlled errors to
stderr and returns exit code 2 for manifest/detection/resolver errors.

Selection is strict and deterministic:

1. If the capability is already present, the dependency is `already_present` and no method
   is selected.
2. If `support_classification=unsupported` or no concrete distribution resolved, the
   result is `out_of_contract` with no executable plan.
3. Candidates are evaluated only in ascending manifest `priority`.
4. A candidate must match the exact technical family, architecture and either the exact
   stable release, exact rolling distribution, or explicitly authorized mapped base release.
5. `external_repo_exact` additionally requires the exact `(target_id, repository.series)`
   pair to be present in `compatible_targets`; nearby series never qualify.
6. Static eligibility is evaluated before any provider call: exact scope/target,
   architecture, method coherence, pins/integrity/postcondition and implementation status.
   A statically invalid source pin or artifact hash is rejected without consulting
   availability.
7. Artifact candidates select exactly one `SelectedArtifact` for the host architecture
   before the provider is called. Providers must answer with structured
   `ArtifactAvailabilityObservation` identity for `available` artifact results: target,
   architecture, asset name, download base, SHA-256 and expected executable must match the
   selected asset exactly. Free-form evidence text is preserved, but it never proves the
   artifact subject; missing or divergent structured identity becomes
   `artifact_subject_mismatch`.
8. Availability comes only from an injected `AvailabilityProvider`; `unknown`, `timeout`,
   `permission_denied`, `malformed_response` and `provider_error` block the chain and mark
   lower-priority candidates as `not_evaluated_due_to_higher_priority_unknown`.
9. Conclusive rejections such as `unavailable`, target mismatch, architecture mismatch and
   incomplete pin metadata allow the chain to continue.
10. The first eligible and available candidate can be selected, but
   `execution_ready=false` throughout this task because the transactional provisioner and
   executor registry belong to 23.7.5.6a.
11. If the chain exhausts after conclusive rejections, the result is `no_safe_route`; if a
   higher-priority candidate cannot be verified, the result is `availability_unknown`.

Support and dependency resolution stay orthogonal. Ubuntu 26.04 can receive an honest
method analysis while staying `experimental`; `family_inferred` distributions are not
promoted by a package candidate; and an `unsupported` target never receives a plan.

Stable and rolling remain separated. Stable candidates use the exact `resolved_release`
and release list from the manifest. Rolling candidates use the concrete rolling
distribution, never a borrowed stable version. Linux Mint 22.3 may use its mapped Ubuntu
base only when a candidate declares `target_identity=mapped_base_release` and explicitly
lists `ubuntu_24_04` as compatible. Kali never receives Debian Stable methods by lineage,
and CachyOS never receives an Arch version.

The Debian/Ubuntu `focal` pin is now represented as data and rejected by policy for
Debian 13: the legacy `amneziawg_debian_legacy_focal_ppa` candidate records `series=focal`
but has an empty `compatible_targets` list, so resolution rejects it with
`target_release_not_explicitly_compatible`. Ubuntu 26.04 similarly rejects the `noble`
PPA candidate because no `(ubuntu_26_04, noble)` target is authorized; the source fallback is
recorded as a future pinned source build, but its revision is intentionally unresolved and
therefore not executable.

Fedora and RHEL-family targets are split where the legacy adapter split matters. Fedora 44
can use DNF official package candidates for OpenVPN. Rocky/Alma/RHEL/CentOS Stream 9 do
not treat EPEL-only packages as official DNF packages. For the complete base runtime
surface, the RHEL-family chain uses a single composite `external_repo_exact` candidate
that represents the official target repositories, exact EPEL 9 prerequisite, the
`epel-release` bootstrap package, OpenVPN from EPEL and the remaining official package
set. The resolver records separate provider observations for repository support,
repository package availability, EPEL-exposed OpenVPN and every declared package. A
partial subset can never satisfy `cap_base_runtime_commands`; unknown EPEL availability
blocks the chain, and unavailable EPEL or missing official packages exhausts to
`no_safe_route`.

Provider observations are preserved per operation. Multi-package methods record a
`package_exists` observation for each package; external repos keep both repository target
evidence, repository package evidence and package evidence; artifacts keep asset
existence and integrity metadata for the selected architecture. Provider type and whether
the evidence is authoritative live in both the CLI wrapper and the domain report/decision.
Each decision also exposes `all_availability_observations`, preserving every provider
consultation across rejected candidates, selected candidates, `availability_unknown` and
`no_safe_route`.

The provider-backed matrix is L1, not real ecosystem evidence. The focused real L2 harness
is separate and requires disposable container infrastructure supplied explicitly through
`WATCHDOGVPN_REAL_L2=1`; without such infrastructure it reports a skipped limitation. L2
checks create uniquely named throwaway Docker/Podman containers and remove them in
`finally` through an observable cleanup result. Package-manager detection runs inside the
container shell as `sh -lc 'command -v -- <controlled-manager>'`; the manager name comes
only from the harness's internal table. Rocky/EPEL queries use an exact architecture URL
(`.../Everything/x86_64/` for the current harness target), never shell-expanded
`$basearch`.

Every runtime-level process call (pull, create, start, exec) first records a
process-level `runtime_status` (`executed`, `timeout`, or `runtime_error` when the
container runtime binary itself could not even be invoked) before any content parser
runs; a content parser never overrides an already-known timeout or infrastructure
error. Only when `runtime_status=executed` is the returncode/stdout/stderr content
interpreted into the phase's final `status`, which is preserved alongside a
`semantic_status` that stays `None` whenever the process never reached completion.
The image `pull` phase has its own dedicated taxonomy —
`available`/`image_not_found`/`timeout`/`runtime_error`/`authentication_error`/
`registry_error`/`unknown` — derived from returncode, stdout, stderr and the raised
exception type, not from a generic non-zero-returncode assumption. Only a
demonstrated `image_not_found` pull result may excuse the `optional_image` Ubuntu
26.04 target; every other pull outcome (including `timeout`, `runtime_error`,
`registry_error`, `authentication_error` and `unknown`) still fails the real L2 gate
like any other target. Classification precedence is deliberate:
`runtime_error` (container-runtime infrastructure markers), `authentication_error`
and `registry_error` are checked **before** `image_not_found`, so a message that
happens to combine an absence phrase with an auth/network marker (real registries
routinely do this — e.g. Docker's "repository does not exist or may require
'docker login'") is never misclassified as a plain missing image. `image_not_found`
itself only accepts unambiguous evidence: the literal `manifest unknown` /
`not found: manifest` phrasing, or the exact requested image identifier appearing
together with both `manifest` and `not found` in the same message; generic phrases
such as "manifest for", "repository does not exist" or "no such image" are
deliberately not sufficient proof on their own. The package-manager lookup
distinguishes a normal absent binary (`manager_unavailable`) from a real
container-runtime infrastructure failure (`runtime_error`, detected from stderr
markers such as "no such container" or "is not running") from a timeout from an
inconclusive result (`unknown`). POSIX only guarantees a non-zero exit status for
`command -v` when the target is not found; it does not fix the exact value. `1` and
`127`, with both stdout and stderr genuinely empty, are the clean, no-output
results admitted here as a demonstrated absence for the shell implementations this
contract covers (dash, bash and similar POSIX-compatible shells) — not "the exact
POSIX code". Return code `126` (POSIX: "found but not executable") and any `1`/`127`
result carrying non-empty output are `unknown`, never assumed to mean "absent". A
superior alternative would normalize the result inside the shell command itself via
a controlled sentinel; that is not required while admitting `{1, 127}` with empty
streams resolves the current contract unambiguously. The package
query for APT requires the full positive contract — executed, exit code zero, and
a real `Candidate:` line — before ever reporting `available`; a non-zero return
code can never resolve to `available` even when stdout happens to contain
text that looks like a valid candidate line, and such a query correctly prevents
the whole package-query aggregate from reporting `available`. `os-release`
identity parsing is skipped entirely (never attempted against stdout) unless the
read phase both executed and returned exit code zero.

The evidence object records target, image, runtime, container name, pull, create,
start, os-release, package-manager, metadata-refresh, per-package query, cleanup,
`probe_aggregate`, `overall_status` and limitations. Each phase stores bounded
stdout/stderr, return code, `runtime_status`, `semantic_status`, `status` and reason.
Cleanup is tracked independently of the probe result: `cleanup.status` is `cleaned` on
success, `not_needed` when the runtime reports no container existed to remove (e.g.
after a pull failure, so an unnecessary cleanup attempt is never conflated with a real
residual risk), or a failure status (`timeout`/`runtime_error`/`unknown`) with
`residual_possible=true` otherwise. `overall_status` folds `probe_aggregate` and
`cleanup` together without ever hiding or replacing the primary probe result: a
successful probe with successful cleanup is `available`; a successful probe whose
cleanup failed is `cleanup_failed`; any other probe result whose cleanup failed is
`<probe_aggregate>_with_cleanup_failure` (e.g. `timeout_with_cleanup_failure`),
preserving the original probe status rather than replacing it. A refresh failure
yields `unknown`/`timeout`/`runtime_error` and cannot continue as available; APT
requires candidate or package metadata; aggregate availability is `available` only
when every package has evidence. With `WATCHDOGVPN_REAL_L2=1`, a required target must
reach `overall_status=available` with `cleanup.status` in
(`cleaned`, `not_needed`) and `residual_possible=false`; ending in `unknown`,
`timeout`, `runtime_error`, `malformed_response` or `cleanup_failed` fails the L2
matrix. Ubuntu 26.04 image absence, demonstrated specifically as a pull
`image_not_found` result, is the only optional limitation. These checks must never be
presented as kernel, TUN, firewall, protocol or physical certification evidence.

`compat/__init__.py` exports `ArtifactAvailabilityObservation` and `SelectedArtifact`
alongside the rest of the dependency-resolution public surface, so a future
availability provider can implement the structured artifact-identity contract (§7)
through the package's published internal API instead of importing
`compat.dependency_resolution` directly.

## Transactional Provisioning Realization (Task 23.7.5.6a)

Task 23.7.5.6a adds the generic transactional-provisioning infrastructure that will
execute a resolver's `execution_ready=true` decision, without migrating any legacy
consumer, without registering a production executor, and without changing any public
support-classification claim. The implementation lives in the `compat/provisioning`
package (`model.py`, `digest.py`, `journal.py`, `lock.py`, `paths.py`, `executors.py`,
`engine.py`); the internal fixture/VM tool lives at `tools/compat_provision.py`; L1
tests live in `tests/test_compat_transactional_provisioning.py`; a standalone,
non-auto-discovered real-process/real-`SIGKILL` validation harness lives at
`tests/vm/phase23_7_5_6a_transactional_provisioning_validation.py` (deliberately not
named `test_*.py` so the routine `python3 -m unittest discover tests` gate never
executes a hard process kill automatically).

### Domain model and state machines

`compat/provisioning/model.py` defines immutable/validated types
(`ProvisioningPlan`, `ProvisioningStep`, `ExecutionResult`, `VerificationResult`,
`RollbackResult`, `RecoveryDecision`, `OwnershipCandidate`, `OwnershipRecord`,
`ProvenanceRecord`, `UninstallPlan`) plus two explicit, table-driven state machines:
`TransactionState` (`planned` → `authorized` → `applying` → `verifying` → `committed`
→ `uninstall_planned` → `uninstalling` → `uninstalled`/`uninstall_failed`, with
`rolling_back` → `rolled_back` → `preparation_failed` or `rollback_failed`, and
`recovery_required` → `recovering` as the ambiguity-resolution path) and `StepState`
(`planned` → `applying` → `applied`/`apply_failed` → `verifying` →
`verified`/`verify_failed` → `undoing` → `undone`/`undo_failed`). Every transition is
validated against an explicit allow-list; an impossible jump (`planned`→`committed`,
`committed`→`applying`, `rolled_back`→`verifying`, `uninstalled`→`applying`, or any
step-level equivalent) raises `InvalidTransitionError` before any journal write, never
silently changing state.

### Plan determinism

`compat/provisioning/digest.py` computes a stable SHA-256 `plan_digest` over a
canonical, sorted-key JSON representation of the plan (capability/dependency id,
resolved target, architecture, support classification, selected method id/kind,
selected asset, postcondition, executor id/version, and the ordered step list). Apply,
recovery, rollback and uninstall all recompute this digest and compare it against the
journal's stored value before proceeding; a mismatch (a manifest/method change since
the transaction started) blocks with `recovery_required` and never reinterprets an
in-flight transaction under a changed plan.

### Trusted executors, never manifest-driven

`compat/provisioning/executors.py` defines `TrustedExecutorRegistry`, keyed by
`(method_kind, method_id)` with an `executor_version` cross-check, mapping to a
concrete, code-registered `Executor` object. There is no dynamic import, no
manifest-supplied module/class name, no `eval`/`exec`, and no shell invocation
anywhere in the resolution path (`tests/test_compat_transactional_provisioning.py`
scans the package source for exactly these tokens). A manifest `implementation_status
= implemented` entry is never sufficient on its own: `build_plan()` additionally
requires `ResolutionDecision.execution_ready == true`, an exact
`(method_kind, method_id)` registry match, the registered executor's own
`supported_method_kind` to agree with the decision's `selected_method_kind`, and a
concrete resolved target/architecture; anything short of all four is
`recipe_not_implemented` (unregistered/kind-mismatched) or `out_of_contract`
(`execution_ready=false`), with zero mutation either way.

No production executor is registered in this task -- no AmneziaWG, no source build,
no real package manager, no real repository, no real artifact download. The only
registered executor is the lab-only `CanaryExecutor`, confined to an injected sandbox
root, which creates two small synthetic files (a marker and a companion) and verifies
their existence, exact content hash, permissions (`0600`) and absence of a symlink.
It is registered only by test and VM-harness code, never by a normal-user code path.

### Path protection

`compat/provisioning/paths.py` requires an absolute path, rejects `..` components,
the filesystem root, and empty paths, checks every ancestor path component for an
unexpected symlink (rejecting both an intermediate and a final symlink), supports an
explicit allow-list of roots plus a forbidden-roots list (`$HOME`, `/etc`, `/usr`,
`/bin`, `/sbin`, `/lib`, `/lib64` during the canary executor), and creates files with
`O_CREAT | O_EXCL | O_NOFOLLOW` so a concurrent or pre-existing target (including a
dangling symlink) is refused rather than silently replaced. Removal
(`remove_file_if_owned`) refuses a symlink or non-regular file outright and verifies
the recorded SHA-256 before deleting anything, raising a controlled ownership-drift
error otherwise.

### Lock, journal and durable storage

`compat/provisioning/lock.py` is a dedicated machine-wide `fcntl.flock` lock, distinct
from `config.persistence`'s restore-transaction lock/journal (that one triggers its
own backup/restore recovery side effects on any `file_lock` use under the shared
config directory, which the provisioner must never couple into). Acquisition is
non-blocking with a bounded retry timeout; a held lock raises a controlled
`ProvisionerLockHeldError` carrying the holder's PID/transaction id (informational
only -- the kernel `flock`, not this metadata, is the actual exclusion mechanism); the
lock file itself is created `0600`. `apply`, `rollback`, `recovery` and `uninstall` all
take this same lock; `dry-run` never touches it (and therefore can never block).

`compat/provisioning/journal.py` defines its own schema (`schema_version`,
`transaction_id`, `operation`, `state`, timestamps, `plan_digest`, capability/
dependency/target/architecture/`support_classification`, selected method, executor,
per-step records, ownership candidates, provenance, failure, recovery), reusing only
`config.persistence`'s atomic-write/`fsync`/parent-directory-`fsync` primitives -- not
the restore-transaction journal itself. Every step and transaction write goes through
this same atomic-write path, so a journal file is 0600 and a torn write is impossible
(temp file + `fsync` + `os.replace` + parent-directory `fsync`). Write-ahead is
literal: `step.state = applying` is written durably *before* the executor's action
runs; the result (`undo_record`) and `step.state = applied` are written immediately
after; `step.state = verified` (with evidence) is written after verification. A
corrupt journal, an unknown `schema_version`, or a structurally invalid document is
converted to `JournalError` and surfaces as a blocking `recovery_required` decision --
the file is never deleted to "unstick" the provisioner. Sensitive-looking journal
content (keys named like `password`/`token`/`secret`/`credential`, or a URL with
embedded credentials) is redacted before being written.

### Dry-run and explicit authorization

`prepare(decision, env, apply=False)` builds the exact same plan `apply=True` would,
describes it (steps, targets, intents, planned verification, planned rollback,
`plan_digest`) and returns without ever acquiring the lock, writing a journal, creating
a lock file, or touching the sandbox -- verified by a before/after full-tree filesystem
snapshot comparison in L1. `apply=True` is the only authorization signal; nothing
(including a profile import) can set it implicitly.

### Idempotency and ownership

Before starting a new transaction, `check_idempotency()` inspects every planned step's
real-world state: nothing present → proceed; everything present and matching, with a
durable `OwnershipRecord` from the same executor/version → `already_provisioned` (no
duplication); everything present and matching, with **no** ownership record →
`already_present` (pre-existing, no write, no uninstall right ever granted for it);
anything partially present, mismatched, or a symlink → `ownership_conflict` /
`preparation_failed` with evidence, never a silent overwrite. `OwnershipRecord`s (one
list per `capability_id`, at `provisioning/ownership/<capability_id>.json`, `0600`)
are written only once a transaction reaches `committed`, and record artifact type,
resource identity, `pre_existing`, method/executor id and version, integrity hash and
the committing transaction id.

### Rollback, interruption and recovery

On any apply/verify failure, the transaction moves to `rolling_back` and every already
`applied`/`verified` step is undone in reverse sequence order using only its recorded,
structured `undo_record` -- never a stored command string. A partial rollback failure
does not stop the loop early: every undoable step is still attempted, and every
failure is recorded as an explicit residual; `rolled_back` (residuals empty) leads to
`preparation_failed`, while any residual leads to `rollback_failed` with the journal
preserved for manual review. `SIGINT`/`SIGTERM` during apply are caught by an
in-process guard that stops before the next step and drives the same rollback path
(`error_kind=interrupted`); `SIGKILL` cannot be caught by definition and is instead
proven safe through recovery, including in the standalone VM harness, which sends a
real, uncatchable `SIGKILL` to a child process at each of the three write-ahead
boundaries (before apply, after apply before verify, after verify before commit) and
confirms the next `recover_pending()` call -- in a completely separate process --
resumes and commits correctly every time. Recovery itself, run at the start of any new
mutating operation, scans every non-terminal transaction, revalidates its
`plan_digest`, and for each step in `applying`/`verifying`/`applied` state inspects the
real target (never trusting the stale journal alone): a demonstrated match resumes
forward, a demonstrated absence retries the (idempotent, `O_EXCL`-guarded) action from
scratch, and any divergence or unexpected symlink is `recovery_required` with **no**
further automatic mutation. A rollback/uninstall attempt that already failed once is
never silently retried; it is surfaced for manual review instead.

### Uninstall

Uninstall is its own transaction (`uninstall_planned` → `uninstalling` →
`uninstalled`/`uninstall_failed`, its own lock acquisition, its own recovery pass) that
can only ever target resources with a durable, `product_owned=true` `OwnershipRecord`;
a capability with no such record (including every pre-existing one, since
`already_present` never creates one) returns a controlled `nothing_to_uninstall` with
zero filesystem interaction, structurally guaranteeing pre-existing components are
never touched. Each removal step re-verifies the resource's SHA-256 against the
recorded integrity value immediately before deleting it; a changed resource is
`ownership_drift`, the step fails, the resource is left untouched, and the transaction
reports `uninstall_failed` with explicit residuals. A second uninstall of an
already-uninstalled (or never-owned) capability is a safe, idempotent
`nothing_to_uninstall`, never an error that corrupts state. `--force` is out of scope
for this task.

### Security and correctness hardening (post-6a correction round)

A follow-up review of the initial 6a implementation found several real gaps between
the "quick" transactional infrastructure and what a genuinely hostile or crash-prone
environment requires. All of the following were closed in the same
`compat/provisioning` package, on top of the already-committed 6a implementation,
without starting 23.7.5.6b:

- **Identifier validation** (`paths.py:validate_identifier`): `transaction_id`,
  `capability_id` and `dependency_id` are validated (non-empty, bounded length,
  `[A-Za-z0-9_-]` only, no `/`, `\`, NUL, `.`/`..`) at every point they are used to
  build a filename -- `journal.py`'s `transaction_path`/`history_path`/`ownership_path`,
  journal/ownership deserialization, and `CanaryExecutor.plan_steps`. A persistent path
  is never built directly from an unvalidated identifier.
- **Strict ownership deserialization**: `OwnershipRecord`/`OwnershipCandidate` JSON is
  validated field-by-field (exact booleans, absolute `resource_identity` without `..`,
  non-negative `uid`/`gid`, a valid file `mode`, a lowercase sha256 `integrity` when
  present) and rejects any unknown field in either the record or its `candidate`
  object -- there is no admitted-but-unvalidated schema surface.
- **Path policy at every choke point**: `validate_target_path` now gates
  `verify_step`, `undo_step`, `inspect_step`, `verify_postcondition` (all in
  `executors.py`) and every uninstall step (`engine._run_uninstall_loop`), not just
  `apply_step`. A forged out-of-sandbox target anywhere in a journal/ownership record
  is rejected as `path_policy_violation` before any read/write/delete, never just at
  the original apply.
- **Private storage** (`compat/provisioning/storage.py`, new module): journals,
  ownership records and the lock file are written through a dedicated
  `atomic_write_private`/`ensure_private_dir` primitive -- directories `0700`, files
  `0600` -- and never through `config.persistence`'s shared-group (`0660`/`02770`
  setgid) primitive, regardless of where `state_root` happens to live (including under
  `/var/lib/watchdogvpn`).
- **Durability**: `create_file_exclusive` and `remove_file_if_owned` (`paths.py`) now
  fsync the parent directory after the create/unlink, reusing the same
  `fsync_parent_directory` primitive as journal writes; a directory-fsync failure
  raises `DurabilityError` and is never absorbed into a false "applied"/"verified"/
  "undone" outcome.
- **Full ownership/verification metadata**: `OwnershipCandidate` now captures
  `uid`/`gid`/`mode` at commit time (`engine._finalize_provenance`), and
  `verify_step`/`verify_postcondition` additionally check `st_nlink == 1` (rejecting a
  hard-linked target) and recheck content hash, not just existence.
- **`selected_asset` persistence**: the prepare journal now stores `plan.selected_asset`
  (already part of `plan_digest`); recovery reconstructs the plan with that exact
  value, so a real resolver decision with a concrete asset recovers correctly, and a
  tampered `selected_asset` is caught as a `plan_digest_mismatch`.
- **Ownership bound to a committed transaction** (`engine.validate_ownership_authority`):
  before any ownership record is trusted as uninstall/idempotency authority, its
  `created_by_transaction` must load, be `committed`, be a `prepare` operation for the
  same `capability_id`, and its provenance must match the *entire* current ownership
  set exactly (resource identity, integrity, artifact type, executor id/version,
  method id) -- an orphaned, partial or divergent record, or one bound to a
  non-committed journal, invalidates the whole set. This closes the window where a
  crash between `_finalize_provenance` (ownership written) and the journal's own
  transition to `committed` could otherwise be read as a valid uninstall right;
  `uninstall()` refuses with a dedicated `ownership_invalid` status and zero mutation
  in that case.
- **Exact idempotency**: `already_provisioned` now requires the *same* source
  transaction, executor id/version, method id, exact resource-path set (no
  more/fewer), matching hash, matching `uid`/`gid`/`mode`, and a freshly re-verified
  postcondition -- a partial match (e.g. one of two owned resources, or a mode drift
  with unchanged content) is `ownership_conflict`, never a silent "close enough".
- **Recovery under mandatory lock**: `recover_pending()` is now the public entry point
  that acquires the provisioner lock itself (`finally`-released); the original
  lock-assuming logic moved to an internal `_recover_pending_locked()`, which
  `prepare()`/`uninstall()` call directly since they already hold the lock. A
  concurrent external `recover_pending()` call now correctly raises
  `ProvisionerLockHeldError` instead of racing another mutator.
- **Uninstall plan digest + full recovery state machine**: the uninstall journal's
  plan is now reverified (`engine._uninstall_source_matches`) -- both against the
  current ownership file's content and against a committed source -- before the very
  first unlink and again on every recovery pass; a divergence blocks with no deletion.
  `_run_uninstall_loop` (`engine.py`) now handles each boundary explicitly: `planned`
  writes ahead to `applying` before the first unlink attempt; resuming `applying`
  inspects the real target first (absent → already done, present-and-matching → retry,
  symlink or hash divergence → fail, never delete); `applied` never re-executes an
  unlink, only advancing to `verifying`; `verifying` checks *only* absence. This also
  surfaced and fixed a real latent bug: recovery of any pending uninstall previously
  crashed with `ExecutorNotRegisteredError` (it tried to resolve an executor for the
  uninstall journal's synthetic `uninstall`/`uninstall` method before ever checking
  `journal.operation`), which meant an interrupted uninstall could never actually be
  recovered through `recover_pending()` at all.
- **Dry-run truly read-only**: `tools/compat_provision.py`'s `_build_env()` now takes
  an explicit `mutating` flag and only creates the sandbox directory for `prepare
  --apply`/`uninstall --apply`/`recover`; `plan`, `prepare`/`uninstall` without
  `--apply`, and `status` create neither the sandbox nor the provisioning state root.

### Second security/correctness hardening round

A second, deeper maintainer review of the first hardening round found further real
gaps, closed in the same `compat/provisioning` package on top of the already-committed
first round, again without starting 23.7.5.6b:

1. **Ownership revocation phase**: uninstall now has an explicit `REVOKING_OWNERSHIP`
   transaction state between `UNINSTALLING` and `UNINSTALLED`. The uninstall journal
   persists an exact, immutable snapshot of the ownership set that authorized the plan
   (`TransactionJournal.owned_snapshot`), which participates in the uninstall
   `plan_digest` (`digest.canonical_ownership_record_mapping`) so any tampering with
   that snapshot at rest is detected. Recovery reconstructs the uninstall plan from this
   journal-owned snapshot -- never the live ownership file, which may already be gone
   by the time recovery runs. Once all resources are confirmed removed,
   `engine._revoke_ownership_and_verify()` durably deletes the ownership file and
   re-verifies its absence (idempotent, safely retriable) before the transaction may
   ever reach `UNINSTALLED`. `engine.validate_ownership_authority()` additionally
   rejects any ownership record still citing a source transaction whose OWN uninstall
   already progressed past resource removal (`_capability_has_completed_uninstall`) --
   stale bookkeeping left behind by a crash between "resources gone" and "ownership
   revoked" is never trusted as authority again, even if a since-recreated file happens
   to match the recorded hash. The maintainer's exact mandatory security scenario
   (install, interrupt uninstall between removal and revocation, manually recreate the
   removed file with the identical hash, uninstall again) is covered by a dedicated
   test: the manual file survives untouched and the result is `ownership_invalid`.
2. **Symlink/uid-safe private state and lock**: `storage.ensure_private_dir()` no
   longer trusts `Path.is_dir()` (which follows symlinks); every directory component is
   opened with `O_NOFOLLOW` and verified via `fstat` (real directory, owned by our own
   uid, `0700` -- tightened via `fchmod` on the already-verified descriptor, never a
   separate lstat-then-chmod race window) before ever being written into. The lock file
   is opened with `O_RDWR|O_CREAT|O_NOFOLLOW`, and `fstat`-verified (regular file,
   `st_nlink == 1`, owned by our uid) BEFORE any `fchmod` or content write -- a symlink
   (`ELOOP`), a directory (`EISDIR`) or a hard-linked victim file are all rejected
   untouched, never chmod'd or overwritten. A newly created directory's parent is
   `fsync`'d.
3. **`UNDOING` as an explicit recovery boundary**: this closed a real, previously
   undetected bug -- `_run_rollback()`'s membership check against
   `UNDOABLE_STEP_STATES` deliberately excludes `UNDOING` (it is not itself undoable,
   it is *in progress*), so a step left in `UNDOING` by a prior crash was silently
   skipped by the loop, letting `_run_rollback` report `rollback_ok=True` while that
   step's real resource was never confirmed undone. `_run_rollback` now inspects a
   resumed `UNDOING` step's real state first: absent means the undo already completed
   and only the `UNDONE` write never landed; present-and-matching means retry; a
   symlink, a content divergence, or an inspection error all become a durable
   `UNDO_FAILED` (residual), never a silent skip.
4. **`DurabilityError` after a visible effect**: a directory-fsync failure right after
   a genuine create is no longer folded into a generic `apply_failed` (which would
   attempt an automatic rollback of a step not even in `UNDOABLE_STEP_STATES`,
   potentially leaking the file with zero residuals reported). It now drives the
   transaction straight to `RECOVERY_REQUIRED` with the step deliberately left exactly
   where its write-ahead journal entry already placed it (`APPLYING`), so the existing
   `APPLYING`-resume recovery machinery -- unchanged -- correctly resolves it on the
   next pass (re-verify and finish committing, since the file is really there). A new
   `PrepareStatus.RECOVERY_REQUIRED` result never reports a clean `PREPARATION_FAILED`,
   always has non-empty `residuals`, and a later real (unmocked) recovery pass
   demonstrably completes to `COMMITTED`.
5. **Never confusing errors with absence**: every place that decided "does this
   resource exist" now distinguishes a genuine `FileNotFoundError` from any other
   `OSError` (permission denied, stale handle, I/O error). `CanaryExecutor.inspect_step`
   reports a non-`FileNotFoundError` as an explicit `inspect_error` (`exists: None`),
   never `exists: False`; `_run_uninstall_loop`'s own inspection and its final
   "verify only absence" check use a single explicit `os.lstat` catching only
   `FileNotFoundError`, never `Path.exists()`/`Path.is_symlink()` (which silently
   swallow any `OSError` into `False`). No injected `PermissionError`, `OSError(EIO)` or
   `OSError(ESTALE)` can result in a false `VERIFIED`/`UNINSTALLED`.
6. **Idempotency tied to the full plan**: `already_provisioned` now additionally loads
   the source transaction's own journal and requires its `plan_digest` to match
   `compute_plan_digest(plan)` for the CURRENT decision exactly -- since `plan_digest`
   already encodes capability/dependency id, resolved target, architecture, support
   classification, selected method, executor and selected asset together with the step
   list, a change in any of those fields since commit now correctly falls through to
   `ownership_conflict` instead of a stale `already_provisioned`.
7. **Full metadata and drift detection**: `_finalize_provenance()` now re-validates
   each resource's path and re-inspects its real identity immediately before commit;
   a stat failure raises instead of ever recording fabricated `None` metadata, driving
   the transaction to `RECOVERY_REQUIRED` rather than a false `COMMITTED`. Uninstall now
   compares each resource's current uid/gid/mode/hard-link-count/canonical path against
   its `OwnershipRecord` (`engine._detect_ownership_drift`) immediately before the
   unlink; any drift (a `chmod`, a `chown`, an added hard link, or a re-pointed path)
   refuses the removal with no unlink attempted (content-hash drift was already
   detected by the pre-existing `remove_file_if_owned` check).
8. **Mandatory canary confinement policy**: `paths.validate_lab_root()` is a new,
   independent confinement check (deliberately not `validate_target_path`, which
   requires its allowed root to already exist) applied to the `--sandbox`/
   `--state-root` CLI arguments in `tools/compat_provision.py` before either argument
   is ever touched: rejects a relative path, `..`, the filesystem root, every reserved
   system root (`/etc`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/boot`, `/dev`,
   `/proc`, `/sys`), the real product's own state directory
   (`/var/lib/watchdogvpn`) or anything under it, `$HOME` itself (a private
   subdirectory *under* `$HOME` remains allowed, since one test VM's `tmpfiles.d`
   empties `/tmp` on every boot), and a symlink at the leaf or any existing ancestor
   component -- checked with real `os.open`/`is_symlink()` before ever calling
   `Path.resolve()` (which would otherwise silently follow a symlink). Both CLI
   arguments are now validated before either is ever created, closing a real ordering
   bug caught by the new tests themselves (the original code created the sandbox
   before validating `--state-root`).

L1 (`tests/test_compat_transactional_provisioning.py`) covers the maintainer's full
35-item checklist plus offline/network-declaration and executor-exception-containment
cases, the first hardening round (identifier validation, strict ownership
deserialization, path-policy choke points, private storage permissions,
durability-failure handling, ownership metadata capture, `selected_asset`
persistence/tampering, ownership-authority binding including the pre-commit-publication
window, exact idempotency, lock-protected recovery, and the uninstall digest/
state-machine boundaries including the discovered `ExecutorNotRegisteredError` recovery
bug), and now the second hardening round above (ownership revocation including the
mandatory security scenario, symlink/uid-safe state and lock, the `UNDOING` recovery
boundary including the newly discovered rollback-skip bug, `DurabilityError` after a
visible effect, errors never confused with absence, idempotency tied to the full plan,
full metadata/drift detection, and canary confinement including the newly discovered
validation-ordering bug) -- 118 tests total in this module. The standalone harness
(`tests/vm/phase23_7_5_6a_transactional_provisioning_validation.py`) reproduces, with
real separate OS processes (including two genuine `SIGKILL`s), lock exclusion between
processes, apply+verify, idempotent re-apply, rollback via an injected failure, both
`SIGKILL` checkpoints plus recovery, uninstall, pre-existing preservation, symlink
rejection and a final residual scan -- confined entirely to an injected sandbox and
state root, touching no package manager, repository, network, DNS, firewall, service
or protocol.

It also has a dedicated `prepare-reboot-checkpoint` / `recover-after-reboot` pair
(plus a `rolling_back_pending` checkpoint alongside the two `SIGKILL` checkpoints) for
exercising recovery and rollback across a literal host reboot. This was executed for
real on a disposable VM (`wdvpn-linuxmint-23-6-7`, snapshotted before and restored
after): `prepare-reboot-checkpoint --checkpoint after_apply_before_verify` and
`--checkpoint rolling_back_pending` each self-killed a real worker process with
`SIGKILL`, the host was rebooted for real (`/proc/sys/kernel/random/boot_id` confirmed
different before/after), and `recover-after-reboot` then confirmed: the journal
survived the reboot with its `plan_digest` intact, the `after_apply_before_verify`
transaction resumed and committed (both canary files present, an `OwnershipRecord`
written), and the `rolling_back_pending` transaction resumed its rollback and reached
`preparation_failed` with the canary file removed and no residuals. Package list,
repository sources, running-service set and network configuration hashes/diffs were
identical before and after across both scenarios, and `/var/lib/watchdogvpn` (the real
product's state directory) was untouched throughout -- confirming the sandbox/state-root
isolation held even under a real reboot on a machine that also runs the real product.

A third pair, `prepare-uninstall-reboot-checkpoint` / `recover-uninstall-after-reboot`,
was added for the security/correctness hardening round above: it commits a real prepare
transaction, then runs a real subprocess that performs the REAL unlink of the owned
marker resource and self-kills with `SIGKILL` before the journal ever records that step
as `APPLIED` -- the exact "uninstall interrupted after unlink and before journal write"
boundary. All three reboot scenarios were re-executed for real on `wdvpn-linuxmint-23-6-7`
against the hardened commit: `after_apply_before_verify` resumed and committed;
`rolling_back_pending` resumed its rollback to `preparation_failed` with no residuals;
and the new uninstall scenario resumed (`recovery_decision.action == "resume"`), reached
`uninstalled`, and deleted the ownership record, with the sandbox left empty -- proving
the `_recover_one`/`_recover_uninstall` fix (see the hardening section above) actually
recovers a real interrupted uninstall across a genuine reboot, not just in a unit test.
This run also surfaced a VM configuration fact worth recording: this host's
`/usr/lib/tmpfiles.d/tmp.conf` uses `D /tmp ... 30d`, which empties `/tmp` on every boot
(not just after 30 days of inactivity), so the harness's sandbox/state-root must live
under a persistent path (e.g. under `$HOME`) for any reboot-crossing scenario on this
particular VM -- unrelated to the provisioning engine itself, but necessary to know when
re-running this validation. `boot_id` was confirmed different before/after; package
list, repository sources, running-service set, and `/var/lib/watchdogvpn` content hashes
were identical before and after (network diff limited to the DHCP lease timer, as
before); real filesystem permissions under the persistent state root were confirmed
`0700` for directories and `0600` for the lock/journal/ownership files.

For the second hardening round, `worker`'s `--kill-after` gained two further
checkpoints exercising the `UNDOING` recovery boundary for real:
`undoing_before_unlink` (step 0 applied+verified, step 1 forced to fail, the
transaction moved to `rolling_back`, step 0 durably written to `UNDOING`, then killed
before the real unlink of its resource is even attempted) and
`undoing_after_unlink_before_undone` (same, but the real unlink genuinely happens
first, then the kill lands before the durable `UNDONE` write). `prepare-uninstall-
reboot-checkpoint`/`recover-uninstall-after-reboot` gained a mandatory `--checkpoint`
flag with three values -- `after_unlink_before_applied` (the original scenario),
`after_verify_before_revoke` (both resources genuinely removed and verified, the
journal durably moved to `revoking_ownership`, then killed before ownership is ever
actually revoked) and `after_revoke_before_uninstalled` (same, but ownership genuinely
revoked for real, then killed before the durable `uninstalled` write) -- each using its
own dedicated `capability_id` so multiple checkpoints can be prepared independently
before a single shared reboot, exactly as the maintainer's correction allowed.

### Second hardening round: real VM re-validation

Executed for real on `wdvpn-linuxmint-23-6-7` against commit `be365c1` (the second
hardening round plus a cross-Python-version test fix -- see below). The pre-existing
clean snapshot (`pre-23.7.5.6a-reboot-validation`) was restored first, L1 was re-run on
the VM (Python 3.12.3), a NEW dedicated snapshot for this round
(`pre-23.7.5.6a-round2-reboot-validation`) was then taken, and all six of the
maintainer's required scenarios were prepared independently (each with its own
capability_id/journal) before a single shared real reboot:

1. `after_apply_before_verify` (apply) -- resumed and committed; both canary files
   present, `OwnershipRecord` written.
2. `undoing_before_unlink` (rollback, crash before the real unlink of step 0's
   resource even starts) -- resumed rollback, reached `preparation_failed`, step 0
   `UNDONE`, zero residuals, sandbox empty.
3. `undoing_after_unlink_before_undone` (rollback, the real unlink already happened,
   crash before the durable `UNDONE` write) -- resumed rollback, reached
   `preparation_failed`, step 0 `UNDONE` without any repeated unlink attempt, sandbox
   empty.
4. `after_unlink_before_applied` (uninstall, the real unlink already happened, crash
   before the journal records `APPLIED`) -- resumed, reached `uninstalled`, ownership
   record deleted, sandbox empty.
5. `after_verify_before_revoke` (uninstall, both resources genuinely removed and
   verified, crash before ownership is ever actually revoked) -- resumed, reached
   `uninstalled`, ownership record deleted, sandbox empty.
6. `after_revoke_before_uninstalled` (uninstall, ownership genuinely revoked for real,
   crash before the durable `uninstalled` write) -- resumed, reached `uninstalled`,
   ownership record deleted, sandbox empty.

`boot_id` (`85471f15-...` before, `f5fb3176-...` after) confirmed one genuine `sudo
reboot`, not a process restart. Package list, repository sources, running-service set
and `/var/lib/watchdogvpn` content hashes were identical before and after (the only
network diff was the expected DHCP lease timer); real filesystem permissions on the
persistent state root (`$HOME/wdvpn-6a-round2-hardening-vm/*/state`) were confirmed
`0700` for `transactions`/`ownership` and the state root itself, `0600` for
`provisioner.lock` and every journal/ownership file. A residual scan across all six
scenario directories found only the exact expected sandbox/state-root contents for
each outcome (populated sandbox for the committed apply scenario, empty sandboxes for
every rollback/uninstall scenario) -- no stray files, no leaked ownership records, no
package/repository/service/network/protocol state anywhere. The VM was powered off and
the round's snapshot restored and confirmed as current (`VBoxManage snapshot list`
with `*`) afterward; neither snapshot was deleted. Private evidence (`0700`/`0600`) at
`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-7-5-6a-round2-reboot-validation`.

This VM run also caught a real, environment-dependent test bug (fixed in commit
`be365c1`, on top of `53c6dd0`): three of the "errors never confused with absence" L1
tests injected a `PermissionError`/`OSError` by mocking `Path.lstat`/`os.lstat`
unconditionally (or by call-count) for a target path that `validate_target_path`'s own
ancestor symlink-walk also touches for the exact same path. `pathlib.Path.is_symlink()`'s
internal error-swallowing behavior for a raised `OSError` differs between Python 3.12.3
(the VM) and 3.14 (the maintainer's host) -- 3.12 propagates it, 3.14 silently returns
`False` -- so the same test produced a clean `inspect_error`/`inspection_error` result on
one Python version and an uncaught exception or a mislabeled `ownership_drift` (caused by
the mock also firing inside the point-7 drift-detection stat call) on the other. The
fix bypasses `validate_target_path` in those specific tests (mocking it as a pass-through)
so the injected fault applies unambiguously to only the single call each test actually
targets, independent of any pathlib version quirk. This was a test-only fragility, not an
engine defect -- the underlying `inspect_step`/`_run_uninstall_loop` behavior was already
correct on both platforms once the tests isolated the right call.

### Out of scope (unchanged in this task)

No production executor was registered. `lib/amneziawg.sh`,
`diagnostics/amneziawg_guidance.py`, `distros/*.sh`, `lib/packages.sh`,
`lib/singbox.sh`, `lib/cloak.sh`, `install.sh`, `update.sh`, `uninstall.sh`,
`doctor.sh`, `README.md`, `ROADMAP.md` and `.github/workflows/*` were not touched. No
package was installed, no repository was added, nothing was downloaded or built, and
no public support-classification claim changed. `profile add` was not modified and
does not start preparation. `cli/main.py` was not modified in this task; the minimal
`watchdog runtime plan/prepare/recover/uninstall/status` CLI surface described in the
task authorization remains available for a future task to add without needing further
engine changes.
