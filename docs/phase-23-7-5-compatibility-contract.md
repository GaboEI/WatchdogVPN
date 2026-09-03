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
- `external_repo_exact` — provider, repository identity, signing-key provenance, exact
  `compatible_targets`, package names, architectures, evidence and postcondition.
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
security fields (including `external_repo_exact` candidates without a declared
signing-key provenance), target identity/scope mismatches, duplicate global candidate IDs,
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

Every `external_repo_exact` candidate must carry non-generic
`signing_key_provenance`. Valid evidence is either an explicit package-signing key
identifier (`keyid` or `fingerprint`) together with a verifiable source such as an
official project security page or keyserver, or a bootstrap trust statement naming the
package installed from already-trusted base repositories and stating that it carries the
external repository GPG key and repository configuration. EPEL 9 satisfies both forms:
the `epel-release` package is installed from the target system's already-trusted base
repositories and carries the EPEL repository GPG key/configuration, while Fedora also
publishes the EPEL 9 package signing key as keyid `8A3872BF3228467C`, fingerprint
`FF8A D134 4597 106E CE81 3B91 8A38 72BF 3228 467C`, on `fedoraproject.org/security`.
Generic descriptions such as naming only the release package are invalid.

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

### Rocky Linux 9 `VERSION_ID` Evidence For L2 Matrix Identity

During Task 23.7.5.9 L2 matrix validation, the real `rockylinux:9` container reported
`VERSION_ID="9.3"` while the manifest still enumerated only `"9"` for `rocky_9`. The
production detection engine therefore resolved the distribution as Rocky but failed to
resolve the stable release: `resolved_release=None`, `resolution_status=release_unknown`,
with identity conflict `VERSION_ID=9.3 does not match an enumerated release`. After the
manifest correction, both the observed container value `9.3` and the separately observed
Rocky VM value `9.6` resolve to `rocky_9` without identity conflicts.

The admitted `rocky_9.os_release_version_ids` list is intentionally exact minor-release
data, not major-version prefix matching. The official Rocky Linux news channel announces
the following Rocky Linux 9 general-availability releases:

| Release | Official Rocky Linux news date | `VERSION_ID` admitted |
|---|---:|---:|
| Rocky Linux 9.0 | July 14, 2022 | `9.0` |
| Rocky Linux 9.1 | November 26, 2022 | `9.1` |
| Rocky Linux 9.2 | May 16, 2023 | `9.2` |
| Rocky Linux 9.3 | November 20, 2023 | `9.3` |
| Rocky Linux 9.4 | May 9, 2024 | `9.4` |
| Rocky Linux 9.5 | November 19, 2024 | `9.5` |
| Rocky Linux 9.6 | June 4, 2025 | `9.6` |
| Rocky Linux 9.7 | December 1, 2025 | `9.7` |
| Rocky Linux 9.8 | May 27, 2026 | `9.8` |

Direct identity observations for this fix:

- CI L2 artifact from run `30708438425`: `rockylinux:9` reported `VERSION_ID="9.3"`.
- Real Rocky VM `wdvpn-rocky9-audit`: `/etc/os-release` reported `VERSION_ID="9.6"` and
  `PRETTY_NAME="Rocky Linux 9.6 (Blue Onyx)"`.

Docker Hub image tags are not treated as the authoritative release list. At the time of
this correction, Docker Hub exposed minor tags for 9.0, 9.1 and 9.2, while 9.4, 9.5, 9.7
and 9.8 were not published as Docker tags. That absence is an image-publishing detail, not
evidence that the Rocky Linux minor releases do not exist; the official Rocky Linux news
announcements above are the release source used for manifest identity coverage. RHEL 9 is
left unchanged until exact `VERSION_ID` evidence is available from an accessible source.

### AlmaLinux 9 `VERSION_ID` Evidence For Manifest Identity

As of Task 23.7.5.11C Bloque A, `almalinux_9` is formally **admitted** as a stable
release (`releases.almalinux_9.policy_state = "admitted"`, listed in
`distributions.almalinux.policy.stable.admitted_releases`). Admission is the policy
promotion of already-recorded facts only; it is not a certification: `almalinux_9`
remains `family_inferred` (Rocky 9 stays the certified redhat_dnf anchor), has no
`cert_*` entry, and its `evidence_refs` stay empty because release `evidence_refs`
are reserved by the validator for current qualifying certification records. The
`os_release_version_ids` list still requires its own evidence because exact stable-release
identity is a manifest input, not something inferred from Rocky Linux or the RHEL family.

The official AlmaLinux blog announces the following AlmaLinux 9 stable releases:

| Release | Official AlmaLinux blog date | `VERSION_ID` admitted |
|---|---:|---:|
| AlmaLinux 9.0 | May 26, 2022 | `9.0` |
| AlmaLinux 9.1 | November 16, 2022 | `9.1` |
| AlmaLinux 9.2 | May 10, 2023 | `9.2` |
| AlmaLinux 9.3 | November 13, 2023 | `9.3` |
| AlmaLinux 9.4 | May 6, 2024 | `9.4` |
| AlmaLinux 9.5 | November 18, 2024 | `9.5` |
| AlmaLinux 9.6 | May 20, 2025 | `9.6` |
| AlmaLinux 9.7 | November 17, 2025 | `9.7` |
| AlmaLinux 9.8 | May 26, 2026 | `9.8` |

Direct release-package identity evidence gathered for this correction also matched that
minor-version pattern: official AlmaLinux release RPMs from `vault.almalinux.org` /
`repo.almalinux.org` exposed `/etc/os-release` `VERSION_ID` values `9.0`, `9.1`, `9.2`,
`9.3`, `9.4`, `9.5`, `9.6`, `9.7` and `9.8` respectively. This evidence only supports
exact identity resolution for `almalinux_9`; it does not promote AlmaLinux to physical
certification and does not change the certification evidence model.

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

### Third security/correctness hardening round

A third, still deeper maintainer review of the second hardening round found seven
further real gaps, closed in the same `compat/provisioning` package on top of the
already-committed second round, again without starting 23.7.5.6b:

- **State-root ancestor boundary** (`storage.py`): `ensure_private_dir` is replaced by
  two boundary-aware primitives, `ensure_private_state_root(state_root)` and
  `ensure_private_subdir(state_root, relative_path)`. The directory directly ABOVE
  `state_root` -- the real product's own `/var/lib/watchdogvpn`, a dedicated lab root,
  `$HOME`, a system temp dir, whatever it is -- is verified read-only
  (`_verify_external_parent_readonly`: must exist, must not be a symlink, must be a real
  directory) and is NEVER chmod'd, chown'd, created or replaced; only `state_root`
  itself and its own descendants are ever created or have their mode enforced to
  `0700`. This closes a real bug: the previous unconditional "recurse into parent"
  logic would climb past `state_root` into its external parent whenever an
  intermediate directory was missing, and then tighten that external parent's mode
  to `0700` -- silently destroying a `02770` setgid, group-shared product config
  directory the first time its own `provisioning/` subdirectory didn't yet exist.
  `journal.py` and `lock.py` now call these two functions explicitly with `state_root`
  passed in, instead of letting `atomic_write_private`/`atomic_write_private_text`
  auto-create arbitrary missing ancestors; `atomic_write_private` now only verifies
  (never creates) its immediate parent, raising `PathPolicyError` if the caller didn't
  establish it first via `ensure_private_subdir`.
- **Positive lab-root confinement, not a denylist** (`paths.py`,
  `tools/compat_provision.py`): the CLI harness gains a mandatory `--lab-root` argument,
  validated by `validate_dedicated_lab_root` -- absolute, no symlink at any component,
  must already exist (never auto-created: a dedicated lab root is something the
  operator creates and approves ahead of time), owned by our own uid, mode exactly
  `0700`, and still rejected outright if it resolves to the filesystem root, a reserved
  system root, the real product state directory, or `$HOME` itself. `--sandbox` and
  `--state-root` are validated by the new `validate_lab_descendant(lab_root, path,
  label=...)` as STRICT descendants of that one approved root (never equal to it, never
  resolving outside it, also independently re-checked against the reserved-destination
  policy as defense in depth) -- an arbitrary path like `/var/log`, `/var/spool`,
  `/opt` or `/srv` is never acceptable just because it fails to match one denylist
  entry. `_build_env` additionally rejects `--sandbox`/`--state-root` being equal to
  each other or containing one another, all checked before any mutation.
- **Ownership authority derived from the committed plan, never from
  `journal.provenance`** (`engine.validate_ownership_authority`): the old check compared
  the standalone ownership file against `journal.provenance`, a second JSON blob living
  inside the very same mutable journal file -- an attacker (or corruption) that edits
  both consistently (point straight at a foreign resource, adjust `provenance` to
  match) would have passed. The source ("prepare") transaction's plan is now
  independently RECONSTRUCTED from the trusted executor's own code
  (`executor.plan_steps`), exactly like `_recover_one` already does for recovery, and
  its digest reverified against the journal's own `plan_digest`; each ownership
  record's `resource_identity` must then match exactly one `VERIFIED` step of that
  reconstructed plan (a set-exact, both-directions check), with `pre_existing`,
  `source`/`version` (must be `None`, matching what this executor genuinely produces),
  `post_install_fingerprint` (must equal `integrity`), `method_id`,
  `executor_id`/`version` and `created_by_transaction` all independently required to
  match. This deliberately never re-stats the live filesystem for uid/gid/mode/nlink --
  this function also runs mid-recovery, where a resume in progress may legitimately
  have already altered the resource; that remains `_detect_ownership_drift`'s job, run
  later and only once, right before the actual unlink. The mandatory security scenario
  (install, complete uninstall, simulate a crash between removal and revocation,
  manually recreate the file with an identical hash, uninstall again) and a lockstep
  tamper of both the ownership file and `journal.provenance` together (steps/plan left
  untouched) both correctly resolve to `ownership_invalid`/`nothing_to_uninstall` with
  zero mutation; tampering only `uid`/`gid`/`mode` on the persisted record still passes
  authority (the path/hash/method/executor identity is unchanged) but is still refused
  at the real unlink by `_detect_ownership_drift`, never causing deletion.
- **Exact final postcondition** (`executors.py`, `engine._finalize_provenance`):
  `CanaryExecutor.plan_steps` now embeds deterministic `expected_mode`/`expected_uid`/
  `expected_gid` in each step's own `intent` (part of `plan_digest`, hence
  tamper-evident); `verify_step` and `verify_postcondition` both check mode and uid/gid
  against those values (`verify_postcondition` previously checked neither). Most
  importantly, `_finalize_provenance` no longer simply adopts whatever metadata it
  finds at commit time as the new ownership expectation -- it now checks the live
  re-stat AGAINST the plan's own `expected_mode`/`expected_uid`/`expected_gid` and
  raises `ProvisioningError` (no commit, no ownership) on any mismatch, closing the
  window between the executor's own `verify_postcondition` and commit. A chmod, a
  simulated chown, a hard link, or a symlink/type substitution injected strictly
  between the last per-step `verify_step` and the transaction-level
  `verify_postcondition` all correctly block commit with zero ownership granted.
- **`REVOKING_OWNERSHIP` boundary independently reconfirmed before revoke**
  (`engine._revocation_boundary_is_safe`): reaching `REVOKING_OWNERSHIP` -- whether just
  transitioned into from a successful unlink loop, or resumed directly at it after a
  crash -- never by itself authorizes a revoke. The new check recomputes the uninstall
  plan digest fresh from `journal.owned_snapshot`, reverifies the snapshot against the
  source transaction via `validate_ownership_authority`, requires every step to be
  exactly `VERIFIED`, and independently re-confirms on disk that none of the
  snapshotted resources are still present; any impossible combination drives the
  transaction to `RECOVERY_REQUIRED` (a new allowed transition from
  `REVOKING_OWNERSHIP` in `model.py`) rather than revoking. `validate_ownership_authority`
  gained an `exclude_uninstall_transaction_id` parameter so this self-referential check
  does not mistake the very journal it is validating for a stale, already-completed
  uninstall of itself. Steps forced to `PLANNED`/`APPLYING`/`APPLIED`/`VERIFYING`, a
  tampered snapshot, a digest mismatch, or a resurrected resource at the boundary all
  correctly block the revoke, leave ownership and the resource intact, and never reach
  `UNINSTALLED`.
- **Truly complete ownership snapshot** (`digest.py`, `model.py`, `journal.py`):
  `canonical_ownership_record_mapping` now includes `source`, `version`,
  `post_install_fingerprint`, `recorded_at` and the candidate's new explicit `nlink`
  field (added to `OwnershipCandidate`/journal (de)serialization) -- tampering any
  single one of these now changes `compute_uninstall_plan_digest`. `write_ownership_records`
  now applies the same `redact_for_journal` credential-URL redaction the transaction
  journal itself already used for `owned_snapshot`, so a credentialed URL in `source`
  is never persisted verbatim into the standalone ownership file either.
- **Controlled-error handling in ownership revocation**
  (`engine._revoke_ownership_and_verify`): now catches `DurabilityError` (in addition to
  plain `OSError`) from the ownership file's own delete -- a directory-fsync failure
  right after a genuine unlink no longer escapes as an unhandled exception crashing
  mid-uninstall; it is reported as a structured `(False, reason)`, driving the
  transaction to the existing recoverable `UNINSTALL_FAILED`/`RECOVERY_REQUIRED` path
  and guaranteeing the transaction can never reach `UNINSTALLED` while revocation
  durability is unconfirmed.

57 new L1 tests were added for this round (175 total in the module), 381 across the
full focused compatibility suite (1 skip), full local suite 2160 OK (1 skip). A
pre-existing, unrelated minor API quirk was noted (not part of this round's scope, not
fixed): the
`PrepareOutcome.transaction_id` that `uninstall()` returns is the outer
provisioner-lock's id, not the uninstall journal's own (a separate uuid minted inside
`_build_uninstall_plan`) -- a caller that wants the uninstall journal must scan
`journal.list_transaction_ids`/`read_journal` for `operation == "uninstall"`, as the L1
tests for this round now do.

### Third hardening round: real VM re-validation

Executed for real on `wdvpn-linuxmint-23-6-7` against commit `b1cc6f7` (third hardening
round code `feb01bd` plus a VM-harness-only fix `b1cc6f7`, see below). The pre-existing
clean snapshot (`pre-23.7.5.6a-round2-reboot-validation`) was restored first, L1 was
re-run on the VM (Python 3.12.3, 175/175 OK), a NEW dedicated snapshot for this round
(`pre-23.7.5.6a-round3-reboot-validation`) was then taken, and all six of the
maintainer's required scenarios were prepared independently (each in its own dedicated
`--sandbox`/`--state-root` pair, since the apply/rollback checkpoints share a fixed
`cap_vm_reboot` capability_id and would otherwise auto-recover each other the moment a
second `prepare()` acquired the same state root's lock) before a single shared real
reboot:

1. `after_apply_before_verify` (apply) -- resumed and committed; both canary files
   present, `OwnershipRecord` written.
2. `undoing_before_unlink` (rollback) -- resumed rollback, reached `preparation_failed`,
   zero residuals, sandbox empty.
3. `undoing_after_unlink_before_undone` (rollback) -- resumed rollback, reached
   `preparation_failed`, sandbox empty.
4. `after_unlink_before_applied` (uninstall) -- resumed, reached `uninstalled`,
   ownership record deleted, sandbox empty.
5. `after_verify_before_revoke` (uninstall) -- resumed, reached `uninstalled`, ownership
   record deleted, sandbox empty.
6. `after_revoke_before_uninstalled` (uninstall) -- resumed, reached `uninstalled`,
   ownership record deleted, sandbox empty.

The real reboot itself used a hypervisor-level hard reset (`VBoxManage controlvm ...
reset`, from the host running VirtualBox) rather than an in-guest `sudo reboot`, since
this VM's account has no passwordless sudo configured; a hard reset is at least as
rigorous a crash test (no graceful shutdown, no buffered-write flush at all) and
`/proc/sys/kernel/random/boot_id` still proves a genuine kernel restart, not a process
restart. `boot_id` (`85471f15-...` before, `4b1d8210-...` after) confirmed this. The
VM's home directory is eCryptfs-encrypted and does not unlock for key-based SSH until a
real password login occurs after boot; the maintainer logged into the VM's graphical
console directly to unlock it, after which key-based SSH resumed working for the
recovery commands -- no password was scripted, stored, or left in any evidence file.

Two additional CLI-level checks specific to this round's points 1 and 2 were run
directly against the real VM filesystem (not through the Python engine harness, which
bypasses the CLI): (a) `storage.ensure_private_state_root` against a simulated
`/var/lib/watchdogvpn`-style parent at mode `02770` with its `provisioning/` subdirectory
missing -- the parent's mode was confirmed unchanged (`0o2770` before and after) while
the new state root came out at `0700`; (b) `tools/compat_provision.py` invoked directly
with `--sandbox=/var/log`, `--sandbox=/opt`, `--state-root=/var/log/wdvpn-state`, and a
sandbox outside the dedicated `--lab-root` entirely -- all four rejected with
`PathPolicyError` and zero mutation, while a valid `--lab-root`/`--sandbox`/
`--state-root` triple under one dedicated root committed normally.

Package list, repository sources, running-service set and `/var/lib/watchdogvpn`
content hashes were identical before and after (the only network diff was the expected
DHCP-lease-timer countdown); real filesystem permissions across all six scenario state
roots were confirmed `0700` for `transactions`/`ownership`/`history`/the state root
itself, `0600` for every journal/ownership/lock file. A residual scan across all six
scenario directories found only the exact expected contents for each outcome (populated
sandbox for the one committed apply scenario, empty sandboxes and empty `ownership/`
directories for every rollback/uninstall scenario) -- no stray files, no leaked
ownership records. The VM was powered off and the round's snapshot restored and
confirmed as current (`VBoxManage snapshot list` showing `pre-23.7.5.6a-round3-reboot-
validation *`) afterward; none of the three snapshots (round 1, round 2, round 3) was
deleted. Private evidence (`0700`/`0600`) at
`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-7-5-6a-round3-reboot-validation`.

This VM run also caught a real bug in the VM harness script itself (fixed in commit
`b1cc6f7`, on top of `feb01bd`): `cmd_uninstall_worker`'s call to
`engine._run_uninstall_loop` still used the old 3-argument signature after this round
added mandatory `registry`/`expected_executor_version` keyword arguments to that
function (needed for the new ownership-authority reconstruction); this crashed the
`after_verify_before_revoke` and `after_revoke_before_uninstalled` scenarios with an
unhandled `TypeError` instead of the intended `SIGKILL`, since those two checkpoints
run the removal loop before self-killing (`after_unlink_before_applied` self-kills
earlier and was unaffected). This is a VM-harness-only defect, not an engine defect --
the actual local L1 suite never exercises this file, since it is deliberately excluded
from `python3 -m unittest discover tests` (it sends real, uncatchable `SIGKILL`s).

### Fourth security/correctness hardening round

A fourth maintainer review of the third hardening round found seven further real
gaps, closed in the same `compat/provisioning` package on top of the already-committed
third round, again without starting 23.7.5.6b:

- **Descriptor-relative state-root/lock identity binding** (`storage.py`, `lock.py`,
  `journal.py`, `engine.py`): a new `StateRootHandle` -- an OPEN, `st_dev`/`st_ino`-bound
  file descriptor for `state_root`, with lazily-cached, equally-open descriptors for its
  `transactions`/`ownership`/`history` subdirectories -- is established ONCE via
  `storage.open_state_root()` when the provisioner lock is acquired
  (`lock.acquire_provisioner_lock` now takes `state_root` itself, not a precomputed lock
  path, and YIELDS this handle) and threaded through every journal/ownership
  read/write/delete/list for the entire duration of that lock-protected transaction.
  `journal.py`'s functions now dispatch on `Path` (legacy, read-only callers outside a
  lock, e.g. `status`/dry-run) vs `StateRootHandle` (every mutating call inside
  `prepare()`/`uninstall()`/`recover_pending()`), using `os.open`/`os.mkdir`/`os.replace`/
  `os.unlink` with `dir_fd=` for the latter -- never a fresh path-based lookup once the
  state root's identity has been established. A real, disposable-subprocess multiprocess
  test proves the property: a holder process acquires the lock, the test process renames
  `state_root` aside (under a `02770` parent, no sticky bit) -- optionally replacing the
  vacated path with a new directory or a symlink -- and the holder's subsequent write
  correctly lands in the ORIGINAL (renamed-away) directory via its descriptor, never
  silently creating a second journal tree at the new path; a symlink placed at the
  vacated path is rejected outright (`PathPolicyError`, fail closed) for any other
  process trying to acquire a lock there. A further test renames the `transactions`
  subdirectory itself mid-transaction, after the holder has already cached its
  descriptor from an earlier write in the SAME critical section, and confirms a second
  write from that same holder still lands in the original, renamed-away subdirectory.
- **Ownership authority derived from an executor-provided canonical expectation, not
  engine-hardcoded assumptions** (`executors.py`, `engine.py`): a new abstract
  `Executor.expected_ownership_for_step(plan, step) -> OwnershipCandidate` is derived
  ONLY from the plan/intent/selected asset/the executor's own registered code -- never
  from a live filesystem read. `validate_ownership_authority` and `_finalize_provenance`
  now compare a persisted record's full field set (`capability_id`, `artifact_type`,
  `resource_identity`, `pre_existing`, `method_id`, `source`, `version`, `integrity`,
  `uid`, `gid`, `mode`, `nlink`, `post_install_fingerprint`, `executor_id`/`version`,
  `created_by_transaction`) against THIS canonical expectation, removing every
  canary-specific assumption that used to be hardcoded directly in `engine.py`
  (`artifact_type` is always `"file"`, `source`/`version` are always `None`,
  `post_install_fingerprint` always equals `integrity`). Because the expectation is
  plan-derived (a fixed value the attacker cannot influence, never a live re-stat that
  would legitimately vary mid-recovery), uid/gid/mode/nlink are safe to compare
  unconditionally, closing a real coordinated-tamper gap: altering BOTH the real
  resource's metadata (a real `chmod`/hardlink) AND the persisted ownership record to
  match each other no longer helps an attacker, since authority never trusts either side
  of that pair in isolation. `recorded_at` is deliberately excluded from the
  authorization check -- declared explicitly informative metadata without authority,
  not silently incorporated. A second, test-only `_DivergentMetadataExecutor` (never
  registered outside tests) that produces non-null `source`/`version` and a
  `post_install_fingerprint` deliberately diverging from the content hash commits and
  uninstalls cleanly through the exact same generic machinery, proving the
  infrastructure is genuinely executor-agnostic.
- **Structural completeness of a COMMITTED source journal** (`engine.py`): before
  granting authority, a new `_journal_steps_match_plan_exactly()` requires
  `journal.steps` to be structurally IDENTICAL to the independently reconstructed plan
  -- same cardinality, unique sequences, and for each sequence an exact match of
  `step_id`/`action_type`/`target`/`intent` -- plus every step exactly `VERIFIED` with
  non-`None` `verification` evidence and `undo_record`. This closes a real gap
  `plan_digest` alone left open: none of a step's own persisted state (its current
  `state`, its recorded `step_id`/`action_type`/`target`/`intent` as actually written to
  disk after journal creation) participates in `plan_digest`, which only ever covered
  the ORIGINAL plan once, at journal-creation time. The mandatory security scenario
  (source journal tampered to leave only one of two steps `VERIFIED`, ownership shrunk
  to just that one still-VERIFIED resource, `plan_digest` left untouched, uninstall
  attempted) correctly resolves to `ownership_invalid` with both resources intact and
  ownership never revoked; further variants cover a missing step, a duplicate step, a
  duplicate sequence, a step left not-`VERIFIED`, and a changed `step_id`/`action_type`/
  `target`/`intent`.
- **`Path.is_symlink()`/`Path.exists()` fully removed from security decisions**
  (`paths.py`): `_reject_symlink_components` and `validate_target_path`'s ancestor walk
  now use `os.lstat` directly and classify explicitly -- `FileNotFoundError` means
  absent where the operation allows it, any OTHER `OSError` (permission denied, `EIO`,
  `ESTALE`) fails closed as `PathPolicyError`, a symlink fails closed as
  `PathPolicyError` -- eliminating the exact cross-Python-version fragility class found
  in the second hardening round (`Path.is_symlink()`'s internal `OSError`-handling
  differs between 3.12 and 3.14). New tests inject `PermissionError`/`EIO`/`ESTALE` on
  an intermediate path component against the REAL policy functions (no bypass, unlike
  the second round's workaround) and must classify identically regardless of Python
  version. This work also surfaced and closed a related gap: `validate_target_path`
  previously resolved straight through an *allowed root* that had itself been replaced
  by a symlink (`root.resolve(strict=True)` follows it silently); it now rejects that
  outright before ever resolving, the same way an intermediate component already was.
- **Descriptor-safe absence reconfirmation before revoke** (`paths.py`, `engine.py`): a
  new `confirm_absent_descriptor_safe()` replaces `_revocation_boundary_is_safe()`'s
  isolated `os.lstat()` on a bare persisted path string. It reconstructs and validates
  the resource's path through the SAME allowlist/forbidden-roots policy, then confirms
  the basename's absence relative to an OPEN, `O_NOFOLLOW` descriptor of its immediate
  parent directory -- closing the window between path validation and the check itself.
  The mandatory test: the resource is still genuinely present, but its parent directory
  (the allowed sandbox root, for this single-level executor) is renamed aside and a
  symlink to an unrelated EMPTY directory is dropped at the original location -- a naive
  `os.lstat()` on the bare path would see `FileNotFoundError` and wrongly conclude
  "absent" even though the real resource is fully intact in the renamed-away directory;
  the new check instead fails the path validation itself (the allowed root is now a
  symlink) and correctly blocks the revoke (`RECOVERY_REQUIRED`, ownership intact).
- **`PrepareOutcome.transaction_id` fixed for `uninstall()`**: `_build_uninstall_plan`
  now takes an explicit, caller-supplied `transaction_id` instead of minting its own
  internally; `uninstall()` passes the SAME id it already uses for the provisioner-lock
  metadata, so the `transaction_id` it returns is always exactly the uninstall journal's
  own id on disk -- never a second, independently generated identifier a caller had no
  way to correlate back to the real journal.
- **Point 6, revisited**: with ownership authority now fully executor-derived (see
  above), the last remaining canary-specific engine assumption is gone; `_finalize_provenance`
  reads `artifact_type`/`pre_existing`/`method_id`/`source`/`version`/
  `post_install_fingerprint` from `executor.expected_ownership_for_step()` rather than
  hardcoding them, while still independently re-stating uid/gid/mode/nlink against that
  same executor-declared expectation before ever persisting an `OwnershipRecord`.

27 new L1 tests were added for this round (202 total in the module), 408 across the
full focused compatibility suite (1 skip), full local suite 2187 OK (1 skip).

### Fourth hardening round: real VM re-validation

Executed for real on `wdvpn-linuxmint-23-6-7` against commit `32cae5b`. The pre-existing
clean snapshot (`pre-23.7.5.6a-round3-reboot-validation`) was restored first, L1 was
re-run on the VM (Python 3.12.3, 202/202 OK) -- including, for real, the mandatory
multiprocess `StateRootIdentityRaceTests` (a genuinely separate holder process, a real
`state_root` rename/replace-by-directory/replace-by-symlink while the lock is held, all
under a `02770` parent) and the mandatory `CoordinatedMetadataTamperTests` (a real
`chmod`/hardlink on the resource coordinated with a matching tamper of the persisted
ownership record) -- a NEW dedicated snapshot for this round
(`pre-23.7.5.6a-round4-reboot-validation`) was then taken, and all six of the
maintainer's required reboot scenarios were prepared independently (each in its own
dedicated `--sandbox`/`--state-root` pair) before a single shared real reboot:

1. `after_apply_before_verify` (apply) -- resumed and committed; both canary files
   present, `OwnershipRecord` written.
2. `undoing_before_unlink` (rollback) -- resumed rollback, reached `preparation_failed`,
   zero residuals, sandbox empty.
3. `undoing_after_unlink_before_undone` (rollback) -- resumed rollback, reached
   `preparation_failed`, sandbox empty.
4. `after_unlink_before_applied` (uninstall) -- resumed, reached `uninstalled`,
   ownership record deleted, sandbox empty.
5. `after_verify_before_revoke` (uninstall) -- resumed, reached `uninstalled`, ownership
   record deleted, sandbox empty.
6. `after_revoke_before_uninstalled` (uninstall) -- resumed, reached `uninstalled`,
   ownership record deleted, sandbox empty.

The real reboot again used a hypervisor-level hard reset (`VBoxManage controlvm ...
reset`); `boot_id` (`85471f15-...` before, `60bd321e-...` after) confirmed a genuine
kernel restart. As in the third round, this VM's home directory is eCryptfs-encrypted
and does not unlock for key-based SSH until a real password login occurs after boot;
the maintainer logged into the VM's graphical console directly to unlock it each time
(once before starting, once again after the real reboot) -- no password was scripted,
stored, or left in any evidence file.

Package list, repository sources, running-service set and `/var/lib/watchdogvpn`
content hashes were identical before and after (the only network diff was the expected
DHCP-lease-timer countdown); real filesystem permissions across all six scenario state
roots were confirmed `0700` for `transactions`/`ownership`/`history`/the state root
itself, `0600` for every journal/ownership/lock file -- exactly one `provisioner.lock`
and one consistent journal tree per scenario, no divergent second tree anywhere. A
residual scan across all six scenario directories found only the exact expected
contents for each outcome (populated sandbox for the one committed apply scenario,
empty sandboxes and empty `ownership/` directories for every rollback/uninstall
scenario) -- no stray files, no leaked ownership records. Both uninstall-operation
journals in each uninstall scenario's `transactions/` directory (the source "prepare"
transaction and the uninstall transaction itself) were present and internally
consistent, directly confirming the point-7 fix: the uninstall journal's own id on disk
matches what a caller would get back from `uninstall()`. The VM was powered off and the
round's snapshot restored and confirmed as current (`VBoxManage snapshot list` showing
`pre-23.7.5.6a-round4-reboot-validation *`) afterward; none of the four snapshots
(rounds 1 through 4) was deleted. Private evidence (`0700`/`0600`) at
`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-7-5-6a-round4-reboot-validation`.

### Fifth security/correctness hardening round

A fifth maintainer review of the fourth hardening round found seven further real gaps,
closed in the same `compat/provisioning` package on top of the already-committed fourth
round, again without starting 23.7.5.6b:

- **Global provisioner lock moved to a dedicated stable root, decoupled from
  `state_root`'s own identity** (`lock.py`, `storage.py`, `engine.py`): the fourth
  round's `StateRootHandle` closed the TOCTOU between opening `state_root` and using it,
  but the lock file itself still lived INSIDE `state_root` -- a tree that can be
  renamed/replaced by anything that can write to its shared parent while the lock is
  held, meaning two processes configured with the identical `state_root` path could, in
  principle, end up contending for two DIFFERENT physical lock files after a rename. The
  lock now lives under a separate, caller-supplied `global_lock_root` (e.g.
  `/run/lock/watchdogvpn/provisioning` in production; a dedicated per-test/per-scenario
  directory that is a SIBLING of, never a descendant of, `state_root`'s own renamable
  parent), keyed by a stable `sha256` of `state_root`'s own CONFIGURED path string --
  never a resolved/canonicalized form, and never the directory's physical identity,
  both of which could themselves be affected by the swap being defended against. The
  global lock is acquired strictly BEFORE `state_root` is ever created, opened or
  recovered (`storage.ensure_private_lock_root` walks and creates only the components
  IT owns, leaving pre-existing system directories like `/run`/`/run/lock` completely
  untouched). Once held, `storage.open_state_root()` establishes the `StateRootHandle`
  and its `transactions`/`ownership`/`history` descriptors are opened EAGERLY, before
  any recovery pass or other use, so a subdirectory renamed away and replaced by an
  empty one afterward can never make a later listing silently read "zero pending" from
  the wrong (new, empty) directory instead of the real one already cached. Both
  `StateRootHandle` and the new `AllowedRootHandle` (see below) gained a
  `verify_identity()` that re-`lstat`s the canonical, configured path and compares
  `st_dev`/`st_ino` against what was captured when the handle was first opened; it is
  called before every mutating journal/ownership write, before finalizing
  provenance/commit, and before revoking ownership -- fd-relative operations remain
  correct even after a rename/replace (since they are bound to the original directory),
  but reporting success anyway would create a split-brain against whatever a fresh
  process using the same configured path would now see, so a divergence instead raises
  `StateRootIdentityError`/`PathPolicyError`, caught by a single outer handler in
  `prepare()`/`uninstall()`/`recover_pending()` and converted to `RECOVERY_REQUIRED`
  (never a crash, never a silent success). Three real, disposable-subprocess
  multiprocess tests cover the mandatory scenarios: `state_root` renamed aside (with no
  replacement, replaced by a new directory, or replaced by a symlink) while a holder
  process is mid-transaction -- in every case the holder's write now fails closed
  (`identity_error:` marker, zero journal ever written claiming success) rather than
  silently landing in the orphaned original directory, a contender configured with the
  identical path is refused a second lock the entire time the holder is active
  regardless of what has happened to `state_root` physically, and no new state root is
  ever silently created at the vacated path; a fourth test renames the `transactions`
  subdirectory strictly between the holder's eager-open and its first
  `list_transaction_ids()` call (a corrupt, genuinely pending journal already sitting in
  it) and confirms the real pending count is still seen through the cached descriptor
  (never misread as "zero pending"), while a second write attempted after the swap is
  detected and fails closed.
- **`AllowedRootHandle` binds every executor operation to a descriptor** (`paths.py`,
  `executors.py`, `engine.py`): a new `AllowedRootHandle(path, fd, dev, ino)`, captured
  under the provisioner lock via `engine._open_locked_context()` immediately before
  apply/rollback/uninstall/recovery, is threaded through a new
  `ExecutionContext.allowed_root_handles` field. `CanaryExecutor.apply_step`/
  `verify_step`/`undo_step`/`verify_postcondition`/`inspect_step` -- and the engine's own
  `_finalize_provenance`/`check_idempotency`/`_detect_ownership_drift`/
  `_run_uninstall_loop` -- now resolve every create/inspect/verify/hash/undo/unlink
  through `handle_for_allowed_root()` and the handle's descriptor
  (`create_file_exclusive_relative`/`stat_identity_relative`/`read_bytes_relative`/
  `remove_file_if_owned_relative`), never re-resolving a bare `Path` for a later
  mutation. A sandbox/allowed-root swap that happens right as `uninstall()` begins (or
  right before finalizing a commit) is reconfirmed via `AllowedRootHandle.verify_identity()`
  and fails closed exactly like the state-root case above -- `RECOVERY_REQUIRED`, never a
  clean `UNINSTALLED`/`COMMITTED`, ownership never revoked, and the resources sitting in
  the renamed-aside original directory survive untouched as inspectable residuals. The
  mandatory test (a real prepare committed, then the sandbox renamed aside strictly at
  the start of `uninstall()`'s real removal loop) and its variants (replaced by a new,
  same-uid empty directory; replaced by a symlink to an empty decoy) all confirm this; a
  further test replaces an INTERMEDIATE subdirectory (not the allowed root itself, one
  level further down a resolved descendant path) with a symlink after the handle was
  opened and confirms the descriptor-relative walk rejects it the same way.
- **The TOCTOU between hashing a resource and unlinking it is eliminated**
  (`paths.py`): `remove_file_if_owned_relative()` opens the target ONCE, `O_NOFOLLOW`,
  and performs every check -- regular-file type, content hash -- against that SAME open
  file descriptor; immediately before the actual `unlink`, the basename's CURRENT
  directory entry is re-`lstat`'d relative to the held parent descriptor and its
  `(dev, ino)` compared against what was just verified, so only a basename that STILL
  resolves to the exact inode just hashed is ever removed. A real, deterministic,
  two-process test (a test-only `paths.UNLINK_REVERIFY_HOOK` seam lets process A pause
  exactly between its own hash verification and the final re-verify+unlink) has process
  B substitute the basename for a foreign file in that exact window; process A detects
  the substitution and refuses to remove it -- the foreign file survives completely
  untouched, with no false `UNINSTALLED`, the step failing as `ownership_drift`/
  `recovery_required`.
- **Structural validation extended to every journal, not just a COMMITTED source**
  (`engine.py`): the fourth round's `_journal_steps_match_plan_exactly()` only gated
  `validate_ownership_authority` (i.e. uninstall/idempotency); it is now ALSO checked
  during ordinary prepare-side recovery (`_recover_one`), immediately after the
  `plan_digest` check and before `_inspect_recovery_boundary` -- a pending "prepare"
  journal read back from disk during recovery is just as capable of having its own
  `steps` tampered as a COMMITTED one. A new `_uninstall_journal_steps_match_plan_exactly()`
  closes an equivalent, previously-unprotected gap on the UNINSTALL side:
  `compute_uninstall_plan_digest()` is computed purely from `capability_id`/
  `target_transaction_id`/`ownership_records`, and `_build_uninstall_plan()` always
  derives its own `steps` fresh from that same ownership snapshot -- meaning
  `journal.steps` (the ones `_run_uninstall_loop` actually iterates) was NEVER covered
  by the digest at all, so an attacker could add, remove, duplicate or alter a step in
  the persisted uninstall journal without ever moving `plan_digest`. The mandatory test
  (a legitimate pending uninstall with an extra step appended targeting an unrelated
  foreign file, its own real hash) now correctly blocks at `recover_pending` with the
  foreign file completely untouched, zero unlink, ownership still live, and the
  transaction never reaching `UNINSTALLED`; further variants cover a missing step, a
  duplicate step, a duplicate sequence, and a changed `step_id`/`action_type`/`target`/
  `intent`. Separately, the PERSISTED `undo_record` is never again trusted as authority
  for rollback: a new `_authoritative_undo_record()` always reconstructs it fresh from
  the executor's own deterministic `reconstruct_undo_record()` and requires the
  persisted value to agree with it exactly; any divergence is treated as unsafe to
  resume automatically (`UNDO_FAILED`/`RECOVERY_REQUIRED`) rather than driving the real
  undo/removal off a value an attacker (or corruption) could otherwise have pointed at
  an unrelated foreign resource. The mandatory test tampers a verified step's persisted
  `undo_record.path`/`expected_sha256` to a real foreign file sitting inside the allowed
  root, with its own real hash, before a simulated crash mid-`ROLLING_BACK`; recovery
  correctly refuses (`undo_record_diverged`), and both the foreign file AND the real
  resource the tampered record tried to hide survive completely untouched.
- **`confirm_absent_descriptor_safe()` bound to an already-captured `AllowedRootHandle`**
  (`paths.py`, `engine.py`): the fourth round's version still reopened the allowed root's
  parent directory from a bare string on every call; it now receives the SAME
  `AllowedRootHandle` the rest of the critical section already uses, re-confirms that
  handle's own identity (`st_dev`/`st_ino`) against a fresh `lstat` of its canonical path
  before ever walking further, and only then checks the resource's basename absence
  relative to that held descriptor chain -- never reopening anything from a string. The
  direct test (allowed root renamed aside, a fresh empty directory placed at the
  original path) confirms the function now returns `False` with an identity-mismatch
  reason, never `True`, closing the residual window between the handle being captured
  and this specific check running.
- **Private journal/ownership reads fail closed on more than just a symlink**
  (`storage.py`): `read_private_relative()` now opens with `O_NOFOLLOW` and `fstat`s
  BEFORE ever parsing content, requiring a regular file, the expected uid, mode exactly
  `0600`, `st_nlink == 1`, and a size under a fixed bound (`MAX_PRIVATE_FILE_SIZE`, 10
  MiB) -- a symlink, a hard link, a loose mode, a different owner, or an oversized file
  all raise a new `CorruptStateError` (wrapped into the existing `JournalError` at the
  `journal.py` boundary, so every existing narrow `except (JournalError, ...)` caller
  keeps working unchanged) instead of being silently followed, truncated or trusted.
  `list_json_names_relative()` now `lstat`s every `*.json` entry the same way before
  including it in a listing, so a symlink or a directory named `*.json` blocks recovery
  (`_recover_pending_locked`'s enumeration itself fails closed with a synthetic
  `REQUIRE_MANUAL` decision) rather than being silently skipped or followed.
  `_capability_has_completed_uninstall()` now fails closed (denies authority) rather
  than granting it when the transactions directory itself cannot even be enumerated.
  Seven new tests cover a journal symlink, an ownership symlink, a journal hard link, a
  directory named `*.json`, a journal at mode `0644`, a journal owned by a different
  (simulated) uid, and an oversized journal.
- **`validate_ownership_authority` compares every `ExpectedOwnership` field for EXACT
  equality, including when the executor's own expectation is `None`** (`engine.py`): the
  fourth round's per-field checks were still guarded by `if expected.X is not None and
  candidate.X != expected.X`, meaning whenever an executor legitimately declared no
  opinion on a field (`uid`/`gid`/`mode`/`nlink`/`integrity`/`post_install_fingerprint`
  all default to `None`), the corresponding PERSISTED value was never checked against
  anything at all -- an attacker could set it to any tampered value undetected. Every
  comparison is now unconditional (`candidate.X == expected.X`, no guard). Symmetrically,
  `_finalize_provenance` no longer silently upgrades "the executor has no opinion"
  (`expected.uid`/`gid`/`mode`/`nlink` is `None`) into a concrete live-stat value when
  persisting the `OwnershipCandidate`: when the executor's own expectation for a field is
  `None`, the persisted candidate now ALSO records `None` for it, so a legitimate,
  untampered record continues to compare equal under the new unconditional rule instead
  of a live-stat value the executor never actually asked to pin. A new test-only
  `_NoneOwnershipFieldsExecutor` (never registered outside tests) declares `uid`/`gid`
  unset; a baseline committed capability validates cleanly, and tampering either
  persisted field from `None` to any concrete value now correctly breaks authority.

27 new L1 tests were added for this round (229 total in the module), 435 across the
full focused compatibility suite (1 skip), full local suite 2214 OK (1 skip).

### Fifth hardening round: real VM re-validation

Executed for real on `wdvpn-linuxmint-23-6-7` against commit `e5709b7d`. The pre-existing
clean snapshot (`pre-23.7.5.6a-round4-reboot-validation`) was restored first (VM powered
off, snapshot restored, VM started); the module L1 suite ran green on the VM's own
Python 3.12.3 (229/229 -- one run out of five flaked on a timing-sensitive multiprocess
test immediately after the fresh boot, most likely background services still settling
right after a snapshot resume; four immediately-repeated runs were all clean, and this
is consistent with real subprocess/timing-based tests under variable VM scheduling load
rather than a logic defect). A NEW dedicated snapshot for this round
(`pre-23.7.5.6a-round5-reboot-validation`) was then taken, and all six of the
maintainer's required reboot scenarios were prepared independently (each in its own
dedicated `--sandbox`/`--state-root`/`--global-lock-root` triple) before a single shared
real reboot:

1. `after_apply_before_verify` (apply) -- resumed and committed; both canary files
   present, `OwnershipRecord` written.
2. `undoing_before_unlink` (rollback) -- resumed rollback, reached `preparation_failed`,
   zero residuals, sandbox empty.
3. `undoing_after_unlink_before_undone` (rollback) -- resumed rollback, reached
   `preparation_failed`, sandbox empty.
4. `after_unlink_before_applied` (uninstall) -- resumed, reached `uninstalled`,
   ownership record deleted, sandbox empty.
5. `after_verify_before_revoke` (uninstall) -- resumed, reached `uninstalled`, ownership
   record deleted, sandbox empty.
6. `after_revoke_before_uninstalled` (uninstall) -- resumed, reached `uninstalled`,
   ownership record deleted, sandbox empty.

The real reboot again used a hypervisor-level hard reset (`VBoxManage controlvm ...
reset`); `boot_id` (`85471f15-...` before, `50e166d8-...` after) confirmed a genuine
kernel restart. As in every prior round, this VM's home directory is eCryptfs-encrypted
and does not unlock for key-based SSH until a real password login occurs after boot;
the maintainer logged into the VM's graphical console directly to unlock it -- no
password was scripted, stored, or left in any evidence file. After the real reboot and
console unlock, the module L1 suite ran green again on the VM's Python 3.12.3 (229/229),
directly exercising the mandatory multiprocess state-root-rename contender, the sandbox
directory-replacement-during-uninstall scenario, the hash/unlink substitution TOCTOU
test, the tampered-`undo_record` recovery test and the uninstall-extra-step structural
test as REAL subprocess/real-filesystem executions against a genuinely freshly-booted
kernel, not merely against the local development machine.

Package list (`dpkg -l`), repository sources, running-service set and
`/var/lib/watchdogvpn` content hashes were identical before and after the real reboot
(the only network diff was the expected DHCP-lease-timer countdown); real filesystem
permissions across all six scenario state roots and their six INDEPENDENT
`global_lock_root` directories were confirmed `0700` for `transactions`/`ownership`/the
state root itself/the global lock root, `0600` for every journal/ownership/lock file --
exactly one `*.lock` file per scenario's global lock root and one consistent journal
tree per scenario, no divergent second tree anywhere. A residual scan across all six
scenario directories found only the exact expected contents for each outcome (populated
sandbox for the one committed apply scenario, empty sandboxes and empty `ownership/`
directories for every rollback/uninstall scenario) -- no stray files, no leaked
ownership records. Both uninstall-operation journals in each uninstall scenario's
`transactions/` directory (the source "prepare" transaction and the uninstall
transaction itself) were present and internally consistent. The VM was powered off and
the round's snapshot restored and confirmed as current (`VBoxManage snapshot list`
showing `pre-23.7.5.6a-round5-reboot-validation *`) afterward; none of the five
snapshots (rounds 1 through 5) was deleted. Private evidence (`0700`/`0600`) at
`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-7-5-6a-round5-reboot-validation`.

### Sixth security/correctness hardening round

A sixth maintainer review of the fifth hardening round's published commits
(`e5709b7d`/`3e5ba9d`) confirmed the chain was real, auditable and linear, and that
several specific fifth-round fixes were genuinely present (exact `ExpectedOwnership`
equality including `None`, structural validation of pending prepare/uninstall journals,
state-root identity checks before internal writes, fail-closed private reads) -- but
found four further HIGH gaps and one MEDIUM evidence-quality gap, closed in the same
`compat/provisioning` package on top of the already-published fifth round, again without
starting 23.7.5.6b:

- **The hash/unlink TOCTOU was narrowed, not closed** (`paths.py`): the fifth round's
  `UNLINK_REVERIFY_HOOK` test seam paused BEFORE the final `lstat()` re-verify, so its
  mandatory test only proved detection of a substitution happening before that check --
  the window AFTER the re-verify and BEFORE the actual `unlink()` syscall (which operates
  on a NAME, not an inode) remained open and untested. `remove_file_if_owned_relative()`
  is now genuinely atomic: after the held-descriptor hash verification, the basename is
  renamed -- a single atomic `renameat` -- into a private, `uuid4`-derived quarantine name
  in the same directory (whatever inode currently sits at the basename at that instant is
  what moves, collapsing "read the name" and "claim the entry" into one kernel operation);
  only the QUARANTINED entry's `(dev, ino)` is then compared against what was hashed, and
  only a match is ever unlinked (by then under a name private to this call, so no further
  substitution is possible). A mismatch means a concurrent actor won the race and the
  quarantined entry is the WRONG (foreign) inode: it is restored to its original name
  best-effort rather than ever deleted, and if the restore itself fails the quarantined
  entry is left in place as recoverable evidence rather than silently disappearing. The
  test seam moved to sit exactly in this new, genuinely closed window; the mandatory real
  two-process test (process B substitutes the basename strictly between A's hash verify
  and the atomic quarantine rename) confirms the foreign file survives completely
  untouched, no inode other than the one hashed is ever removed, and the step fails as
  `ownership_drift`/`recovery_required` -- never a false `UNINSTALLED`.
- **`AllowedRootHandle` bound only the top-level root's identity, not intermediate path
  components** (`paths.py`, `engine.py`): `_relative_to_handle()` re-opened every
  intermediate directory fresh by name on every call and closed it immediately afterward,
  with no caching or identity comparison -- so a resource nested under an intermediate
  directory (e.g. `sandbox/resources/component.bin`) was exposed to the intermediate
  itself (`sandbox/resources`) being renamed aside and replaced by a NEW, same-uid, real
  directory between the handle being opened and the resource actually being used; the
  fifth round's own "intermediate subdirectory replaced" test only covered a SYMLINK
  substitution, trivially caught by the existing `O_NOFOLLOW` flags, never the
  actually-dangerous real-directory case. `AllowedRootHandle` gained a per-handle
  `intermediate_fd(relative_parts)` that recursively opens and CACHES each intermediate
  component's `fd`/`dev`/`ino` on first use (reusing cached parents), returning the same
  fd on every subsequent call; `verify_identity()` now re-`lstat`s every cached
  intermediate's canonical path against its captured identity in addition to the root's
  own check, and `close()` closes every cached intermediate fd. Since a handle is opened
  once per `prepare()`/`uninstall()`/recovery call, caching-on-first-use alone would still
  miss a swap that happens before the very first access; a new
  `engine._eager_cache_intermediates_for_targets()` pre-opens and caches the full
  intermediate chain for every target immediately after the plan/ownership set is known
  and the lock is held -- before idempotency checks, removal, or any other operation
  touches these paths -- mirroring exactly how `state_root`'s own subdirectories are
  eagerly opened under the lock. Wired into `prepare()`, `uninstall()`, `_recover_one()`
  and `_recover_uninstall()`. `confirm_absent_descriptor_safe()` now delegates its whole
  identity check to `AllowedRootHandle.verify_identity()`, automatically extending its
  protection to cached intermediates too. The mandatory test (a nested resource under
  `sandbox/nested`, committed, then `nested` renamed aside and replaced by a new, empty,
  same-uid real directory strictly between eager-caching and the resource's actual use
  during uninstall) confirms: no `UNINSTALLED`, ownership intact, the real resource still
  sitting untouched in the renamed-aside directory, the new replacement directory empty,
  `RECOVERY_REQUIRED`; variants cover the same swap during a fresh apply/commit and a
  direct `confirm_absent_descriptor_safe()` call against a primed handle.
- **The global lock root's own directory was never enforced private or identity-bound**
  (`storage.py`, `lock.py`): `ensure_private_lock_root()` left every PRE-EXISTING
  component unenforced for mode/uid as long as it was already a directory -- including
  the LEAF component, i.e. `global_lock_root` itself (e.g. a pre-existing
  `/run/lock/watchdogvpn/provisioning` at mode `0770`, group-writable, was accepted
  as-is). The leaf is now always run through the same `_verify_and_secure_directory_fd`
  helper `state_root` itself uses: owned by us with a loose mode gets tightened to exactly
  `0700`; owned by a different uid is rejected outright. Separately, `_open_global_root()`
  never captured or re-verified `global_lock_root`'s own identity during the lock's
  lifetime, so nothing defended against a same-privilege actor renaming/replacing
  `global_lock_root` itself while a holder was active -- a fresh contender using the
  substitute directory would acquire an "independent" primary lock while still racing on
  the real, shared `state_root`. `_open_global_root()` now also returns the captured
  `(dev, ino)` and re-checks the mode is exactly `0700`; immediately after the primary
  flock succeeds (before writing holder metadata), `acquire_provisioner_lock()` re-`lstat`s
  `global_lock_root` and compares identity, releasing the flock and raising
  `PathPolicyError` on any divergence. Since a fresh contender through a genuinely swapped
  directory cannot be stopped by `global_lock_root`-side checks alone (it is, from the
  kernel's point of view, a different, real, independently-lockable inode), a SECOND,
  non-blocking `flock` directly on the `state_root` directory descriptor itself was added
  right after `open_state_root()` succeeds -- immune to any `global_lock_root` swap, since
  `state_root` is a separate, unaffected directory, this closes the residual gap as long as
  both processes agree on the real `state_root` path, which they must to interact with the
  same installation at all. Mandatory/variant tests cover: a pre-existing leaf at `0770`
  and `0777` tightened to `0700`; a leaf owned by a different (simulated) uid rejected; the
  global root swapped between open and flock, detected; and a real two-process test where
  a holder is active, `global_lock_root` is renamed/replaced while it holds the lock, and a
  contender using the SAME `state_root` and the swapped `global_lock_root` is still refused
  via the secondary `state_root` flock.
- **An individual unreadable uninstall journal was silently skipped during the
  completed-uninstall scan, rather than failing closed** (`engine.py`):
  `_capability_has_completed_uninstall()` already failed closed when the WHOLE
  transactions directory couldn't be enumerated, but for an individual unreadable/corrupt
  journal hit while scanning transaction IDs one at a time, it just `continue`d past it as
  irrelevant. Concretely: an uninstall reaches `REVOKING_OWNERSHIP` with all resources
  genuinely removed but the ownership record still live (a crash simulated before
  revocation); the uninstall journal itself later becomes unreadable (mode `0644`,
  hardlinked, corrupt JSON, wrong uid, or oversized -- all already rejected by the fifth
  round's fail-closed private reads); a file is recreated at the original path with
  matching content. The scan cannot prove that unreadable journal is irrelevant without
  reading it, so skipping it risked `validate_ownership_authority` granting authority over
  the recreated file and removing it. The function's return type is now a 3-state
  `_UninstallScanResult` (`NONE_FOUND` / `COMPLETED_FOUND` / `UNKNOWN`): ANY unreadable or
  unvalidatable journal hit during the scan -- individually or via a whole-directory
  enumeration failure -- now immediately yields `UNKNOWN`, and the sole caller
  (`validate_ownership_authority`) denies authority for anything other than `NONE_FOUND`.
  Five tests cover the mandatory chmod-`0644` scenario plus hardlinked, corrupt-JSON,
  wrong-uid and oversized variants, in every case confirming the recreated resource
  survives untouched and the result is never `UNINSTALLED`.
- **Flake diagnosis and deterministic multiprocess synchronization** (test-only, no
  production code): the fifth round's VM evidence noted "1 of 5 pre-reboot runs flaked on
  a timing-sensitive multiprocess test" without naming the test or ruling out a genuine
  synchronization defect. The module suite ran 50 consecutive times locally after this
  round's fixes (0 failures) and again on the VM before and after the real reboot (see
  below); the original single flake was never reproduced. The ready/go signaling in the
  five most security-critical real-subprocess multiprocess tests --
  `StateRootIdentityRaceTests` (all three holder scripts), `HashUnlinkToctouTests`
  (the direct mandatory test for the first finding above) and
  `GlobalLockRootHardeningTests`'s two-process scenario -- was migrated off a
  `Path.exists()` sleep-poll loop onto a genuine blocking primitive: a POSIX FIFO whose
  read end is opened non-blocking by the waiter before the signaling side can possibly
  exist (removing the race the poll loop could not close either), with `select()`'s
  timeout used strictly as a watchdog, never as the synchronization mechanism itself.
  Shared `_fifo_create`/`_fifo_open_reader`/`_fifo_wait`/`_fifo_signal` helpers live at
  module level in the test file and are imported directly by the generated subprocess
  scripts. Older, already-passing multiprocess tests outside this critical set were left
  on the pre-existing polling pattern (with generous timeouts) rather than fully migrated,
  given no evidence tied the original flake to a specific test and the underlying
  protections being validated (lock exclusion, identity checks) are themselves
  deterministic and do not depend on the test's own polling timing.

13 new L1 tests were added for this round (242 total in the module), 448 across the full
focused compatibility suite (1 skip), full local suite 2227 OK (1 skip). The module suite
was additionally run 50 consecutive times locally (0 failures) as part of the flake
diagnosis above.

### Sixth hardening round: real VM re-validation

Executed for real on `wdvpn-linuxmint-23-6-7` against commit `e5709b7d` plus this round's
uncommitted working tree (verified identical via `sha256sum` between the local checkout and
the VM's copy before every run). The pre-existing clean snapshot
(`pre-23.7.5.6a-round5-reboot-validation`) was restored first (VM powered off, snapshot
restored, VM started); the module L1 suite ran green on the VM's own Python 3.12.3
(242/242), then 50 consecutive repetitions of the module suite ran clean (0 failures) --
this is where the flake diagnosis above actually reproduced: run 7 of this first VM batch
hit a genuine `subprocess.TimeoutExpired` on `proc.wait(5)` in
`test_06_lock_contention_between_two_processes` (full traceback captured), root-caused to
an insufficiently generous teardown-wait bound under this VM's own CPU contention (2
vCPUs, load average 1.17 at the time) -- not a synchronization defect, since the
security-relevant assertions (`ProvisionerLockHeldError`, `holder_pid`) had already passed
before that line ever ran. Both occurrences of this bound (here and in
`RecoveryLockTests`) were widened from 5s to 15s, matching the convention already used
everywhere else in the file; the equivalent bound in this harness's own "lock exclusion"
scenario was widened the same way. The fix was re-synced (hashes re-verified identical)
and the 50-repetition batch re-run clean (0 failures) before proceeding. The `run-all`
scenario matrix (including this round's four new attack scenarios) then ran clean in a
single pass, with results identical to the local pre-VM validation:
`toctou_race_after_last_inode_check` (`uninstall_failed`, foreign file survives),
`intermediate_component_swapped_for_real_directory` (`recovery_required`, ownership
intact, resource survives in the renamed-aside directory, replacement directory empty),
`global_lock_root_swapped_while_holder_active` (contender refused via the secondary
`state_root` flock), `unreadable_uninstall_journal_never_reactivates_ownership`
(`ownership_invalid`, recreated resource survives untouched).

A NEW dedicated snapshot for this round (`pre-23.7.5.6a-round6-reboot-validation`) was then
taken, and all six of the maintainer's required reboot scenarios were prepared
independently (each in its own dedicated `--sandbox`/`--state-root`/`--global-lock-root`
triple) before a single shared real reboot -- identical checkpoints and identical expected
outcomes to every prior round (`after_apply_before_verify` resumed/committed;
`undoing_before_unlink` and `undoing_after_unlink_before_undone` resumed
rollback/`preparation_failed`/sandbox empty; `after_unlink_before_applied`,
`after_verify_before_revoke` and `after_revoke_before_uninstalled` resumed/`uninstalled`/
ownership record deleted/sandbox empty). The real reboot again used a hypervisor-level hard
reset (`VBoxManage controlvm ... reset`); `boot_id` (`85471f15-...` before, `a0e2c526-...`
after) confirmed a genuine kernel restart, not a process restart. As in every prior round,
this VM's home directory is eCryptfs-encrypted and does not unlock for key-based SSH until
a real password login occurs after boot; the maintainer logged into the VM's graphical
console directly to unlock it -- no password was scripted, stored, or left in any evidence
file. After the real reboot and console unlock, all six scenarios recovered exactly as
expected (`ok: true` in every case), and the module L1 suite ran green again on the VM's
freshly-booted kernel (242/242), followed by 50 further consecutive clean repetitions
post-reboot, directly exercising the atomic quarantine-rename removal, the eager
intermediate-component identity binding, the hardened global lock root and secondary
state-root flock, and the fail-closed 3-state uninstall-completion scan as REAL
subprocess/real-filesystem executions against a genuinely freshly-booted kernel.

Real filesystem permissions across all six scenario state roots and their six INDEPENDENT
`global_lock_root` directories were confirmed `0700` for `transactions`/`ownership`/the
state root itself/the global lock root, `0600` for every journal/ownership/lock file --
exactly one `*.lock` file per scenario's global lock root and one consistent journal tree
per scenario, no divergent second tree anywhere. A residual scan across all six scenario
directories found only the exact expected contents for each outcome (populated sandbox for
the one committed apply scenario, empty sandboxes for every rollback/uninstall scenario) --
no stray files, no leaked ownership records. Both uninstall-operation journals in each
uninstall scenario's `transactions/` directory (the source "prepare" transaction and the
uninstall transaction itself) were present and internally consistent. The VM was powered
off and the round's snapshot restored and confirmed as current (`VBoxManage snapshot list`
showing `pre-23.7.5.6a-round6-reboot-validation *`) afterward; none of the six snapshots
(rounds 1 through 6) was deleted. Private evidence (`0700`/`0600`) at
`/home/gabodev/Desktop/temporales/watchdogvpn-task-23-7-5-6a-round6-reboot-validation`.
Package list, repository sources and running-service set were captured after the reboot for
completeness, but -- unlike prior rounds -- a separate BEFORE-reboot snapshot of these
specific baselines was not captured this round (an evidence-collection gap on my part, not
a masked finding); this round's code changes are 100% confined to
`compat/provisioning/{engine,lock,paths,storage}.py` and never touch package management,
repositories, or services, so there is no mechanism by which they could have altered any of
those, but the omission should not repeat in a future round.

### Seventh hardening round: focused residual correction

A seventh focused review of Task 23.7.5.6a identified residual gaps in the sixth-round
implementation and evidence package. This round stays on the same 23.7.5.6a compatibility
contract branch and does not start 23.7.5.6b.

- **Deletion is now bound to the verified resource after the move, not just before it**
  (`paths.py`): `remove_file_if_owned_relative()` now keeps the original fd open across
  the whole destructive protocol, moves the basename into a same-directory quarantine
  entry with Linux `renameat2(RENAME_NOREPLACE)`, fsyncs the directory after the
  quarantine move, opens the quarantine entry with `O_NOFOLLOW`, checks regular-file type,
  compares `(st_dev, st_ino)` against the original fd, recomputes the sha256 from the
  moved object, and then reopens/revalidates the quarantine entry again immediately before
  unlink. There is intentionally no `os.rename()` fallback for the no-replace primitive:
  unsupported platforms fail closed rather than weakening the guarantee. Restore also uses
  `RENAME_NOREPLACE` and never overwrites a basename that reappeared. If restore cannot be
  completed, the quarantine entry remains as an explicit recovery residue and the caller
  receives a closed failure instead of a clean removal result. The quarantine parent is
  verified as a real private directory owned by the current uid and not group/world
  writable; the implementation does not treat a UUID-like quarantine name as a security
  boundary.
- **Product-owned resources now persist intermediate component identity** (`model.py`,
  `journal.py`, `digest.py`, `engine.py`, `paths.py`): ownership records gained a durable
  `IntermediateIdentity` chain containing relative component name, `st_dev`, `st_ino`,
  uid and mode. The ownership record digest includes this chain, journal
  serialization/deserialization validates it, and provenance captures it when ownership is
  finalized. Uninstall authority rejects nested ownership records that omit the persisted
  chain, and locked uninstall/recovery revalidates the current descriptor-bound chain
  against the persisted identities before resource removal, before ownership revocation,
  and before clean terminal states. `_eager_cache_intermediates_for_targets()` now fails
  closed on path-policy errors instead of silently skipping them.
- **The global lock root now rejects unsafe immediate parents** (`storage.py`): the
  configured lock root's immediate parent must be owned by root or the current uid and
  must not be group/world writable. Tests cover pre-existing `0770`, `02770` and
  world-writable parents being rejected before the leaf lock root is created.
- **Clean terminal states are rechecked at the boundary** (`engine.py`): allowed-root
  identity and persisted intermediate identities are checked before `COMMITTED`, before
  `ROLLED_BACK`, between `ROLLED_BACK` and `PREPARATION_FAILED`, before clean recovery
  rollback decisions, before ownership revocation, and before `UNINSTALLED`. A divergence
  returns `RECOVERY_REQUIRED` or invalid ownership instead of reporting a clean terminal
  state.
- **Evidence correction from the sixth round**: the first VM repetition batch failed on
  run 7 in `test_06_lock_contention_between_two_processes` with
  `subprocess.TimeoutExpired` at `proc.wait(5)`. The correction applied was to widen that
  teardown wait bound to 15 seconds in the relevant tests. The later evidence was a second
  VM batch of 50/50 clean repetitions and a post-reboot batch of 50/50 clean repetitions.
  The earlier failure is not classified as harmless merely because preceding assertions had
  passed; the classification depends on the exact traceback location, the already-observed
  lock-refusal result before teardown, the VM load context captured at the time, and the
  clean 50/50 reruns after the wait-bound correction. The prior absence of a complete
  pre-reboot package/repository/service/network/state baseline is recorded as a historical
  evidence omission; this seventh round must capture and compare a full before/after VM
  baseline before closure.

Local pre-VM evidence for this seventh round: `tests/test_compat_transactional_provisioning.py`
ran 254/254 clean; the focused new round-seven subset ran 20/20 clean;
`python -m compileall -q compat/provisioning tests/test_compat_transactional_provisioning.py`,
`tests/syntax.sh`, `git diff --check`, `python tools/compat_read.py validate`, the four
fixture probes (`detect`, `capabilities`, `evaluate`, `report`), the four fixture resolve
commands (`dependency dep_python_runtime`, `all`, `explain dep_python_runtime`, `matrix`)
and a real-host unknown-availability `resolve all` pass all completed with rc=0.
`tests/unit.sh` completed with rc=0. `python -m unittest discover -s tests -p
'test_*.py'` ran 2239 tests with 1 skip and rc=0. The focused provisioning module was then
run 50 consecutive times locally with no retries: 50/50 clean, no `FAILED`/`ERROR`/
traceback/`TimeoutExpired` in the per-run logs, no quarantine residues found under `/tmp`
after any run, and no test holder process left alive; the only matching Python process in
the post-run snapshots was the pre-existing `/usr/bin/python3 -m daemon.main`, unrelated
to the test runs. The VM validation harness was extended with the new round-seven
scenarios and its local `run-all` pass completed with rc=0, including observed
`round7_quarantine_substitution_after_verify`, `round7_quarantine_in_place_modification`,
`round7_quarantine_restore_noreplace`, `round7_intermediate_swap_before_uninstall`,
`round7_global_lock_parent_rejections`, and
`round7_identity_loss_before_terminal_state` records.

During the first real VM pre-reboot 50-run batch on `fb62511b`, runs 1-49 completed with
rc=0 and run 50 failed in `test_06_lock_contention_between_two_processes` with
`subprocess.TimeoutExpired` at `proc.wait(15)`. Post-failure capture showed no live
`holder.py` process, and the lock-contention assertion had already observed
`ProvisionerLockHeldError` before the teardown wait. The applied correction widens only
the non-security teardown waits for these holder processes from 15s to 60s in the unit
test and VM harness; the barrier-based race scenario watchdogs remain unchanged. A fresh
50/50 batch must be run after this correction; the failed 49/50+failure batch is retained
as evidence and is not counted as clean.

The first fresh VM batch after that wait-bound correction (`8312d48`) failed on run 9 in
the same test with `ProvisionerLockHeldError not raised`. That is not a retryable green
result: the child holder still used `time.sleep(1.5)` as the lock-retention mechanism, so
under VM scheduling pressure it could release the lock before the parent attempted
contention. The applied correction replaces that sleep with an explicit FIFO release
barrier in both the unit test and VM harness lock-exclusion scenario; the holder now keeps
the lock until the parent has observed the contender refusal and signals release. A fresh
50/50 batch was then run on the VM before reboot against
`99f8a9cfc5c7d69a8ec697832f850f544082aacd`: 50/50 clean, no failure markers, no
tracebacks, no timeout hits, no quarantine residues, and no test holder/worker process
left alive. The failed 8/50+failure batch is retained as evidence and is not counted as
clean.

Real VM validation for the final code-bearing seventh-round SHA was executed on
`wdvpn-linuxmint-23-6-7` against
`99f8a9cfc5c7d69a8ec697832f850f544082aacd`; the later documentation-only commit
records this evidence without changing executable provisioning code or tests. A full
BEFORE baseline was captured under `/home/gabodev/Desktop/temporales/watchdogvpn-task-23-7-5-6a-round7-reboot-validation`
before reboot: `boot_id`, `dpkg -l`, apt repository files, running services, `ip addr`,
routes, `ss -tulpn`, WatchdogVPN-related processes, `/var/lib/watchdogvpn` permissions,
listing and sha256 hashes, including a sudo-readable capture for the private subtree. The
pre-reboot VM checks then passed on that code-bearing SHA: focused provisioning module 254/254 OK,
VM `run-all` rc=0, and the 50-run batch described above completed 50/50 clean.

The six mandatory reboot checkpoints were first prepared under `/tmp`, but the hard reset
correctly demonstrated that `/tmp` is not a valid persistence location for reboot-crossing
state on this VM: recovery found no pending transactions. That failed evidence attempt is
retained under the round-seven evidence tree and is not counted as a passing recovery. The
next preparation under `/var/tmp` initially failed closed because the VM's `umask` created
scenario parents as `0775`; the newly hardened global-lock parent policy rejected those
group-writable parents before mutation. The final preparation explicitly created each
scenario parent as `0700` under `/var/tmp/wdvpn_round7_reboot_99f8a9c`; all six checkpoints
then prepared cleanly with SIGKILL at the intended barrier and persisted journals:
`after_apply_before_verify`, `undoing_before_unlink`,
`undoing_after_unlink_before_undone`, `after_unlink_before_applied`,
`after_verify_before_revoke`, and `after_revoke_before_uninstalled`.

Two snapshots were created during this validation:
`pre-23.7.5.6a-round7-reboot-validation` (`97c60b49-0994-4c09-b75a-ed6407941b3f`) and
`pre-23.7.5.6a-round7-prepared-reboot-validation`
(`07c4f423-c2e6-4f86-b028-52fd1c44ff04`). The actual recovery reset used a
hypervisor-level hard reset from VirtualBox. `boot_id` changed from
`ecbb3ff4-905c-4013-83b1-e85091b094ac` before reset to
`c18effdc-bd12-4ded-a29b-e185b30236a0` after reset. As in earlier rounds, the VM's
eCryptfs home required one interactive password SSH login after reboot before key-based
SSH was usable again; no password was written to evidence files. After the reset, all six
pending scenarios recovered with rc=0. The prepare recovery results were:
`after_apply_before_verify` resumed to `committed`; `undoing_before_unlink` and
`undoing_after_unlink_before_undone` resumed rollback to `preparation_failed` with empty
sandboxes. The uninstall recovery results were: `after_unlink_before_applied`,
`after_verify_before_revoke`, and `after_revoke_before_uninstalled` resumed to
`uninstalled`, each with `remaining_ownership_records: 0`.

Post-reboot VM checks then passed on the same SHA: focused provisioning module 254/254 OK,
VM `run-all` rc=0 including the round-seven quarantine/intermediate/lock/terminal-state
records, and 50 consecutive `run-all` repetitions on ext4-backed `/var/tmp` completed
50/50 clean. A first post-reboot 50-run attempt under the evidence directory in `$HOME`
failed on run 1 with a rollback residue because this VM's `$HOME` is eCryptfs-backed; that
attempt is retained as environmental evidence and is not counted as clean. The successful
post-reboot `/var/tmp` batch produced 50 logs, no `FAILED_RUN`, no traceback or timeout
hits, zero non-empty residue scans, and no leftover test worker/holder process; the only
matching process line across post-run captures was the pre-existing
`/usr/bin/python3 -m daemon.main`.

The AFTER baseline was captured with the same categories as BEFORE. Normalized comparison
showed `dpkg -l`, IP address (ignoring DHCP lease lifetime), routes,
`/var/lib/watchdogvpn` listing and `/var/lib/watchdogvpn` sha256 hashes unchanged.
Repository content was unchanged; the raw diff differs only because the before capture
included `ls -la` header lines and the after capture listed source filenames directly.
The running-service set differed by `fwupd.service` no longer being in the post-reboot
`running` set; `watchdogvpn.service` remained running. Socket differences were limited to
ephemeral mDNS UDP port values and ordering. `/var/lib/watchdogvpn/private` remained
`0700`, files remained `0600`/`0660` according to their prior ownership, and content hashes
matched exactly.

### Integral follow-up correction: descriptor custody, full path authority, and stable domain lock

The follow-up correction after the seventh round keeps the scope inside Task 23.7.5.6a and
does not start 23.7.5.6b. It addresses the remaining architectural weakness directly
rather than adding another name-based recheck around the old protocol.

- **Destructive removal now unlinks only inside descriptor-bound custody** (`paths.py`):
  `remove_file_if_owned_relative()` still opens the original resource with `O_NOFOLLOW`
  and keeps that fd open, but the quarantine destination is no longer a sibling basename
  in the resource parent. The file is moved with `renameat2(RENAME_NOREPLACE)` into a
  private `0700` custody directory opened relative to the allowed-root fd, verified to be
  on the same filesystem, then reopened from that custody fd with `O_NOFOLLOW`. The moved
  object's `st_dev`/`st_ino` and post-move sha256 must match the authorized original before
  the final unlink. The final unlink is still necessarily name-based at the kernel API
  level, but the name being unlinked lives in a descriptor-held private custody directory;
  if custody cannot be proven private and same-filesystem, deletion fails closed. Empty
  custody is removed after a clean delete; non-empty custody is retained as recovery
  evidence.
- **Ownership records now carry full durable path authority** (`model.py`, `journal.py`,
  `digest.py`, `engine.py`, `paths.py`): each product-owned candidate persists a
  `PathAuthority` containing the configured root path, exact target-relative path, exact
  component count, and ordered root/intermediate component identities (`index`,
  `relative_name`, `st_dev`, `st_ino`, uid, mode). The authority participates in the
  canonical ownership/uninstall digest and is serialized in ownership snapshots. Uninstall
  authority rejects records without this authority, with truncated chains, with reordered
  components, or with a substituted root/intermediate. Direct children of the root are
  explicit: their authority contains the root component and the full target-relative leaf
  name, not an implicit empty chain.
- **The exclusion domain uses a persistent primary lock** (`lock.py`): the durable flock
  under the dedicated `global_lock_root` is the primary machine-wide domain. The abstract
  Unix socket, when available, is defense-in-depth only because abstract sockets are scoped
  to a network namespace and cannot be the only authority for a machine-wide provisioner
  lock.
- **Terminal authority now requires full path authority** (`engine.py`): clean
  `COMMITTED`, rollback-clean, recovery-clean and `UNINSTALLED` paths verify allowed-root
  identity plus every product-owned record's durable `PathAuthority`. Legacy records that
  only have the older intermediate identity chain are not sufficient authority for
  destructive uninstall.

Local evidence for this follow-up correction: `PYTHONPATH=. python
tests/test_compat_transactional_provisioning.py` ran 258/258 clean after adding tests for
missing/truncated/reordered path authority and simultaneous `global_lock_root`/`state_root`
parent substitution. `python -m compileall -q compat/provisioning
tests/test_compat_transactional_provisioning.py tools/compat_provision.py`,
`git diff --check`, `tests/syntax.sh`, `python tools/compat_read.py validate`, the four
fixture probes, the four fixture resolve commands, and the real-host unknown-only resolve
pass all completed with rc=0. `tests/unit.sh` completed with rc=0. `PYTHONPATH=. python
-m unittest discover -s tests -p 'test_*.py'` ran 2243 tests with 1 skip and rc=0. The
focused provisioning suite then ran 50 consecutive local repetitions with no retries:
50/50 clean, no `FAILED`/`ERROR`/traceback/`TimeoutExpired` markers, no `.wdvpn-custody`
or `.wdvpn-quarantine*` residues found after any run, and logs retained under
`/tmp/wdvpn-23-7-5-6a-local50.X5TUTu`. The VM harness local `run-all` pass completed with
rc=0 against a temporary 0700 lab root, including descriptor-custody quarantine
substitution, in-place modification, no-replace restore, persisted intermediate swap,
unsafe lock-parent rejection, identity loss before terminal state, post-last-check TOCTOU,
intermediate real-directory swap, global-lock-root swap, and unreadable uninstall-journal
reactivation scenarios.

Real VM evidence for the final follow-up SHA
`16d2e7f22a889282ccca935cd248765004299962` was then executed on
`wdvpn-linuxmint-23-6-7`. The VM checkout was reset to that exact SHA. Before the hard
reset, the six mandatory reboot checkpoints were prepared with real SIGKILL boundaries:
`after_apply_before_verify`, `undoing_before_unlink`,
`undoing_after_unlink_before_undone`, `after_unlink_before_applied`,
`after_verify_before_revoke`, and `after_revoke_before_uninstalled`. The final durable
baseline was captured under `/var/tmp/wdvpn-round8-16d2e7f-reboot3` with an explicit
`sync` before the snapshot and hard reset; a previous baseline attempt without that sync
was rejected because the pre-reboot evidence files were observed as zero-length after the
hard reset. The accepted snapshot is
`pre-23.7.5.6a-round8-reboot3-synced-pre-hard-reset-16d2e7f`
(`facecc7b-ef97-4493-962c-f1adb1582aa7`). The accepted boot IDs are
`e58373b7-4c01-4106-9b59-065fd61b4163` before reset and
`5ba9cc02-2682-43d7-b298-b6127c8d67df` after reset. As in prior rounds, the VM's
eCryptfs home required one interactive password SSH login after the hard reset before
key-based SSH could read the checkout; no password was written to a file, command line,
commit or evidence artifact.

All six post-reboot recoveries completed with rc=0 on the same SHA. The apply checkpoint
resumed to `committed`; the two rollback checkpoints resumed rollback to
`preparation_failed` with no remaining capability files; all three uninstall checkpoints
resumed to `uninstalled`, removed the capability files, and left zero ownership records.
The before/after VM baseline comparison was explicit: `dpkg -l`, apt repository files,
running services, and `/var/lib/watchdogvpn` permissions/content hashes were byte-clean.
Only expected dynamic fields changed: `boot_id` and timestamp, the DHCP lease lifetime in
`ip addr`, and PIDs/command lines for the validation process itself. The post-reboot
focused provisioning suite ran 258/258 clean on the VM, post-reboot `run-all` completed
with rc=0, and a post-reboot 50-run batch completed 50/50 clean with no
`FAILED`/`ERROR`/traceback/`TimeoutExpired` markers, no live harness child processes after
any run, and no unexpected `.wdvpn-custody` or `.wdvpn-quarantine*` residues. The accepted
post-reboot 50-run logs are under
`/var/tmp/wdvpn-round8-16d2e7f-postreboot-vm50-final.ROEOry`. Earlier post-reboot 50-run
attempts with observer bugs were discarded rather than counted: one `grep -R` inspection
blocked on a FIFO, one `awk` filter was misquoted, and one process scan captured its own
controller shell.

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

### Structural correction after remote audit of 3f25f846

Remote audit of `3f25f8469e87cd661a8df796782f7ddcef3eab1c` did not close
Task 23.7.5.6a. This correction remains inside the provisioning subsystem and does not
start 23.7.5.6b.

- **Durable custody records** (`model.py`, `journal.py`, `paths.py`, `engine.py`):
  destructive removal now persists `CustodyRecord` entries for `MOVE_PENDING`, `MOVED`,
  and `DELETED`. `MOVE_PENDING` records the resource id, original identity, authorized
  hash, custody directory identity, and custody name before the rename. `MOVED` is written
  only after the no-replace rename and parent/custody directory fsyncs, with post-move
  identity and hash. `DELETED` is written only after the custody unlink and custody fsync.
  Pending custody records block clean uninstall/revocation instead of being interpreted as
  absence of the original basename.
- **Explicit custody isolation policy** (`paths.py`): custody remains descriptor-bound,
  same-filesystem, exact `0700`, and group/world non-writable. Callers that must defend
  against another process with the same uid can require uid separation; when the custody
  directory is owned by that configured adversary uid and no trusted custody uid applies,
  deletion fails closed before the rename/unlink. The code no longer treats a same-uid
  `0700` directory as proof of same-uid isolation.
- **PathAuthorityV2** (`model.py`, `journal.py`, `digest.py`, `paths.py`, `engine.py`):
  ownership now carries schema, transaction id, plan digest, resource id, configured root,
  root path, exact target-relative path, exact component count, ordered components, a
  canonical chain digest, and an authority digest. Components include root, every
  intermediate, and an explicit leaf. The leaf records `st_dev`, `st_ino`, uid, gid, mode,
  `st_nlink`, and integrity; direct children therefore persist exactly two components
  (`root`, `leaf`). Validation rejects a leaf replacement even if content, uid, gid, mode,
  and link count match.
- **Terminal prepare and uninstall protocol** (`model.py`, `engine.py`): prepare publishes
  ownership/provenance, fsyncs, revalidates the published authority, writes
  `PREPARE_TERMINAL_PREPARED`, fsyncs, revalidates again, and only then writes
  `COMMITTED`. Uninstall keeps ownership live through durable `UNINSTALLED`: after all
  resources are absent, it writes `REVOKING_OWNERSHIP`, validates the revocation boundary,
  writes `UNINSTALL_TERMINAL_PREPARED`, revalidates root/intermediate authority, writes
  `UNINSTALLED`, and only then attempts idempotent ownership cleanup.
- **Persistent lock domain is primary** (`lock.py`): the filesystem-backed flock under the
  dedicated global lock root is acquired before the optional abstract socket and is the
  only primary authority. The socket remains diagnostic/defense-in-depth, not a condition
  required for a machine-wide exclusion proof.

Local evidence for this correction: `python -m compileall compat/provisioning
tests/test_compat_transactional_provisioning.py` completed with rc=0, and
`python -m unittest tests.test_compat_transactional_provisioning` ran 263 tests in
12.493s with rc=0. The added tests cover durable custody state publication, crash
boundaries after `MOVE_PENDING` and after rename-before-`MOVED`, same-uid custody
fail-closed policy, direct-child `PathAuthorityV2` structure, and leaf replacement with
matching content and metadata but a different inode. `tests/syntax.sh`,
`python tools/compat_read.py validate`, and `git diff --check` completed with rc=0.
The full repository unittest discovery then ran 2248 tests in 342.284s with rc=0 and
1 skip.

### Same-UID custody isolation closure after audit of b2637b0

A final self-audit of `b2637b0f858865c4e455c398c78d3ede8ff41515` found one
remaining HIGH issue: the same-UID custody isolation defense existed only as an
optional policy on the primitive, while the normal rollback/uninstall flow still
used a lab-permissive default. That meant the implementation could still be
misread as protecting against another process with the same uid without enforcing
real privilege separation on the destructive path.

This correction makes strict custody isolation the default authority:

- `paths.py` now exposes `STRICT_CUSTODY_ISOLATION_POLICY` and
  `LAB_CUSTODY_ISOLATION_POLICY`. The descriptor-bound custody primitive defaults
  to the strict policy, which requires effective uid separation unless the custody
  directory uid is explicitly trusted. A same-uid `0700` custody directory is
  therefore fail-closed by default and is never documented as protection against a
  same-uid adversary.
- `ExecutionContext` carries the custody isolation policy. `CanaryExecutor`
  rollback and `engine.uninstall()` pass that policy into the real custody unlink
  primitive, so destructive engine flows do not silently fall back to lab
  semantics.
- The synthetic CLI and VM/unit harnesses opt into `LAB_CUSTODY_ISOLATION_POLICY`
  explicitly because they run as same-uid canary fixtures inside a dedicated lab
  root. The opt-out is visible in the call site; it is not the primitive or engine
  default.
- The VM reboot checkpoints that need to crash after a real unlink now call the
  descriptor-relative custody protocol through the locked `AllowedRootHandle`.
  They no longer use the legacy path-only `remove_file_if_owned()` as a surrogate
  for custody deletion.
- New regressions prove both primitive and engine behavior: a default
  `remove_file_if_owned_relative()` call rejects same-uid custody and preserves the
  target, and strict-policy uninstall fails closed without deleting marker or
  companion files and without revoking live ownership.

Local evidence for this correction: `python -m compileall compat/provisioning
tests/test_compat_transactional_provisioning.py
tests/vm/phase23_7_5_6a_transactional_provisioning_validation.py
tools/compat_provision.py` completed with rc=0; `python -m unittest
tests.test_compat_transactional_provisioning` ran 265 tests in 8.704s with rc=0;
`bash tests/syntax.sh`, `python tools/compat_read.py validate`, `git diff
--check`, the four fixture probes, the four fixture resolve commands, and the
real-host unknown-only resolve command all completed with rc=0. Full repository
unittest discovery ran 2250 tests in 258.154s with rc=0 and 1 skip. The focused
provisioning suite then ran 50 consecutive local repetitions with no retries:
50/50 clean from `2026-07-29T13:38:18Z` to `2026-07-29T13:45:54Z`, with zero
live provisioning Python processes and zero `.wdvpn-custody` or
`.wdvpn-quarantine*` residues after every run. Logs were retained under
`/tmp/wdvpn-23-7-5-6a-focused-50.Rc5DUI`. The VM harness `run-all` was also run
locally after the checkpoint migration and completed with rc=0, including the
real descriptor-custody unlink checkpoints and the post-last-check race scenarios;
evidence was retained at
`/tmp/wdvpn-6a-sameuid-postdoc.2f2ArI/phase23_7_5_6a_vm_evidence.json`.

VM evidence for code commit `56e4b00951d8127c307429328d516cb1c6259b0e` was
executed on `wdvpn-linuxmint-23-6-7` from an exact `git archive` deployment under
`/var/tmp/wdvpn-23-7-5-6a-56e4b00-20260729T134840Z/src`. The VM baseline recorded
Python 3.12.3 and boot id `5ba9cc02-2682-43d7-b298-b6127c8d67df`. The focused
provisioning suite completed with rc=0, the VM harness `run-all` completed with
rc=0, and the exact VM tree then ran 50 consecutive focused repetitions with no
retries: 50/50 clean from `2026-07-29T13:50:18Z` to
`2026-07-29T14:29:05Z`, with zero live provisioning Python processes after every
run. The scoped custody/quarantine scan reported six retained entries, all from
the intentional fail-closed `run-all` quarantine scenarios (`substitute`,
`inplace`, and `restore`, each retaining the custody directory plus the
quarantined object as recovery evidence); the count stayed constant throughout
the 50-run batch and did not represent new residue growth from the repetitions.
VM evidence paths:
`/var/tmp/wdvpn-23-7-5-6a-56e4b00-20260729T134840Z/evidence/focused.log`,
`/var/tmp/wdvpn-23-7-5-6a-56e4b00-20260729T134840Z/evidence/run-all.log`, and
`/var/tmp/wdvpn-23-7-5-6a-56e4b00-20260729T134840Z/evidence/vm-focused-50`.

Final HEAD `2ec6999b2d835e14fc45fc2171ee925cb186beec` then received a real
reboot recovery check on the same VM from an exact archive deployment under
`/var/tmp/wdvpn-23-7-5-6a-2ec6999-reboot-20260729T143244Z/src`. The six reboot
checkpoints were prepared independently, synced, and followed by a real
VirtualBox reset: `after_apply_before_verify`, `undoing_before_unlink`,
`undoing_after_unlink_before_undone`, `after_unlink_before_applied`,
`after_verify_before_revoke`, and `after_revoke_before_uninstalled`. Boot id
changed from `5ba9cc02-2682-43d7-b298-b6127c8d67df` to
`98a0d5c3-2780-4c20-b3f9-a7a2cbbc4a48`. All six post-reboot recoveries completed
with rc=0, the post-reboot focused provisioning suite completed with rc=0, the
reboot case custody/quarantine scan returned zero retained entries, and the
post-reboot live-process scan returned zero provisioning Python processes.
Evidence was retained under
`/var/tmp/wdvpn-23-7-5-6a-2ec6999-reboot-20260729T143244Z/evidence`.

Independent closure audit result: Task 23.7.5.6a was technically approved with
0 HIGH, 0 MEDIUM, and 1 non-blocking LOW finding. `LOW-01`: when uninstall is
deliberately executed under strict same-UID custody in the non-root lab harness,
the fail-closed path correctly preserves product-owned files, keeps ownership
live, and returns `uninstall_failed`, but leaves an empty `.wdvpn-custody`
directory in the sandbox. This is not a destructive-integrity failure: no
foreign inode is removed, no ownership is revoked, and no clean terminal state is
reported. The recommended follow-up, if the cosmetic residue is later cleaned
up, is to remove an empty custody directory best-effort when it was created by
the current call and strict validation fails before any file is moved, followed
by a parent-directory fsync.

### Task 23.7.5.6b AmneziaWG userspace source-build provisioning

Task 23.7.5.6b starts only the AmneziaWG userspace source-build migration. It
does not start Task 23.7.5.7, does not expose a public CLI surface, does not
wire `profile add`, `install.sh`, `update.sh`, `doctor.sh`, legacy distro
adapters, package-manager PPA execution, DKMS or kernel-module installation.
The executable surface for this task is the internal audit/VM tool
`tools/compat_runtime_prepare.py`.

The compatibility manifest now pins every AmneziaWG source-build component by
official release tag and exact Git commit:

- `amneziawg-tools`: upstream `https://github.com/amnezia-vpn/amneziawg-tools`,
  tag `v1.0.20260618-2`, commit
  `61e741780e8465a67a7d7fb6cffe14a8a15d624a`.
- `amneziawg-go`: upstream `https://github.com/amnezia-vpn/amneziawg-go`, tag
  `v3.0.2`, commit `0527dfa47639714dd8f5c9ffbd9d40d19083f0ba`.

The resolver marks a `pinned_source_build` candidate as execution-ready only
when the candidate is `implemented` and every component declares a release tag
plus immutable commit. The 23.7.5.6b internal provider deliberately reports
package-manager candidates as out of scope for this task, so the source-build
path can be audited without pretending that PPA/repository mutation was
migrated.
If the host already reports the AmneziaWG runtime present, `plan` and
non-mutating `prepare` report the resolver decision without constructing a fake
source-build plan. Recovery and uninstall register all pinned source-build
executors so existing WatchdogVPN ownership/journal authority can be handled
even when the live resolver no longer needs a new install.

The new production executor is
`compat.provisioning.amneziawg.AmneziaWGUserspaceSourceBuildExecutor`. It
installs exactly three userspace outputs under the configured install root,
defaulting to `/usr/local/bin`: `awg`, `awg-quick`, and `amneziawg-go`.
`/usr/local/bin` is used because this is a WatchdogVPN-managed source build,
not a distribution package; `/usr/bin` remains reserved for package-manager
owned files. If any target already exists and is not WatchdogVPN-owned, the
transactional engine returns an ownership conflict before writing anything and
grants no uninstall authority.

The executor never checks out a default branch. It fetches the exact tag,
resolves the checked-out commit, and aborts before build if the observed commit
does not match the manifest commit. The build user is explicit: mutating
provisioning commands require `--build-user <user>`, and that user must exist
and must not be root. Source workspace preparation, Git fetch/checkout and
build commands run as that build user; installation, recovery and uninstall
remain governed by the 23.7.5.6a provisioner lock, journal, custody, ownership
and terminal-state protocols. Command execution is isolated behind
`compat.provisioning.process` and uses argv-only subprocesses with
`shell=False`.
Git and make subprocesses receive an explicit sanitized build environment and
never inherit arbitrary parent-process variables. The allowlist is:
`HOME` (the selected build user's home), a fixed `PATH`
(`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`), fixed
`LANG=C.UTF-8`, fixed `LC_ALL=C.UTF-8`, `USER`, `LOGNAME`, and
`GIT_TERMINAL_PROMPT=0` so Git cannot block on an interactive credential
prompt.

Because source-build output hashes are known only after compilation, ownership
authority records the verified output SHA-256 at commit time. The plan must
declare `integrity_policy=record_verified_sha256`; the engine then stores that
verified digest in the ownership record, PathAuthorityV2 leaf integrity and
post-install fingerprint, and validates idempotency against the live file hash.
Static-digest executors keep the existing 23.7.5.6a behavior.

Local evidence at implementation time:

- `python -m compileall -q compat/provisioning tools/compat_runtime_prepare.py
  tests/test_compat_amneziawg_provisioning.py
  tests/test_compat_dependency_resolution.py tools/compat_read.py` completed
  with rc=0.
- `python -m unittest tests.test_compat_amneziawg_provisioning` ran 11 tests
  with rc=0, covering dynamic output digests, PathAuthorityV2 integrity,
  pre-existing-output preservation, commit mismatch before install, uninstall
  of owned outputs, idempotent second prepare, already-present CLI handling and
  source-build executor registration for recovery/uninstall, sanitized
  subprocess environment inheritance rejection, and VM post-reboot `boot_id`
  enforcement. The suite also covers recovery of a pending source-build prepare
  whose resumed apply fails, proving recovery persists `ROLLING_BACK` before
  completing rollback instead of attempting an invalid `APPLYING -> ROLLED_BACK`
  transition.
- `python -m unittest tests.test_compat_dependency_resolution` ran 32 tests
  with rc=0 after updating the AWG source-build contract from future/unresolved
  to implemented/pinned.
- `python tools/compat_read.py validate` completed with rc=0.
- Internal CLI smoke with a Debian 13 os-release fixture and
  `--force-runtime-absent plan` selected
  `amneziawg_pinned_source_build_apt_stable_future` with
  `execution_ready=true`.
- Internal CLI smoke on the local host without fixture completed with rc=0 and
  reported `already_present` with `plan=null`, proving the tool does not
  invent a source-build plan when the runtime is already available.
- `bash tests/syntax.sh` completed with rc=0.
- `git diff --check` completed with rc=0.
- Full repository unittest discovery ran 2261 tests in 308.799s with rc=0 and
  1 skip.
- The four fixture compatibility probes (`detect`, `capabilities`, `evaluate`,
  `report`) completed with rc=0. The four fixture resolver commands
  (`dependency`, `all`, `explain`, `matrix`) completed with rc=0; the AWG
  source-build fixture selected the pinned source-build candidate with
  `execution_ready=true`.
- The 23.7.5.6b VM harness smoke ran in non-mutating mode with rc=0 and
  produced v2 baseline evidence including boot id, package inventory probes,
  repository state, running services, network state, relevant processes,
  permissions, `/var/lib/watchdogvpn`, and output state.
- Real 23.7.5.6b VM reboot-recovery campaign on `wdvpn-linuxmint-23-6-7`
  completed with rc=0 using the internal harness, root-owned temporary
  state/lock/install/evidence roots under `/var/lib/wdvpn-6b-medium-*`, and a
  build workspace under `/home/gabodev/wdvpn-6b-medium-work`. The VM validation
  environment was prepared with `golang-go 2:1.22~2build1` so the real
  `amneziawg-go` source-build could complete; that package is visible in the
  captured pre-reboot package baseline. Pre-reboot evidence
  `/var/lib/wdvpn-6b-medium-evidence/pre.json` recorded boot id
  `a5acfe68-88b0-4b9f-b78e-578b35fef624`, baseline size 216848 bytes, and a
  durable pending prepare journal
  `vm6b_reboot_cb30a3bf0d67a145` in state `applying` with all three steps still
  `planned`. After a real VirtualBox reset, post-reboot evidence
  `/var/lib/wdvpn-6b-medium-evidence/post.json` recorded boot id
  `26fc162a-83df-4d31-bdcb-2d307482fbd0`, `boot_id_changed=true`, `recover`
  rc=0 with action `resume` and reason `resumed and committed`, post-recovery
  `status` showing the pending prepare `committed`, cleanup `uninstall --apply`
  status `uninstalled 3 resource(s)`, cleanup `status` rc=0, baseline size
  418043 bytes, and an empty temporary install root.
- The new AWG focal suite ran 50 consecutive repetitions with no retries:
  50/50 clean in 27s.
- Final independent audit of Task 23.7.5.6b approved the task technically with
  0 HIGH, 0 MEDIUM, and 0 LOW after verifying the synchronized worktree,
  GitHub/origin and `archvm` all at
  `f076dd678dbee3b9f4cbe8976b70e3eb592dfbcc`, plus the copied primary reboot
  evidence under
  `/home/gabodev/Desktop/temporales/watchdogvpn-23-7-5-6b-reboot-evidence/`.

The VM harness for this task is
`tests/vm/phase23_7_5_6b_amneziawg_validation.py`. It captures baseline
evidence and drives only the internal tool. Its `run-all` command remains a
single-boot smoke. Reboot recovery evidence is split into
`prepare-reboot-campaign` before the real VM reboot and `recover-after-reboot`
after the reboot; the latter refuses success unless the pre-reboot and
post-reboot `boot_id` values differ. Its `--apply` mode is intended for
disposable VMs; it does not activate profiles, mutate VPN/DNS/firewall state or
claim L4 traffic certification.

### Task 23.7.5.7 System migration

Task 23.7.5.7 migrates the legacy shell distro-detection layer to the manifest
and engine built in the preceding tasks, without changing the manifest, the
pure domain modules, the transactional provisioner, the AmneziaWG migration or
any public CLI surface.

The new entrypoint `tools/compat_distro_classify.py` is an internal wrapper that
reads `compat/compatibility.json`, invokes `compat.detection` to resolve the
host identity and support classification, and emits a stable JSON document.
`lib/distro.sh` consumes that document as its primary source of truth for:

- `DISTRO_SUPPORTED` — set when the engine reports `certified`, `supported` or
  `family_inferred`.
- `DISTRO_FUTURE` — set when the engine reports `experimental`.
- `DISTRO_UNSUPPORTED` — set when the engine reports `unsupported`.
- `DISTRO_ADAPTER_ID`, `DISTRO_FAMILY`, `DISTRO_PACKAGE_MANAGER` — identity
  fields used by the legacy adapter-loading path.

The shell↔engine contract is the JSON shape produced by
`tools/compat_distro_classify.py`; the wrapper intentionally consumes an
internal Python function from `compat.detection` and is maintained in lock-step
with that module during this phase.

If Python or the engine is unavailable, `lib/distro.sh` falls back to a minimal
pure-Bash bootstrap reader. That fallback resolves only mechanical identity:
`DISTRO_ID`, `DISTRO_NAME`, adapter/family and a package-manager seed. It does
not reconstruct `support_classification`, does not mark any distro as supported
and does not produce `DISTRO_FUTURE=1`. In that degraded state the distro is
reported as `DISTRO_UNDETERMINED=1` and the installer/doctor/updater treat it as
unsupported. This preserves the design rule that the manifest+engine is the
single source of truth for support policy.

`doctor.sh`, `install.sh` and `update.sh` now distinguish three outcomes:

- supported → continue normally;
- future → fail with "planned for a future release";
- unsupported/undetermined → fail with "unsupported distro".

Files added or modified in this task: `tools/compat_distro_classify.py`,
`lib/distro.sh`, `lib/common.sh` (helper messages only), `install.sh`,
`update.sh`, `doctor.sh` (message wiring), `tests/unit/test_distro_detection.sh`,
`tests/test_compat_system_migration.py` and this document. Files explicitly not
touched: `compat/compatibility.json`, `compat/compatibility.schema.json`,
`compat/support_model.py`, `compat/detection.py`, `compat/dependency_resolution.py`,
`compat/provisioning/*`, `lib/amneziawg.sh`,
`diagnostics/amneziawg_guidance.py`, `tools/compat_runtime_prepare.py`,
`distros/*.sh`, `lib/packages.sh`, `lib/singbox.sh`, `lib/cloak.sh` and
`cli/main.py`.

### Task 23.7.5.8 L1 coverage audit & closure

Task 23.7.5.8 audits the L1 test coverage of tasks 23.7.5.1 through 23.7.5.7,
closes the mandatory L1 gaps found, and produces an auditable coverage report.
No product feature, manifest, detection/provisioning semantics, public CLI or
host mutation is added.

Independent audit verdict: **APPROVED** — 0 HIGH / 0 MEDIUM / 0 LOW. The final
audit was performed on `archvm` against commit
`491ff4d97e1f0e0ac9d2534840197e9ffc1834a2`, with `HEAD = origin`, ahead/behind
`0 0`, and `main` intact at `8b15d470e8abca62a5bb3b72873be6bfecbaf56f`.

Two documentation-traceability findings were raised and corrected during the
audit cycle before final approval:

- MEDIUM: `docs/phase-23-7-5-8-l1-coverage-report.md` initially left the
  implementation commit as a placeholder and attributed validation results to
  the previous base commit. This was corrected to record
  `fc9f1ced310b922f1ab424ed55bb5ebf33490e12` as the implementation commit and to
  state that final validations were run against that commit.
- LOW: the handoff/memory files initially marked 23.7.5.8 as closed before
  final auditor approval, and a trailing-whitespace issue was left in the L1
  report. Both were corrected before final approval.

Mandatory gaps closed in this task:

- Exit-code contract of `tools/compat_distro_classify.py`: usage errors return
  exit code `1`; manifest/detection errors return exit code `2`.
- Multi-family pure-Bash fallback in `lib/distro.sh`: the fallback derives
  mechanical identity for arch, redhat and suse families without ever claiming
  support or setting `DISTRO_FUTURE=1`.
- Engine-failure degradation in `lib/distro.sh`: invalid JSON, non-zero exit and
  timeout from the Python engine all degrade to the pure-Bash fallback.
- `lib/common.sh` state-message helpers: `print_unsupported_distro`,
  `print_future_distro` and `print_undetermined_distro` emit the expected text.
- `doctor.sh` read-only wiring: future, unsupported and undetermined distro
  states are reported correctly.
- Transactional provisioner cross-operation lock: `prepare()` and `uninstall()`
  contend for the same global lock and never run concurrently.

Files added or modified in this task:
`tests/test_compat_system_migration.py`,
`tests/test_compat_transactional_provisioning.py`,
`tests/unit/test_distro_detection.sh`,
`tests/unit/test_shell_distro_state.sh`,
`tests/unit/test_doctor_distro_state.sh`,
`tools/compat_distro_classify.py`,
`docs/phase-23-7-5-8-l1-coverage-report.md` and this document.
Files explicitly not touched: `compat/compatibility.json`,
`compat/compatibility.schema.json`, `compat/detection.py`,
`compat/dependency_resolution.py`, `compat/support_model.py`,
`compat/provisioning/*`, `lib/packages.sh`, `distros/*.sh`, `lib/distro.sh`,
`lib/common.sh`, `install.sh`, `update.sh`, `doctor.sh` and all public CLI /
runtime / network / VPN / DNS / firewall code.

Validation recorded for the closure commit:
`bash tests/unit/test_distro_detection.sh` rc=0;
`bash tests/unit/test_shell_distro_state.sh` rc=0;
`bash tests/unit/test_doctor_distro_state.sh` rc=0;
`python3 -m unittest tests.test_compat_system_migration` 6 tests rc=0;
`python3 -m unittest tests.test_compat_transactional_provisioning` 266 tests rc=0;
`python3 -m unittest discover -s tests -p 'test_compat_*.py'` 489 tests rc=0 with 1 skip;
`python3 -m unittest discover -s tests` 2268 tests rc=0 with 1 skip;
`bash tests/syntax.sh` rc=0;
`python3 tools/compat_read.py validate` rc=0;
`python3 tools/compat_distro_classify.py classify` on Arch reports
`support_classification: certified`;
fallback simulation with empty `PATH` reports
`DISTRO_ID=arch SUPPORTED=0 FUTURE=0 UNSUPPORTED=0 UNDETERMINED=1`;

### Task 23.7.5.9 `pruebas_por_versiones`

Task 23.7.5.9 adds the L2 per-version layer: a CI container matrix that runs real,
disposable-container dependency resolution against every supported family/release,
a scheduled repository-availability job, and explicit offline negative-test coverage.

Files added or modified in this task:
`tests/test_compat_dependency_l2_negative.py`,
`tests/test_compat_dependency_l2_real.py`,
`tests/test_compat_l2_reporter.py`,
`tools/compat_l2_reporter.py`,
`tools/run_compat_l2_matrix.py`,
`.github/workflows/compat-l2-matrix.yml`,
`.github/workflows/repo-availability-cron.yml`,
`compat/compatibility.json`,
`compat/detection.py`,
`docs/phase-23-7-5-9-plan.md` and this document.
Files explicitly not touched:
`compat/compatibility.schema.json`,
`compat/dependency_resolution.py`,
`compat/support_model.py`,
`compat/provisioning/*`,
`lib/distro.sh`,
`lib/common.sh`,
`install.sh`,
`update.sh`,
`doctor.sh` and all public CLI / runtime / network / VPN / DNS / firewall code.

Design deviation recorded: the frozen design listed a single
`.github/workflows/ci.yml` containing both the matrix and the scheduled job.
This task splits them into `.github/workflows/compat-l2-matrix.yml` (PR/push
and manual dispatch) and `.github/workflows/repo-availability-cron.yml` (daily
06:00 UTC). The split isolates the heavy, network-dependent L2 matrix from the
fast L1/unit/syntax gate and matches the different trigger cadence. The two
workflows together implement the single "CI container matrix + scheduled
repo-availability job" requirement from the frozen design.

Key implementation details:

- `tests/test_compat_dependency_l2_negative.py` exercises the resolver with the
  injected `StaticAvailabilityProvider` without containers. Coverage includes
  target-series rejection, availability propagation, unsupported/EOL
  classification, recipe-not-implemented vs method-selected, manifest
  integrity/data regression checks, and unsupported architecture.
- `tests/test_compat_dependency_l2_real.py` contains
  `ContainerAvailabilityProvider`, which probes packages, repository metadata,
  source-build tags and pinned artifacts inside disposable containers.
  `execute_l2_matrix_case()` builds `DistroFacts` from `/etc/os-release`,
  evaluates support, runs `resolver.resolve_all()`, and queries the packages
  declared by the selected candidate for every dependency requirement.
- `tools/run_compat_l2_matrix.py` drives `execute_l2_matrix_case()` over all
  `CASES` and writes raw and rendered reports.
- `tools/compat_l2_reporter.py` reads raw results and produces
  `compat-l2-matrix.json` / `compat-l2-matrix.md`. It also runs the scheduled
  cron checks and produces `repo-availability-report.json`.
- `.github/workflows/compat-l2-matrix.yml` detects Docker/Podman, fails fast if
  neither is available, runs the matrix, uploads reports, and fails if any
  mandatory target is not green.
- `.github/workflows/repo-availability-cron.yml` runs read-only availability
  checks daily at 06:00 UTC, uploads the report, and fails on any unavailable
  external resource. It does not open issues, does not commit the manifest, and
  does not create PRs.

GitHub Actions platform limitation recorded for Task 23.7.5.9: the repository
availability cron could not be executed as a real `workflow_dispatch` run during
this task because GitHub does not index newly added manually-dispatchable
workflows until the workflow file exists on the default branch. The workflow file
exists on `phase-23-7-5-compatibility-contract`, but it is not present on `main`,
so `gh workflow run repo-availability-cron.yml --ref
phase-23-7-5-compatibility-contract` returns GitHub API HTTP 404 and the workflow
is absent from the repository workflow index. This is a known platform indexing
limitation, not a defect in the reporter or workflow code.

The cron reporter logic was still verified with real network execution against
the corrected code: `run_cron_checks()` produced 17 checks total, 10 available,
0 unavailable and 7 unknown container-image checks because no available
environment had Docker or Podman. The corrected EPEL repository metadata URLs use
`/epel/9/Everything/<arch>/repodata/repomd.xml` and returned real `HEAD 200`
results for both `x86_64` and `aarch64`; the rejected `/epel/epel9/...` form is
not used.

Follow-up for Task 23.7.5.14 `cierre_y_merge`: after this branch is merged to
`main`, manually dispatch `.github/workflows/repo-availability-cron.yml` for the
first time from GitHub Actions and inspect the uploaded
`repo-availability-report.json` artifact to confirm the real scheduled-workflow
path on the default branch.

`validation_metadata.per_release_ci` is never updated by an automated workflow
commit; it is updated only by a human-reviewed commit after inspecting the
artifact.

Artifact inspection during the L2 matrix hardening found two real version-level
breaks that the matrix must not hide. First, `rockylinux:9` already includes a
working `curl` implementation via `curl-minimal`, so the matrix now prepares the
HTTP probe tool idempotently with `command -v curl || <package-manager install>`
instead of forcing DNF to replace `curl-minimal` with `curl`. Second, Ubuntu
26.04 and Debian 13 no longer have `dnsutils` as the exact installable package
used by the DNS helper capability: Ubuntu 26.04 exposes `dnsutils` as a virtual
package provided by `bind9-dnsutils`, and the Debian 13 APT index lists
`bind9-dnsutils` while omitting `dnsutils`. The manifest therefore keeps
`dnsutils` for Ubuntu 24.04 / Linux Mint 22.3 and adds a separate exact APT
candidate for Debian 13 / Ubuntu 26.04 using `bind9-dnsutils`.

For `external_repo_exact` APT candidates, L2 now validates package availability
against the declared external repository's `Packages.gz` index instead of asking
the base container's unconfigured APT cache. The repository metadata probe still
has to pass first, and the package name must be listed by the exact declared
series before the candidate can qualify.

`git diff --check` rc=0.

### Task 23.7.5.10a `validacion_en_vms` - Debian/Ubuntu/Mint L3 wave

Task 23.7.5.10a is approved and closed for the Debian/Ubuntu/Mint L3 wave. It
validated the certified Debian 13.6, Ubuntu 24.04.4 LTS and Linux Mint 22.3 VMs
against the compatibility contract without performing L4 real-traffic field
certification. Evidence is stored outside the repository under
`/home/gabodev/Desktop/temporales/evidencia_phase23/watchdogvpn-task-23-7-5-10a-l3-debian-ubuntu-mint/`.

Debian's doctor.sh gate required an out-of-plan `systemd-resolved` installation via `update.sh --yes` to pass; this action was retroactively authorized by the maintainer after full disclosure, and is recorded as accepted remediation, not as a pure in-scope L3 validation. It also confirms `update.sh` correctly reconciles a pre-23.7.5.4 certified install to the current capability contract.

Validated scope:

- Version gates from `/etc/os-release`, not VirtualBox `OSType`: Debian 13.6
  (`trixie`), Ubuntu 24.04.4 LTS and Linux Mint 22.3 (`zena`, base
  `UBUNTU_CODENAME=noble`).
- Manifest validation and distro classification: all three resolved as
  `certified`; Mint resolved as `linuxmint_22_3` mapped to `ubuntu_24_04`.
- L3 canary run-all on clean private checkouts in `/var/tmp`.
- Six reboot-recovery checkpoints per VM:
  `after_apply_before_verify`, `undoing_before_unlink`,
  `undoing_after_unlink_before_undone`, `after_unlink_before_applied`,
  `after_verify_before_revoke` and `after_revoke_before_uninstalled`.
- `doctor.sh` `FAIL=0` on Ubuntu and Mint in the in-scope run; Debian reached
  `FAIL=0` after the maintainer-approved retroactive remediation above.
- Evidence permissions repaired and re-verified: all evidence directories `0700`
  and files `0600`.
- Teardown residue remediated and verified absent for
  `/var/tmp/wdvpn-23-7-5-10a-debian`,
  `/var/tmp/wdvpn-23-7-5-10a-ubuntu` and
  `/var/tmp/wdvpn-23-7-5-10a-linuxmint`.

Findings and corrections recorded during closure:

- Process finding: the Debian `update.sh --yes` mutation was originally outside
  the approved 10a scope; the maintainer accepted it retroactively after full
  disclosure.
- Positive product finding: a Phase 23.5-certified Debian install that lacked
  `systemd-resolved` was reconciled to the current post-23.7.5.4 capability
  contract by `update.sh --yes` without additional manual product changes.
- Audit findings corrected: `known_hosts` evidence files were changed from `0644`
  to `0600`; the Debian gate typo `bookworm` was corrected to `trixie`; leftover
  `/var/tmp` L3 workdirs were removed from all three VMs and verified absent.
- Linux Mint `casper-md5check.service` was confirmed as a pre-existing live-ISO
  checksum unit failure (`/cdrom/md5sum.txt` absent), observed in both current
  and previous boot journals, unrelated to WatchdogVPN.
- Gabo separately requested a Linux Mint lab optimization to allow SSH access
  before graphical eCryptFS unlock by using `/etc/ssh/authorized_keys/gabodev`;
  this was outside the 10a validation scope and is recorded as maintainer-requested
  lab setup, not product behavior.

No product code was changed in Task 23.7.5.10a. The product checkout used for L3
validation was `bf0b8ef`; this closure is documentation-only. No L4 real traffic
or field certification was performed in 10a; those remain explicitly out of scope
until the 23.7.5.11.x waves. The next planned L3 wave is 23.7.5.10b
Arch/CachyOS, but it must not start without explicit maintainer authorization.

## Kali NetworkManager DNS/TUN remediation (2026-08-11)

Before H1 work, a real regression observed on the bridge-only Kali VM was
closed: after applying DNS through NetworkManager, sing-box teardown could leave
`wdvpn-tun0` and its transient NM profile behind, or capture that interface in
the DNS restoration snapshot.

The correction was published in four commits:

- `0545fc9`: isolates privileged TUN-profile cleanup in a fixed root unit, a
  no-argument helper and a Polkit rule limited to starting that exact unit.
  Disconnect fails closed if privileged cleanup cannot run.
- `450366f`: excludes `wdvpn-tun0` and `watchdogvpn_awg` from DNS snapshots by
  connection name or device.
- `8a61090` and `ac38c4a`: remove inherited setgid from the root DNS restoration
  directory and enforce final mode `root:root:0700`.

Local validation passed the complete Python suite with 2362 tests and 2 skips,
plus `tests/unit.sh`, `tests/syntax.sh`, installation-security contracts, runtime
transaction tests, `git diff --check` and manifest validation. The L2 matrix for
exact HEAD `ac38c4a` passed in run #40 (`31496744105`). Earlier runs #36/#37
classified Rocky 9 as `unknown` after a transient EPEL query timeout; their six
other targets and cleanup were green.

Installed validation on exact HEAD `ac38c4a` passed VLESS
`ubuntu_gabo_yahoo_firefox`, NetworkManager DNS apply and real SOCKS HTTPS with
status 200. Disconnect returned to `standby` with no TUN, NM profile, route,
rule, sing-box nftables table, process, listener or DNS snapshot; the resolver
returned to NetworkManager/DHCP (`192.168.0.1`) and journal contained no
restore/cleanup error or `runtime_mismatch`.

This block does not promote Kali: it remains `experimental`, creates no
`cert_kali_rolling`, does not update `last_validated`, and does not modify the
manifest.

## H1 installed runtime provenance

H1 closes the forward-looking evidence gap exposed by the unrecoverable
historical Kali marker. `tools/installed_provenance.py` builds and verifies a
canonical SHA-256 inventory of the complete shipped runtime tree. Publication is
inside the existing install/update transaction and occurs only after the daemon
smoke test. Source and installed path sets and bytes must match exactly; unsafe
symlinks, special file types, missing files, added files or changed bytes refuse
publication and trigger rollback.

The provenance manifest records the full source commit, source state, install
timestamp, shipped top-level path set, installed ownership/modes, per-file hashes
and canonical tree/generation digests. The public `installed-version` marker
binds that manifest by SHA-256. A commit is attributable only when each observed
shipped path's type, executable mode and bytes match the immutable blobs of the
resolved `HEAD`, with no extra shipped paths. Dirty, unversioned or unverifiable
sources fail closed before publication; install/update require a clean committed
checkout before replacing runtime files, and the provenance builder repeats the
Git-blob attribution check before writing the manifest. Legacy commit-only
markers remain readable for version-skew diagnostics but cannot satisfy H1. A
missing marker, a legacy marker or an incomplete schema-2 marker/manifest pair
is a hard doctor failure for an H1 runtime.

Before publication, install/update compare the active wrapper and unit with
their pre-deployment expected hashes, reject an effective fragment, drop-in or
`ExecStart` outside the inventoried chain, and require the newly started daemon
to report the same digest as a fresh local generation fingerprint. These checks
remain inside the rollback boundary. Active publication receives that exact
smoke-approved digest and refuses to build a manifest for any generation that
changed before publication. The explicit inactive/hibernated path has no active
digest to bind and is accepted only after `ActiveState=inactive` and `MainPID=0`.

The installed daemon launcher fingerprints the installed tree, active wrapper
and deployed service unit before and after importing the Python daemon. It
refuses a generation that changes across that boundary. `watchdog status --json`
exposes the stable startup digest as `payload.runtime_provenance`. `doctor.sh`
verifies root ownership and modes (including protected ancestors), current
installed and deployed bytes, and the marker/manifest binding, then requires the
active daemon's captured generation digest to match the installed manifest. File
drift, manifest tampering or a stale daemon generation is a hard doctor failure.
The effective systemd fragment must be the inventoried unit and out-of-scope
drop-ins are rejected. Runtime/deployment ancestor policy is repeated at build,
launch, pre-publication verification and doctor time, while deployment file
descriptors remain held through a final joint name/inode check. A hibernated or
automation-disabled install may skip active-generation IPC only when systemd is
inactive and `MainPID` is zero.

H1 changes neither `compat/compatibility.json` nor any Kali support evidence.
It provides a prerequisite for future installed validation; it does not recover
or retroactively attribute the historical unavailable commit.

### H1 validation and strict-contract remediation (2026-08-11)

H1 was implemented in `df836ee` and its first independent acceptance audit found
one HIGH race between the successful active-daemon smoke and manifest
construction. Commit `300353c` closed that race by making the exact
smoke-approved generation digest a mandatory active-publication precondition. A
later stricter audit rejected the broader H1 blocker because dirty,
unversioned/unverifiable source and absent/legacy provenance still degraded
instead of failing closed, and because TUN cleanup still selected NetworkManager
profiles by global name. The strict remediation changes that contract: `8476757`
makes install/update preflight reject dirty or untracked source, manifest
publication reject non-clean attribution, existing unattributed manifests fail
verification, and `doctor.sh` mark missing/legacy hashed provenance as `FAIL`.
It also replaces name-only TUN cleanup with a root-owned registered UUID. Commit
`961bd3f` fixes the real Kali update failure where root-owned staging required
`sudo` for compileall.

A second independent judge rejection found that the new registry still lived
under daemon-controlled `/run/watchdogvpn`, and that install/update could still
mutate runtime dependencies before rejecting dirty source. Commit `c39b12b`
moves the registry to `/run/watchdogvpn-nm-tun/owned-uuid`, backed by systemd
`RuntimeDirectory=watchdogvpn-nm-tun`, `RuntimeDirectoryMode=0700`,
`RuntimeDirectoryPreserve=yes`, and `ReadWritePaths=/run/watchdogvpn-nm-tun`.
Registry IO now uses descriptor validation plus `O_NOFOLLOW`, `O_CREAT`,
`O_EXCL`, `fstat`, `fsync` and atomic rename. install/update now run
`require_clean_source_checkout` immediately after argument parsing and before
distro checks, privilege checks, dependency provisioning or runtime mutation.

Strict-remediation local validation for `c39b12b` passed 2403 Python tests with
2 skips, 171 focal H1/TUN/sing-box tests, `tests/unit.sh`, `tests/syntax.sh`,
compileall, manifest validation and `git diff --check`. A later live Kali TUN
evidence run found that `c39b12b` was still not sufficient: the installed
`python -m drivers.networkmanager_tun_cleanup` wrapper dispatched by
`sys.argv[0]`, so the register unit executed the cleanup path and did not create
`/run/watchdogvpn-nm-tun/owned-uuid`. Commit `78a56da` fixes that real blocker
by passing explicit `register` and `cleanup` modes from the systemd units and
making the Python entrypoint reject unknown modes. Independent suite validation
for the current tree reported 2403 Python tests with 2 skips, and focused local
validation for `78a56da` passed the focused
`tests.test_networkmanager_tun_cleanup` suite, `tests/unit/test_install_security_contracts.sh`,
`tests/syntax.sh`, compileall and `git diff --check`. The stricter H1/Polkit/TUN
remediation was later approved by audit as a technical prerequisite for Kali
23.7.5.10e, not as Kali promotion or task closure.

The bridge-only Kali installation on exact commit `78a56da` published
`source_state=clean`, 247 inventoried entries, tree digest
`f3d5482e06064f1f0e693b5c53bdc87552ae615b5a75e8b275d636e60455f4bf`,
generation digest
`6907215c332fd2b6b13bdd87bd780a36e477058a8d5a00b11e11b77d0b585f33`,
and manifest digest
`0e97b5d2ef85a2a4a28758b53d3ac2f38d5df838fd3cc53d0acaeacf190189cd`.
The active daemon reported the same generation. The first synthetic Kali gate
evidence at `/var/tmp/wdvpn-h1-polkit-tun-78a56da-evidence-20260812T003253Z/`
proved the helper and UUID semantics but did not prove the full WatchdogVPN
connect/disconnect route. The accepted live-route revalidation evidence is
stored on Kali at
`/var/tmp/wdvpn-real-route-h1-polkit-tun-78a56da-evidence-20260812T071632Z/`.
In that run, WatchdogVPN connected the real `ubuntu_gabo_yahoo_firefox` VLESS
profile through sing-box, created the real active `wdvpn-tun0`, and
`watchdogvpn-nm-tun-register.service` executed with
`ExecStart=/usr/local/bin/watchdogvpn-nm-tun-register register`. The register
unit wrote `/run/watchdogvpn-nm-tun/owned-uuid` as `root:root 600`; the UUID
matched the active owned TUN profile exactly while a deliberately foreign
inactive same-name TUN profile used a different UUID. Normal `watchdog
disconnect --json` then executed `watchdogvpn-nm-tun-cleanup.service` with
`ExecStart=/usr/local/bin/watchdogvpn-nm-tun-cleanup cleanup`, returned the
daemon to standby, removed only the registered owned profile, preserved the
foreign same-name TUN profile until explicit root cleanup, and left final
inventory with no `wdvpn-tun0`, WatchdogVPN routes/rules, registry entry,
dummy profile or `sing-box` residue. The synthetic gate also verified that a
deliberately untracked source file made `update.sh --dry-run` fail in the
`Source provenance preflight` section before `Runtime dependencies`,
`Protocol runtime provisioning` or `Replace product files`, and that Polkit
denied unrelated systemd actions and foreign NetworkManager profile
mutation/delete/add attempts.

Before the 10e certification, the installed doctor correctly retained one global
`FAIL` because Kali remained `experimental`; that was not an H1 failure or
support promotion. H1 created no `cert_kali_rolling` and did not update
`last_validated`. The final H1/Polkit/TUN audit approved that work as a
technical prerequisite; the subsequent full 10e certification and audit are
documented below.

### Kali 23.7.5.10e certification and promotion

Kali rolling was certified in Task 23.7.5.10e on 2026-08-12 after the complete
bridge-only L3 validation and independent audit. The validated checkout was
HEAD `7035b933c257f129dcc314bd191ad4f1ced8ac83` (short `7035b93`) and the
reference snapshot was `pre-23-7-5-10e-kali-l3-validation`. The private evidence
is stored under
`/home/gabodev/Desktop/temporales/evidencia_phase23/watchdogvpn-task-23-7-5-10e-kali-protocol-matrix-20260812T104756Z/`
and the lifecycle evidence for the same task.

The certification matrix contains 9 `green` protocol results with real egress:
VLESS, Trojan, Hysteria2, AmneziaWG, OpenVPN+Cloak, VMess, TUIC, SOCKS and
HTTP. WireGuard, Shadowsocks and plain OpenVPN are `formal_non_green` Plan-B /
no-egress rows and are not counted as green. Provider lifecycle, DNS,
app-policy-neutral, kill switch, rotation, manual-off, sleep/wake, reboot and
final cleanup also passed. The manifest record is `cert_kali_rolling` with
`scope=physical_field_certification`.

The `--certification-lab` mechanism is an explicit field-validation escape hatch
for a distribution that is still classified as `experimental`. It is enabled
only when the caller supplies both `WATCHDOGVPN_CERTIFICATION_LAB=1` and
`WATCHDOGVPN_FIELD_VALIDATION=1`, together with the `--certification-lab` CLI
flag. The `distro_certification_lab_enabled()` function is the shared gate used
by install/update. It permits the controlled installation and validation needed
for Kali 10e, but it does not itself promote a distribution, change the manifest,
or create a certification record. The mechanism was added in commit `75a1e63`.
Kali's later promotion is represented separately by `cert_kali_rolling` and its
rolling `last_validated` metadata after the full audit approval.

### Real end-user experimental-distro override (distinct from the lab gate)

`--certification-lab` was never meant for real users - it exists for our own
field-validation runs and requires internal environment variables no ordinary
installer invocation sets. Before this override existed, a distro that
resolved to `experimental` had no path forward for an actual user except
editing the shell scripts directly, which is exactly what happened in
practice: independent reports surfaced of users running WatchdogVPN
successfully on Manjaro, Pop!_OS and Zorin OS after locating and bypassing
`require_supported_distro()`'s hard exit themselves.

`lib/distro.sh` now exposes `distro_experimental_override_accepted()` and
`distro_record_experimental_override()`, and `lib/common.sh` exposes
`prompt_experimental_distro_override()`. When `DISTRO_FUTURE=1`,
`install.sh`/`update.sh` offer three ways forward, checked in this order:

1. The internal `--certification-lab` gate (unchanged, still lab-only).
2. A previously recorded acceptance for the *same* `DISTRO_ID`
   (`${WATCHDOGVPN_ETC_CONFIG_DIR:-/etc/watchdogvpn}/.experimental-distro-override`,
   parent directory created as `0700`, marker mode `600`) - a stale acceptance
   for a different distro never carries over.
3. `--accept-experimental-distro-risk` for non-interactive/scripted runs, or an
   interactive `[y/N]` prompt on a real TTY.

None of these three paths change `support_classification` in the manifest or
create a certification record - the distro remains honestly `experimental`.
They only let WatchdogVPN run because the user explicitly chose to accept
that risk, instead of requiring them to edit product code to do so.
`doctor.sh` reports the override state honestly too: `WARN` instead of `FAIL`
on `DISTRO_FUTURE` when an accepted override is on record for the currently
detected distro. Tests: `tests/unit/test_experimental_distro_override.sh`
(new), `tests/unit/test_doctor_distro_state.sh` (extended with the override
case).

### Task 23.7.5.11A.1 Ubuntu 24.04 field recertification

Ubuntu 24.04 was recertified under the 23.7.5.11A contract on 2026-08-13 and
approved by an independent `juez-tester` audit. The target host was `nls1`
(`Ubuntu 24.04.4 LTS`, kernel `6.8.0-137-generic`) with a clean checkout and
final installed runtime aligned to commit `c0a525e8950001700a9cb85699aef2818a053993`.
The private evidence root is
`/home/gabodev/Desktop/temporales/evidencia_phase23/watchdogvpn-task-23-7-5-11A-1-ubuntu-20260813T104226Z/`.

The initial protocol matrix contained 11 `green` protocol results with real
traffic: VLESS, Trojan, Hysteria2, OpenVPN+Cloak, AmneziaWG, WireGuard, VMess,
Shadowsocks, SOCKS, HTTP and TUIC. WireGuard and Shadowsocks are green for
Ubuntu for the first time in the project history because this run produced fresh
real-egress evidence. Plain OpenVPN was initially kept as `formal_non_green`: the
repaired HMAC/origin profile and the new unique-CN client reached TLS and pool
assignment, but both direct OpenVPN and WatchdogVPN-routed tests had no useful
real egress at that time.

OpenVPN+Cloak is green through an authorized bridge-only Ubuntu 24.04 VM
(`wdvpn-ubuntu-2404`) using `04_OpenVPN_Cloak_gabo_nuevo_FIX.vpn`. The `nls1`
attempt showed a server-specific zero-RX tunnel symptom and is documented as a
target-specific failure, not hidden or used as a substitute for green evidence.
AmneziaWG was green after the product-guided Ubuntu PPA path supplied `awg`,
`awg-quick` and the runtime module; no source-build fallback was used.

The certification uncovered and fixed a real installed-provenance bug. Normal
Python CLI/runtime imports can create `__pycache__/*.pyc` under the installed
runtime. The manifest publication already excluded Python cache files from the
source tree, but installed-tree publication, generation fingerprinting and
verification were not fully symmetric. This made `doctor.sh` report provenance
drift after normal CLI use even though only benign bytecode cache files had
changed. Commit `76d1b42` makes `collect_tree(..., exclude_python_cache=True)`
apply consistently to installed generation fingerprinting, manifest publication
and verification, and rejects cache paths inside published manifests. The
regression test now asserts that raw `fingerprint_tree()` still sees bytecode
changes, while `fingerprint_generation()` stays stable and
`verify_installation()` returns `verified`.

Commit `c0a525e` updates `cert_ubuntu_24_04` to date `2026-08-13T00:00:00Z`
with per-protocol evidence notes. It also relaxes the manifest validator so a
protocol whose global category is `formal_non_green` may remain
`formal_non_green` for older certifications or become `green` when fresh real
egress evidence exists; resilient and normal compatibility protocols still
require `green`. This preserves historical non-green certifications while
allowing Ubuntu's fresh WireGuard and Shadowsocks greens.

Independent and executor validations both passed: full suite `2425 OK, 2
skipped`, `python3 tools/compat_read.py validate` OK, `bash tests/syntax.sh` OK
and `git diff --check` clean. On `nls1`, after final install from `c0a525e`,
five `watchdog status --json` calls returned rc=0; `python3 -m compileall -q
/usr/local/lib/watchdogvpn` generated 158 `.pyc` files; installed-provenance
verification still returned rc=0; and final `doctor.sh` returned
`OK=146 WARN=1 FAIL=0`. The auditor independently reproduced the provenance fix
with normal CLI commands generating bytecode, then confirmed `doctor.sh` still
reported `FAIL=0` without reinstalling.

A second-pass audit found one evidence-handling issue: two repaired OpenVPN
profiles containing embedded private material were stored as `0664`. Their
containing evidence directory was `0700`, but the explicit evidence-secret rule
requires `0600`. The files were corrected to `0600` and rechecked as
`-rw-------`; no file content changed.

The Ubuntu OpenVPN plain row was reopened in a strictly focal pass on 2026-08-14
after the Debian 11A.2 investigation identified and corrected real WatchdogVPN
OpenVPN bugs affecting that earlier Ubuntu non-green result. The reopening did
not repeat the other 11 protocol rows because they were not affected by the
OpenVPN-specific fixes and their original 11A.1 evidence remains reused. The
focal target was `nls1` running Ubuntu `24.04.1 LTS`; the installed runtime was
from commit `28565250b050b56bc003a4d49b95ad30027d22d6`, which includes the
OpenVPN fixes through `17348e6`. Profile `openvpn-138.124.91.224-1194` connected
with rc `0`, produced egress IP `138.124.91.224`, returned HTTP `200` for
YouTube, Facebook and Instagram, disconnected with rc `0`, and left a clean
teardown (`standby`, no TUN/runtime artifacts, inactive kill switch). The judge
approved the field revalidation. The focal evidence bundle is
`watchdogvpn-task-23-7-5-11A-1-ubuntu-openvpn-retest-youtube-facebook-instagram-20260814T104827Z.tar.gz`
with SHA256 `43bf270944ef6769839f50d8a0d568267dc8910f7b38ab30450615292474c871`.
`cert_ubuntu_24_04` is therefore dated `2026-08-14T00:00:00Z`, plain OpenVPN is
promoted to `green`, and Ubuntu 11A.1 now has 12/12 `green` protocol results.

### Task 23.7.5.11A.2 Debian 13 field recertification

Debian 13 was recertified under the 23.7.5.11A contract on 2026-08-14 and
approved by an independent `juez-tester` audit. The target host was `nls1`,
with final installed runtime aligned to commit
`17348e660aff6aed9a6d584b04c323999816b1c4`. The private final evidence root is
`/home/gabodev/Desktop/temporales/evidencia_phase23/watchdogvpn-task-23-7-5-11A-2-debian-final-20260814T0800Z/`.
The final bundle is
`watchdogvpn-task-23-7-5-11A-2-debian-final-20260814T0800Z.tar.gz` with SHA256
`d64d0cf013759a7ae1dd9a99394c17ff58a586b691a5dfbbb0217c601747df8a`.

The final protocol matrix contains 12 `green` protocol results with real
traffic: VLESS, Trojan, Hysteria2, AmneziaWG, WireGuard, VMess, Shadowsocks,
SOCKS, HTTP, TUIC, plain OpenVPN and OpenVPN+Cloak. WireGuard, Shadowsocks and
plain OpenVPN become green for Debian for the first time in the project history
because this run produced fresh real-egress evidence for those rows. The HTTP
row had one initial IP-probe timeout (`rc=28`), then a documented retry
(`09_http_retry`) produced egress `138.124.91.224`, HTTP `204` and clean
teardown.

OpenVPN+Cloak is green through the authorized bridge-only Debian VM
`wdvpn-debian13-openvpn-cloak` using `oc-138.124.91.224-wdvpnkal`. This is
recorded as an explicit VM substitution for that row, not as an `nls1` success.
All other rows were validated on `nls1`: VLESS `ubuntu_gabo_yahoo_firefox`,
Trojan `gaboturbo.serveminecraft.net`, Hysteria2
`gaboturbo.serveminecraft.net-2`, AmneziaWG `awg-138.124.91.224-LI3jGvaI`,
WireGuard `10.9.0.2/32`, VMess `vmess-138.124.91.224-ubuntu`, Shadowsocks
`shadowsocks-138.124.91.224-ubuntu`, SOCKS `socks-138.124.91.224-ubuntu`, HTTP
`http-138.124.91.224-ubuntu`, TUIC `tuic-138.124.91.224-ubuntu` and plain
OpenVPN `openvpn-138.124.91.224-1194`.

The Debian run also found and fixed real runtime safety bugs before the final
recertification was accepted. Commits `f18179d`, `0c08936` and `17348e6` make
OpenVPN endpoint validation fail closed before the driver, native policy driver
or kill switch mutate state. Invalid OpenVPN profiles with hostnames, private
IPv4 remotes or multiple remotes now return rc `70` before teardown or route
mutation. Field evidence on `nls1` confirmed H-01/H-02/H-03 did not dismantle an
active valid OpenVPN tunnel.

Commit `17348e6` is the technical runtime baseline for the final Debian field
run. The closure commit updates `cert_debian_13` to date
`2026-08-14T00:00:00Z` and promotes WireGuard, Shadowsocks and plain OpenVPN to
`green` based on the fresh Debian 11A.2 real-egress evidence. Final
provenance/doctor state was clean: `nls1` reported `status=verified`, generation
`57a8b1314162943c36d36b6af80b027d9327930079def7c2833cafd33538c486`, no TUN or
runtime artifacts, kill switch inactive, and doctor `OK=146 WARN=1 FAIL=0`; the
authorized VM reported `status=verified`, the same generation, no TUN or runtime
artifacts, kill switch inactive, and doctor `OK=144 WARN=3 FAIL=0`.

### Task 23.7.5.11A.3 Linux Mint 22.3 field recertification

Linux Mint 22.3 was recertified under the 23.7.5.11A contract on 2026-08-14 and
approved for closure by the maintainer. The target host was `nls1` (`Linux Mint
22.3 (Zena)`, `ID=linuxmint`, `UBUNTU_CODENAME=noble`, kernel
`7.0.0-28-generic`), with final deployed runtime aligned to commit
`aa1d3bf6c97f3a1c63577e435dfba4ab15170e76`
(`fix(runtime): respect manual VPN supervision`) and installed provenance
verified (`status=verified`). The private protocol-matrix evidence is under
`/root/wdvpn-23-7-5-11A-3-mint-protocols/evidence`; the controlled deploy/reboot
evidence is under
`/home/gabodev/Desktop/temporales/evidencia_phase23/watchdogvpn-task-23-7-5-11A-3-mint-aa1d3bf-controlled-deploy-20260814T222516Z/`;
the isolated fault-validation evidence is under
`/home/gabodev/Desktop/temporales/evidencia_phase23/watchdogvpn-task-23-7-5-11A-3-mint-aa1d3bf-isolated-fault-validation-20260814T231258Z/`;
and the post-test contamination restoration evidence is under
`/home/gabodev/Desktop/temporales/evidencia_phase23/watchdogvpn-task-23-7-5-11A-3-mint-test-contamination-cleanup-20260815T002147Z/`.

The final protocol matrix contains 12 `green` protocol results with real
traffic: VLESS, Trojan, Hysteria2, AmneziaWG, OpenVPN+Cloak, VMess, SOCKS, HTTP,
TUIC, plain OpenVPN, WireGuard and Shadowsocks. WireGuard, Shadowsocks and plain
OpenVPN were historically `formal_non_green` Plan-B/no-egress rows in the Mint
certification; they are promoted to `green` based on fresh Linux Mint 22.3 11A.3
real-egress field evidence. No `formal_non_green` row remains in this
certification.

The real reboot lifecycle on `nls1` was validated in both directions: with
`autoconnect=false`, a reboot returned to `standby` with no TUN, inactive kill
switch, and direct DNS/egress; with `autoconnect=true`, a reboot recovered
automatically with `wdvpn-tun0`, sing-box, the nftables kill switch applied and
VPN egress `138.124.91.224`. Final cleanup left profiles `[]`, `standby`,
`desired_state=off`, `active_profile_id` empty, no TUN/sing-box/routes/rules,
direct DNS and direct egress `79.137.197.255`.

The isolated fault harness (real `RuntimeWorker` with isolated
`StateManager`/`ProfileStore`/DNS snapshot and fake driver/kill-switch) verified
that `dns_restore_failed` and `kill_switch_disable_failed` remain fail-closed,
are diagnostically recorded in `last_failure_reason`, and never trigger automatic
connect/recovery/rotation on subsequent ticks.

Honest limitation recorded: no real DNS/firewall fault injection was performed on
live `nls1`. Closure was accepted on the basis of real successful reboots, real
recovery and cleanup, isolated-harness fail-closed coverage, and complete green
local tests. The cross-cutting follow-up (a real fault-injection test must only
run on a disposable VM/snapshot, and tests must isolate persistent paths so they
never write `/var/lib/watchdogvpn` when run as root) does not block this closure
and must not be attributed to Arch/CachyOS as any form of distro certification.

Sub-phase 23.7.5.11A (Debian family) is now fully closed for its three certified
releases: Ubuntu 24.04 (11A.1) and Linux Mint 22.3 (11A.3) belong to technical
family `ubuntu_apt`; Debian 13 (11A.2) belongs to `debian_apt`. Certification is
per-release — other Debian/Ubuntu derivatives remain `family_inferred`, not
`certified`.

### Task 23.7.5.11B Arch Linux field recertification closure (2026-08-15)

Arch Linux (rolling) was field recertified under the 23.7.5.11B contract on
`nls1` (Arch Linux rolling, kernel `7.1.8-arch1-3`, hostname `nls-1`, KVM).
Final runtime HEAD: `cd112b4` (`fix(daemon): tolerate incomplete driver cleanup
on shutdown with fail-closed barrier`). This was the first distribution of
sub-phase 11B; CachyOS was subsequently recertified (2026-08-17), closing the
sub-phase.

Final matrix: **12/12 `green`** protocol results with real egress on `nls1`.
WireGuard, Shadowsocks and plain OpenVPN — historically `formal_non_green` in
`cert_arch_rolling` — are promoted to `green` based on fresh 11B real-egress
field evidence. The other nine (VLESS, Trojan, Hysteria2, OpenVPN+Cloak,
AmneziaWG, VMess, TUIC, SOCKS, HTTP) remain green.

Validated on `nls1`:
- Clean install + provenance (`status=verified`, generation `a1a16df8...`),
  doctor `FAIL=0`.
- 12/12 real-egress protocol matrix (per-protocol connect/disconnect with
  clean teardown, kill switch applied per connection, no residue between
  protocols).
- Reboot lifecycle: `autoconnect=false` reboot -> standby clean with direct
  egress; `autoconnect=true` reboot -> automatic recovery with real VPN egress.
- Isolated fault harness (real `RuntimeWorker` with isolated state/profile/DNS
  and fake driver/kill-switch): `dns_restore_failed` and
  `kill_switch_disable_failed` stay fail-closed, never auto-reconnect, remain
  diagnosed in `last_failure_reason`.
- Shutdown FAILURE fix (`cd112b4`): the daemon no longer exits with
  `status=1/FAILURE` when stopped/rebooted with an active connection while the
  fail-closed barrier is applied.
- Final cleanup: standby, profiles `[]`, no TUN, firewall base only.

### Task 23.7.5.11B CachyOS field recertification closure (2026-08-17)

CachyOS (rolling) was field recertified under the 23.7.5.11B contract on `nls1`
(CachyOS rolling, hostname `nls-1`, KVM, root ext4, GRUB BIOS). Installation used
checkout `a88bef3` with verified provenance; AmneziaWG used the CachyOS rolling
pinned source-build method and was verified as `awg`, `awg-quick`, and
`amneziawg-go`. This closes the second distribution of sub-phase 11B, making the
whole 11B (Arch Linux + CachyOS) complete.

Final matrix: **12/12 `green`** protocol results with real egress on `nls1`.
WireGuard, Shadowsocks and plain OpenVPN — historically `formal_non_green` in
`cert_cachyos_rolling` — are promoted to `green` based on fresh 11B CachyOS
real-egress field evidence. The other nine (VLESS, Trojan, Hysteria2,
OpenVPN+Cloak, AmneziaWG, VMess, TUIC, SOCKS, HTTP) remain green.

Five blocks were executed and independently audited:
1. **Installation & provenance**: clean install on `a88bef3`, provenance verified,
   doctor `FAIL=0`.
2. **12/12 real-egress protocol matrix** with HTTP 200x3 per profile; WireGuard,
   Shadowsocks and plain OpenVPN promoted from `formal_non_green` to `green`.
3. **Reboot lifecycle A/B**: `autoconnect=false` reboot -> standby clean/direct
   egress; `autoconnect=true` reboot -> automatic recovery of WireGuard
   `10.9.0.2/32` with tunnel, kill switch and real VPN egress.
4. **Isolated fault harness** (real `RuntimeWorker` with isolated
   state/profile/DNS): `dns_restore_failed` and `kill_switch_disable_failed` stay
   fail-closed over four real worker ticks, no auto-reconnect, diagnosed in
   `last_failure_reason`.
5. **Final cleanup**: deploy key GitHub `160429004` revoked, build-user
   `wdvpn-build-11b-cachyos` removed, temporary SSH keys and certification
   artifacts removed; firewall base verified structurally intact (diff empty) pre
   and post; no-regression confirmed.

Final host state: standby, profiles `[]`, firewall base only (default-deny
intact), no TUN, no protocol processes, clock synchronized, zero failed units,
doctor `OK=146 WARN=1 FAIL=0` (sole WARN: truth state DOWN in standby, accepted
and non-blocking).

Evidence (private): `evidencia_phase23/watchdogvpn-task-23-7-5-11B-cachyos-nls1-*`
(install, matrix, reboot-lifecycle, reboot-plan, isolated-fault, cierre).

### 23.7.5.11.x official structure (§14.1, realigned 2026-08-16)

Mandatory order (external design §14.1, revision 5):

```
11-PRE → 11A → 11B → 11C → 11D → 11E → 11F → 11G → 11H
```

| Sub-phase | Distributions | Notes |
|---|---|---|
| 11-PRE | (policy only) | CLOSED. Certification-review advisory signal. |
| 11A | Ubuntu, Debian, Linux Mint | Debian family. CLOSED (12/12 each). |
| 11B | Arch Linux, CachyOS | Arch family, rolling. **CLOSED (2026-08-17)** — Arch Linux (2026-08-15) and CachyOS (2026-08-17), 12/12 each. |
| 11C | Fedora, Rocky Linux, AlmaLinux 9 | RPM family. AlmaLinux officially in scope (two-step admission + field cert). **Fedora CLOSED (2026-08-20)** — 12/12 green with real egress on nls1. **Rocky Linux CLOSED (2026-08-21)** — 12/12 green, reboot lifecycle, isolated fault harness and final cleanup, all APROBADO. AlmaLinux 9 not yet authorized. |
| 11D | openSUSE Leap, Tumbleweed | Tumbleweed must be fully validated. |
| 11E | Kali Linux | Audit 10e evidence first; may reuse if it satisfies. |
| 11F | CentOS Stream | Official; full L1-L5 pass from zero. RHEL out of scope. |
| 11G | Pop!_OS | New community-requested distribution; full admission/cert from zero. |
| 11H | Manjaro | New community-requested distribution; full admission/cert from zero. **Last reactive community addition to this list** - see policy note below. |

**Policy note (2026-08-16):** 11H Manjaro is the last sub-phase added reactively
to a community report. Future community distro requests (e.g. Zorin OS) are
logged as backlog candidates, not automatic new sub-phases; they are handled
primarily through the real end-user experimental-distro override described
above, and only become a new formal sub-phase by a fresh, explicit maintainer
decision comparable in weight to 11G/11H (real recurring usage, low
incremental cost via an already-certified family, or a concrete business
reason) - never as a default reaction to a single message.

#### 11B — Arch family (Arch Linux, CachyOS)

- Rolling model, no min-anchor concept. No expiry-driven deadline; the
  11-PRE review signal is advisory only.
- Reuse/delta-audit policy: AmneziaWG is a mandatory fresh real-traffic re-run
  in every sub-phase; other protocols are reused only with an explicit audit
  note when a clean 10.x L3 wave exists under the current HEAD. A full
  12-protocol validation is authorized whenever a clean server reinstall is
  actually happening (it did for 11B Arch Linux).
- **Arch Linux is on `nls1`'s panel template list** (normal one-click
  reinstall, no pre-phase needed) and is now field recertified.
- **CachyOS is not** on the template list: it needs the "Pre-phase: server
  image transplant" procedure (install in a local VM, transplant the installed
  disk to `/dev/vda`), with the `mkinitcpio` HOOKS/virtio check taken
  seriously before assuming it boots on the target hardware.

History: sub-phase 11A (Debian family) is fully closed. 23.7.5.11B Arch Linux
was closed on 2026-08-15 and 23.7.5.11B CachyOS on 2026-08-17, so sub-phase 11B
(Arch family) is now **fully closed** (12/12 each). The next sub-phase is 11C
(RPM family: Fedora, Rocky Linux, AlmaLinux 9), not yet authorized.

#### 11C — RPM family (Fedora, Rocky Linux, AlmaLinux 9)

**Fedora 44 field recertification CLOSED (2026-08-20)** on `nls1` (Fedora 44
Cloud, kernel 7.1.8-200, runtime `bd316eb`, provenance verified). Five blocks
closed and **APROBADO** by juez-tester:

- **Block 1 (install):** WatchdogVPN installed with provenance verified (gen
  `f39d2241...`). Real product bug found and fixed (TDD, commit `bd316eb`):
  installer/doctor rejected the legitimate Fedora global systemd drop-in
  `/usr/lib/systemd/system/service.d/10-timeout-abort.conf`; fixed to tolerate
  global package drop-ins while still rejecting service-specific drop-ins.
  Doctor `OK=146 WARN=3 FAIL=0` after publish.
- **Block 2 (matrix 12/12):** All **12 protocols GREEN** with real egress HTTP
  200x3 on `nls1`. WireGuard, Shadowsocks and OpenVPN plain promoted from
  `formal_non_green` to `green` with fresh field evidence. OpenVPN plain
  operational finding: first attempt `rc=70` due to NAT/forward on `aeza-vps`
  server (resolved by maintainer, infra not product); second attempt with
  `ovpn_auto.sh` auto-disconnect succeeded with real egress HTTP 200x3x6.
  Evidence: `...-matrix-20260819T183659Z.tar.gz` (SHA
  `667398662ca795691cb6620bd66115d5af64b5b6f0c088f1f6004f13548240d9`).
- **Block 3 (reboot lifecycle):** Executed by another implementer. Evidence:
  `...-reboot-lifecycle-20260819T211139Z.tar.gz`.
- **Block 4 (isolated fault harness):** `dns_restore_failed` and
  `kill_switch_disable_failed` validated fail-closed, 4 ticks each, no
  auto-reconnect, isolation manifest pre/post sha256 identical. Profile sintético,
  total isolation (CachyOS pattern). Evidence:
  `...-isolated-fault-20260820T003918Z.tar.gz`.
- **Block 5 (cleanup):** 11 profiles removed with backup verification (H1),
  per-step verification (H2), doctor full text (H3), secrets outside bundle
  (H4). Final state: `perfiles=[]`, standby, no TUN, firewall intact
  (`ssh`+`dhcpv6-client`), SELinux Enforcing. Evidence:
  `...-cierre-20260820T082700Z.tar.gz`.

Deploy key `nls1-11c-deploy-readonly-*` (ID 160832574) NOT revoked — still
needed for AlmaLinux 9 within 11C.

**Rocky Linux 9.8 field recertification CLOSED (2026-08-20)** on `nls1`
(Rocky Linux 9.8 Blue Onyx, kernel `5.14.0-687.39.1.el9_8`, runtime `b23577b`,
provenance verified). Bloque Pre + Bloque 1 + Bloque 2 closed and APROBADO by
juez-tester:

- **Bloque Pre (sanitization):** SELinux **Enforcing** (was Disabled, full
  relabel, no AVC denials), sudoers reduced to `root ALL=(ALL) ALL` (`%wheel`
  removed), firewalld public `ssh`+`dhcpv6-client` (cockpit removed), LLMNR off
  (5355 not listening), journal clean, egress v4 `79.137.197.255` + v6
  `2a12:5940:2bba::2`.
- **Bloque 1 (install):** cloned `phase-23-7-5-11C-rpm` HEAD `b23577b`,
  `compat_distro_classify.py classify` → `rocky rocky_9 certified`, install OK,
  provenance `status=verified` (`source_commit=b23577b`,
  `generation_sha256=29c8c1296c...`), doctor `OK=145 WARN=3 FAIL=0`. No
  product-specific Rocky SELinux bugs under Enforcing.
- **Bloque 2 (matrix 12/12 green with real egress):** all 12 protocols
  connected with real egress HTTP 200x3 on `nls1`. **WireGuard, Shadowsocks
  and plain OpenVPN promoted from `formal_non_green` to `green`** with real
  egress HTTP 200x3 **plus a 100MiB download** (`size=104857600`, dl_rc=0)
  through the tunnel. AmneziaWG used the product's guided flow (COPR
  `amneziawg-tools` + `amneziawg-go` source-build). OpenVPN plain re-validated
  with the `ovpn_auto.sh` auto-disconnect-by-timeout pattern (validated in
  Fedora) — the SSH session dropped on `def1` route redirect and the server
  recovered automatically, confirming the mechanism is required on Rocky too.
  Evidence:
  `evidencia_phase23/watchdogvpn-task-23-7-5-11C-rocky-nls1-matrix-20260820T193340Z.tar.gz`
  (SHA256 `2bbce34d5a278d6716054311df1894a9c0b96bb0dd9ff0f7bdf4352c761b65e5`).
- **Work extra (maintainer-ordered, outside Bloque 2 plan):** provider
  `netz-tg-provider` (35 nodes) added and rotation proven between nodes
  (UK→AT→EE→BG, real egress each); controlled DNS-leak test showed **no leak**
  (all DNS incl. forced queries to 1.1.1.1/8.8.8.8/OpenDNS/Quad9 resolve to
  fakeip `198.18.0.x`, responses from `172.19.0.2`); **fakeip working**
  (domains resolve to `198.18.0.0/15`, traffic via sing-box listener). Split
  tunnel domain rule `facebook.com→direct` does NOT divert facebook data
  traffic in sing-box/fakeip mode (documented honest finding).

`cert_rocky_9` updated: date 2026-08-20, 12/12 green, scope
`physical_field_certification`, evidence referencing the matrix tarball SHA.

**Rocky Linux 9.8 Bloque 3 — reboot lifecycle CLOSED (2026-08-21)** on `nls1`,
both scenarios executed against runtime `0f086e8`.

- **Product bug found and fixed (TDD, previous session):** the daemon entered a
  crash-loop at startup with `autoconnect=true` when endpoint resolution failed
  (`EndpointPolicyConnectionError` escaped `runtime.startup()` →
  `status=1/FAILURE` restart loop). Fix `0f086e8`
  (`fix(daemon): degrade to standby on endpoint resolution failure during
  startup`) captures the error and degrades to standby with
  `last_failure_reason=endpoint_resolution_failed`. Scope: `core/watchdog.py`
  (+4) and `tests/test_core_watchdog.py` (+48). Full suite 2469 OK (2 skipped);
  CI L2 run `32415905576` green. Independent judge verdict: APROBADO (HIGH risk
  verified point by point; cryptographic proof that `nls1` was NOT redeployed
  before the fix).
- **Escenario B (autoconnect=true):** redeployed `nls1` to `0f086e8`
  (provenance `status=verified`, 247 files, generation `ab7c0932...`);
  `watchdog_panic wake` after maintainer's `watchdog_panic sleep` (the
  `.hibernating` marker correctly kept `update.sh` from auto-starting the
  service); doctor FAIL=0; Trojan connected (TUN + kill switch + HTTP 200x3);
  real reboot → **NRestarts=0, no crash-loop, standby retrying cleanly**
  (startup logged `watchdog_startup_endpoint_resolution_failed` and stayed
  alive); manual reconnect verified (TUN + kill switch + HTTP 200x3); clean
  manual disconnect; final doctor `OK=146 WARN=2 FAIL=0`.
  - **Operational finding H1 (HIGH, pre-existing, non-blocking for this
    scenario):** automatic post-reboot recovery cannot complete for
    hostname-endpoint profiles: the startup kill switch only allows DNS to the
    internal resolver `172.19.0.2` (requires sing-box running), so endpoint
    resolution stays blocked and retries never succeed until manual
    disconnect→connect. The scenario's explicit criterion ("standby retrying
    cleanly; crash-loop is not acceptable") is met; the fix does exactly what
    it promises. Maintainer decision pending: accept as documented limitation
    or open new work (e.g. kill-switch DNS exemption for profile endpoints).
- **Escenario A (autoconnect=false):** clean initial state (standby, doctor
  FAIL=0, no residue); `vpn_autoconnect_enabled=false` verified by direct read
  of `/var/lib/watchdogvpn/state.toml` (a manual disconnect already sets it
  false via the respect-manual-supervision semantics of `aa1d3bf`, which is why
  `watchdog setup --autoconnect disable` reported `no_changes`); Trojan
  connected (TUN + kill switch + HTTP 200x3); real reboot → daemon started,
  logged `standby mode - autoconnect disabled`, did NOT attempt to connect;
  standby with empty active profile, kill switch inactive, nftables table
  absent, DNS resolving normally, **direct egress with exact server IP
  `79.137.197.255`**, doctor `OK=146 WARN=2 FAIL=0`, NRestarts=0, journal
  clean, no residue.
- Evidence (private):
  `evidencia_phase23/watchdogvpn-task-23-7-5-11C-rocky-nls1-reboot-lifecycle-20260821T080614Z.tar.gz`
  (Escenario B, 220 files, SHA256 `c531f0f6...`) and
  `...reboot-lifecycle-scenarioA-20260821T085822Z.tar.gz` (Escenario A, 80
  files, SHA256 `fea640f0...`). Implementer self-audits: both APROBADO.

**Rocky Linux 9.8 Bloque 4 — isolated fault harness CLOSED (2026-08-21)** on
`nls1`, executed against the `0f086e8` checkout (same commit as the deployed
runtime). Real `WatchdogRuntime` and `RuntimeWorker` over per-scenario
`TemporaryDirectory` sandboxes; no real DNS/firewall/VPN mutation.

- **Scenario A (`dns_restore_failed`):** synthetic WireGuard profile
  `sintetico-wg-fault`; sandbox state seeded `desired=on`,
  `autoconnect=false`; DNS snapshot with manager `systemd-resolved` restored
  through the real `SystemDNSStateManager` path with the runner forced to fail
  on `resolvectl flush-caches`. `startup()` returned
  `dns_restore_failed` (core/watchdog.py:501-503), kept the fail-closed
  diagnostic state (`vpn_desired_state` stayed `on`, `active_profile_id`
  preserved, snapshot not unlinked), and 4 real worker ticks each reported
  `dns_restore_failed` in standby with zero `connect`/`health_check` calls.
- **Scenario B (`kill_switch_disable_failed`):** DNS restore succeeded first
  (snapshot consumed), then the injected kill switch reported
  `disable()=True` while staying active (partial-disable mode, the stricter
  half of the `core/watchdog.py:505` condition). `startup()` returned
  `kill_switch_disable_failed`; 4 real worker ticks each reported the same
  status with zero connect/health calls and the kill switch still active.
- **Isolation:** every `WatchdogRuntime` field with real I/O redirected to the
  sandbox (21-field table in the evidence `design_notes.md`); env-var safety
  net (`WATCHDOGVPN_CONFIG_DIR` + all `*_FILE`/`*_DIR` overrides) so any
  forgotten default lands in the sandbox; wide isolation manifest
  (`/var/lib/watchdogvpn` full tree, `/etc/watchdogvpn`, `resolv.conf`, nft
  tables, firewalld, links, protocol processes, failed units, checkout
  cleanliness, `/tmp` residue, AVC window, daemon error journal) byte-identical
  pre/post; explicit AVC check validated as reliable before trusting its
  result (`avc_new_events_in_window=0`, SELinux Enforcing); doctor
  `OK=146 WARN=2 FAIL=0` pre and post; checkout clean at `0f086e8`; no
  residue. Evidence permissions 0700/0600.
- Evidence (private):
  `evidencia_phase23/watchdogvpn-task-23-7-5-11C-rocky-nls1-isolated-fault-20260821T122253Z.tar.gz`
  (24 files, SHA256 `2b2b9deb895afa24025d7ea4d386a07904b50bde0ee699a4c99345daefec6d13`).
  Implementer self-audit: APROBADO.

**Rocky Linux 9.8 Bloque 5 — final cleanup CLOSED (2026-08-21)** on `nls1`,
executed as a real destructive operation with per-step traceability:

- **Backup before any deletion:** `watchdog backup create --section profiles`
  (rc=0) to `/root/wdvpn-23-7-5-11C-rocky-cierre-backup/` — kept OUTSIDE the
  evidence bundle (secrets never travel with the package). Independent
  verification two ways: `watchdog backup inspect --json` (rc=0, valid) and
  direct zip read of the inner `profiles.json` → **exactly 47 entries**
  (`{"items": [...], "schema_version": ...}`), id set identical to the live
  profile set.
- **Per-profile deletion, 47→0:** each of the 47 profiles (35 subscription +
  12 manual) removed individually via `watchdog profile remove --json`; every
  step recorded rc=0 plus a real recount from the CLI after the deletion
  (descending 47→0, no bulk command). Final count: **0**; on-disk
  `/var/lib/watchdogvpn/profiles.json` is literally `[]`.
- **Integrity:** `/var/lib/watchdogvpn/state.toml` sha256 identical before and
  after the whole backup+deletion sequence (`190fd3b1...`, unchanged); clean
  state content (`active_profile_id=""`, `last_failure_reason=""`).
- **Final state:** standby, desired off, kill switch inactive, no TUN,
  firewall base intact (`public`: ssh + dhcpv6-client), zero failed units, no
  protocol processes, doctor full text `OK=146 WARN=2 FAIL=0`. Honest note:
  `providers.json` still holds the registered provider entry (scope was
  profiles only).
- Evidence (private):
  `evidencia_phase23/watchdogvpn-task-23-7-5-11C-rocky-nls1-cierre-20260821T201051Z.tar.gz`
  (12 files, SHA256 `4bc47055834b7c70d6aeb27e1a72a1aff6ea15a79ca8aee2de0f8cbefc3d0241`;
  contains ids/counts/rcs/hashes only — no credentials). Backup archive stays
  server-side only. Implementer self-audit (checkpoint): APROBADO.

**Rocky Linux 9.8 FULLY CLOSED within 11C (2026-08-21):** Bloques Pre+1+2
(`06e7b1e`), Bloque 3 reboot lifecycle (`8ad1bd8`, daemon fix `0f086e8`),
Bloque 4 isolated fault harness (`692b467`) and Bloque 5 final cleanup all
CLOSED and APROBADO by independent audit. `cert_rocky_9` verified current at
12/12 green, date 2026-08-20, scope `physical_field_certification`.

**AlmaLinux 9.5 field recertification — Bloque 2 (matrix 12/12 green) CLOSED
(2026-09-02)** on `nls1` (AlmaLinux 9.5 Teal Serval, kernel
`5.14.0-503.15.1.el9_5`, runtime `9258219` after the import-fix update,
provenance verified). Bloques A, Pre and 1 closed previously (see
`02_11c_almalinux_9_evidence.md`). Bloque 2 closed and self-audited
APROBADO, pending independent juez-tester audit:

- **Bloque 2 (matrix 12/12 green with real egress):** all 12 protocols
  connected with real egress HTTP 200x3 on `nls1`. **WireGuard, Shadowsocks
  and plain OpenVPN promoted from `formal_non_green` to `green`** with real
  egress HTTP 200x3 **plus a verified 100MiB download** (`size=104857600`,
  dl_rc=0) through the tunnel, file deleted after verification. AmneziaWG used
  the product's guided flow (COPR `tigro/amneziawg` + `amneziawg-go`
  source-build, doctor `OK=146 WARN=2 FAIL=0` after). OpenVPN plain used the
  `ovpn_auto.sh` auto-disconnect-by-timeout pattern (the `def1` route redirect
  drops the admin SSH session; the short window plus a disconnect trap keeps
  the host recoverable without a manual reboot). **Protocol 01 VLESS certified
  with `01_VLESS_ubuntu_gabo.txt` (`ubuntu_tls_test`)**: connect rc=0, egress
  HTTP 200x3, pubip `138.124.91.224` (through the tunnel, distinct from the
  `nls1` direct IP `79.137.197.255`), teardown clean. Supplementary VLESS
  findings (not the primary certification evidence): imported `operators-vpn`
  (`op-node1.webvork.site:443`, pubip `188.245.244.135`, provided by the
  maintainer as a test profile while the reality server was down, since
  removed) and the provider node `netz-tg-provider:united-kingdom` (pubip
  `217.179.223.170`).
  Evidence:
  `phase23_evidence/watchdogvpn-task-23-7-5-11C-alma-nls1-bloque2-20260902T212559Z.tar.gz`
  (SHA256 `a406e7e070a8996e1d46373068321e9fe49d8318da02135db93c52c56b88ff69`);
  primary VLESS evidence
  `phase23_evidence/watchdogvpn-task-23-7-5-11C-alma-nls1-bloque2-vless-ubuntu-tls-20260902T223041Z.tar.gz`
  (SHA256 `33c72888b9118d73f36921f39d2d22a7f4abff4d39c6b166712938353e54e678`).
- **Real product bug found and fixed (TDD, commit `9258219`):** the sing-box
  JSON importer kept `tls.reality.public_key/short_id` (and
  `tls.server_name`/`utls.fingerprint`) nested, while the driver reads
  `pbk/sid/sni/fp` at top level, so a native sing-box VLESS profile produced
  `public_key: None` → sing-box `FATAL invalid public_key` → connect failed.
  Latent since the parser was added (2026-06-29); never seen before because
  every previous matrix imported VLESS as a `vless://` URI (which flattens
  those fields). Fix flattens the nested fields in `_build_profile` only,
  without overriding explicit top-level values and without touching URI,
  v2ray or the driver. 2 new tests; full suite 2474 tests OK (skipped=2). CI
  L2 run `33681775438` green.
- **Provider `netz-tg-provider` (36 nodes):** subscription live (expires
  2026-09-16), validated on a **bridge-only VM** (AlmaLinux 9.5 exact, Vagrant
  box `9.5.20241203`) because the provider ignores the `nls1` egress IP
  (`de.netzrun.at:5222` TCP-unreachable from `nls1`, reachable from the VM).
  Three real nodes green with real egress (germany-1-h trojan
  `5.230.95.227`, united-kingdom vless `217.179.223.170`, estonia vless
  `185.155.222.104`) and automatic rotation proven with `health_check_ok` and
  real egress after each hop (austria-vienna-3gbit `94.177.9.148`, bulgaria
  `185.199.38.90`, bulgaria-2 `88.80.147.29`). Evidence:
  `phase23_evidence/watchdogvpn-task-23-7-5-11C-alma-VM-bridge-validation-20260902T212200Z.txt`.
- **Work extra (maintainer-ordered):** **§10 split tunnel OPERATIONAL** when
  the `facebook.com→direct` rule is configured **before** connecting: a new
  session loads the policy and Facebook data traffic leaves **direct** through
  `enp0s3` to Meta. tcpdump header capture during real curls shows 708 packets
  from `nls1` to `57.144.248.1:443` (certificate `CN=*.facebook.com`,
  O=Meta Platforms, Inc.) while the tunnel (`138.124.91.224:443`) carries the
  rest. Honest note: adding the rule to an **already active** session does not
  divert traffic until reconnect ("active session keeps its current routing
  rules"). **§11 no DNS leak** (forced 1.1.1.1/8.8.8.8/OpenDNS/Quad9 all
  resolve to fakeip `198.18.0.11`). **§12 fakeip working** (domains resolve to
  `198.18.0.0/15`/`fc00::/18`, TUN rx increased while traffic flowed to the
  sing-box listener, egress through the tunnel). Evidence:
  `phase23_evidence/watchdogvpn-task-23-7-5-11C-alma-nls1-bloque2-s10-reconnect-20260903T003934Z.tar.gz`
  (SHA256 `2fcbf09dba319caeac21bbe0ed192d4c0e771c5e61b9b8f51f0693569bacd95d`);
  §11/§12
  `phase23_evidence/watchdogvpn-task-23-7-5-11C-alma-nls1-bloque2-s10-12-20260902T235919Z.tar.gz`
  (SHA256 `9ae87a5d24d06aee7610882389c76f13381b7937afe0bbc8f202f863ec341eb5`).
- **Infrastructure finding (not product):** the five maintainer VLESS profiles
  pointing at `gaboturbo.serveminecraft.net` (all sids `d32dfe4438fa06b1`,
  `c98565c172f03aeb`, `8a7b91d66b82bfee`, `45082fae4605a856`,
  `31d38336b3d5ffaf`) do not transport reality flow from `nls1` or the VM
  (`endpoint_censorship_or_network_interference_suspected`, 0/2), while a
  VLESS of another provider (`operators-vpn`) and the provider nodes connect.
  The maintainer's reality server (gaboturbo = `138.124.91.224`) is the
  blocker, not the product.

`cert_almalinux_9` is **not created in Bloque 2**: it is published in Block 6
only after Blocks 2-5 (matrix, reboot lifecycle, isolated fault harness,
cleanup) are all satisfied, per the AlmaLinux route. The manifest still keeps
`almalinux_9` as `admitted` / `family_inferred` until then.

Deploy key `160954345` stays active for AlmaLinux through Block 5/7.

**Bloque 3 (reboot lifecycle A/B) CLOSED and APROBADO (2026-09-03)** on `nls1`
(runtime `9258219`, provenance verified; initial boot
`B0=53063369-aca7-4c6d-ab2a-79d540af8822`):

- **Scenario A (autoconnect=false) GREEN:** real reboot with `ubuntu_tls_test`
  connected. After reboot (`A-post=a4854fde-d079-4afb-807c-79a62d3cd686`) the
  daemon stayed active with NRestarts=0, autoconnect false, clean standby,
  desired off, no auto-connect attempt, no TUN/kill-switch/rules/processes/
  listeners residue, DNS restored, direct egress `79.137.197.255` with HTTP
  200x3, firewalld `ssh+dhcpv6-client`, SELinux Enforcing, zero AVC, doctor
  FAIL=0. Two stable readings captured.
- **Scenario B (autoconnect=true): H1 REAPPEARED, fail-closed without
  crash-loop (controlled re-run for re-audit).** Real reboot with `ubuntu_tls_test`
  connected and autoconnect enabled. After reboot (`B-post=9ddf09b6-7752-448b-b10b-14cb2c0810ee`)
  the daemon reported `watchdog_startup_endpoint_resolution_failed` for
  `gaboturbo.serveminecraft.net`: `nft list table inet watchdogvpn` shows policy
  drop accepting only DNS to the internal resolver `172.19.0.2` (`udp/tcp 53`)
  and rejecting all other `udp/tcp 53/853`; retries every 30s
  (`reconnect_retry 1/3`, `2/3`, `all_failed_kill_switch action=keep_active`);
  no crash-loop, NRestarts=0, desired on, kill switch active/consistent, TUN
  off. DNS probes with rc: `172.19.0.2:53` rc=0 (accepted), `1.1.1.1:53` rc=1
  (rejected), `getent gaboturbo.serveminecraft.net` rc=2, `dig @1.1.1.1` rc=124.
  Direct egress blocked (`curl` `http=000` rc=6). Recovery per the approved
  Rocky pattern succeeded: disconnect → clean standby/DNS restored/tabla nft
  removed → manual connect (connected, TUN on, kill switch applied, HTTP 200x3,
  tunnel IP `138.124.91.224`) → clean disconnect. **H1 is documented, not fixed**
  (cross-cutting maintainer decision, same as Rocky).
- Final state: `autoconnect=false`, standby, desired off, TUN/proxy/ksw off,
  app policy off, zero rules, zero residue, doctor `OK=145 WARN=3 FAIL=0`.
  Evidence (corrected bundle):
  `phase23_evidence/watchdogvpn-task-23-7-5-11C-alma-nls1-bloque3-r2-20260903T084534Z.tar.gz`
  (SHA256 `22ac67c279edc34a2a5561415f85ea7ab851d2cba983211886d44faa026164e9`).

#### 11H — Manjaro (new full admission and certification, 2026-08-16)

Added by explicit maintainer decision after a community developer report that
WatchdogVPN runs on Manjaro once the (then code-only) experimental gate is
bypassed. Same pattern as 11G Pop!_OS: a real, unsolicited community report,
not something WatchdogVPN's own roadmap ever targeted.

- **Not an Arch Linux carry-over.** Manjaro resolves via `ID=manjaro`,
  `ID_LIKE=arch` today (already used for AmneziaWG guidance messaging in
  `tests/test_amneziawg_guidance.py`, but never for a manifest support
  decision). 11B Arch Linux's own certification does not transfer to
  Manjaro; per the contract's precedence rules, `family_inferred` requires
  its own qualifying facts, not just family lineage.
- **Full admission/certification from zero**, comparable in depth to 11G
  Pop!_OS: manifest entry, detection, host/protocol readiness, the 12-protocol
  field matrix with real egress, reboot lifecycle, isolated fault harness,
  cleanup, and docs/manifest closure - the same pattern as every other 11.x
  sub-phase.
- **Image source and panel availability are still open questions**, to be
  resolved when 11H is actually scheduled for execution: Manjaro was not in
  `nls1`'s Aeza template list at the time of the 11B Arch Linux closure
  (confirmed live: ArchLinux, Ubuntu 26.04, Debian 13, CentOS 9 Stream,
  AlmaLinux 10, Alpine 3.23, Rocky Linux 9). If it remains absent, 11H needs
  the same "Pre-phase: server image transplant" procedure as CachyOS/Mint,
  including its own `mkinitcpio` HOOKS/virtio verification - Manjaro is Arch
  family, so the same rolling-kernel risk applies.
- **This is the last community-requested sub-phase added reactively.** See
  the policy note above the §14.1 table: after 11H, new community distro
  reports are handled through the real end-user experimental-distro override
  (`prompt_experimental_distro_override()` / `--accept-experimental-distro-risk`,
  documented above), not through an automatically-growing sub-phase list.

11H closure condition: same as every other sub-phase - manifest, docs and
external planning documents all updated together, with independent judge
audit approval, before Manjaro is represented as anything other than
`experimental`.

**Not authorized to start.** 11H Manjaro requires its own fresh, explicit
"go" from the maintainer, exactly like 11B CachyOS did after 11B Arch Linux
closed.
