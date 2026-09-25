# Distribution compatibility contract

WatchdogVPN runs on Linux, but "runs on Linux" is not a support statement. This
document defines the compatibility model the product uses to decide what a
distribution release means, what a specific machine is ready for, and which
protocols can actually operate. It is the durable contract behind the installer,
`doctor`, the CLI and the published platform documentation.

## Why the model exists

Certifying one distribution image does not prove a whole family, and a protocol
being technically compatible does not mean its install path is automatic,
reproducible or universal. A guided protocol path that depended on a package
repository with no series for a newer release failed exactly that way: the
protocol itself was compatible, but provisioning was not.

The model removes that class of gap structurally — through version-aware
detection, capability contracts, integrity-checked provisioning with ordered fallbacks,
honest support classification, and a single source of truth — instead of
per-version manual exceptions.

## Three orthogonal classifications

Compatibility is not one dimension. Three classifications are kept separate and
never silently promote or demote one another:

- **`support_classification`** — a policy statement about a distribution
  *release*, computed from policy and current certifications. Never from a probe
  of a single machine.
- **`host_readiness`** — whether *this* concrete machine has every required core
  capability, computed from runtime probes.
- **`protocol_readiness`** — per protocol, whether it is operable on this host.

A protocol missing on a machine affects only that protocol. It does not change
the host's readiness for other protocols, and it does not change the release's
`support_classification`.

## Support classification

Five states, and only these five:

- **`certified`** — the strongest support state, held by the exact release
  only. It is never inherited from another release or from a distribution's
  packaging family. RHEL is not certified through CentOS Stream.
- **`supported`** — a release expressly admitted by policy, vendor-maintained,
  whose declared capability contract resolves successfully, and whose family is
  anchored by a certified release.
- **`family_inferred`** — a release resolved to a family adapter, sharing the
  family contract but without its own certification, whose technical family has
  a current qualifying certification anchor. **Family inference is never
  certification.** Red Hat Enterprise Linux is `family_inferred`, not certified.
- **`experimental`** — recognized by lineage but future or not yet evaluated: a
  release that is neither admitted nor expressly excluded, or a rolling
  distribution whose certification has expired. Not a guarantee.
- **`unsupported`** — no adapter, or expressly excluded by policy, EOL or
  withdrawn, or below the technical capability floor. The product stops early
  with a clear reason.

Support is **admitted-release + policy** based, not a continuous
"minimum-to-maximum" range: a numerically intermediate release is not
automatically `supported`.

Precedence is deterministic and non-overlapping:

- Known family, future or not-yet-evaluated release → `experimental`.
- Rolling with an expired certification → `experimental`.
- Expressly excluded by policy → `unsupported`.
- EOL or withdrawn → `unsupported`.
- Below the technical floor → `unsupported`.
- Family without an adapter → `unsupported`.
- An admitted release on an incomplete machine keeps its
  `support_classification`; the host becomes `needs_preparation`.

## Host and protocol states

- `host_readiness`: `ready`, `needs_preparation`, `preparation_failed`,
  `incompatible`.
- `protocol_readiness`: `operable`, `provisionable`, `absent`,
  `unsupported_here`.

An exhausted provisioning chain on an in-contract distribution ends in
`preparation_failed` (a host state), never in `unsupported`. The release stays
classified by policy.

## Capabilities: core vs protocol

- **Core host capabilities** gate `host_readiness`: init system, network
  manager, DNS backend, TUN, firewall backend, policy routing, kernel,
  architecture, Python runtime floor, package manager, privileged execution,
  persistence, rollback and the diagnostic surface.
- **Protocol capabilities** gate only their own `protocol_readiness` (for
  example sing-box, OpenVPN, OpenVPN with the Cloak client, and the AmneziaWG
  tools with either the kernel module or the userspace runtime). A missing
  protocol runtime never makes the whole host not ready.
- **Firewall backend:** `nftables` is required for the atomic kill switch.
  `iptables` is diagnostic and legacy-cleanup only. Promoting `iptables` to an
  alternative backend, or retiring it, is an explicit future decision.
- Family-specific diagnostics (for example SELinux, AppArmor, firewalld) are
  reported where relevant but do not lower `host_readiness`.

## Provisioning

When a capability is missing, provisioning tries methods in a strict,
version-aware order. No package built for a different release is used as a
generic fallback:

1. Official package for the exact release.
2. External repository explicitly compatible with the exact release.
3. Official compatible artifact, pinned and integrity-checked.
4. Reproducible build from a pinned version or commit.
5. Otherwise `preparation_failed` with a comprehensible reason.

Provisioning is product-managed and transactional. Its user-visible guarantees:

- **Dry-run first.** The plan can be produced and inspected without acquiring
  the lock, writing a journal, or touching the system.
- **Explicit authorization.** Applying is its own signal; a plain profile import
  performs no silent system mutation.
- **Idempotency and ownership.** Already-present, matching resources are
  recognized and not duplicated; a pre-existing component with no product
  ownership record is left untouched and never gains uninstall rights.
- **Rollback and recovery.** A failure rolls back what the transaction applied;
  an interrupted operation is resumed, retried or refused with a clear decision
  rather than reinterpreted under a changed plan.
- **Uninstall preserves user software.** Uninstall removes only what
  WatchdogVPN itself provisioned and recorded. A second uninstall is safe and
  idempotent.
- **Pinned source builds.** A source build pins the release tag and commit,
  checks integrity, records installed files, and supports rollback and
  uninstall. The build runs as an explicit, non-root build user.

## Consistent support statements

Public support statements never promise more than the installer and runtime
provide. Per-release compatibility facts are published in the platform
documentation; this document does not restate them. For the current platform
list, see the supported platforms section of `README.md`.

## Stable vs rolling

- **Discrete-version families** use admitted-release + version policy.
- **Rolling distributions** use a capability-and-freshness policy with a
  certification date and an expiry rule, not a numeric minimum. When that
  certification expires, the release returns to `experimental`.
- **Derivatives** are mapped by exact identity (for example a specific base
  codename), never by approximate equivalence. A rolling derivative uses its own
  rolling policy and never borrows a stable version.

## Detection and resolution

What an operator needs to know:

- **Detection** reads host identity from `os-release`, never by executing shell
  data, and resolves the release against the published compatibility data.
  Unknown releases are not approximated to a nearby release.
- **Support facts** are stored as primitive policy data. Calculated states such
  as `support_classification`, `host_readiness` and `protocol_readiness` are
  never hand-authored.
- **Dependency resolution** selects an execution-ready method for the exact
  release. A capability that cannot be confirmed without mutating the system is
  treated conservatively as not confirmed.

## Limitations

- Support is admitted-release + policy based; an intermediate release between
  two admitted ones is not automatically supported.
- `family_inferred` is not certification. Red Hat Enterprise Linux shares the
  Red Hat-family adapter but is not certified.
- `experimental` is not a guarantee, and a rolling certification expires.
- A missing protocol runtime affects only that protocol.
- `nftables` is required; there is no supported alternative firewall backend.
- Uninstall never removes pre-existing or user-owned software.
- If the compatibility data cannot be read, detection falls back to mechanical
  identity only, does not determine support, and treats the distro as unsupported.
- A distro classified as `experimental` can still be used through an explicit,
  recorded user risk acceptance. That acceptance does not change the
  classification and creates no certification.
