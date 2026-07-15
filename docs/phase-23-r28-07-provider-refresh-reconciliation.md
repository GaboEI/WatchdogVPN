# Phase 23 R28-007 - Provider Refresh Reconciliation

Status: CLOSED after source, installed-runtime, and field validation.

## Finding

Refreshing one provider was rejected with "provider profile membership does not
match owned profiles". The refresh transaction correctly built the target
provider's replacement, but transaction validation derived ownership only from
profiles whose source was subscription.

The installed VM also contained one pre-existing Phase 18 profile with a valid
provider_id and a historical manual source marker. That record belonged to its
provider according to the persisted ownership edge, but the validator ignored
it. The result was a fail-closed rejection of unrelated provider updates.

No profile, provider, subscription URL, or credential is recorded here.

## Remediation

SubscriptionProvider._owned_profile_ids_by_provider() is now the single
ownership derivation used by both update construction and transaction
validation:

- provider ownership is determined by provider_id;
- subscription profiles without a provider still fail closed;
- profiles referring to an unknown provider still fail closed;
- duplicate provider references and duplicate profile IDs still fail closed;
- the maximum of two external providers remains enforced;
- a refresh derives its provider list from the exact final replacement payload,
  so stale nodes are removed atomically and source order becomes canonical.

Historical records are not silently rewritten: the legacy profile keeps its
manual source marker while its valid provider ownership is honored. Dedicated
migration or cleanup of legacy source metadata is outside this finding.

## Evidence

- Focused provider suite: 24/24 passed, including exact replacement/order,
  transactional rollback, two-provider limit, and historical-provider
  regressions.
- Full Python suite, shell syntax checks, and git diff --check passed.
- Source-runtime field refresh of the real Phase 23 provider returned
  {"changes": 0, "provider_id": "phase23-provider"} with no VPN runtime
  mutation.
- Installed-runtime field refresh returned the same result after installation.

## Closure

R28-007 is closed. It does not authorize deletion or consolidation of the
historical duplicate AmneziaWG imports; that is separate, explicitly
reversible follow-up work.
