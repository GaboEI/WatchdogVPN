# Phase 23 Task 23.3.6 CLI Inventory And Documentation Parity

Date: 2026-07-13
Finding: WDCLI-020

## Problem

The professional CLI audit compared the checkout parser with `docs/cli.md` and
found 35 command routes that were present in code but absent from the manual
inventory. The missing routes included DNS CRUD, route chains, advanced node
groups, per-rule mutations, rule-set lifecycle mutations and newer app-policy
matchers. A hand-maintained command list could become stale again after any
parser change.

The audit recorded 107 routes at that intermediate snapshot. The stabilized
parser now contains additional routes from subsequent hardening, including the
canonical maintenance namespace. Acceptance therefore uses the current parser
rather than preserving the obsolete count.

## Source Of Truth

`cli.main._build_parser()` remains the canonical CLI definition. Public route
metadata is extracted without executing command handlers. Argparse-backed
routes provide their command path, summary, normalized usage and public
arguments. The maintenance command selector uses
`DocumentedPassthroughAction`, so its eight delegated commands are part of the
same parser metadata instead of a second documentation-only list.

The generated snapshot contains:

- 121 documented routes including the canonical root;
- 120 command routes excluding the root;
- 113 argparse-backed routes;
- 8 documented maintenance passthrough routes;
- 17 root/group routes and 104 leaf routes.

Suppressed internal override arguments are excluded because they are test and
recovery-path controls, not public CLI contracts.

## Generated Artifacts

- `docs/generated/cli-command-inventory.json` is the schema-versioned,
  machine-readable snapshot.
- `docs/generated/cli-command-inventory.md` is the complete human-readable
  route, usage and argument reference.
- `docs/cli.md` links both snapshots and retains reviewed narrative contracts,
  safety notes and examples for high-risk operations.

The reviewed manual covers every route family named by WDCLI-020, including
DNS CRUD and its apply boundary, rule priorities and per-rule state, all Linux
app-policy matchers, provider-backed node-group controls, multi-hop route
chains, and rule-set trust-registry add/remove operations. The narrative is
deliberately retained beside the generated reference because route presence
alone cannot explain fail-closed behavior, validation boundaries or rollback
expectations.

Regenerate after an intentional parser change:

```sh
python3 scripts/generate_cli_inventory.py
```

Verify without writing:

```sh
python3 scripts/generate_cli_inventory.py --check
```

## Enforcement

`tests/test_cli_command_inventory.py` rebuilds the inventory and compares both
committed artifacts byte-for-byte. It also pins route counts, uniqueness,
maintenance expansion, non-empty summaries/help discovery and exclusion of
suppressed internal overrides. A dedicated assertion pins the reviewed
WDCLI-020 safety contracts in `docs/cli.md`. `tests/unit.sh` runs the generator
in `--check` mode as a fast parity gate.

Any parser route, summary, usage or public argument change therefore fails the
test suite until the generated documentation is deliberately regenerated and
reviewed. The acceptance contract is current parser/documentation parity, not
a manually asserted partial route list.
