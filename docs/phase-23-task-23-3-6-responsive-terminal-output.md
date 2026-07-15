# Phase 23 Task 23.3.6 Responsive Terminal Output

Date: 2026-07-13
Findings: WDCLI-018, WDCLI-019, WDCLI-021

## Problem

The professional CLI audit reproduced three related discoverability failures:

- `watchdog profile list` built column widths from unbounded stored values, so
  a 127-profile inventory overflowed both 40- and 80-column terminals;
- root help was a fixed 73-column text block and overflowed 40 columns;
- common command typos printed the complete argparse choice list without a
  correction hint.

These are important for operators working over narrow SSH or mobile terminals,
where wrapped identifiers and buried recovery guidance make urgent actions
harder to scan.

## Responsive Output Contract

`cli.terminal` provides one bounded display-width implementation for terminal
size discovery, ANSI-aware visible width, East Asian wide characters, safe
cell normalization, truncation, padding and wrapping. Terminal width honors
`COLUMNS`, falls back to 80, and is bounded against hostile environment values.

Normal `profile list` output selects one of three layouts:

- below 72 columns: a stacked profile view;
- 72 through 99 columns: a compact table with combined state;
- 100 columns and above: separate enabled and rotation columns.

Every normal line is constrained to the detected width. Profile names, IDs and
provider labels are untrusted display data; control characters are neutralized
before rendering so escape sequences and embedded newlines cannot bypass the
width contract. When values are shortened, the CLI points to `--wide` or
`--json`. `--wide` is the explicit untruncated human-output mode and is the only
profile-list mode allowed to exceed the terminal width.

Large inventories can be reduced with composable source, protocol, health,
provider and enabled/disabled filters. The same filters apply to JSON without
truncating its values.

Root help is generated from structured section metadata and wraps command
descriptions to the same detected width instead of returning a fixed text
block. Argparse-owned route help uses the same terminal-width ceiling, while
the generated CLI inventory records canonical parser syntax independently of
human terminal reflow.

## Typo Safety Contract

Only invalid argparse subcommand choices are eligible for a suggestion. The
matcher uses bounded Damerau-Levenshtein distance, recognizes adjacent
transpositions, prefers an unambiguous prefix completion and refuses distant or
tied guesses. A suggestion never reparses or executes a command. Human and JSON
parse failures retain exit code 2 and point to the relevant help route.

## Validation

Regression coverage uses isolated profile/provider stores and no live runtime
state. It pins:

- zero normal visible-width overflow at 40, 80 and 120 columns for a synthetic
  127-profile inventory and root help;
- zero visible-width overflow at 40 columns across all 113 argparse-owned help
  routes;
- explicit `--wide` overflow with complete values;
- filter composition and complete JSON values;
- control-sequence neutralization and Unicode display width;
- exact suggestions for `statu`, `profile lst` and `dns statsu`, bounded refusal
  for distant input, JSON parity, exit code 2 and non-execution.

The generated CLI inventory is regenerated and checked whenever the new public
filter arguments change parser metadata.
