# Phase 23 R28-05 - Aggregate Metrics Redaction

Status: CLOSED for R28-005.

Aggregate metrics now use a closed set of non-identifying counter dimensions.
The permitted dimensions are command outcomes, manual/scheduled rotation
attempts and finite lifecycle statuses, health/recovery lifecycle statuses,
node-group test result categories, and generic runtime/profile/route/rule
event counts. Profile IDs, node-group names, rule-group names, route actions,
error labels and arbitrary counter keys are not persisted.

The enforcement boundary is MetricsStore, not only MetricsRecorder. Every
write filters the document to that allowlist. Every load sanitizes a legacy
metrics file and atomically republishes it if it contained identifier-derived
keys. The privacy-mode command first loads the current file, so changing to
aggregate deliberately migrates existing detailed/legacy counters; the user
can still use stats purge for complete removal. Detailed request history
remains unsupported and all currently persisted counters follow the same
aggregate contract.

Implementation e6d31feb050382b6b15ce329c279ee806047e3ba. Focused tests cover
email, hostname, IPv4, URL, secret-like labels, recorder output, legacy
on-disk migration, privacy-mode migration and stats summary output (60/60).
Unit, syntax and diff checks passed; the full source suite passed 1665/1665
in 207.439 seconds.

The exact commit was pushed and installed. The daemon refreshed from PID
144122 to 155761. An isolated import from /usr/local/lib/watchdogvpn migrated
a legacy aggregate file containing email, IPv4, URL and private-label canaries;
only the safe command counter remained and none of the canaries remained on
disk. At code-runtime validation, source, origin and installed runtime aligned
at e6d31fe; doctor has zero FAIL, the desired-off standby remains clean and
the bypass timer remains disabled. No accepted technical debt.

All R28 implementation items are now closed. Phase 23 is still open and
unmergeable until the R28 exit gate is completed: complete installed protocol
matrix, restoration verification and an independent detection-only
re-audit before PR approval.
