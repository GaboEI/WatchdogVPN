# Phase 23 R28-04 - Bootstrap Resolver Acyclicity

Status: CLOSED for R28-004.

A hostname DNS resolver now requires an independently resolvable bootstrap
server: an enabled bootstrap resolver using an IP address, local, or DHCP.
The planner skips hostname bootstrap candidates, so a hostname bootstrap never
receives its own tag as domain_resolver. If no independent bootstrap exists,
configuration generation fails before it can produce a recursive or implicitly
resolved sing-box configuration.

The generated DNS server dependency graph is validated before configuration
publication. Missing dependency targets, malformed dependencies, self-cycles,
and multi-node cycles are rejected with actionable errors that include the
dependency path.

Implementation dd72c82da137256dd68f1a7a2ec775890b4f4b96. Focused DNS generation
tests cover hostname bootstrap with a later IP bootstrap, IP bootstrap,
disabled independent bootstrap, and self/two-node cycle rejection (24/24).
Driver integration passed 102/102; an independently generated complete
hostname-bootstrap configuration passed sing-box check. Unit, syntax and
diff checks passed, and the full source suite passed 1662/1662 in 200.676
seconds.

The exact commit was pushed and installed. The daemon refreshed from PID
131391 to 142261. An isolated import from /usr/local/lib/watchdogvpn proved
the installed hostname bootstrap uses the independent IP tag, rejects a
multi-node cycle, and emits a configuration accepted by sing-box check.
At code-runtime validation, source, origin and installed runtime aligned at
dd72c82; doctor has zero FAIL, desired-off standby is clean, and the bypass
timer remains disabled. No
accepted technical debt. R28-005 requires explicit authorization; Task 23.4
and Phase 23 remain open and unmergeable pending the remaining R28 work.
