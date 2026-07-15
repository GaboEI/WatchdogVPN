# Phase 23 R28-03 - Robust Network Context Decoding

Status: CLOSED for R28-003.

Malformed nmcli or ip text decoding is caught at both subprocess boundaries. A decode failure returns ERROR with a fixed non-sensitive diagnostic; observe preserves ERROR instead of downgrading it to PARTIAL, so policy evaluation returns manual with no runtime action. Missing tools and controlled nonzero commands retain their prior PARTIAL semantics.

Implementation db9d815af1b63156e27ebdcbfcac588f3021fb99. Tests cover malformed nmcli, malformed ip, timeout and nonzero cases, generic diagnostics and manual decision. Focused 32 of 32, unit/syntax/diff and full 1658 of 1658 in 240.718 seconds passed. Installed proof passed; daemon 119055 to 129584, runtime alignment at db9d815, doctor zero FAIL, clean desired-off standby and bypass timer disabled/inactive. No debt. R28-004 requires explicit authorization.
