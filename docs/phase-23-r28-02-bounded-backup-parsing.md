# Phase 23 R28-02 - Bounded Backup Parsing

Date: 2026-07-15
Status: CLOSED for R28-002 after source, installed-runtime, and closure re-audit validation.

## Finding

R28-002 found that backup inspection read ZIP members and encrypted payloads fully into memory without limits for member count, compressed bytes, uncompressed bytes, aggregate expansion, or compression ratio.

## Remediation

Backup inspection now rejects archives before reading members when any of these limits is exceeded: 32 members, 16 MiB physical or declared compressed bytes, 2 MiB per member uncompressed bytes, 8 MiB aggregate uncompressed bytes, or a 100 to 1 compression ratio. Each member is then read through ZipFile.open in 64 KiB chunks with a second observed-size and aggregate budget.

The same checks run on plaintext archives, the encrypted outer container before payload decrypt, and the decrypted inner ZIP before any manifest or section is parsed. AES-GCM decryption is reached only after the ciphertext has passed the bounded reader; the decrypted inner archive is itself capped before parsing.

## Evidence

Code implementation: 4bf197794009831dcc7409c4b68345b325ed37a0, published on phase-23-cli-field-validation. Source gates passed: focused backup suite 40 of 40, tests/unit.sh, tests/syntax.sh, diff check, and full Python suite 1655 of 1655 in 238.461 seconds.

Adversarial coverage rejects excess member count, oversized plaintext member, excess compressed bytes, aggregate expansion, high compression ratio, oversized encrypted payload before decryption, and an excessive inner encrypted ZIP. A regression patches ZipFile.read to fail and confirms valid inspection uses only the bounded reader.

The exact code commit was installed. The update refreshed the daemon from PID 106513 to 117211 and passed the IPC smoke test. An isolated installed-runtime proof rejected high-ratio input and an oversized encrypted payload. At runtime validation, source, origin, and installed marker aligned at 4bf1977; doctor had zero FAIL, desired state remained off, standby was clean, and the bypass timer remained disabled/inactive.

No R28-002 debt is accepted. R28-003 remains pending explicit authorization. Phase 23 and Task 23.4 remain open and unmergeable.
