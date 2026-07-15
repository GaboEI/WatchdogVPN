# Test Fixtures

Most current unit tests generate their command fixtures in a temporary
directory at runtime. This keeps the tests isolated from the host VPN, DNS,
systemd and filesystem state.

Static fixtures can be added here when a test needs stable sample output, log
lines or parser inputs.

Fixtures and generated parser payloads must be reviewable and fully sanitized.
Never add live VPN exports, endpoints, account identifiers, certificates,
private keys or provider credentials to the repository. Use documentation-only
address ranges, `.invalid` domains and unmistakable `TEST-ONLY` credential
markers. Real private profiles belong only in the opt-in field-validation
workflow outside unittest discovery.
