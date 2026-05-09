# Test Fixtures

Most current unit tests generate their command fixtures in a temporary
directory at runtime. This keeps the tests isolated from the host VPN, DNS,
systemd and filesystem state.

Static fixtures can be added here when a test needs stable sample output, log
lines or parser inputs.
