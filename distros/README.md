# Distro adapter contract

Each distro adapter is the single place for package-manager-specific product
data. `lib/distro.sh` resolves the adapter from `/etc/os-release`; consumers
must use `distro_adapter_path` instead of parsing distribution identifiers on
their own.

For AmneziaWG, an adapter may define:

```bash
DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
  "first reviewed command"
  "second reviewed command"
)
```

Those commands are displayed only after an AmneziaWG profile is imported and
the local runtime is missing. WatchdogVPN never executes them. An adapter that
does not define the array gets official upstream links instead of guessed
commands. To support a new distribution, add or extend its adapter and the
existing resolver mapping; do not add distro branches to the CLI or duplicate
the guidance in Python.
