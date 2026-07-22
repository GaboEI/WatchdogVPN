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

Every current or future adapter must also define the complete distro runtime
package set and Python cryptography package. The package set must cover the
atomic nftables backend, legacy iptables cleanup tooling, OpenVPN, ping,
process recovery, NetworkManager, Polkit and notification/runtime utilities;
install and update reconcile it unconditionally. `fedora.sh` is the Fedora and
Red Hat-family `dnf` adapter used by Fedora, RHEL, CentOS, RockyLinux and
AlmaLinux detection. `opensuse.sh` is the openSUSE `zypper` adapter used by
Leap, Tumbleweed and the explicit `ID=opensuse` spelling. Adapter support means
WatchdogVPN owns package reconciliation for those IDs; it is not a
certification claim until the installed SELinux/AppArmor/firewalld lifecycle
and real-traffic evidence tasks close.

Derivatives that do not report a natively supported `ID` are resolved through a
conservative `ID_LIKE` fallback: `arch` maps to the Arch adapter, `ubuntu` to
the Ubuntu adapter and `debian` to the Debian adapter, with Ubuntu taking
precedence when a derivative reports both (for example Linux Mint's
`ID_LIKE="ubuntu debian"`). Every other `ID_LIKE` remains unsupported, so an
unrelated or SUSE-like derivative is never silently promoted to supported.
