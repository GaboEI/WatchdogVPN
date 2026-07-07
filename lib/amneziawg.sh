#!/usr/bin/env bash
set -euo pipefail

# AmneziaWG has no official Ubuntu/Debian/Arch repository package that could
# be installed unattended without adding a third-party APT/AUR trust root, and
# its kernel module (amneziawg-dkms) needs to be built against the running
# kernel. WatchdogVPN therefore only detects it here and prints accurate,
# verified upstream source links; it does not add repositories, build from
# source, or install anything automatically. This matches Task 18.3's "install
# or clearly check" requirement via the "clearly check" branch.
AMNEZIAWG_TOOLS_UPSTREAM="https://github.com/amnezia-vpn/amneziawg-tools"
AMNEZIAWG_KERNEL_MODULE_UPSTREAM="https://github.com/amnezia-vpn/amneziawg-linux-kernel-module"

amneziawg_userspace_available() {
  have_cmd awg-quick || have_cmd amneziawg-quick || have_cmd wg-quick \
    || [[ -x /usr/local/bin/awg-quick ]] || [[ -x /usr/local/bin/amneziawg-quick ]] \
    || [[ -x /usr/bin/awg-quick ]] || [[ -x /usr/bin/amneziawg-quick ]]
}

amneziawg_kernel_module_available() {
  # The AmneziaWG kernel module registers itself as "amneziawg"; the vanilla
  # WireGuard module ("wireguard") is accepted as a compatible fallback,
  # matching drivers/amneziawg_driver.py's own awg-quick-preferred /
  # wg-quick-fallback tolerance.
  [[ -d /sys/module/amneziawg ]] || [[ -d /sys/module/wireguard ]] \
    || modinfo amneziawg >/dev/null 2>&1 || modinfo wireguard >/dev/null 2>&1
}

print_amneziawg_dependency_notice() {
  cat <<EOF
AmneziaWG runtime check:
  WatchdogVPN cannot automatically install AmneziaWG tooling. There is no
  official Ubuntu/Debian/Arch repository package, and its kernel module must
  be built against the running kernel, so an unattended install here would
  require adding a third-party repository or building from source without
  your review.

  If you plan to use AmneziaWG profiles, install manually before connecting:
    Tools:         $AMNEZIAWG_TOOLS_UPSTREAM
    Kernel module: $AMNEZIAWG_KERNEL_MODULE_UPSTREAM

  Standard WireGuard tooling (wg-quick/wg, wireguard kernel module) is
  accepted as a compatible fallback if AmneziaWG-specific packages are not
  available for your distro.
EOF
}

check_amneziawg_dependency() {
  if amneziawg_userspace_available && amneziawg_kernel_module_available; then
    ok "AmneziaWG (or compatible WireGuard) tooling detected"
    return 0
  fi

  warn "AmneziaWG tooling not fully detected"
  print_amneziawg_dependency_notice
}
