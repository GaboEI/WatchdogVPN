#!/usr/bin/env bash
set -euo pipefail

# Fedora and Red Hat-family adapter. This enables installer/update package
# reconciliation only; distro certification remains a separate installed
# evidence task.
DISTRO_PACKAGE_MANAGER="dnf"
DISTRO_CERTIFICATION_STATE="implemented_not_certified"
DISTRO_SUPPORT_NOTE="Fedora/Red Hat-family adapter implemented; installed certification remains pending Phase 23.6 evidence."
DISTRO_BASE_PACKAGES=(
  bash git coreutils findutils grep gawk sed gzip glibc-common shadow-utils systemd
  sudo kmod ca-certificates python3 curl tar iproute NetworkManager logrotate
  libnotify openvpn util-linux polkit nftables iptables-nft iputils procps-ng
  firewalld systemd-resolved
)
DISTRO_DNS_PACKAGES=(bind-utils)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"
DISTRO_POLKIT_PACKAGE="polkit"

# RHEL9-family default python3 is 3.9 (RHEL9's platform Python), too old for
# this codebase's pervasive use of dataclass(slots=True), a Python 3.10+
# feature - unlike real Fedora, whose system python3 is already well past
# 3.10. Pin the modern interpreter the runtime resolver
# (lib/common.sh:watchdogvpn_python) should use; python3.11 and its matching
# cryptography package ship directly in RHEL9 AppStream, no EPEL needed for
# these two specifically. This does not retarget the OS default python3,
# which system tools use. Plain variable assignment (not the
# distro_prepare_package_repos function below) because it has no side
# effect - safe to run whenever this adapter is merely sourced, same as
# every other adapter variable.
if [[ "${DISTRO_ID:-}" != "fedora" ]]; then
  DISTRO_PYTHON="python3.11"
  DISTRO_BASE_PACKAGES+=(python3.11)
  DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3.11-cryptography"
fi

# This adapter is shared by real Fedora and, via lib/distro.sh's native
# rhel|centos|rocky|almalinux case, the whole RHEL-family. Real Fedora ships
# every package this adapter declares (including openvpn) in its own repos.
# The RHEL-family derivatives do not: openvpn and others are EPEL-only there,
# so a plain `dnf install` of DISTRO_BASE_PACKAGES fails with "Unable to find
# a match" on a stock Rocky/Alma/RHEL/CentOS image. Package reconciliation
# (lib/packages.sh:validate_required_commands) calls this once before
# installing DISTRO_BASE_PACKAGES; it is a no-op on real Fedora. Defined as a
# function (not top-level code) so merely sourcing this adapter - which
# doctor.sh also does, read-only - never mutates the system; only the
# explicit call from install/update package reconciliation does.
distro_prepare_package_repos() {
  [[ "${DISTRO_ID:-}" == "fedora" ]] && return 0
  if ! rpm -q epel-release >/dev/null 2>&1; then
    run_step sudo dnf install -y epel-release
  fi
}
# AmneziaWG has no official Fedora package, so the guided trust-boundary
# setup builds the userspace stack from Amnezia's official source. The
# userspace amneziawg-go path is deliberately preferred over the DKMS kernel
# module here: it needs no kernel headers and is not blocked by Secure Boot
# module signing, so it strands far fewer users while carrying identical
# real traffic. Migrate this guidance to a real Fedora package if one becomes
# available upstream. WatchdogVPN never runs these commands; it verifies awg
# and amneziawg-go afterwards.
DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
  "sudo dnf install -y golang git make gcc"
  "git clone https://github.com/amnezia-vpn/amneziawg-tools /tmp/amneziawg-tools && make -C /tmp/amneziawg-tools/src && sudo make -C /tmp/amneziawg-tools/src install"
  "git clone https://github.com/amnezia-vpn/amneziawg-go /tmp/amneziawg-go && (cd /tmp/amneziawg-go && make) && sudo install -m 0755 /tmp/amneziawg-go/amneziawg-go /usr/local/bin/amneziawg-go"
)

# The RHEL-family branch has a real advantage Fedora does not: tigro/amneziawg
# (https://copr.fedorainfracloud.org/coprs/tigro/amneziawg/) publishes a
# prebuilt amneziawg-tools binary for epel-9, so awg/awg-quick do not need to
# be built from source here. It also ships amneziawg-dkms (a kernel module),
# but the userspace amneziawg-go path is kept for the same reason as Fedora
# (no kernel headers, no Secure Boot signing issue) - amneziawg-go itself has
# no prebuilt package in that copr, so it is still built from source.
# Verified end to end on a Rocky Linux 9.6 certification VM (Task 23.6.5b).
if [[ "${DISTRO_ID:-}" != "fedora" ]]; then
  DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
    "sudo dnf install -y dnf-plugins-core && sudo dnf copr enable -y tigro/amneziawg && sudo dnf install -y amneziawg-tools"
    "sudo dnf install -y golang git make gcc"
    "git clone https://github.com/amnezia-vpn/amneziawg-go /tmp/amneziawg-go && (cd /tmp/amneziawg-go && make) && sudo install -m 0755 /tmp/amneziawg-go/amneziawg-go /usr/local/bin/amneziawg-go"
  )
fi
