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
# AmneziaWG has no official Fedora package (the upstream copr only ships
# EPEL/RHEL builds), so the guided trust-boundary setup builds the userspace
# stack from Amnezia's official source. The userspace amneziawg-go path is
# deliberately preferred over the DKMS kernel module here: it needs no kernel
# headers and is not blocked by Secure Boot module signing, so it strands far
# fewer users while carrying identical real traffic. Migrate this guidance to a
# real Fedora package if one becomes available upstream. WatchdogVPN never runs
# these commands; it verifies awg and amneziawg-go afterwards.
DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
  "sudo dnf install -y golang git make gcc"
  "git clone https://github.com/amnezia-vpn/amneziawg-tools /tmp/amneziawg-tools && make -C /tmp/amneziawg-tools/src && sudo make -C /tmp/amneziawg-tools/src install"
  "git clone https://github.com/amnezia-vpn/amneziawg-go /tmp/amneziawg-go && (cd /tmp/amneziawg-go && make) && sudo install -m 0755 /tmp/amneziawg-go/amneziawg-go /usr/local/bin/amneziawg-go"
)
