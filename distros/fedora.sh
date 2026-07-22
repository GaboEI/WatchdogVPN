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
