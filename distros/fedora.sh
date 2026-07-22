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
