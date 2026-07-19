#!/usr/bin/env bash
set -euo pipefail

# Future Red Hat-family foundation. lib/distro.sh deliberately keeps this
# adapter non-supported until the Phase 23.6 SELinux/firewalld and installed
# lifecycle gates close; its package contract is prepared now so that work
# does not begin from an empty installer path.
DISTRO_PACKAGE_MANAGER="dnf"
DISTRO_BASE_PACKAGES=(
  bash coreutils findutils grep gawk sed gzip glibc-common shadow-utils systemd
  sudo kmod ca-certificates python3 curl tar iproute NetworkManager logrotate
  libnotify openvpn util-linux polkit nftables iptables-nft iputils procps-ng
)
DISTRO_DNS_PACKAGES=(bind-utils)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"
DISTRO_POLKIT_PACKAGE="polkit"
