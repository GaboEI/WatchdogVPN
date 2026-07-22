#!/usr/bin/env bash
set -euo pipefail

# openSUSE adapter. This enables installer/update package reconciliation only;
# distro certification remains a separate installed evidence task.
DISTRO_PACKAGE_MANAGER="zypper"
DISTRO_CERTIFICATION_STATE="implemented_not_certified"
DISTRO_SUPPORT_NOTE="openSUSE adapter implemented; installed certification remains pending Phase 23.6 evidence."
DISTRO_BASE_PACKAGES=(
  bash git coreutils findutils grep gawk sed gzip glibc shadow systemd sudo kmod
  ca-certificates python3 curl tar iproute2 NetworkManager logrotate
  libnotify-tools openvpn util-linux polkit nftables iptables iputils procps
  systemd-resolved firewalld apparmor-utils
)
DISTRO_DNS_PACKAGES=(bind-utils)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"
DISTRO_POLKIT_PACKAGE="polkit"
