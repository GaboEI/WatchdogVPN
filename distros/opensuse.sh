#!/usr/bin/env bash
set -euo pipefail

# openSUSE adapter. This enables installer/update package reconciliation only;
# distro certification remains a separate installed evidence task.
DISTRO_PACKAGE_MANAGER="zypper"
# openSUSE Leap's default `python3` is 3.6, too old for the runtime
# (`from __future__ import annotations` needs 3.7+). Pin the modern interpreter
# the runtime resolver (lib/common.sh:watchdogvpn_python) should use; the
# matching python311 packages are in the base set and the cryptography package
# below. This does not retarget the OS default python3, which system tools use.
DISTRO_PYTHON="python3.11"
DISTRO_CERTIFICATION_STATE="implemented_not_certified"
DISTRO_SUPPORT_NOTE="openSUSE adapter implemented; installed certification remains pending Phase 23.6 evidence."
DISTRO_BASE_PACKAGES=(
  bash git coreutils findutils grep gawk sed gzip glibc shadow systemd sudo kmod
  ca-certificates python3 curl tar iproute2 NetworkManager logrotate
  libnotify-tools openvpn util-linux polkit nftables iptables iputils procps
  systemd-resolved firewalld apparmor-utils python311
)
DISTRO_DNS_PACKAGES=(bind-utils)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python311-cryptography"
DISTRO_POLKIT_PACKAGE="polkit"
