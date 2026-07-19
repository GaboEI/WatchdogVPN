#!/usr/bin/env bash
set -euo pipefail

DISTRO_PACKAGE_MANAGER="pacman"
DISTRO_BASE_PACKAGES=(
  bash git coreutils findutils grep gawk sed gzip glibc shadow systemd sudo kmod
  ca-certificates python curl tar iproute2 networkmanager logrotate libnotify
  openvpn util-linux polkit nftables iptables iputils procps-ng
)
DISTRO_DNS_PACKAGES=(bind)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python-cryptography"
DISTRO_POLKIT_PACKAGE="polkit"
DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
  'kernel_pkgbase="$(cat "/usr/lib/modules/$(uname -r)/pkgbase")" && sudo pacman -S --needed base-devel git "${kernel_pkgbase}-headers"'
  "git clone https://aur.archlinux.org/amneziawg-dkms.git /tmp/amneziawg-dkms && (cd /tmp/amneziawg-dkms && makepkg -si)"
  "git clone https://aur.archlinux.org/amneziawg-tools.git /tmp/amneziawg-tools && (cd /tmp/amneziawg-tools && makepkg -si)"
  "git clone https://aur.archlinux.org/amneziawg-go.git /tmp/amneziawg-go && (cd /tmp/amneziawg-go && makepkg -si)"
)
