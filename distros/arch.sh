#!/usr/bin/env bash
set -euo pipefail

DISTRO_PACKAGE_MANAGER="pacman"
DISTRO_BASE_PACKAGES=(python curl tar iproute2 networkmanager logrotate libnotify openvpn util-linux)
DISTRO_DNS_PACKAGES=(bind)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python-cryptography"
DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
  "sudo pacman -S --needed base-devel git linux-headers"
  "git clone https://aur.archlinux.org/amneziawg-dkms.git /tmp/amneziawg-dkms && (cd /tmp/amneziawg-dkms && makepkg -si)"
  "git clone https://aur.archlinux.org/amneziawg-tools.git /tmp/amneziawg-tools && (cd /tmp/amneziawg-tools && makepkg -si)"
  "git clone https://aur.archlinux.org/amneziawg-go.git /tmp/amneziawg-go && (cd /tmp/amneziawg-go && makepkg -si)"
)
