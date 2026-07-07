#!/usr/bin/env bash
set -euo pipefail

DISTRO_PACKAGE_MANAGER="pacman"
DISTRO_BASE_PACKAGES=(python curl tar iproute2 networkmanager logrotate libnotify openvpn)
DISTRO_DNS_PACKAGES=(bind)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python-cryptography"
