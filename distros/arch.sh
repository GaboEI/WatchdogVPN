#!/usr/bin/env bash
set -euo pipefail

DISTRO_PACKAGE_MANAGER="pacman"
DISTRO_BASE_PACKAGES=(python curl iproute2 networkmanager logrotate libnotify)
DISTRO_CONKY_PACKAGE="conky"
