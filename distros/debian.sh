#!/usr/bin/env bash
set -euo pipefail

DISTRO_PACKAGE_MANAGER="apt"
DISTRO_BASE_PACKAGES=(python3 curl iproute2 network-manager logrotate libnotify-bin)
DISTRO_CONKY_PACKAGE="conky-all"
