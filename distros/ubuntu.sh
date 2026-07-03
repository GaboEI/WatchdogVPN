#!/usr/bin/env bash
set -euo pipefail

DISTRO_PACKAGE_MANAGER="apt"
DISTRO_BASE_PACKAGES=(python3 curl tar iproute2 network-manager logrotate libnotify-bin openvpn)
DISTRO_DNS_PACKAGES=(dnsutils)
