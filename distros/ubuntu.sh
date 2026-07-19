#!/usr/bin/env bash
set -euo pipefail

DISTRO_PACKAGE_MANAGER="apt"
DISTRO_BASE_PACKAGES=(
  bash coreutils findutils grep gawk sed gzip libc-bin passwd systemd sudo kmod
  ca-certificates python3 curl tar iproute2 network-manager logrotate
  libnotify-bin openvpn util-linux polkitd nftables iptables iputils-ping procps
)
DISTRO_POLKIT_PACKAGE="polkitd"
DISTRO_DNS_PACKAGES=(dnsutils)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"
DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
  "sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-\$(uname -r)"
  "sudo add-apt-repository -y ppa:amnezia/ppa"
  "sudo apt-get update"
  "sudo apt-get install -y amneziawg"
)
