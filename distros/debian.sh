#!/usr/bin/env bash
set -euo pipefail

DISTRO_PACKAGE_MANAGER="apt"
DISTRO_BASE_PACKAGES=(
  bash git coreutils findutils grep gawk sed gzip libc-bin passwd systemd sudo kmod
  ca-certificates python3 curl tar iproute2 network-manager logrotate
  libnotify-bin openvpn util-linux polkitd nftables iptables iputils-ping procps
)
DISTRO_DNS_PACKAGES=(dnsutils)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"
DISTRO_POLKIT_PACKAGE="polkitd"
DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
  "sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-\$(uname -r)"
  "sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828"
  "echo 'deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main' | sudo tee -a /etc/apt/sources.list"
  "echo 'deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main' | sudo tee -a /etc/apt/sources.list"
  "sudo apt-get update"
  "sudo apt-get install -y amneziawg"
)
