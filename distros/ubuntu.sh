#!/usr/bin/env bash
set -euo pipefail

DISTRO_PACKAGE_MANAGER="apt"
DISTRO_BASE_PACKAGES=(
  bash git coreutils findutils grep gawk sed gzip libc-bin passwd systemd sudo kmod
  ca-certificates python3 curl tar iproute2 network-manager logrotate
  libnotify-bin openvpn util-linux polkitd nftables iptables iputils-ping procps
  systemd-resolved
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
# The AmneziaWG PPA only publishes packages for the Ubuntu series it has built
# for; a newer release (for example Ubuntu 26.04 "resolute" before the PPA
# catches up) returns a 404 and cannot install the packaged runtime. Fall back
# to building the userspace amneziawg-go runtime from source: it needs no
# prebuilt package, no kernel headers and no DKMS module, so it works on any
# release and kernel, mirroring the Fedora/openSUSE adapters.
DISTRO_AMNEZIAWG_FALLBACK_COMMANDS=(
  "sudo apt install -y golang-go git make gcc"
  "git clone https://github.com/amnezia-vpn/amneziawg-tools /tmp/amneziawg-tools && make -C /tmp/amneziawg-tools/src && sudo make -C /tmp/amneziawg-tools/src install"
  "git clone https://github.com/amnezia-vpn/amneziawg-go /tmp/amneziawg-go && (cd /tmp/amneziawg-go && make) && sudo install -m 0755 /tmp/amneziawg-go/amneziawg-go /usr/local/bin/amneziawg-go"
)
