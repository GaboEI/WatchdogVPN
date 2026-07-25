#!/usr/bin/env bash
set -euo pipefail

DISTRO_PACKAGE_MANAGER="apt"
DISTRO_BASE_PACKAGES=(
  bash git coreutils findutils grep gawk sed gzip libc-bin passwd systemd sudo kmod
  ca-certificates python3 curl tar iproute2 network-manager logrotate
  libnotify-bin openvpn util-linux polkitd nftables iptables iputils-ping procps
  systemd-resolved
)
DISTRO_DNS_PACKAGES=(dnsutils)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python3-cryptography"
DISTRO_POLKIT_PACKAGE="polkitd"
DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
  "sudo apt install -y python3-launchpadlib gnupg2 linux-headers-\$(uname -r)"
  "tmpdir=\$(mktemp -d) && GNUPGHOME=\"\$tmpdir\" gpg --batch --keyserver keyserver.ubuntu.com --recv-keys 57290828 && GNUPGHOME=\"\$tmpdir\" gpg --batch --export 57290828 | sudo gpg --dearmor --yes -o /usr/share/keyrings/amneziawg-archive-keyring.gpg; rm -rf \"\$tmpdir\""
  "sudo chmod 0644 /usr/share/keyrings/amneziawg-archive-keyring.gpg"
  "echo 'deb [signed-by=/usr/share/keyrings/amneziawg-archive-keyring.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/amneziawg-ppa.list"
  "echo 'deb-src [signed-by=/usr/share/keyrings/amneziawg-archive-keyring.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main' | sudo tee -a /etc/apt/sources.list.d/amneziawg-ppa.list"
  "sudo apt-get update"
  "sudo apt-get install -y amneziawg"
)
# If the pinned AmneziaWG apt repository has no packages for this Debian/kernel
# combination, fall back to building the userspace amneziawg-go runtime from
# source: it needs no prebuilt package, no kernel headers and no DKMS module, so
# it works on any release and kernel, mirroring the Fedora/openSUSE adapters.
DISTRO_AMNEZIAWG_FALLBACK_COMMANDS=(
  "sudo apt install -y golang-go git make gcc"
  "git clone https://github.com/amnezia-vpn/amneziawg-tools /tmp/amneziawg-tools && make -C /tmp/amneziawg-tools/src && sudo make -C /tmp/amneziawg-tools/src install"
  "git clone https://github.com/amnezia-vpn/amneziawg-go /tmp/amneziawg-go && (cd /tmp/amneziawg-go && make) && sudo install -m 0755 /tmp/amneziawg-go/amneziawg-go /usr/local/bin/amneziawg-go"
)
