#!/usr/bin/env bash
set -euo pipefail

# openSUSE adapter. This enables installer/update package reconciliation only;
# distro certification remains a separate installed evidence task.
DISTRO_PACKAGE_MANAGER="zypper"
# openSUSE Leap's default `python3` is 3.6, too old for the runtime
# (`from __future__ import annotations` needs 3.7+). Pin the modern interpreter
# the runtime resolver (lib/common.sh:watchdogvpn_python) should use; the
# matching python311 packages are in the base set and the cryptography package
# below. This does not retarget the OS default python3, which system tools use.
DISTRO_PYTHON="python3.11"
DISTRO_CERTIFICATION_STATE="implemented_not_certified"
DISTRO_SUPPORT_NOTE="openSUSE adapter implemented; installed certification remains pending Phase 23.6 evidence."

# Phase 23.7.5.11D sequencing bootstrap: openSUSE Leap 15.6 ships python3=3.6,
# too old for the detection engine (3.7+). When the engine cannot run yet, the
# installer bootstraps ONLY the interpreter package below, then re-runs
# authoritative detection through the engine. Declaring this hook is what opts
# the adapter into that sequencing step; adapters whose default python3 already
# meets the detection floor never declare it.
distro_python_bootstrap_package() {
  printf '%s\n' "python311"
}
DISTRO_BASE_PACKAGES=(
  bash git coreutils findutils grep gawk sed gzip glibc shadow systemd sudo kmod
  ca-certificates python3 curl tar iproute2 NetworkManager logrotate
  libnotify-tools openvpn util-linux polkit nftables iptables iputils procps
  firewalld apparmor-utils python311
)
DISTRO_DNS_PACKAGES=(bind-utils)
DISTRO_PYTHON_CRYPTOGRAPHY_PACKAGE="python311-cryptography"
DISTRO_POLKIT_PACKAGE="polkit"
# AmneziaWG has no official openSUSE package, so the guided trust-boundary
# setup builds the userspace stack from Amnezia's official source, same as
# Fedora's distros/fedora.sh. The userspace amneziawg-go path is deliberately
# preferred over the DKMS kernel module here: it needs no kernel headers and
# is not blocked by Secure Boot module signing, so it strands far fewer users
# while carrying identical real traffic. Every command pins an official release
# tag plus its exact commit - main/master/HEAD is never used. WatchdogVPN never
# runs these commands; it verifies awg and amneziawg-go afterwards.
DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS=(
  "sudo zypper --non-interactive install go gcc make git"
  "git clone --branch v1.0.20260618-2 https://github.com/amnezia-vpn/amneziawg-tools /tmp/amneziawg-tools && git -C /tmp/amneziawg-tools checkout 61e741780e8465a67a7d7fb6cffe14a8a15d624a && make -C /tmp/amneziawg-tools/src WITH_WGQUICK=yes WITH_SYSTEMDUNITS=no WITH_BASHCOMPLETION=no && sudo make -C /tmp/amneziawg-tools/src install"
  "git clone --branch v3.0.2 https://github.com/amnezia-vpn/amneziawg-go /tmp/amneziawg-go && git -C /tmp/amneziawg-go checkout 0527dfa47639714dd8f5c9ffbd9d40d19083f0ba && make -C /tmp/amneziawg-go && sudo install -m 0755 /tmp/amneziawg-go/amneziawg-go /usr/local/bin/amneziawg-go"
)
