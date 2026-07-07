#!/usr/bin/env bash
set -euo pipefail

# AmneziaWG has no official Ubuntu/Debian/Arch repository package that could
# be installed unattended without adding a third-party APT/AUR trust root, and
# its kernel module (amneziawg-dkms) needs to be built against the running
# kernel. WatchdogVPN never adds that repository or builds anything itself
# without the user seeing and running the commands. Instead, install.sh walks
# the user through it: it prints the exact, distro-specific, official commands
# (so the user never has to research or guess them), waits for the user to run
# them in their own terminal, then re-checks and reports success/failure,
# repeating until AmneziaWG is confirmed working or the user gives up. This is
# the "clearly check" + guided-manual-install middle ground between full
# unattended automation and a bare link.
AMNEZIAWG_TOOLS_UPSTREAM="https://github.com/amnezia-vpn/amneziawg-tools"
AMNEZIAWG_KERNEL_MODULE_UPSTREAM="https://github.com/amnezia-vpn/amneziawg-linux-kernel-module"

amneziawg_userspace_available() {
  have_cmd awg-quick || have_cmd amneziawg-quick || have_cmd wg-quick \
    || [[ -x /usr/local/bin/awg-quick ]] || [[ -x /usr/local/bin/amneziawg-quick ]] \
    || [[ -x /usr/bin/awg-quick ]] || [[ -x /usr/bin/amneziawg-quick ]]
}

amneziawg_kernel_module_available() {
  # The AmneziaWG kernel module registers itself as "amneziawg"; the vanilla
  # WireGuard module ("wireguard") is accepted as a compatible fallback,
  # matching drivers/amneziawg_driver.py's own awg-quick-preferred /
  # wg-quick-fallback tolerance.
  [[ -d /sys/module/amneziawg ]] || [[ -d /sys/module/wireguard ]] \
    || modinfo amneziawg >/dev/null 2>&1 || modinfo wireguard >/dev/null 2>&1
}

print_amneziawg_dependency_notice() {
  cat <<EOF
AmneziaWG runtime check:
  WatchdogVPN cannot automatically install AmneziaWG tooling. There is no
  official Ubuntu/Debian/Arch repository package, and its kernel module must
  be built against the running kernel, so an unattended install here would
  require adding a third-party repository or building from source without
  your review.

  If you plan to use AmneziaWG profiles, install manually before connecting:
    Tools:         $AMNEZIAWG_TOOLS_UPSTREAM
    Kernel module: $AMNEZIAWG_KERNEL_MODULE_UPSTREAM

  Standard WireGuard tooling (wg-quick/wg, wireguard kernel module) is
  accepted as a compatible fallback if AmneziaWG-specific packages are not
  available for your distro.
EOF
}

check_amneziawg_dependency() {
  if amneziawg_userspace_available && amneziawg_kernel_module_available; then
    ok "AmneziaWG (or compatible WireGuard) tooling detected"
    return 0
  fi

  warn "AmneziaWG tooling not fully detected"
  print_amneziawg_dependency_notice
}

# Exact, official, copy-pasteable commands per distro. Sourced from the
# upstream amneziawg-linux-kernel-module README (Ubuntu/Debian) and the
# official AUR packages (Arch), verified before being hardcoded here.
amneziawg_setup_commands_ubuntu() {
  cat <<'EOF'
sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r)
sudo add-apt-repository -y ppa:amnezia/ppa
sudo apt-get update
sudo apt-get install -y amneziawg
EOF
}

amneziawg_setup_commands_debian() {
  cat <<'EOF'
sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r)
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828
echo "deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" | sudo tee -a /etc/apt/sources.list
echo "deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" | sudo tee -a /etc/apt/sources.list
sudo apt-get update
sudo apt-get install -y amneziawg
EOF
}

amneziawg_setup_commands_arch() {
  cat <<'EOF'
sudo pacman -S --needed --noconfirm base-devel git linux-headers
git clone https://aur.archlinux.org/amneziawg-dkms.git /tmp/amneziawg-dkms && (cd /tmp/amneziawg-dkms && makepkg -si --noconfirm)
git clone https://aur.archlinux.org/amneziawg-tools.git /tmp/amneziawg-tools && (cd /tmp/amneziawg-tools && makepkg -si --noconfirm)
EOF
}

amneziawg_setup_commands() {
  case "${DISTRO_ADAPTER_ID:-${DISTRO_ID:-}}" in
    ubuntu) amneziawg_setup_commands_ubuntu ;;
    debian) amneziawg_setup_commands_debian ;;
    arch) amneziawg_setup_commands_arch ;;
    *) return 1 ;;
  esac
}

# Walks the user through installing AmneziaWG step by step: prints the exact
# commands for their distro, waits for them to run it in their own terminal,
# then re-checks and reports whether it worked. WatchdogVPN never runs these
# commands itself - they add a third-party APT repository / build an AUR
# package, which the user must knowingly execute. Skips without prompting
# under --dry-run so scripted/CI installs never block on terminal input.
guide_amneziawg_setup() {
  local attempt max_attempts=3 answer commands

  if amneziawg_userspace_available && amneziawg_kernel_module_available; then
    ok "AmneziaWG (or compatible WireGuard) tooling detected"
    return 0
  fi

  if [[ "${INSTALL_DRY_RUN:-0}" == "1" ]]; then
    printf '[DRY-RUN] skip interactive AmneziaWG setup guide\n'
    return 0
  fi

  printf '\nAmneziaWG is not installed yet. It is only needed if you plan to use\n'
  printf 'AmneziaWG profiles; other Custom VPS protocols do not need it.\n'

  if ! prompt_yes_no "Walk through installing AmneziaWG step by step now?" no; then
    printf '[SKIP] AmneziaWG guided setup skipped.\n'
    print_amneziawg_dependency_notice
    return 0
  fi

  commands="$(amneziawg_setup_commands)" || {
    warn "no guided AmneziaWG setup is available for this distro yet"
    print_amneziawg_dependency_notice
    return 0
  }

  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    printf '\nRun the following commands in this terminal (they need sudo, and will ask\n'
    printf 'for your password):\n\n'
    printf '%s\n' "$commands"
    read -r -p $'\nPress Enter once you have run them, or type skip to stop: ' answer
    if [[ "$answer" == "skip" ]]; then
      printf '[SKIP] AmneziaWG guided setup stopped.\n'
      print_amneziawg_dependency_notice
      return 0
    fi

    if amneziawg_userspace_available && amneziawg_kernel_module_available; then
      ok "AmneziaWG detected - setup complete"
      return 0
    fi

    warn "AmneziaWG still not detected after attempt $attempt/$max_attempts"
    amneziawg_userspace_available || printf '  still missing: awg-quick/amneziawg-quick (or wg-quick) userspace tools\n'
    amneziawg_kernel_module_available || printf '  still missing: amneziawg (or wireguard) kernel module - a reboot may be required after a kernel/header update\n'
  done

  warn "AmneziaWG setup did not complete after $max_attempts attempts"
  printf 'Run ./doctor.sh later to check again once the issue above is resolved.\n'
}
