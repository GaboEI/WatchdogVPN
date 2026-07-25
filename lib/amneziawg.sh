#!/usr/bin/env bash
set -euo pipefail

# Shared AmneziaWG availability and user guidance. Callers must run
# detect_distro from lib/distro.sh before requesting distro-specific guidance.
# This is intentionally the single source of truth for doctor.sh and the CLI.

AMNEZIAWG_TOOLS_UPSTREAM="https://github.com/amnezia-vpn/amneziawg-tools"
AMNEZIAWG_KERNEL_MODULE_UPSTREAM="https://github.com/amnezia-vpn/amneziawg-linux-kernel-module"
AMNEZIAWG_GO_UPSTREAM="https://github.com/amnezia-vpn/amneziawg-go"

amneziawg_userspace_available() {
  have_cmd awg || [[ -x /usr/local/bin/awg ]] || [[ -x /usr/bin/awg ]]
}

amneziawg_kernel_module_available() {
  # Plain WireGuard cannot run AmneziaWG profiles with obfuscation keys.
  [[ -d /sys/module/amneziawg ]] || modinfo amneziawg >/dev/null 2>&1
}

amneziawg_userspace_fallback_available() {
  have_cmd amneziawg-go || [[ -x /usr/local/bin/amneziawg-go ]] || [[ -x /usr/bin/amneziawg-go ]]
}

amneziawg_runtime_available() {
  amneziawg_userspace_available && (amneziawg_kernel_module_available || amneziawg_userspace_fallback_available)
}

amneziawg_setup_commands() {
  declare -p DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS >/dev/null 2>&1 || return 1
  ((${#DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS[@]} > 0)) || return 1
  printf '%s\n' "${DISTRO_AMNEZIAWG_GUIDANCE_COMMANDS[@]}"
}

# Optional per-adapter from-source fallback for distributions whose packaged
# AmneziaWG path can fail on a release the upstream repository has not published
# yet (for example a brand-new Ubuntu series missing from the AmneziaWG PPA).
# Adapters that cannot fail this way simply leave the array undefined.
amneziawg_fallback_commands() {
  declare -p DISTRO_AMNEZIAWG_FALLBACK_COMMANDS >/dev/null 2>&1 || return 1
  ((${#DISTRO_AMNEZIAWG_FALLBACK_COMMANDS[@]} > 0)) || return 1
  printf '%s\n' "${DISTRO_AMNEZIAWG_FALLBACK_COMMANDS[@]}"
}

amneziawg_import_guidance_text() {
  local commands

  printf 'AmneziaWG profile saved, but its local runtime is not ready yet.\n'
  printf 'Required: awg tools plus the AmneziaWG kernel module or amneziawg-go.\n'
  printf 'Detected distro: %s (adapter: %s)\n' "${DISTRO_NAME:-Unknown Linux}" "${DISTRO_ADAPTER_ID:-unknown}"
  if commands="$(amneziawg_setup_commands)"; then
    printf 'Run these commands one at a time in a terminal, then return here:\n'
    local index=0 command
    while IFS= read -r command; do
      index=$((index + 1))
      printf '  %d. %s\n' "$index" "$command"
    done <<<"$commands"
  else
    printf 'No prevalidated command list is available for this distro.\n'
  fi
  local fallback_commands
  if fallback_commands="$(amneziawg_fallback_commands)"; then
    printf 'If your distribution release has no prebuilt AmneziaWG packages yet\n'
    printf '(the packaged step above cannot find them), build the userspace\n'
    printf 'runtime from source instead - it needs no prebuilt package:\n'
    local findex=0 fcommand
    while IFS= read -r fcommand; do
      findex=$((findex + 1))
      printf '  %d. %s\n' "$findex" "$fcommand"
    done <<<"$fallback_commands"
  fi
  printf 'Official sources:\n'
  printf '  tools: %s\n' "$AMNEZIAWG_TOOLS_UPSTREAM"
  printf '  kernel module: %s\n' "$AMNEZIAWG_KERNEL_MODULE_UPSTREAM"
  printf '  userspace fallback: %s\n' "$AMNEZIAWG_GO_UPSTREAM"
  printf 'Standard WireGuard tooling is not a substitute for AmneziaWG profiles.\n'
  printf 'Verify before connecting: watchdog doctor\n'
}

amneziawg_import_guidance_json() {
  local commands="" fallback_cmds="" message
  commands="$(amneziawg_setup_commands 2>/dev/null || true)"
  fallback_cmds="$(amneziawg_fallback_commands 2>/dev/null || true)"
  message="$(amneziawg_import_guidance_text)"
  "$(watchdogvpn_python)" - \
    "$(amneziawg_runtime_available && printf true || printf false)" \
    "${DISTRO_ID:-unknown}" \
    "${DISTRO_ADAPTER_ID:-unknown}" \
    "$(amneziawg_userspace_available && printf true || printf false)" \
    "$(amneziawg_kernel_module_available && printf true || printf false)" \
    "$(amneziawg_userspace_fallback_available && printf true || printf false)" \
    "$commands" \
    "$fallback_cmds" \
    "$message" <<'PY'
import json
import sys

available, distro, adapter, tools, kernel, fallback, commands, fallback_cmds, message = sys.argv[1:]
json.dump(
    {
        "available": available == "true",
        "distro": distro,
        "distro_adapter": adapter,
        "tools_available": tools == "true",
        "kernel_module_available": kernel == "true",
        "userspace_fallback_available": fallback == "true",
        "commands": commands.splitlines() if commands else [],
        "fallback_commands": fallback_cmds.splitlines() if fallback_cmds else [],
        "message": message,
    },
    sys.stdout,
)
PY
}
