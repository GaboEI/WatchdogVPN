#!/usr/bin/env bash
set -uo pipefail
umask 077

# L3.3 harness: strict real traffic and independent direct profile checks.
# Provider and profile identifiers come from the environment so no secrets or
# private profile data are written to the repository.

EVIDENCE_DIR="${L3_3_EVIDENCE_DIR:?L3_3_EVIDENCE_DIR is required}"
PROVIDER_URL="${L3_3_PROVIDER_URL:-}"
PROVIDER_ID="${L3_3_PROVIDER_ID:-l3-3-test}"
PROVIDER_NAME="${L3_3_PROVIDER_NAME:-L3.3 corrected provider}"
PROFILE_A="${L3_3_PROFILE_A:?L3_3_PROFILE_A is required}"
PROFILE_B="${L3_3_PROFILE_B:?L3_3_PROFILE_B is required}"
PROFILE_C="${L3_3_PROFILE_C:?L3_3_PROFILE_C is required}"

mkdir -p "$EVIDENCE_DIR"
chmod 700 "$EVIDENCE_DIR"

record() {
  local name="$1"
  shift
  "$@" >"$EVIDENCE_DIR/$name" 2>&1
  local rc=$?
  printf '%s\n' "$rc" >"$EVIDENCE_DIR/$name.rc"
  return "$rc"
}

capture_checkpoint() {
  local label="$1"
  record "${label}_status.json" sudo -n "$WATCHDOG" status --json || return 1
  record "${label}_route.txt" ip route get 1.1.1.1 || return 1
  record "${label}_routes.txt" sh -c 'ip route; ip -6 route; ip rule' || return 1
  record "${label}_interfaces.json" ip -j addr show || return 1
  record "${label}_dns.txt" getent ahostsv4 www.facebook.com || return 1
  record "${label}_egress_ip.txt" curl -4 --fail --show-error --connect-timeout 10 --max-time 30 https://api.ipify.org || return 1

  : >"$EVIDENCE_DIR/${label}_traffic.tsv"
  printf 'site\tattempt\texit_code\thttp_status\tbytes\tremote_ip\ttimestamp\tduration_seconds\n' \
    >"$EVIDENCE_DIR/${label}_traffic.tsv"
  local site
  local -a failed_sites=()

  check_site() {
    local site_name="$1"
    local attempt_number="$2"
    local evidence_label="$3"
    local site_output site_rc site_code site_bytes site_remote site_timestamp site_duration
    site_output="$EVIDENCE_DIR/${label}_${evidence_label}_${attempt_number}.txt"
    site_timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    curl -4 -L --fail --show-error --connect-timeout 10 --max-time 30 \
      -o /dev/null -w 'http_code=%{http_code}\tbytes=%{size_download}\tremote_ip=%{remote_ip}\ttime_total=%{time_total}\turl=%{url_effective}\n' \
      "https://$site_name" >"$site_output" 2>&1
    site_rc=$?
    site_code="$(awk -F'\t' '/http_code=/{sub(/^http_code=/, "", $1); print $1}' "$site_output" | tail -n 1)"
    site_bytes="$(awk -F'\t' '/bytes=/{sub(/^bytes=/, "", $2); print $2}' "$site_output" | tail -n 1)"
    site_remote="$(awk -F'\t' '/remote_ip=/{sub(/^remote_ip=/, "", $3); print $3}' "$site_output" | tail -n 1)"
    site_duration="$(awk -F'\t' '/time_total=/{sub(/^time_total=/, "", $4); print $4}' "$site_output" | tail -n 1)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$site_name" "$attempt_number" "$site_rc" "${site_code:-000}" "${site_bytes:-0}" \
      "${site_remote:-}" "$site_timestamp" "${site_duration:-}" \
      >>"$EVIDENCE_DIR/${label}_traffic.tsv"
    [[ "$site_rc" -eq 0 && "${site_code:-000}" =~ ^2[0-9][0-9]$ && -n "$site_remote" && "${site_bytes:-0}" -gt 0 ]]
  }

  for site in www.facebook.com www.instagram.com www.youtube.com; do
    local site_failed=0
    for attempt in 1 2; do
      if ! check_site "$site" "$attempt" "$site"; then
        site_failed=$((site_failed + 1))
      fi
    done
    [[ "$site_failed" -eq 2 ]] && failed_sites+=("$site")
  done

  local fallback_site fallback_attempt fallback_failed
  local -a fallback_sites=(github.com www.wikipedia.org www.debian.org)
  local -a replacement_sites=(www.mozilla.org www.kernel.org www.gnu.org)
  for site in "${failed_sites[@]}"; do
    fallback_failed=0
    fallback_attempt=0
    for fallback_site in "${fallback_sites[@]}"; do
      fallback_attempt=$((fallback_attempt + 1))
      if ! check_site "$fallback_site" "$fallback_attempt" "fallback1_${fallback_site}"; then
        fallback_failed=$((fallback_failed + 1))
      fi
    done
    [[ "$fallback_failed" -eq 0 ]] && continue
    fallback_failed=0
    fallback_attempt=0
    for fallback_site in "${replacement_sites[@]}"; do
      fallback_attempt=$((fallback_attempt + 1))
      if ! check_site "$fallback_site" "$fallback_attempt" "fallback2_${fallback_site}"; then
        fallback_failed=$((fallback_failed + 1))
      fi
    done
    [[ "$fallback_failed" -eq 0 ]] || return 1
  done
}

WATCHDOG=/usr/local/bin/watchdog
cleanup_needed=0

cleanup_on_exit() {
  [[ "$cleanup_needed" -eq 1 ]] || return 0
  sudo -n "$WATCHDOG" disconnect --json >/dev/null 2>&1 || true
  sudo -n "$WATCHDOG" provider remove "$PROVIDER_ID" --json >/dev/null 2>&1 || true
}
trap cleanup_on_exit EXIT

record baseline_status.json sudo -n "$WATCHDOG" status --json || exit 1
record baseline_profiles.json sudo -n "$WATCHDOG" profile list --json || exit 1
record baseline_providers.json sudo -n "$WATCHDOG" provider list --json || exit 1
record direct_ip.txt curl -4 --fail --show-error --connect-timeout 10 --max-time 30 https://api.ipify.org || exit 1
if [[ "${L3_3_SKIP_IMPORT:-0}" == "1" ]]; then
  record provider_add.json sh -c 'printf "%s\n" "provider import skipped; existing provider is under test"'
else
  [[ -n "$PROVIDER_URL" ]] || { printf 'L3_3_PROVIDER_URL is required\n' >&2; exit 1; }
  record provider_add.json sudo -n "$WATCHDOG" provider add "$PROVIDER_URL" --name "$PROVIDER_NAME" --json || exit 1
  cleanup_needed=1
fi
record provider_list_after_add.json sudo -n "$WATCHDOG" provider list --json || exit 1

if [[ "${L3_3_SKIP_IMPORT:-0}" != "1" ]]; then
  PROVIDER_ID="$(python3 - "$EVIDENCE_DIR/provider_add.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
print(data["provider"]["id"])
PY
  )"
fi
[[ -n "$PROVIDER_ID" ]] || exit 1
# Verify the required profiles were imported. Rotation is intentionally out of
# scope for L3.
record profiles_after_add.json sudo -n "$WATCHDOG" profile list --json || exit 1
if ! python3 - "$EVIDENCE_DIR/profiles_after_add.json" "$PROVIDER_ID" "$PROFILE_A" "$PROFILE_B" "$PROFILE_C" <<'PY'
import json
import sys

path, provider_id, *required = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    profiles = json.load(handle)
ids = {item["id"] for item in profiles if item.get("provider_id") == provider_id}
missing = set(required) - ids
if missing:
    raise SystemExit(f"required profiles missing: {sorted(missing)}")
PY
then
  exit 1
fi

for profile in "$PROFILE_A" "$PROFILE_B" "$PROFILE_C"; do
  label="${profile##*:}"
  record "connect_${label}.json" sudo -n "$WATCHDOG" connect "$profile" --json || exit 1
  capture_checkpoint "$label" || exit 1
  record "disconnect_${label}.json" sudo -n "$WATCHDOG" disconnect --json || exit 1
done

record provider_remove.json sudo -n "$WATCHDOG" provider remove "$PROVIDER_ID" --json || exit 1
record final_profiles.json sudo -n "$WATCHDOG" profile list --json || exit 1
record final_providers.json sudo -n "$WATCHDOG" provider list --json || exit 1
record final_status.json sudo -n "$WATCHDOG" status --json || exit 1
record final_doctor.json sudo -n "$WATCHDOG" doctor --json || exit 1

# Cleanup must restore the exact previous profile set; do not claim zero
# profiles when the host had legitimate manual profiles.
if ! python3 - "$EVIDENCE_DIR/baseline_profiles.json" "$EVIDENCE_DIR/final_profiles.json" "$PROVIDER_ID" <<'PY'
import json
import sys

def ids(path, provider_id):
    with open(path, encoding="utf-8") as handle:
        return {
            item["id"]
            for item in json.load(handle)
            if item.get("provider_id") != provider_id
        }

before, after = ids(sys.argv[1], sys.argv[3]), ids(sys.argv[2], sys.argv[3])
if before != after:
    raise SystemExit(f"profile cleanup changed baseline: before={sorted(before)} after={sorted(after)}")
PY
then
  exit 1
fi

mapfile -t evidence_files < <(find "$EVIDENCE_DIR" -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | sort)
(cd "$EVIDENCE_DIR" && sha256sum "${evidence_files[@]}" >SHA256SUMS)
(cd "$EVIDENCE_DIR" && sha256sum -c SHA256SUMS >SHA256SUMS.verify)
chmod 600 "$EVIDENCE_DIR"/*
cleanup_needed=0
printf 'L3_3_CORRECTED_PASS\n'
