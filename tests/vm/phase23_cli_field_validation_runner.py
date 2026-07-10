#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from phase23_cli_field_validation_plan import ManifestError, _read_manifest, validate_manifest


GUARD_ENV = "WATCHDOGVPN_FIELD_VALIDATION"
BRANCH = "phase-23-cli-field-validation"
PROCESS_PATTERN = "sing-box|openvpn|ck-client|awg|wireguard|watchdog"


class FieldValidationError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-._").lower()
    return slug[:80] or "command"


def _redact(text: str, secrets: list[str]) -> str:
    result = text
    for secret in secrets:
        if secret:
            result = result.replace(secret, "<redacted>")
    return result


def _json_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _text_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _extract_json_document(text: str) -> Any:
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, _end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        return value
    raise FieldValidationError("command output did not contain a JSON document")


class Runner:
    def __init__(
        self,
        plan: dict[str, Any],
        *,
        section: str,
        external_vpn_state: str,
        dry_run: bool,
        selected_protocols: list[str] | None,
    ) -> None:
        self.plan = plan
        self.section = section
        self.external_vpn_state = external_vpn_state
        self.dry_run = dry_run
        self.selected_protocol_names = selected_protocols
        self.evidence_dir = Path(str(plan["evidence_dir"]))
        self.command_index = 0
        self.failures: list[str] = []
        self.secrets: list[str] = []
        self.last_stdout = ""
        self.started_at = _utc_now()

    def selected_profiles(self) -> list[dict[str, Any]]:
        profiles = list(self.plan["profiles"])
        if self.selected_protocol_names is None:
            return profiles
        selected = {protocol.strip() for protocol in self.selected_protocol_names if protocol.strip()}
        available = {profile["protocol"] for profile in profiles}
        unknown = sorted(selected - available)
        if unknown:
            raise FieldValidationError(f"unknown protocol selection: {', '.join(unknown)}")
        selected_profiles = [profile for profile in profiles if profile["protocol"] in selected]
        if not selected_profiles:
            raise FieldValidationError("protocol selection did not match any manifest profiles")
        return selected_profiles

    def require_guard(self) -> None:
        if self.dry_run:
            return
        if os.environ.get(GUARD_ENV) != "1":
            raise FieldValidationError(
                f"refusing to run disruptive field validation without {GUARD_ENV}=1"
            )

    def section_dir(self, name: str | None = None) -> Path:
        label = name or self.section
        return self.evidence_dir / label

    def command_path(self, section: str, label: str) -> Path:
        self.command_index += 1
        return self.section_dir(section) / f"{self.command_index:03d}-{_slug(label)}.json"

    def run(
        self,
        section: str,
        label: str,
        command: list[str],
        *,
        timeout: int = 120,
        ok_codes: set[int] | None = None,
        display_command: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> int:
        ok_codes = ok_codes or {0}
        display = display_command or command
        record: dict[str, Any] = {
            "label": label,
            "section": section,
            "started_at": _utc_now(),
            "command": display,
            "dry_run": self.dry_run,
        }
        if self.dry_run:
            self.last_stdout = ""
            record.update({"returncode": None, "stdout": "", "stderr": "", "finished_at": _utc_now()})
            _json_write(self.command_path(section, label), record)
            print(f"PHASE23_DRY_RUN {section} {label}")
            return 0

        try:
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            record.update(
                {
                    "returncode": "timeout",
                    "stdout": _redact(stdout, self.secrets),
                    "stderr": _redact(stderr, self.secrets),
                    "finished_at": _utc_now(),
                }
            )
            self.failures.append(f"{section}:{label}: timeout")
            _json_write(self.command_path(section, label), record)
            print(f"PHASE23_CMD_TIMEOUT {section} {label}", file=sys.stderr)
            return 124

        stdout = _redact(completed.stdout, self.secrets)
        stderr = _redact(completed.stderr, self.secrets)
        self.last_stdout = stdout
        record.update(
            {
                "returncode": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "finished_at": _utc_now(),
            }
        )
        if completed.returncode not in ok_codes:
            self.failures.append(f"{section}:{label}: rc={completed.returncode}")
            record["status"] = "failed"
            print(f"PHASE23_CMD_FAILED {section} {label} rc={completed.returncode}", file=sys.stderr)
        else:
            record["status"] = "ok"
            print(f"PHASE23_CMD_OK {section} {label}")
        _json_write(self.command_path(section, label), record)
        return completed.returncode

    def write_environment(self) -> None:
        text = "\n".join(
            [
                f"started_at={self.started_at}",
                f"host={socket.gethostname()}",
                f"section={self.section}",
                f"external_vpn_state={self.external_vpn_state}",
                f"evidence_dir={self.evidence_dir}",
                f"python={sys.version.split()[0]}",
                f"guard={GUARD_ENV}={os.environ.get(GUARD_ENV, '')}",
                "",
            ]
        )
        if not self.dry_run:
            _text_write(self.evidence_dir / "00-environment.txt", text)

    def snapshot(self, label: str) -> None:
        section = f"state-{label}"
        commands = [
            ("ip-rule", ["ip", "rule"]),
            ("ip-route", ["ip", "route"]),
            ("ip6-route", ["ip", "-6", "route"]),
            ("listeners", ["ss", "-H", "-ltnup"]),
            ("resolv-conf-sha256", ["sha256sum", "/etc/resolv.conf"]),
            ("nft-ruleset", ["sudo", "nft", "list", "ruleset"]),
            ("processes", ["pgrep", "-a", PROCESS_PATTERN]),
        ]
        for command_label, command in commands:
            self.run(section, f"{label}-{command_label}", command, ok_codes={0, 1}, timeout=30)

    def preflight(self) -> None:
        self.write_environment()
        self.run("preflight", "git-status", ["git", "status", "--short", "--branch"], timeout=30)
        self.run(
            "preflight",
            "git-rev-parse",
            ["git", "rev-parse", "HEAD", f"origin/{BRANCH}", "origin/main", "main"],
            timeout=30,
        )
        self.run("preflight", "update-installed-runtime", ["./update.sh", "--yes"], timeout=600)
        self.run("preflight", "watchdog-doctor", ["watchdog", "doctor", "--json"], timeout=180)
        self.run("preflight", "watchdog-status", ["watchdog", "status", "--json"], timeout=60)
        self.run("preflight", "profile-list", ["watchdog", "profile", "list", "--json"], timeout=60)
        self.run("preflight", "provider-list", ["watchdog", "provider", "list", "--json"], timeout=60)
        self.run("preflight", "dns-status", ["watchdog", "dns", "status", "--json"], timeout=60)
        self.run("preflight", "app-policy-status", ["watchdog", "app-policy", "status", "--json"], timeout=60)
        self.snapshot(f"baseline-{self.external_vpn_state}")

    def imports(self) -> None:
        profile_id_map: dict[str, str] = {}
        for profile in self.selected_profiles():
            rc = self.run(
                "profile-imports",
                f"import-{profile['protocol']}",
                ["watchdog", "profile", "add", "--file", profile["fixture_path"], "--json"],
                timeout=120,
            )
            if self.dry_run or rc != 0:
                continue
            try:
                payload = _extract_json_document(self.last_stdout)
                imported = payload.get("profiles", []) if isinstance(payload, dict) else []
            except FieldValidationError as exc:
                self.failures.append(f"profile-imports:import-{profile['protocol']}: {exc}")
                continue
            if not imported:
                self.failures.append(f"profile-imports:import-{profile['protocol']}: no imported profile in JSON")
                continue
            first = imported[0]
            actual_protocol = first.get("protocol")
            actual_id = first.get("id")
            if actual_protocol != profile["protocol"]:
                self.failures.append(
                    f"profile-imports:import-{profile['protocol']}: protocol mismatch "
                    f"expected={profile['protocol']} actual={actual_protocol}"
                )
                continue
            if not isinstance(actual_id, str) or not actual_id:
                self.failures.append(f"profile-imports:import-{profile['protocol']}: missing imported profile id")
                continue
            profile_id_map[profile["protocol"]] = actual_id
        self.run("profile-imports", "profile-list-after-import", ["watchdog", "profile", "list", "--json"])
        if profile_id_map and not self.dry_run:
            _json_write(self.evidence_dir / "phase23-profile-id-map.json", profile_id_map)

    def profile_id_for(self, profile: dict[str, Any]) -> str:
        profile_id_map_path = self.evidence_dir / "phase23-profile-id-map.json"
        if profile_id_map_path.is_file():
            profile_id_map = json.loads(profile_id_map_path.read_text(encoding="utf-8"))
            mapped = profile_id_map.get(profile["protocol"])
            if isinstance(mapped, str) and mapped:
                return mapped
        return str(profile["expected_id"])

    def protocols(self) -> None:
        for profile in self.selected_profiles():
            profile_id = self.profile_id_for(profile)
            section = f"protocols-{self.external_vpn_state}-{profile['protocol']}"
            connect_rc = self.run(section, "connect", ["watchdog", "connect", profile_id, "--json"], timeout=180)
            if connect_rc != 0:
                self.run(section, "status-after-failed-connect", ["watchdog", "status", "--json"], timeout=60, ok_codes={0, 69, 70})
                self.snapshot(f"post-failed-connect-{self.external_vpn_state}-{profile['protocol']}")
                continue
            self.run(section, "status-connected", ["watchdog", "status", "--json"], timeout=60)
            self.egress_probes(section)
            self.run(section, "disconnect", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
            self.run(section, "status-disconnected", ["watchdog", "status", "--json"], timeout=60, ok_codes={0, 69})
            self.snapshot(f"post-{self.external_vpn_state}-{profile['protocol']}")

    def egress_probes(self, section: str) -> None:
        url = f"https://{self.plan['probe_domain']}"
        self.run(section, "egress-normal", ["curl", "--fail", "--show-error", "--max-time", "20", url], timeout=45)
        self.run(
            section,
            "egress-socks",
            ["curl", "--fail", "--show-error", "--max-time", "20", "--socks5-hostname", "127.0.0.1:2080", url],
            timeout=45,
        )
        self.run(
            section,
            "egress-http",
            ["curl", "--fail", "--show-error", "--max-time", "20", "--proxy", "http://127.0.0.1:2081", url],
            timeout=45,
        )

    def provider(self) -> None:
        provider = self.plan["provider"]
        url_path = Path(provider["url_file"])
        if self.dry_run:
            provider_url = "<provider-url-from-file>"
        else:
            provider_url = url_path.read_text(encoding="utf-8").strip()
            if not provider_url:
                raise FieldValidationError(f"provider URL file is empty: {url_path}")
            self.secrets.append(provider_url)
        redacted_url = "<provider-url-from-file>"
        self.run(
            "provider",
            "provider-add",
            ["watchdog", "provider", "add", provider_url, "--name", provider["name"], "--json"],
            display_command=["watchdog", "provider", "add", redacted_url, "--name", provider["name"], "--json"],
            timeout=240,
        )
        self.run("provider", "provider-list", ["watchdog", "provider", "list", "--json"], timeout=60)
        self.run("provider", "provider-stats", ["watchdog", "provider", "stats", provider["expected_provider_id"], "--json"])
        self.run("provider", "provider-update", ["watchdog", "provider", "update", provider["expected_provider_id"], "--json"], timeout=240)
        self.run("provider", "provider-stats-after-update", ["watchdog", "provider", "stats", provider["expected_provider_id"], "--json"])
        self.run("provider", "connect-provider-node", ["watchdog", "connect", provider["expected_node_id"], "--json"], timeout=180)
        self.run("provider", "status-provider-node", ["watchdog", "status", "--json"], timeout=60)
        self.egress_probes("provider")
        self.run("provider", "disconnect-provider-node", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
        self.snapshot(f"post-provider-{self.external_vpn_state}")

    def app_policy(self) -> None:
        policy = self.plan["app_policy"]
        curl_binary = shutil.which("curl")
        if curl_binary is None:
            raise FieldValidationError("curl not found")
        curl_path = Path(curl_binary)
        for key in ("direct_probe_path", "vpn_probe_path", "block_probe_path"):
            link = Path(policy[key])
            if not self.dry_run:
                if link.exists() or link.is_symlink():
                    link.unlink()
                link.symlink_to(curl_path)
        section = "app-policy"
        self.run(section, "enable", ["watchdog", "app-policy", "enable", "--json"])
        self.run(section, "mode-blacklist", ["watchdog", "app-policy", "mode", "blacklist", "--json"])
        self.run(
            section,
            "add-direct",
            ["watchdog", "app-policy", "add", "--process-path", policy["direct_probe_path"], "--action", "direct", "--id", "phase23-direct", "--json"],
        )
        self.run(
            section,
            "add-current",
            ["watchdog", "app-policy", "add", "--process-path", policy["vpn_probe_path"], "--action", "current", "--id", "phase23-vpn", "--json"],
        )
        self.run(
            section,
            "add-block",
            ["watchdog", "app-policy", "add", "--process-path", policy["block_probe_path"], "--action", "block", "--id", "phase23-block", "--json"],
        )
        self.run(section, "status", ["watchdog", "app-policy", "status", "--json"])
        url = f"https://{self.plan['probe_domain']}"
        self.run(section, "direct-probe", [policy["direct_probe_path"], "--fail", "--show-error", "--max-time", "20", url], timeout=45)
        self.run(section, "current-probe", [policy["vpn_probe_path"], "--fail", "--show-error", "--max-time", "20", url], timeout=45)
        self.run(section, "block-probe", [policy["block_probe_path"], "--fail", "--show-error", "--max-time", "20", url], timeout=45, ok_codes={0, 6, 7, 28, 35, 56})
        self.run(section, "remove-direct", ["watchdog", "app-policy", "remove", "phase23-direct", "--json"], ok_codes={0, 65, 70})
        self.run(section, "remove-current", ["watchdog", "app-policy", "remove", "phase23-vpn", "--json"], ok_codes={0, 65, 70})
        self.run(section, "remove-block", ["watchdog", "app-policy", "remove", "phase23-block", "--json"], ok_codes={0, 65, 70})
        self.run(section, "disable", ["watchdog", "app-policy", "disable", "--json"], ok_codes={0, 70})
        self.snapshot(f"post-app-policy-{self.external_vpn_state}")

    def dns(self) -> None:
        section = "dns"
        self.run(section, "status-before", ["watchdog", "dns", "status", "--json"])
        self.run(section, "diagnose", ["watchdog", "dns", "diagnose", "--domain", self.plan["probe_domain"], "--json"])
        self.run(section, "apply-dry-run", ["watchdog", "dns", "apply", "--dry-run", "--json"])
        self.run(section, "apply", ["watchdog", "dns", "apply", "--yes", "--json"], timeout=120)
        self.run(section, "status-after-apply", ["watchdog", "dns", "status", "--json"])
        self.run(section, "resolver-probe", ["getent", "hosts", self.plan["probe_domain"]], timeout=45)
        self.run(section, "reset", ["watchdog", "dns", "reset", "--yes", "--json"], timeout=120, ok_codes={0, 70})
        self.snapshot(f"post-dns-{self.external_vpn_state}")

    def kill_switch(self) -> None:
        profile_id = self.plan["rotation"]["primary_profile_id"]
        section = "kill-switch"
        self.run(section, "enable", ["watchdog", "setup", "--yes", "--acknowledge-backup-warning", "--kill-switch", "enable", "--json"])
        self.run(section, "connect", ["watchdog", "connect", profile_id, "--json"], timeout=180)
        self.run(section, "status-enabled", ["watchdog", "status", "--json"])
        self.egress_probes(section)
        self.run(section, "disconnect", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
        self.run(section, "disable", ["watchdog", "setup", "--yes", "--acknowledge-backup-warning", "--kill-switch", "disable", "--json"])
        self.run(section, "status-disabled", ["watchdog", "status", "--json"], ok_codes={0, 69})
        self.snapshot(f"post-kill-switch-{self.external_vpn_state}")

    def rotation(self) -> None:
        rotation = self.plan["rotation"]
        provider = self.plan["provider"]
        section = "rotation"
        self.run(section, "primary-rotation-on", ["watchdog", "profile", "rotation", rotation["primary_profile_id"], "--enable", "--json"])
        self.run(section, "secondary-rotation-on", ["watchdog", "profile", "rotation", rotation["secondary_profile_id"], "--enable", "--json"])
        self.run(section, "pool-list", ["watchdog", "profile", "list", "--pool", "--json"])
        self.run(section, "connect-primary", ["watchdog", "connect", rotation["primary_profile_id"], "--json"], timeout=180)
        self.run(section, "rotate-force", ["watchdog", "rotate", "--force", "--json"], timeout=180, ok_codes={0, 70})
        self.run(section, "status-after-rotate", ["watchdog", "status", "--json"], ok_codes={0, 69})
        self.run(section, "provider-rotation-on", ["watchdog", "provider", "rotation", provider["expected_provider_id"], "--enable", "--json"], ok_codes={0, 65, 70})
        self.run(
            section,
            "provider-node-rotation-on",
            ["watchdog", "provider", "node", provider["expected_provider_id"], provider["expected_node_id"], "--rotation", "--enable", "--json"],
            ok_codes={0, 65, 70},
        )
        self.run(section, "rotate-provider", ["watchdog", "rotate", "--force", "--json"], timeout=180, ok_codes={0, 70})
        for profile_id in rotation["all_failed_profile_ids"]:
            self.run(section, f"disable-{profile_id}", ["watchdog", "profile", "disable", profile_id, "--json"], ok_codes={0, 65, 70})
        self.run(section, "rotate-all-failed", ["watchdog", "rotate", "--force", "--json"], timeout=180, ok_codes={0, 70})
        self.run(section, "status-all-failed", ["watchdog", "status", "--json"], ok_codes={0, 69})
        for profile_id in rotation["all_failed_profile_ids"]:
            self.run(section, f"reenable-{profile_id}", ["watchdog", "profile", "enable", profile_id, "--json"], ok_codes={0, 65, 70})
        self.run(section, "disconnect", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
        self.snapshot(f"post-rotation-{self.external_vpn_state}")

    def manual_off(self) -> None:
        section = "manual-off"
        self.run(section, "disconnect-before-manual-off", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
        self.snapshot("pre-manual-off")
        self.run(section, "systemctl-stop", ["sudo", "systemctl", "stop", "watchdogvpn.service"], timeout=120, ok_codes={0, 3, 4, 5})
        self.run(section, "status-after-stop", ["watchdog", "status", "--json"], timeout=60, ok_codes={0, 69})
        self.snapshot("after-systemctl-stop")
        self.run(section, "systemctl-start", ["sudo", "systemctl", "start", "watchdogvpn.service"], timeout=120)
        self.run(section, "status-after-start", ["watchdog", "status", "--json"], timeout=60, ok_codes={0, 69})
        self.run(section, "panic-sleep", ["watchdog", "panic", "sleep"], timeout=180, ok_codes={0, 1})
        self.run(section, "panic-status", ["watchdog", "panic", "status"], timeout=60, ok_codes={0, 1})
        self.run(section, "panic-wake", ["watchdog", "panic", "wake"], timeout=180, ok_codes={0, 1})
        self.run(section, "status-after-panic-wake", ["watchdog", "status", "--json"], timeout=60, ok_codes={0, 69})
        self.snapshot("post-manual-off")
        self.write_reboot_runbook()

    def write_reboot_runbook(self) -> None:
        connected_profile_id = self.plan["reboot"]["connected_profile_id"]
        path = self.evidence_dir / "10-reboot-manual-off" / "reboot-operator-steps.md"
        text = f"""# Phase 23 Reboot Operator Steps

Run these manually in the VM snapshot. Capture outputs in `10-reboot-manual-off/`.

## Reboot While Disconnected

```bash
watchdog disconnect --json
ip rule
ip route
ip -6 route
ss -H -ltnup
sha256sum /etc/resolv.conf
sudo nft list ruleset
sudo reboot
```

After the VM returns:

```bash
watchdog doctor --json
watchdog status --json
ip rule
ip route
ip -6 route
ss -H -ltnup
sha256sum /etc/resolv.conf
sudo nft list ruleset
```

## Reboot While Connected

```bash
watchdog connect {connected_profile_id} --json
watchdog status --json
ip rule
ip route
ip -6 route
ss -H -ltnup
sha256sum /etc/resolv.conf
sudo nft list ruleset
sudo reboot
```

After the VM returns:

```bash
watchdog doctor --json
watchdog status --json
curl --fail --show-error --max-time 20 https://{self.plan['probe_domain']}
watchdog disconnect --json
watchdog dns reset --yes --json
watchdog panic wake
```
"""
        if not self.dry_run:
            _text_write(path, text)
        print(f"PHASE23_REBOOT_RUNBOOK={path}")

    def cleanup(self) -> None:
        section = "cleanup"
        self.run(section, "disconnect", ["watchdog", "disconnect", "--json"], timeout=180, ok_codes={0, 70})
        self.run(section, "dns-reset", ["watchdog", "dns", "reset", "--yes", "--json"], timeout=120, ok_codes={0, 70})
        self.run(section, "app-policy-disable", ["watchdog", "app-policy", "disable", "--json"], ok_codes={0, 70})
        self.run(section, "panic-wake", ["watchdog", "panic", "wake"], timeout=180, ok_codes={0, 1})
        self.run(section, "status", ["watchdog", "status", "--json"], ok_codes={0, 69})
        self.run(section, "doctor", ["watchdog", "doctor", "--json"], timeout=180, ok_codes={0, 1})
        self.snapshot("final-cleanup")

    def write_summary(self) -> None:
        summary = {
            "section": self.section,
            "external_vpn_state": self.external_vpn_state,
            "started_at": self.started_at,
            "finished_at": _utc_now(),
            "dry_run": self.dry_run,
            "protocols": self.selected_protocol_names or "all",
            "failures": self.failures,
            "failure_count": len(self.failures),
        }
        if not self.dry_run:
            _json_write(self.evidence_dir / f"summary-{_slug(self.section)}-{int(time.time())}.json", summary)
        print("PHASE23_FIELD_SECTION_FAILED" if self.failures else "PHASE23_FIELD_SECTION_OK")
        print(json.dumps(summary, indent=2, sort_keys=True))

    def dispatch(self) -> int:
        self.require_guard()
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        if self.section in {"all", "preflight"}:
            self.preflight()
        if self.section in {"all", "imports"}:
            self.imports()
        if self.section in {"all", "protocols"}:
            self.protocols()
        if self.section in {"all", "provider"}:
            self.provider()
        if self.section in {"all", "app-policy"}:
            self.app_policy()
        if self.section in {"all", "dns"}:
            self.dns()
        if self.section in {"all", "kill-switch"}:
            self.kill_switch()
        if self.section in {"all", "rotation"}:
            self.rotation()
        if self.section in {"all", "manual-off"}:
            self.manual_off()
        if self.section in {"all", "cleanup"}:
            self.cleanup()
        self.write_summary()
        return 1 if self.failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Operator-run Phase 23 CLI field validation runner")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument(
        "--section",
        required=True,
        choices=[
            "all",
            "preflight",
            "imports",
            "protocols",
            "provider",
            "app-policy",
            "dns",
            "kill-switch",
            "rotation",
            "manual-off",
            "cleanup",
        ],
    )
    parser.add_argument("--external-vpn-state", choices=["absent", "present"], default="absent")
    parser.add_argument(
        "--protocols",
        help="comma-separated protocol subset for staged imports/protocol validation",
    )
    parser.add_argument("--dry-run", action="store_true", help="Write command records without executing commands")
    args = parser.parse_args()

    try:
        plan = validate_manifest(_read_manifest(args.manifest))
        runner = Runner(
            plan,
            section=args.section,
            external_vpn_state=args.external_vpn_state,
            dry_run=bool(args.dry_run),
            selected_protocols=args.protocols.split(",") if args.protocols else None,
        )
        return runner.dispatch()
    except (ManifestError, FieldValidationError, OSError, ValueError) as exc:
        print(f"PHASE23_FIELD_RUNNER_FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
