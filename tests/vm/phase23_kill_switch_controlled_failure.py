#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GUARD_ENV = "WATCHDOGVPN_FIELD_VALIDATION"
SERVICE = "watchdogvpn.service"
NFT_TABLE = ("inet", "watchdogvpn")
IPTABLES_CHAIN = "WATCHDOGVPN-OUTPUT"


class ControlledFailureError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(command: list[str], *, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ControlledFailureError(f"command timed out: {command[0]}") from exc


def _require_ok(command: list[str], *, timeout: int = 45) -> str:
    completed = _run(command, timeout=timeout)
    if completed.returncode != 0:
        raise ControlledFailureError(
            f"command failed: {command[0]} rc={completed.returncode}"
        )
    return completed.stdout


def _status_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip().lower()] = value.strip()
    return fields


def _validated_probe_domain(value: str) -> str:
    domain = value.rstrip(".").lower()
    if len(domain) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
        domain,
    ):
        raise ControlledFailureError("probe domain is not a valid DNS hostname")
    return domain


def _select_target_ip(payload: dict[str, Any], firewall_snapshot: str) -> str:
    for answer in payload.get("Answer", []):
        if not isinstance(answer, dict):
            continue
        value = str(answer.get("data", "")).strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4 and address.is_global and value not in firewall_snapshot:
            return value
    raise ControlledFailureError(
        "resolver returned no global IPv4 target distinct from firewall allowances"
    )


def _nft_drop_packet_count(snapshot: str) -> int:
    total = 0
    pattern = re.compile(r"\bcounter packets (\d+) bytes \d+ drop\b")
    for line in snapshot.splitlines():
        match = pattern.search(line)
        if match:
            total += int(match.group(1))
    return total


def _iptables_drop_packet_count(snapshot: str) -> int:
    total = 0
    for line in snapshot.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0].isdigit() and fields[2] in {"DROP", "REJECT"}:
            total += int(fields[0])
    return total


def _firewall_snapshot(backend: str) -> tuple[str, int]:
    if backend == "nftables":
        snapshot = _require_ok(
            ["sudo", "-n", "nft", "list", "table", *NFT_TABLE]
        )
        return snapshot, _nft_drop_packet_count(snapshot)
    if backend in {"iptables", "ip6tables"}:
        snapshot = _require_ok(
            ["sudo", "-n", "iptables", "-L", IPTABLES_CHAIN, "-n", "-v", "-x"]
        )
        return snapshot, _iptables_drop_packet_count(snapshot)
    raise ControlledFailureError(f"unsupported active kill-switch backend: {backend}")


def _main_pid() -> int:
    value = _require_ok(
        ["systemctl", "show", "--property", "MainPID", "--value", SERVICE]
    ).strip()
    if not value.isdigit() or int(value) <= 1:
        raise ControlledFailureError("watchdogvpn.service has no valid MainPID")
    return int(value)


def _owned_sing_box_child(daemon_pid: int, *, proc_root: Path = Path("/proc")) -> int:
    task_root = proc_root / str(daemon_pid) / "task"
    child_values: set[str] = set()
    try:
        children_paths = list(task_root.glob("*/children"))
        for children_path in children_paths:
            child_values.update(children_path.read_text(encoding="utf-8").split())
    except OSError as exc:
        raise ControlledFailureError("cannot inspect daemon child processes") from exc
    if not children_paths:
        raise ControlledFailureError("daemon task list is unavailable")

    matches: list[int] = []
    for value in child_values:
        if not value.isdigit():
            continue
        child_pid = int(value)
        try:
            command = (proc_root / str(child_pid) / "comm").read_text(encoding="utf-8").strip()
            status = (proc_root / str(child_pid) / "status").read_text(encoding="utf-8")
            cgroup = (proc_root / str(child_pid) / "cgroup").read_text(encoding="utf-8")
        except OSError:
            continue
        ppid_match = re.search(r"^PPid:\s+(\d+)$", status, re.MULTILINE)
        if (
            command == "sing-box"
            and ppid_match is not None
            and int(ppid_match.group(1)) == daemon_pid
            and SERVICE in cgroup
        ):
            matches.append(child_pid)
    if len(matches) != 1:
        raise ControlledFailureError(
            f"expected exactly one owned sing-box child, found {len(matches)}"
        )
    return matches[0]


def _process_is_running(pid: int) -> bool:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
    except OSError:
        return False
    return len(fields) > 2 and fields[2] != "Z"


def _write_private(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def controlled_failure(
    *, physical_interface: str, probe_domain: str, evidence_dir: Path
) -> dict[str, Any]:
    probe_domain = _validated_probe_domain(probe_domain)
    record: dict[str, Any] = {
        "started_at": _utc_now(),
        "physical_interface": physical_interface,
        "probe_domain": probe_domain,
    }
    daemon_pid: int | None = None
    daemon_stopped = False

    _require_ok(["ip", "link", "show", "dev", physical_interface])
    status = _status_fields(_require_ok(["watchdog", "status"]))
    if status.get("status") != "connected":
        raise ControlledFailureError("WatchdogVPN is not connected")
    if status.get("kill switch state") != "applied":
        raise ControlledFailureError("kill switch is not applied")
    backend = status.get("kill switch backend", "")
    record["backend"] = backend

    before_snapshot, drop_before = _firewall_snapshot(backend)
    _write_private(evidence_dir / "firewall-before.txt", before_snapshot)

    doh = _require_ok(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            "--socks5-hostname",
            "127.0.0.1:2080",
            f"https://dns.google/resolve?name={probe_domain}&type=A",
        ],
        timeout=40,
    )
    try:
        payload = json.loads(doh)
    except json.JSONDecodeError as exc:
        raise ControlledFailureError("DoH response is not valid JSON") from exc
    target_ip = _select_target_ip(payload, before_snapshot)
    _write_private(evidence_dir / "resolver-response.json", doh)

    daemon_pid = _main_pid()
    child_pid = _owned_sing_box_child(daemon_pid)
    record["daemon_pid"] = daemon_pid
    record["child_pid"] = child_pid

    try:
        _require_ok(["sudo", "-n", "kill", "-STOP", str(daemon_pid)])
        daemon_stopped = True
        _require_ok(["sudo", "-n", "kill", "-KILL", str(child_pid)])
        time.sleep(2)
        if _process_is_running(child_pid):
            raise ControlledFailureError("owned sing-box child survived SIGKILL")

        curl_result = _run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "8",
                "--interface",
                physical_interface,
                "--resolve",
                f"{probe_domain}:443:{target_ip}",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                f"https://{probe_domain}/",
            ],
            timeout=15,
        )
        ping_result = _run(
            [
                "ping",
                "-n",
                "-c",
                "1",
                "-W",
                "2",
                "-I",
                physical_interface,
                target_ip,
            ],
            timeout=10,
        )
        after_snapshot, drop_after = _firewall_snapshot(backend)
        _write_private(evidence_dir / "firewall-after.txt", after_snapshot)

        record.update(
            {
                "curl_returncode": curl_result.returncode,
                "curl_http_code": curl_result.stdout.strip(),
                "ping_returncode": ping_result.returncode,
                "drop_before": drop_before,
                "drop_after": drop_after,
                "drop_delta": drop_after - drop_before,
            }
        )
        if curl_result.returncode not in {7, 28} or curl_result.stdout.strip() != "000":
            raise ControlledFailureError(
                "forced physical HTTPS did not fail closed before data transfer"
            )
        if ping_result.returncode != 1:
            raise ControlledFailureError("forced physical ICMP did not fail closed")
        if drop_after <= drop_before:
            raise ControlledFailureError("kill-switch DROP counters did not increase")
    finally:
        if daemon_stopped and daemon_pid is not None:
            resumed = _run(["sudo", "-n", "kill", "-CONT", str(daemon_pid)])
            daemon_stopped = False
            if resumed.returncode != 0:
                raise ControlledFailureError("could not resume watchdogvpn daemon")

    status_rc = 1
    for _attempt in range(10):
        status_rc = _run(["watchdog", "status"], timeout=15).returncode
        if status_rc == 0:
            break
        time.sleep(2)
    record["status_after_resume_returncode"] = status_rc
    record["finished_at"] = _utc_now()
    if status_rc != 0:
        raise ControlledFailureError("daemon did not answer after controlled failure")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed kill-switch field validation for an active sing-box session"
    )
    parser.add_argument("--physical-interface", required=True)
    parser.add_argument("--probe-domain", required=True)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()

    if os.environ.get(GUARD_ENV) != "1":
        print(
            f"refusing controlled failure without {GUARD_ENV}=1",
            file=sys.stderr,
        )
        return 64

    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = controlled_failure(
            physical_interface=args.physical_interface,
            probe_domain=args.probe_domain,
            evidence_dir=args.evidence_dir,
        )
    except (ControlledFailureError, OSError, ValueError) as exc:
        _write_private(
            args.evidence_dir / "controlled-failure-error.txt",
            f"{type(exc).__name__}: {exc}\n",
        )
        print(f"PHASE23_KILL_SWITCH_CONTROLLED_FAILURE_FAILED: {exc}", file=sys.stderr)
        return 1

    _write_private(
        args.evidence_dir / "controlled-failure.json",
        json.dumps(result, indent=2, sort_keys=True) + "\n",
    )
    print(
        "PHASE23_KILL_SWITCH_CONTROLLED_FAILURE_OK "
        f"backend={result['backend']} drop_delta={result['drop_delta']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
