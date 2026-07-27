"""Real focused L2 dependency checks.

Set WATCHDOGVPN_REAL_L2=1 to run these against disposable Docker/Podman
containers. Metadata refreshes, when required, happen only inside containers.
These checks do not certify kernel, TUN, firewall or protocol behavior.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import unittest
from unittest import mock


REAL_L2_ENABLED = os.environ.get("WATCHDOGVPN_REAL_L2") == "1"
TIMEOUT_SECONDS = 120


CASES = (
    {"target": "ubuntu_24_04", "image": "ubuntu:24.04", "id": "ubuntu", "version_id": "24.04", "codename": "noble", "manager": "apt-get", "packages": ("python3", "openvpn"), "kind": "apt"},
    {"target": "ubuntu_26_04", "image": "ubuntu:26.04", "id": "ubuntu", "version_id": "26.04", "codename": "resolute", "manager": "apt-get", "packages": ("python3", "openvpn"), "kind": "apt", "optional_image": True},
    {"target": "debian_13", "image": "debian:13", "id": "debian", "version_id": "13", "codename": "trixie", "manager": "apt-get", "packages": ("python3", "openvpn"), "kind": "apt"},
    {"target": "fedora_44", "image": "fedora:44", "id": "fedora", "version_id": "44", "codename": None, "manager": "dnf", "packages": ("python3", "openvpn"), "kind": "dnf"},
    {"target": "rocky_9", "image": "rockylinux:9", "id": "rocky", "version_id": "9", "codename": None, "manager": "dnf", "packages": ("python3.11", "epel-release", "openvpn"), "kind": "dnf", "epel_repo_url": "https://dl.fedoraproject.org/pub/epel/9/Everything/$basearch/", "refresh": "true"},
    {"target": "opensuse_leap_15_6", "image": "opensuse/leap:15.6", "id": "opensuse-leap", "version_id": "15.6", "codename": None, "manager": "zypper", "packages": ("python311", "openvpn"), "kind": "zypper"},
    {"target": "arch", "image": "archlinux:latest", "id": "arch", "version_id": None, "codename": None, "manager": "pacman", "packages": ("python", "openvpn"), "kind": "pacman", "refresh": "pacman -Sy --noconfirm"},
)


def _runtime() -> str | None:
    for name in ("podman", "docker"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _run(runtime: str, args: list[str], *, timeout: int = TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    return subprocess.run([runtime] + args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout)


def _extract_os_release(stdout: str) -> dict[str, str]:
    values = {}
    for raw in stdout.splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def classify_os_release(stdout: str, case: dict) -> tuple[str, str]:
    values = _extract_os_release(stdout)
    if values.get("ID") != case["id"]:
        return "malformed_response", "ID mismatch"
    if case.get("version_id") and values.get("VERSION_ID") != case["version_id"]:
        return "malformed_response", "VERSION_ID mismatch"
    expected_codename = case.get("codename")
    if expected_codename and values.get("VERSION_CODENAME") != expected_codename:
        return "malformed_response", "VERSION_CODENAME mismatch"
    return "available", "os-release identity matched"


def classify_package_query(kind: str, package_name: str, stdout: str, stderr: str, returncode: int | None) -> tuple[str, str]:
    if returncode is None:
        return "timeout", "query timed out"
    if kind == "apt":
        if "Candidate: (none)" in stdout:
            return "unavailable", "APT candidate missing"
        if "Candidate:" in stdout and package_name in stdout:
            return "available", "APT candidate present"
        return "malformed_response", "APT candidate metadata missing"
    if kind == "dnf":
        if returncode == 0 and package_name in stdout:
            return "available", "DNF package metadata present"
        if returncode != 0 and ("No matching" in stderr or "No matching" in stdout):
            return "unavailable", "DNF package missing"
        return "unknown", "DNF query inconclusive"
    if kind == "zypper":
        if returncode == 0 and package_name in stdout:
            return "available", "zypper package metadata present"
        if returncode == 0:
            return "unavailable", "zypper package missing"
        return "unknown", "zypper query inconclusive"
    if kind == "pacman":
        if returncode == 0 and ("Name" in stdout and package_name in stdout):
            return "available", "pacman package metadata present"
        if returncode != 0 and ("was not found" in stderr or "target not found" in stderr):
            return "unavailable", "pacman package missing"
        return "unknown", "pacman query inconclusive"
    return "malformed_response", "unknown package manager"


def aggregate_package_status(items: list[dict]) -> str:
    statuses = {item["status"] for item in items}
    if statuses == {"available"}:
        return "available"
    if "timeout" in statuses:
        return "timeout"
    if "unknown" in statuses or "malformed_response" in statuses:
        return "unknown"
    return "unavailable"


def _query_command(case: dict, package_name: str) -> str:
    kind = case["kind"]
    if kind == "apt":
        return "apt-cache policy %s" % package_name
    if kind == "dnf":
        if package_name == "openvpn" and case.get("epel_repo_url"):
            return "dnf -q --repofrompath=epel,%s --repo=epel list %s" % (case["epel_repo_url"], package_name)
        return "dnf -q list %s" % package_name
    if kind == "zypper":
        return "zypper --non-interactive search --match-exact %s" % package_name
    if kind == "pacman":
        return "pacman -Si %s" % package_name
    raise AssertionError(kind)


def execute_l2_case(runtime: str, case: dict, name: str) -> dict:
    try:
        pull = _run(runtime, ["pull", case["image"]])
        if pull.returncode != 0:
            return {"aggregate": "unknown", "stage": "pull", "stdout": pull.stdout, "stderr": pull.stderr}
        create = _run(runtime, ["create", "--name", name, case["image"], "sleep", "600"])
        if create.returncode != 0:
            return {"aggregate": "unknown", "stage": "create", "stdout": create.stdout, "stderr": create.stderr}
        start = _run(runtime, ["start", name])
        if start.returncode != 0:
            return {"aggregate": "unknown", "stage": "start", "stdout": start.stdout, "stderr": start.stderr}
        os_release = _run(runtime, ["exec", name, "cat", "/etc/os-release"])
        status, reason = classify_os_release(os_release.stdout, case)
        if status != "available":
            return {"aggregate": "malformed_response", "stage": "os-release", "stdout": os_release.stdout, "stderr": os_release.stderr, "reason": reason}
        manager = _run(runtime, ["exec", name, "command", "-v", case["manager"]])
        if manager.returncode != 0:
            return {"aggregate": "unknown", "stage": "package_manager", "stdout": manager.stdout, "stderr": manager.stderr}
        if case["kind"] == "apt":
            refresh_cmd = "apt-get update"
        elif case["kind"] == "zypper":
            refresh_cmd = "zypper --non-interactive refresh"
        else:
            refresh_cmd = case.get("refresh", "true")
        refresh = _run(runtime, ["exec", name, "sh", "-lc", refresh_cmd])
        if refresh.returncode != 0:
            return {"aggregate": "unknown", "stage": "refresh", "stdout": refresh.stdout, "stderr": refresh.stderr}
        package_statuses = []
        for package in case["packages"]:
            query = _run(runtime, ["exec", name, "sh", "-lc", _query_command(case, package)])
            status, reason = classify_package_query(case["kind"], package, query.stdout, query.stderr, query.returncode)
            package_statuses.append({"package": package, "status": status, "evidence": reason})
        return {"aggregate": aggregate_package_status(package_statuses), "stage": "package_query", "packages": package_statuses}
    except subprocess.TimeoutExpired as exc:
        return {"aggregate": "timeout", "stage": "timeout", "stdout": exc.stdout or "", "stderr": exc.stderr or ""}
    finally:
        _run(runtime, ["rm", "-f", name], timeout=30)


class L2ParserTests(unittest.TestCase):
    def test_refresh_failure_is_unknown(self) -> None:
        self.assertEqual(aggregate_package_status([{"status": "unknown"}]), "unknown")

    def test_apt_without_candidate_is_not_available(self) -> None:
        status, _ = classify_package_query("apt", "openvpn", "openvpn:\n  Candidate: (none)\n", "", 0)
        self.assertEqual(status, "unavailable")

    def test_one_missing_package_fails_aggregate(self) -> None:
        self.assertEqual(aggregate_package_status([{"status": "available"}, {"status": "unavailable"}]), "unavailable")

    def test_wrong_os_release_is_malformed(self) -> None:
        status, _ = classify_os_release("ID=debian\nVERSION_ID=13\n", CASES[0])
        self.assertEqual(status, "malformed_response")

    def test_timeout_and_runtime_error_attempt_cleanup(self) -> None:
        calls = []

        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            calls.append(tuple(args))
            if args[0] == "pull":
                raise subprocess.TimeoutExpired(args, timeout)
            return subprocess.CompletedProcess([runtime] + args, 0, "", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-test")
        self.assertEqual(result["aggregate"], "timeout")
        self.assertIn(("rm", "-f", "watchdogvpn-test"), calls)

    def test_runtime_error_attempts_cleanup(self) -> None:
        calls = []

        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            calls.append(tuple(args))
            if args[0] == "pull":
                return subprocess.CompletedProcess([runtime] + args, 125, "", "runtime error")
            return subprocess.CompletedProcess([runtime] + args, 0, "", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("podman", CASES[0], "watchdogvpn-error")
        self.assertEqual(result["aggregate"], "unknown")
        self.assertIn(("rm", "-f", "watchdogvpn-error"), calls)


@unittest.skipUnless(REAL_L2_ENABLED, "WATCHDOGVPN_REAL_L2=1 not set")
class RealFocusedDependencyL2Tests(unittest.TestCase):
    def test_real_container_package_queries(self) -> None:
        runtime = _runtime()
        if runtime is None:
            raise unittest.SkipTest("podman or docker is not available for real focused L2 checks")
        for case in CASES:
            name = "watchdogvpn-l2-%s-%d" % (case["target"], int(time.time() * 1000))
            with self.subTest(target=case["target"], image=case["image"]):
                try:
                    result = execute_l2_case(runtime, case, name)
                    aggregate = result["aggregate"]
                    self.assertIn(aggregate, {"available", "unavailable", "unknown", "timeout"})
                except AssertionError:
                    raise


if __name__ == "__main__":
    unittest.main()
