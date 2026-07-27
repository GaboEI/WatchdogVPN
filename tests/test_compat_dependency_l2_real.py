"""Real focused L2 dependency checks.

Set WATCHDOGVPN_REAL_L2=1 to run these against disposable Docker/Podman
containers. Metadata refreshes, when required, happen only inside containers.
These checks do not certify kernel, TUN, firewall or protocol behavior.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
import unittest
from unittest import mock


REAL_L2_ENABLED = os.environ.get("WATCHDOGVPN_REAL_L2") == "1"
TIMEOUT_SECONDS = 120
OUTPUT_LIMIT = 12000
CONTROLLED_MANAGERS = frozenset(("apt-get", "dnf", "zypper", "pacman"))


CASES = (
    {"target": "ubuntu_24_04", "image": "ubuntu:24.04", "id": "ubuntu", "version_id": "24.04", "codename": "noble", "manager": "apt-get", "packages": ("python3", "openvpn"), "kind": "apt"},
    {"target": "ubuntu_26_04", "image": "ubuntu:26.04", "id": "ubuntu", "version_id": "26.04", "codename": "resolute", "manager": "apt-get", "packages": ("python3", "openvpn"), "kind": "apt", "optional_image": True},
    {"target": "debian_13", "image": "debian:13", "id": "debian", "version_id": "13", "codename": "trixie", "manager": "apt-get", "packages": ("python3", "openvpn"), "kind": "apt"},
    {"target": "fedora_44", "image": "fedora:44", "id": "fedora", "version_id": "44", "codename": None, "manager": "dnf", "packages": ("python3", "openvpn"), "kind": "dnf"},
    {"target": "rocky_9", "image": "rockylinux:9", "id": "rocky", "version_id": "9", "codename": None, "manager": "dnf", "packages": ("python3.11", "epel-release", "openvpn"), "kind": "dnf", "architecture": "x86_64", "repository_id": "epel_9", "series": "epel9", "epel_repo_url": "https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/", "refresh": "true"},
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


def _trim(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[:OUTPUT_LIMIT]


def _phase(status: str, completed: subprocess.CompletedProcess[str] | None = None, *, reason: str = "") -> dict:
    return {
        "status": status,
        "returncode": completed.returncode if completed is not None else None,
        "stdout": _trim(completed.stdout) if completed is not None else "",
        "stderr": _trim(completed.stderr) if completed is not None else "",
        "reason": reason,
    }


def _run_phase(runtime: str, args: list[str], *, timeout: int = TIMEOUT_SECONDS) -> dict:
    try:
        completed = _run(runtime, args, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timeout",
            "returncode": None,
            "stdout": _trim(exc.stdout),
            "stderr": _trim(exc.stderr),
            "reason": "runtime command timed out",
        }
    except OSError as exc:
        return {
            "status": "unknown",
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "reason": "runtime execution failed",
        }
    return _phase("available" if completed.returncode == 0 else "unknown", completed)


def _cleanup_container(runtime: str, name: str) -> dict:
    result = _run_phase(runtime, ["rm", "-f", name], timeout=30)
    result["attempted"] = True
    if result["status"] == "available":
        result["status"] = "cleaned"
        result["residual_possible"] = False
    else:
        result["residual_possible"] = True
        if not result["reason"]:
            result["reason"] = "container cleanup did not complete cleanly"
    return result


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


def classify_package_manager(stdout: str, returncode: int | None) -> tuple[str, str]:
    if returncode is None:
        return "timeout", "manager lookup timed out"
    if returncode != 0:
        return "unavailable", "package manager executable not found"
    if not stdout.strip():
        return "malformed_response", "package manager path was empty"
    return "available", "package manager path observed"


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


def _manager_command(manager: str) -> str:
    if manager not in CONTROLLED_MANAGERS:
        raise AssertionError("uncontrolled package manager: %s" % manager)
    return "command -v -- %s" % shlex.quote(manager)


def _refresh_command(case: dict) -> str:
    if case["kind"] == "apt":
        return "apt-get update"
    if case["kind"] == "zypper":
        return "zypper --non-interactive refresh"
    return case.get("refresh", "true")


def _base_result(runtime: str, case: dict, name: str) -> dict:
    return {
        "target": case["target"],
        "image": case["image"],
        "runtime": runtime,
        "container_name": name,
        "pull": _phase("not_run"),
        "create": _phase("not_run"),
        "start": _phase("not_run"),
        "os_release": _phase("not_run"),
        "package_manager": _phase("not_run"),
        "metadata_refresh": _phase("not_run"),
        "package_queries": [],
        "cleanup": {"attempted": False, "status": "not_run", "returncode": None, "stdout": "", "stderr": "", "reason": "", "residual_possible": False},
        "aggregate": "unknown",
        "limitations": [],
    }


def execute_l2_case(runtime: str, case: dict, name: str) -> dict:
    result = _base_result(runtime, case, name)
    try:
        pull = _run_phase(runtime, ["pull", case["image"]])
        result["pull"] = pull
        if pull["status"] != "available":
            result["aggregate"] = "timeout" if pull["status"] == "timeout" else "unknown"
            result["limitations"].append("image pull failed")
            return result
        create = _run_phase(runtime, ["create", "--name", name, case["image"], "sleep", "600"])
        result["create"] = create
        if create["status"] != "available":
            result["aggregate"] = "timeout" if create["status"] == "timeout" else "unknown"
            result["limitations"].append("container create failed")
            return result
        start = _run_phase(runtime, ["start", name])
        result["start"] = start
        if start["status"] != "available":
            result["aggregate"] = "timeout" if start["status"] == "timeout" else "unknown"
            result["limitations"].append("container start failed")
            return result
        os_release = _run_phase(runtime, ["exec", name, "cat", "/etc/os-release"])
        status, reason = classify_os_release(os_release["stdout"], case)
        os_release["status"] = status
        os_release["reason"] = reason
        values = _extract_os_release(os_release["stdout"])
        os_release["observed_id"] = values.get("ID", "")
        os_release["observed_version_id"] = values.get("VERSION_ID", "")
        result["os_release"] = os_release
        if status != "available":
            result["aggregate"] = "malformed_response"
            return result
        manager_command = _manager_command(case["manager"])
        manager = _run_phase(runtime, ["exec", name, "sh", "-lc", manager_command])
        if manager["status"] == "timeout":
            manager_status, manager_reason = "timeout", "manager lookup timed out"
        elif manager["returncode"] is None:
            manager_status, manager_reason = "unknown", "runtime failed during manager lookup"
        else:
            manager_status, manager_reason = classify_package_manager(manager["stdout"], manager["returncode"])
        manager["status"] = manager_status
        manager["reason"] = manager_reason
        manager["command"] = manager_command
        manager["path"] = manager["stdout"].strip()
        result["package_manager"] = manager
        if manager_status != "available":
            result["aggregate"] = "timeout" if manager_status == "timeout" else "unknown"
            result["limitations"].append("package manager lookup failed")
            return result
        refresh_cmd = _refresh_command(case)
        refresh = _run_phase(runtime, ["exec", name, "sh", "-lc", refresh_cmd])
        refresh["command"] = refresh_cmd
        result["metadata_refresh"] = refresh
        if refresh["status"] != "available":
            result["aggregate"] = "timeout" if refresh["status"] == "timeout" else "unknown"
            result["limitations"].append("metadata refresh failed")
            return result
        package_statuses = []
        for package in case["packages"]:
            command = _query_command(case, package)
            query = _run_phase(runtime, ["exec", name, "sh", "-lc", command])
            status, reason = classify_package_query(case["kind"], package, query["stdout"], query["stderr"], query["returncode"])
            query["status"] = status
            query["reason"] = reason
            query["package"] = package
            query["command"] = command
            if package == "openvpn" and case.get("repository_id"):
                if "Everything//" in case["epel_repo_url"] or "$" in case["epel_repo_url"]:
                    query["status"] = "malformed_response"
                    query["reason"] = "EPEL repository URL is not exact"
                query["repository_id"] = case["repository_id"]
                query["series"] = case["series"]
                query["architecture"] = case["architecture"]
                query["repository_url_exact"] = case["epel_repo_url"]
                query["target"] = case["target"]
            package_statuses.append(query)
        result["package_queries"] = package_statuses
        result["aggregate"] = aggregate_package_status(package_statuses)
        return result
    finally:
        result["cleanup"] = _cleanup_container(runtime, name)


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
        self.assertEqual(result["pull"]["status"], "timeout")
        self.assertIn(("rm", "-f", "watchdogvpn-test"), calls)
        self.assertEqual(result["cleanup"]["status"], "cleaned")

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
        self.assertEqual(result["cleanup"]["status"], "cleaned")

    def test_manager_lookup_runs_command_inside_shell(self) -> None:
        calls = []

        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            calls.append(tuple(args))
            if args[0] == "exec" and args[2:] == ["sh", "-lc", "command -v -- apt-get"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/apt-get\n", "")
            if args[0] == "exec" and args[2:] == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-manager")
        self.assertIn(("exec", "watchdogvpn-manager", "sh", "-lc", "command -v -- apt-get"), calls)
        self.assertEqual(result["package_manager"]["status"], "available")
        self.assertEqual(result["package_manager"]["path"], "/usr/bin/apt-get")
        self.assertNotEqual(result["metadata_refresh"]["status"], "not_run")

    def test_epel_repository_url_is_exact_for_architecture(self) -> None:
        rocky = CASES[4]
        command = _query_command(rocky, "openvpn")
        self.assertIn("Everything/x86_64/", command)
        self.assertNotIn("$basearch", command)
        self.assertNotIn("Everything//", command)

    def test_cleanup_statuses_are_observable_and_do_not_hide_primary_result(self) -> None:
        cleanup_statuses = (
            subprocess.CompletedProcess(["docker", "rm", "-f", "name"], 1, "out", "denied"),
            subprocess.TimeoutExpired(["docker", "rm", "-f", "name"], 30, output="partial", stderr="slow"),
            OSError("runtime missing"),
        )
        for failure in cleanup_statuses:
            with self.subTest(failure=type(failure).__name__):
                calls = []

                def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
                    calls.append(tuple(args))
                    if args[0] == "pull":
                        raise subprocess.TimeoutExpired(args, timeout, output="pull", stderr="timeout")
                    if args[0] == "rm":
                        if isinstance(failure, BaseException):
                            raise failure
                        return failure
                    return subprocess.CompletedProcess([runtime] + args, 0, "", "")

                with mock.patch(__name__ + "._run", side_effect=fake_run):
                    result = execute_l2_case("docker", CASES[0], "watchdogvpn-cleanup")
                self.assertEqual(result["aggregate"], "timeout")
                self.assertEqual(result["pull"]["status"], "timeout")
                self.assertTrue(result["cleanup"]["attempted"])
                self.assertTrue(result["cleanup"]["residual_possible"])
                self.assertIn(("rm", "-f", "watchdogvpn-cleanup"), calls)

    def test_success_result_preserves_phase_evidence(self) -> None:
        def fake_run(runtime, args, timeout=TIMEOUT_SECONDS):
            if args[0] == "exec" and args[2:] == ["cat", "/etc/os-release"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "")
            if args[0] == "exec" and args[2:] == ["sh", "-lc", "command -v -- apt-get"]:
                return subprocess.CompletedProcess([runtime] + args, 0, "/usr/bin/apt-get\n", "")
            if args[0] == "exec" and args[-1].startswith("apt-cache policy"):
                package = args[-1].split()[-1]
                return subprocess.CompletedProcess([runtime] + args, 0, "%s:\n  Candidate: 1.0\n" % package, "")
            return subprocess.CompletedProcess([runtime] + args, 0, "ok\n", "")

        with mock.patch(__name__ + "._run", side_effect=fake_run):
            result = execute_l2_case("docker", CASES[0], "watchdogvpn-phases")
        self.assertEqual(result["aggregate"], "available")
        for key in ("target", "image", "runtime", "container_name", "pull", "create", "start", "os_release", "package_manager", "metadata_refresh", "package_queries", "cleanup", "aggregate", "limitations"):
            self.assertIn(key, result)
        self.assertEqual(result["os_release"]["observed_id"], "ubuntu")
        self.assertEqual(result["os_release"]["observed_version_id"], "24.04")
        self.assertEqual(result["package_manager"]["path"], "/usr/bin/apt-get")
        self.assertTrue(result["package_queries"])


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
                    if case.get("optional_image") and result["pull"]["status"] != "available":
                        self.assertIn("image pull failed", result["limitations"])
                        continue
                    self.assertEqual(aggregate, "available", result)
                except AssertionError:
                    raise


if __name__ == "__main__":
    unittest.main()
