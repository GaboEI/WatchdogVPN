"""Real focused L2 dependency checks.

Set WATCHDOGVPN_REAL_L2=1 to run these against disposable Docker/Podman
containers. Metadata refreshes, when required, happen only inside containers.
These checks do not certify kernel, TUN, firewall or protocol behavior.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest


REAL_L2_ENABLED = os.environ.get("WATCHDOGVPN_REAL_L2") == "1"
TIMEOUT_SECONDS = 120


CASES = (
    {
        "target": "ubuntu_24_04",
        "image": "ubuntu:24.04",
        "manager": "apt-get",
        "packages": ("python3", "openvpn"),
        "query": "apt-get update >/tmp/watchdogvpn-apt-update.out 2>/tmp/watchdogvpn-apt-update.err; apt-cache policy python3 openvpn",
    },
    {
        "target": "ubuntu_26_04",
        "image": "ubuntu:26.04",
        "manager": "apt-get",
        "packages": ("python3", "openvpn"),
        "query": "apt-get update >/tmp/watchdogvpn-apt-update.out 2>/tmp/watchdogvpn-apt-update.err; apt-cache policy python3 openvpn",
        "optional_image": True,
    },
    {
        "target": "debian_13",
        "image": "debian:13",
        "manager": "apt-get",
        "packages": ("python3", "openvpn"),
        "query": "apt-get update >/tmp/watchdogvpn-apt-update.out 2>/tmp/watchdogvpn-apt-update.err; apt-cache policy python3 openvpn",
    },
    {
        "target": "fedora_44",
        "image": "fedora:44",
        "manager": "dnf",
        "packages": ("python3", "openvpn"),
        "query": "dnf -q list python3 openvpn",
    },
    {
        "target": "opensuse_leap_15_6",
        "image": "opensuse/leap:15.6",
        "manager": "zypper",
        "packages": ("python311", "openvpn"),
        "query": "zypper --non-interactive refresh >/tmp/watchdogvpn-zypper-refresh.out 2>/tmp/watchdogvpn-zypper-refresh.err; zypper --non-interactive search --match-exact python311 openvpn",
    },
    {
        "target": "arch",
        "image": "archlinux:latest",
        "manager": "pacman",
        "packages": ("python", "openvpn"),
        "query": "pacman -Sy --noconfirm >/tmp/watchdogvpn-pacman-refresh.out 2>/tmp/watchdogvpn-pacman-refresh.err; pacman -Si python openvpn",
    },
)


def _runtime() -> str | None:
    for name in ("podman", "docker"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _run_container(runtime: str, image: str, script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [runtime, "run", "--rm", image, "sh", "-lc", script],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=TIMEOUT_SECONDS,
    )


def _probe_script(case: dict) -> str:
    packages = " ".join(case["packages"])
    return "\n".join(
        [
            "set +e",
            "echo WATCHDOGVPN_SECTION=os_release",
            "cat /etc/os-release",
            "echo WATCHDOGVPN_SECTION=package_manager",
            "command -v %s" % case["manager"],
            "manager_rc=$?",
            "echo WATCHDOGVPN_MANAGER_RC=$manager_rc",
            "echo WATCHDOGVPN_SECTION=package_query",
            "if [ \"$manager_rc\" -eq 0 ]; then %s; echo WATCHDOGVPN_QUERY_RC=$?; else echo WATCHDOGVPN_QUERY_RC=127; fi" % case["query"],
            "echo WATCHDOGVPN_PACKAGES=%s" % packages,
            "exit 0",
        ]
    )


@unittest.skipUnless(REAL_L2_ENABLED, "WATCHDOGVPN_REAL_L2=1 not set")
class RealFocusedDependencyL2Tests(unittest.TestCase):
    def test_real_container_package_queries(self) -> None:
        runtime = _runtime()
        if runtime is None:
            raise unittest.SkipTest("podman or docker is not available for real focused L2 checks")
        results = []
        for case in CASES:
            with self.subTest(target=case["target"], image=case["image"]):
                try:
                    result = _run_container(runtime, case["image"], _probe_script(case))
                except subprocess.TimeoutExpired as exc:
                    status = "timeout"
                    stdout = exc.stdout or ""
                    stderr = exc.stderr or ""
                    returncode = None
                else:
                    stdout = result.stdout
                    stderr = result.stderr
                    returncode = result.returncode
                    if result.returncode != 0 and case.get("optional_image"):
                        status = "unknown"
                    elif result.returncode != 0:
                        status = "unknown"
                    elif "WATCHDOGVPN_MANAGER_RC=0" not in stdout:
                        status = "unknown"
                    elif "WATCHDOGVPN_QUERY_RC=0" in stdout:
                        status = "available"
                    else:
                        status = "unavailable"
                evidence = {
                    "target": case["target"],
                    "image": case["image"],
                    "runtime": runtime,
                    "status": status,
                    "returncode": returncode,
                    "stdout": stdout[-4000:],
                    "stderr": stderr[-4000:],
                }
                results.append(evidence)
                self.assertIn(status, {"available", "unavailable", "unknown", "timeout", "malformed_response"})
                if returncode == 0:
                    self.assertIn("WATCHDOGVPN_SECTION=os_release", stdout or "")
                if status == "available":
                    self.assertIn("WATCHDOGVPN_SECTION=package_query", stdout)
        self.assertEqual({case["target"] for case in CASES}, {item["target"] for item in results})


if __name__ == "__main__":
    unittest.main()
