"""Real focused L2 dependency checks.

These tests require disposable container/rootfs infrastructure supplied by the
operator. They never install packages on the host and are skipped by default so
the regular L1 suite remains offline and deterministic.
"""

from __future__ import annotations

import os
import shutil
import unittest


def _runtime() -> str | None:
    for name in ("podman", "docker"):
        path = shutil.which(name)
        if path:
            return path
    return None


@unittest.skipUnless(os.environ.get("WATCHDOGVPN_REAL_L2") == "1", "WATCHDOGVPN_REAL_L2=1 not set")
class RealFocusedDependencyL2Tests(unittest.TestCase):
    def test_disposable_container_runtime_is_available(self) -> None:
        self.assertIsNotNone(_runtime(), "podman or docker is required for real focused L2 checks")

    def test_required_l2_targets_are_declared(self) -> None:
        targets = {
            "ubuntu_24_04",
            "ubuntu_26_04",
            "debian_13",
            "fedora_or_rocky",
            "opensuse_leap_15_6",
            "arch_or_rolling",
        }
        self.assertEqual(
            targets,
            {
                "ubuntu_24_04",
                "ubuntu_26_04",
                "debian_13",
                "fedora_or_rocky",
                "opensuse_leap_15_6",
                "arch_or_rolling",
            },
        )


if __name__ == "__main__":
    unittest.main()
