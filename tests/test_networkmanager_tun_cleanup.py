from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from drivers.networkmanager_tun_cleanup import (
    NetworkManagerTunCleanupError,
    remove_stale_tun_connections,
)


UUID_ONE = "11111111-1111-1111-1111-111111111111"
UUID_TWO = "22222222-2222-2222-2222-222222222222"


class NetworkManagerTunCleanupTests(unittest.TestCase):
    def test_absent_connection_is_an_idempotent_success(self) -> None:
        with patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=f"{UUID_ONE}:Home\n", stderr="")
            self.assertFalse(remove_stale_tun_connections())

        self.assertEqual(run.call_count, 1)

    def test_deletes_only_exact_fixed_name_by_validated_uuid(self) -> None:
        listing = "\n".join((
            f"{UUID_ONE}:wdvpn-tun0",
            f"{UUID_TWO}:wdvpn-tun0-foreign",
            "not-a-uuid:wdvpn-tun0",
        ))
        with patch("drivers.networkmanager_tun_cleanup.subprocess.run") as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout=listing, stderr=""),
                subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ]
            self.assertTrue(remove_stale_tun_connections())

        self.assertEqual(
            run.call_args_list[1].args[0],
            ["nmcli", "connection", "delete", "uuid", UUID_ONE],
        )

    def test_listing_or_delete_failure_is_not_reported_as_clean(self) -> None:
        for side_effect in (
            [subprocess.CompletedProcess([], 1, stdout="", stderr="denied")],
            [
                subprocess.CompletedProcess([], 0, stdout=f"{UUID_ONE}:wdvpn-tun0\n", stderr=""),
                subprocess.CompletedProcess([], 1, stdout="", stderr="failed"),
            ],
        ):
            with self.subTest(side_effect=side_effect), patch(
                "drivers.networkmanager_tun_cleanup.subprocess.run", side_effect=side_effect
            ), self.assertRaises(NetworkManagerTunCleanupError):
                remove_stale_tun_connections()


if __name__ == "__main__":
    unittest.main()
