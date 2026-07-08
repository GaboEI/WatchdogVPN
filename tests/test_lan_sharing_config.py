from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from config.lan_sharing import load_or_create_lan_sharing_credentials


class LANSharingConfigTests(unittest.TestCase):
    def test_credentials_are_private_and_reused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lan-sharing-credentials.json"

            first = load_or_create_lan_sharing_credentials(path)
            second = load_or_create_lan_sharing_credentials(path)

            self.assertEqual(first, second)
            self.assertEqual(first["username"], "watchdogvpn")
            self.assertTrue(first["password"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
