from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config.lan_sharing import _write_private_json, load_or_create_lan_sharing_credentials
from config.persistence import PersistentStoreError


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

    def test_private_credential_publish_reports_directory_durability_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lan-sharing-credentials.json"
            _write_private_json(path, {"username": "watchdogvpn", "password": "old"})

            with patch(
                "config.lan_sharing.fsync_parent_directory",
                side_effect=PersistentStoreError("durability is not confirmed"),
            ):
                with self.assertRaisesRegex(PersistentStoreError, "durability"):
                    _write_private_json(path, {"username": "watchdogvpn", "password": "new"})

            self.assertIn('"new"', path.read_text(encoding="utf-8"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
