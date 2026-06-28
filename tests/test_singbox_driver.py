from __future__ import annotations

import unittest
from unittest.mock import patch

from drivers.singbox_driver import SingBoxDriver


class SingBoxDriverBinaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SingBoxDriver()

    @patch("drivers.singbox_driver.shutil.which", return_value="/usr/bin/sing-box")
    @patch("drivers.singbox_driver.os.path.exists", return_value=False)
    @patch("drivers.singbox_driver.os.access", return_value=False)
    def test_find_binary_falls_back_to_which(self, access_mock, exists_mock, which_mock) -> None:
        self.assertEqual(self.driver.find_singbox_binary(), "/usr/bin/sing-box")

    @patch("drivers.singbox_driver.shutil.which", return_value=None)
    @patch("drivers.singbox_driver.os.path.exists", return_value=False)
    @patch("drivers.singbox_driver.os.access", return_value=False)
    def test_find_binary_returns_none_when_missing(self, access_mock, exists_mock, which_mock) -> None:
        self.assertIsNone(self.driver.find_singbox_binary())

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch("drivers.singbox_driver.subprocess.run")
    def test_check_version_returns_output(self, run_mock, binary_mock) -> None:
        run_mock.return_value.stdout = "sing-box version 1.10.0"
        run_mock.return_value.stderr = ""
        self.assertEqual(self.driver.check_version(), "sing-box version 1.10.0")
        run_mock.assert_called_once_with(
            ["/usr/bin/sing-box", "version"],
            text=True,
            capture_output=True,
            check=False,
        )

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value=None)
    def test_check_version_raises_when_missing(self, binary_mock) -> None:
        with self.assertRaises(FileNotFoundError):
            self.driver.check_version()

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    def test_is_available_uses_binary_presence(self, binary_mock) -> None:
        self.assertTrue(self.driver.is_available())

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value=None)
    def test_is_available_is_false_when_missing(self, binary_mock) -> None:
        self.assertFalse(self.driver.is_available())


if __name__ == "__main__":
    unittest.main()
