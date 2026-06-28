from __future__ import annotations

import unittest
from unittest.mock import patch

from providers.legacy.adguard_provider import AdGuardProvider


class AdGuardProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = AdGuardProvider()

    @patch.object(AdGuardProvider, "is_available", return_value=False)
    def test_load_profiles_returns_empty_when_unavailable(self, available_mock) -> None:
        self.assertEqual(self.provider.load_profiles(), [])

    @patch.object(AdGuardProvider, "_run")
    @patch.object(AdGuardProvider, "is_available", return_value=True)
    def test_load_profiles_parses_locations(self, available_mock, run_mock) -> None:
        run_mock.return_value.stdout = "DK Copenhagen\nSE Stockholm\n# comment\n"
        profiles = self.provider.load_profiles()
        self.assertEqual([p.id for p in profiles], ["DK", "SE"])
        self.assertEqual(profiles[0].config["location"], "DK")

    @patch.object(AdGuardProvider, "is_available", return_value=True)
    def test_update_returns_availability(self, available_mock) -> None:
        self.assertTrue(self.provider.update())

    @patch.object(AdGuardProvider, "load_profiles", return_value=[])
    @patch.object(AdGuardProvider, "is_available", return_value=True)
    def test_status_reports_metadata(self, available_mock, load_mock) -> None:
        status = self.provider.status()
        self.assertEqual(status["provider"], "adguard")
        self.assertTrue(status["available"])

    @patch("providers.legacy.adguard_provider.shutil.which", return_value="/usr/local/bin/adguardvpn-cli")
    @patch("providers.legacy.adguard_provider.os.path.exists", return_value=True)
    def test_is_available_checks_binary(self, exists_mock, which_mock) -> None:
        self.assertTrue(self.provider.is_available())


if __name__ == "__main__":
    unittest.main()
