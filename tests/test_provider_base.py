from __future__ import annotations

import unittest

from models.profile import Profile, ProfileSource, ProtocolType
from providers.base import BaseProvider


class BaseProviderContractTests(unittest.TestCase):
    def test_base_provider_is_abstract(self) -> None:
        with self.assertRaises(TypeError):
            BaseProvider()

    def test_subclass_must_implement_contract(self) -> None:
        class IncompleteProvider(BaseProvider):
            def load_profiles(self) -> list[Profile]:
                return []

        with self.assertRaises(TypeError):
            IncompleteProvider()

    def test_contract_signatures_are_present(self) -> None:
        expected = {"load_profiles", "update", "status"}
        self.assertTrue(expected.issubset(set(BaseProvider.__abstractmethods__)))

    def test_contract_types_are_importable(self) -> None:
        profile = Profile(
            id="p1",
            name="demo",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
        )
        self.assertEqual(profile.name, "demo")


if __name__ == "__main__":
    unittest.main()
