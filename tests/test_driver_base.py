from __future__ import annotations

import unittest

from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType


class BaseDriverContractTests(unittest.TestCase):
    def test_base_driver_is_abstract(self) -> None:
        with self.assertRaises(TypeError):
            BaseDriver()

    def test_subclass_must_implement_contract(self) -> None:
        class IncompleteDriver(BaseDriver):
            def connect(self, profile: Profile) -> bool:
                return True

            def disconnect(self) -> bool:
                return True

        with self.assertRaises(TypeError):
            IncompleteDriver()

    def test_contract_signatures_are_present(self) -> None:
        expected = {"connect", "disconnect", "health_check", "status", "is_available"}
        self.assertTrue(expected.issubset(set(BaseDriver.__abstractmethods__)))

    def test_contract_types_are_importable(self) -> None:
        profile = Profile(
            id="p1",
            name="demo",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
        )
        state = ConnectionState()
        self.assertEqual(profile.name, "demo")
        self.assertEqual(state.status, "standby")


if __name__ == "__main__":
    unittest.main()
