from __future__ import annotations

import unittest

from drivers.amneziawg_driver import AmneziaWGDriver
from drivers.base import DRIVER_POLICY_CAPABILITIES, BaseDriver
from drivers.openvpn_cloak_driver import OpenVPNCloakDriver
from drivers.openvpn_driver import OpenVPNDriver
from drivers.singbox_driver import SingBoxDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType


class BaseDriverContractTests(unittest.TestCase):
    def test_base_driver_is_abstract(self) -> None:
        with self.assertRaises(TypeError):
            BaseDriver()

    def test_subclass_must_implement_contract(self) -> None:
        class IncompleteDriver(BaseDriver):
            def connect(
                self,
                profile: Profile,
                dns_policy=None,
                *,
                mode: str = "global",
                groups=None,
                app_policy=None,
                final_policy: str = "current_profile",
                rule_set_tags=None,
                rule_set_declarations=None,
                chain_runtime_plans=None,
                lan_proxy=None,
                lan_gateway=None,
            ) -> bool:
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

    def test_real_driver_policy_capability_contracts_are_explicit(self) -> None:
        self.assertEqual(SingBoxDriver.policy_capabilities, DRIVER_POLICY_CAPABILITIES)
        for driver_type in (OpenVPNDriver, OpenVPNCloakDriver, AmneziaWGDriver):
            self.assertEqual(driver_type.policy_capabilities, frozenset())


if __name__ == "__main__":
    unittest.main()
