from __future__ import annotations

import unittest
from unittest.mock import Mock

from drivers.native_policy_driver import NativePolicyDriver
from drivers.singbox_driver import SingBoxDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType


class NativePolicyDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = Profile("native", "native", ProtocolType.AMNEZIAWG, {}, ProfileSource.MANUAL)
        self.native = Mock()
        self.native.connect.return_value = True
        self.native.health_check.return_value = "ok"
        self.native.disconnect.return_value = True
        self.native.status.return_value = ConnectionState(active_profile_id="native", status="connected")
        self.native.is_available.return_value = True
        self.companion = Mock(spec=SingBoxDriver)
        self.companion.connect.return_value = True
        self.companion.preflight_native_management_routes.return_value = {}
        self.companion.health_check.return_value = "ok"
        self.companion.disconnect.return_value = True
        self.companion.status.return_value = ConnectionState(tun_active=True, proxy_active=True, status="connected")
        self.companion.is_available.return_value = True
        self.driver = NativePolicyDriver(self.native, self.companion)

    def test_companion_failure_rolls_back_native_transport(self) -> None:
        self.companion.connect.return_value = False
        self.companion.last_error = "companion failed"

        self.assertFalse(self.driver.connect(self.profile, mode="rules"))
        self.native.connect.assert_called_once_with(self.profile)
        self.companion.connect.assert_called_once_with(
            self.profile, dns_policy=None, mode="rules", native_transport=True
        )
        self.companion.disconnect.assert_called_once_with()
        self.native.disconnect.assert_called_once_with()
        self.assertEqual(self.driver.status().status, "standby")

    def test_connected_status_requires_both_owners(self) -> None:
        self.assertTrue(self.driver.connect(self.profile, mode="rules"))
        state = self.driver.status()
        self.assertEqual(state.status, "connected")
        self.assertTrue(state.tun_active)
        self.assertTrue(state.proxy_active)

    def test_disconnect_stops_companion_before_native(self) -> None:
        calls = []
        self.companion.disconnect.side_effect = lambda: calls.append("companion") or True
        self.native.disconnect.side_effect = lambda: calls.append("native") or True
        self.assertTrue(self.driver.connect(self.profile))
        self.assertTrue(self.driver.disconnect())
        self.assertEqual(calls[-2:], ["companion", "native"])


if __name__ == "__main__":
    unittest.main()
