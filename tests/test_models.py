from __future__ import annotations

import unittest
from datetime import datetime

from models.connection_state import ALLOWED_STATUSES, ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType
from models.provider import Provider


class ModelTests(unittest.TestCase):
    def test_profile_round_trip(self) -> None:
        profile = Profile(
            id="p1",
            name="Paris",
            protocol=ProtocolType.VLESS,
            config={"server": "example.com", "port": 443},
            source=ProfileSource.MANUAL,
            provider_id="prov1",
            in_rotation_pool=True,
            enabled=True,
            created_at=datetime(2026, 6, 1, 12, 30, 0),
            last_used=datetime(2026, 6, 2, 12, 30, 0),
            last_health_check=datetime(2026, 6, 3, 12, 30, 0),
            health_status="ok",
        )
        restored = Profile.from_dict(profile.to_dict())
        self.assertEqual(restored, profile)

    def test_provider_round_trip(self) -> None:
        provider = Provider(
            id="prov1",
            name="My Provider",
            url="https://example.com/sub",
            last_updated=datetime(2026, 6, 4, 10, 0, 0),
            profiles=["p1", "p2"],
            rotation_enabled=True,
            auto_update=False,
            update_interval_hours=12,
        )
        restored = Provider.from_dict(provider.to_dict())
        self.assertEqual(restored, provider)

    def test_connection_state_round_trip(self) -> None:
        state = ConnectionState(
            active_profile_id="p1",
            connected_at=datetime(2026, 6, 5, 8, 0, 0),
            mode="global",
            tun_active=True,
            proxy_active=False,
            kill_switch_active=False,
            lan_gateway_active=True,
            lan_gateway_interface="enp0s8",
            lan_gateway_client_cidr="192.168.50.0/24",
            lan_gateway_dns_mode="manual",
            lan_gateway_status="applied",
            status="connected",
        )
        restored = ConnectionState.from_dict(state.to_dict())
        self.assertEqual(restored, state)

    def test_connection_state_rejects_invalid_status(self) -> None:
        with self.assertRaises(ValueError):
            ConnectionState(status="broken")

    def test_allowed_statuses_cover_spec(self) -> None:
        self.assertIn("connected", ALLOWED_STATUSES)
        self.assertIn("standby", ALLOWED_STATUSES)
        self.assertIn("kill_switch_active", ALLOWED_STATUSES)
        self.assertIn("rotation_unavailable", ALLOWED_STATUSES)


if __name__ == "__main__":
    unittest.main()
