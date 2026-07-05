from __future__ import annotations

import unittest

from models.profile import (
    PROTOCOL_RESILIENCE_CATEGORY,
    ProtocolType,
    ResilienceCategory,
    profile_resilience_category,
)
from models.profile import Profile, ProfileSource


class ResilienceCategoryCompletenessTests(unittest.TestCase):
    def test_every_protocol_type_is_classified(self) -> None:
        unclassified = [
            protocol for protocol in ProtocolType if protocol not in PROTOCOL_RESILIENCE_CATEGORY
        ]
        self.assertEqual(
            unclassified,
            [],
            "unclassified ProtocolType values (Repo Maintenance Bloque 2 "
            "requires every protocol to be classified resilient or "
            "compatibility): " + ", ".join(p.value for p in unclassified),
        )

    def test_mapping_has_no_extra_entries(self) -> None:
        extra = [protocol for protocol in PROTOCOL_RESILIENCE_CATEGORY if protocol not in ProtocolType]
        self.assertEqual(extra, [])


class ResilienceCategoryClassificationTests(unittest.TestCase):
    """Pins the classification against the master plan's Profile Categories
    doctrine (Phase 2/4.6/5.5) - resilient examples are anti-DPI transports,
    compatibility examples are broad-interoperability transports."""

    def test_resilient_protocols(self) -> None:
        for protocol in (
            ProtocolType.VLESS,
            ProtocolType.TROJAN,
            ProtocolType.HYSTERIA2,
            ProtocolType.AMNEZIAWG,
            ProtocolType.OPENVPN_CLOAK,
        ):
            self.assertEqual(
                PROTOCOL_RESILIENCE_CATEGORY[protocol],
                ResilienceCategory.RESILIENT,
                f"{protocol} must be classified resilient",
            )

    def test_compatibility_protocols(self) -> None:
        for protocol in (
            ProtocolType.VMESS,
            ProtocolType.TUIC,
            ProtocolType.SHADOWSOCKS,
            ProtocolType.WIREGUARD,
            ProtocolType.SOCKS,
            ProtocolType.HTTP,
            ProtocolType.OPENVPN,
        ):
            self.assertEqual(
                PROTOCOL_RESILIENCE_CATEGORY[protocol],
                ResilienceCategory.COMPATIBILITY,
                f"{protocol} must be classified compatibility",
            )

    def test_profile_resilience_category_derives_from_protocol(self) -> None:
        profile = Profile(
            id="p1",
            name="test",
            protocol=ProtocolType.VLESS,
            config={},
            source=ProfileSource.MANUAL,
        )

        self.assertEqual(profile_resilience_category(profile), ResilienceCategory.RESILIENT)


if __name__ == "__main__":
    unittest.main()
