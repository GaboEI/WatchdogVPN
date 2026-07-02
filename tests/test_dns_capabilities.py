from __future__ import annotations

import unittest

from dns.capabilities import supports_fakeip
from models.profile import ProtocolType


class DNSCapabilitiesTests(unittest.TestCase):
    def test_fakeip_is_supported_for_singbox_backed_protocols(self) -> None:
        for protocol in (
            ProtocolType.VLESS,
            ProtocolType.VMESS,
            ProtocolType.TROJAN,
            ProtocolType.HYSTERIA2,
            ProtocolType.TUIC,
            ProtocolType.SHADOWSOCKS,
            ProtocolType.WIREGUARD,
            ProtocolType.SOCKS,
            ProtocolType.HTTP,
        ):
            with self.subTest(protocol=protocol):
                self.assertTrue(supports_fakeip(protocol))

    def test_fakeip_is_not_claimed_for_native_or_legacy_drivers(self) -> None:
        for protocol in (
            ProtocolType.AMNEZIAWG,
            ProtocolType.OPENVPN,
            ProtocolType.OPENVPN_CLOAK,
        ):
            with self.subTest(protocol=protocol):
                self.assertFalse(supports_fakeip(protocol))


if __name__ == "__main__":
    unittest.main()
