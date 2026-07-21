from __future__ import annotations

import socket
import unittest

from models.profile import Profile, ProfileSource, ProtocolType
from parsers.endpoint_policy import (
    EndpointPolicyError,
    canonicalize_remote_endpoint,
    profile_endpoint_host,
    validate_profile_endpoint,
)


def _resolver(*addresses: str):
    return lambda *_args, **_kwargs: [
        (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))
        for address in addresses
    ]


class EndpointPolicyTests(unittest.TestCase):
    def test_legacy_ipv4_spellings_are_resolved_and_rejected(self) -> None:
        for host in ("127.0.0.1", "127.1", "2130706433", "0x7f000001", "0177.0.0.1"):
            with self.subTest(host=host):
                with self.assertRaisesRegex(EndpointPolicyError, "non-global"):
                    canonicalize_remote_endpoint(host)

    def test_ipv6_and_non_global_ranges_are_rejected(self) -> None:
        for host in ("::1", "10.0.0.1", "169.254.1.1", "fc00::1"):
            with self.subTest(host=host):
                with self.assertRaisesRegex(EndpointPolicyError, "non-global"):
                    canonicalize_remote_endpoint(host)

    def test_dns_answer_with_any_private_address_is_rejected(self) -> None:
        with self.assertRaisesRegex(EndpointPolicyError, "10.0.0.1"):
            canonicalize_remote_endpoint(
                "cdn.example",
                resolver=_resolver("203.0.113.10", "10.0.0.1"),
            )

    def test_captured_fakeip_ranges_can_be_treated_as_inconclusive(self) -> None:
        self.assertEqual(
            canonicalize_remote_endpoint(
                "cdn.example",
                resolver=_resolver("198.18.0.4", "fc00::11"),
                require_resolution=True,
                allow_captured_fakeip_ranges=("198.18.0.0/15", "fc00::/18"),
            ),
            "cdn.example",
        )

    def test_fakeip_allowlist_does_not_allow_private_real_answers(self) -> None:
        with self.assertRaisesRegex(EndpointPolicyError, "10.0.0.1"):
            canonicalize_remote_endpoint(
                "cdn.example",
                resolver=_resolver("198.18.0.4", "10.0.0.1"),
                require_resolution=True,
                allow_captured_fakeip_ranges=("198.18.0.0/15", "fc00::/18"),
            )

    def test_dns_answer_with_only_global_addresses_is_accepted(self) -> None:
        self.assertEqual(
            canonicalize_remote_endpoint(
                "vpn.example.",
                resolver=_resolver("1.1.1.1", "2606:4700:4700::1111"),
            ),
            "vpn.example",
        )

    def test_resolution_failure_is_fail_closed(self) -> None:
        def failing_resolver(*_args, **_kwargs):
            raise socket.gaierror(socket.EAI_NONAME, "not found")

        with self.assertRaisesRegex(EndpointPolicyError, "resolution failed"):
            canonicalize_remote_endpoint(
                "missing.example", resolver=failing_resolver, require_resolution=True
            )

    def test_wireguard_bracketed_ipv6_endpoint_is_extracted(self) -> None:
        profile = Profile(
            id="test",
            name="test",
            protocol=ProtocolType.WIREGUARD,
            config={"endpoint": "[2001:4860:4860::8888]:51820"},
            source=ProfileSource.MANUAL,
        )
        self.assertEqual(profile_endpoint_host(profile), "2001:4860:4860::8888")

    def test_profile_validation_threads_fakeip_allowlist(self) -> None:
        profile = Profile(
            id="test",
            name="test",
            protocol=ProtocolType.VLESS,
            config={"server": "cdn.example"},
            source=ProfileSource.MANUAL,
        )

        self.assertEqual(
            validate_profile_endpoint(
                profile,
                resolver=_resolver("198.18.0.8", "fc00::8"),
                require_resolution=True,
                allow_captured_fakeip_ranges=("198.18.0.0/15", "fc00::/18"),
            ),
            "cdn.example",
        )


if __name__ == "__main__":
    unittest.main()
