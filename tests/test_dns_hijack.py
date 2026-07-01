from __future__ import annotations

import unittest
from pathlib import Path

from dns.hijack import DNSHijackController, DNSHijackError
from dns.models import DNSMode, DNSPolicy
from dns.resolver_inventory import ResolverInventory, ResolverManager
from dns.state_manager import DNSStateError, DNSStateSnapshot, LocalDNSEntryPoint


def _snapshot() -> DNSStateSnapshot:
    return DNSStateSnapshot(
        inventory=ResolverInventory(
            manager=ResolverManager.RESOLV_CONF,
            resolv_conf_path=Path("/tmp/resolv.conf"),
            nameservers=["203.0.113.53"],
        ),
        resolv_conf_content="nameserver 203.0.113.53\n",
    )


class FakeStateManager:
    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.applied_entrypoints: list[LocalDNSEntryPoint] = []
        self.restored_snapshots: list[DNSStateSnapshot] = []
        self.snapshot = _snapshot()

    def apply_local_dns(
        self,
        entrypoint: LocalDNSEntryPoint,
        snapshot: DNSStateSnapshot | None = None,
    ) -> DNSStateSnapshot:
        self.applied_entrypoints.append(entrypoint)
        if self.should_fail:
            raise DNSStateError("forced apply failure")
        return snapshot or self.snapshot

    def restore_state(self, snapshot: DNSStateSnapshot) -> None:
        self.restored_snapshots.append(snapshot)


class FakeKillSwitch:
    def __init__(self, active: bool) -> None:
        self.active = active

    def is_active(self) -> bool:
        return self.active


class DNSHijackControllerTests(unittest.TestCase):
    def test_apply_noops_when_policy_is_off(self) -> None:
        manager = FakeStateManager()
        controller = DNSHijackController(state_manager=manager)

        result = controller.apply(DNSPolicy(mode=DNSMode.OFF))

        self.assertFalse(result.applied)
        self.assertEqual(result.reason, "dns policy is off")
        self.assertEqual(manager.applied_entrypoints, [])

    def test_apply_noops_when_tun_hijack_is_disabled(self) -> None:
        manager = FakeStateManager()
        controller = DNSHijackController(state_manager=manager)

        result = controller.apply(DNSPolicy(tun_hijack=False))

        self.assertFalse(result.applied)
        self.assertEqual(result.reason, "tun hijack is disabled")
        self.assertEqual(manager.applied_entrypoints, [])

    def test_apply_uses_local_dns_entrypoint(self) -> None:
        manager = FakeStateManager()
        controller = DNSHijackController(state_manager=manager)

        result = controller.apply(DNSPolicy(), systemd_link="tun0")

        self.assertTrue(result.applied)
        self.assertIs(result.snapshot, manager.snapshot)
        self.assertEqual(manager.applied_entrypoints, [
            LocalDNSEntryPoint(address="127.0.0.1", port=53, systemd_link="tun0")
        ])

    def test_restore_uses_saved_snapshot(self) -> None:
        manager = FakeStateManager()
        controller = DNSHijackController(state_manager=manager)
        snapshot = _snapshot()

        controller.restore(snapshot)

        self.assertEqual(manager.restored_snapshots, [snapshot])

    def test_failed_apply_with_active_kill_switch_reports_fail_closed(self) -> None:
        manager = FakeStateManager(should_fail=True)
        controller = DNSHijackController(
            state_manager=manager,
            kill_switch=FakeKillSwitch(active=True),
        )

        with self.assertRaisesRegex(DNSHijackError, "fail-closed"):
            controller.apply(DNSPolicy())

    def test_failed_apply_without_active_kill_switch_reports_apply_failure(self) -> None:
        manager = FakeStateManager(should_fail=True)
        controller = DNSHijackController(
            state_manager=manager,
            kill_switch=FakeKillSwitch(active=False),
        )

        with self.assertRaisesRegex(DNSHijackError, "dns hijack apply failed"):
            controller.apply(DNSPolicy())


if __name__ == "__main__":
    unittest.main()
