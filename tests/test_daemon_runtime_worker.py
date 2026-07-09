from __future__ import annotations

import queue
import threading
import tempfile
import unittest
from pathlib import Path

from config.profile_store import ProfileStore
from config.state_manager import StateManager
from core.watchdog import WatchdogRuntime
from daemon.event_bus import EventBus
from daemon.protocol import (
    COMMAND_CONNECT,
    COMMAND_DISCONNECT,
    COMMAND_NODE_GROUP_AUTO_TEST,
    COMMAND_ROTATE,
    COMMAND_STATUS,
    EVENT_HEALTH_CHECK,
    EVENT_ROTATION,
    EVENT_STATE_CHANGED,
)
from daemon.runtime_worker import RuntimeWorker, WorkerRequest
from drivers.base import BaseDriver
from dns.models import DNSPolicy
from metrics.models import MetricsDocument
from metrics.recorder import MetricsRecorder
from metrics.store import MetricsStore
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType


class FakeWorkerDriver(BaseDriver):
    def __init__(self) -> None:
        self.connected_profile_id = ""
        self.connect_calls: list[str] = []
        self.disconnect_calls = 0
        self.connect_result = True
        self.disconnect_result = True

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
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
        self.connect_calls.append(profile.id)
        if self.connect_result:
            self.connected_profile_id = profile.id
        return self.connect_result

    def disconnect(self) -> bool:
        self.disconnect_calls += 1
        self.connected_profile_id = ""
        return self.disconnect_result

    def health_check(self) -> str:
        return "ok" if self.connected_profile_id else "down"

    def status(self) -> ConnectionState:
        return ConnectionState(
            active_profile_id=self.connected_profile_id,
            mode="rules" if self.connected_profile_id else "standby",
            proxy_active=bool(self.connected_profile_id),
            status="connected" if self.connected_profile_id else "standby",
        )

    def is_available(self) -> bool:
        return True


class FakeRuntime:
    def __init__(self, profile_store: ProfileStore) -> None:
        self.profile_store = profile_store
        self.connected_profile_id = ""
        self.disconnect_calls = 0
        self.rotate_calls: list[bool] = []
        self.auto_test_calls: list[str] = []
        self.run_iteration_queue: list[ConnectionState] = []
        self.scheduled_rotate_calls = 0
        self.scheduled_rotate_result: ConnectionState | None = None

    def connect(self, profile: Profile) -> bool:
        self.connected_profile_id = profile.id
        return True

    def disconnect(self) -> bool:
        self.disconnect_calls += 1
        self.connected_profile_id = ""
        return True

    def status(self) -> ConnectionState:
        return ConnectionState(
            active_profile_id=self.connected_profile_id,
            mode="rules" if self.connected_profile_id else "standby",
            status="connected" if self.connected_profile_id else "standby",
        )

    def rotate_now(self, force: bool = False) -> ConnectionState:
        self.rotate_calls.append(force)
        self.connected_profile_id = "rotated"
        return ConnectionState(active_profile_id="rotated", mode="rules", status="recovered")

    def run_iteration(self) -> ConnectionState:
        if self.run_iteration_queue:
            return self.run_iteration_queue.pop(0)
        return self.status()

    def scheduled_rotate(self) -> ConnectionState:
        self.scheduled_rotate_calls += 1
        if self.scheduled_rotate_result is not None:
            return self.scheduled_rotate_result
        return self.status()

    def node_group_auto_test(self, group_name: str) -> dict:
        self.auto_test_calls.append(group_name)
        return {"group_name": group_name, "result": "unavailable"}


class ThreadTrackingRuntime(FakeRuntime):
    def __init__(self, profile_store: ProfileStore) -> None:
        super().__init__(profile_store)
        self.thread_ids: list[int] = []

    def _record_thread(self) -> None:
        self.thread_ids.append(threading.get_ident())

    def connect(self, profile: Profile) -> bool:
        self._record_thread()
        return super().connect(profile)

    def disconnect(self) -> bool:
        self._record_thread()
        return super().disconnect()

    def status(self) -> ConnectionState:
        self._record_thread()
        return super().status()

    def node_group_auto_test(self, group_name: str) -> dict:
        self._record_thread()
        return super().node_group_auto_test(group_name)


class RaisingTickRuntime(FakeRuntime):
    def run_iteration(self) -> ConnectionState:
        raise RuntimeError("boom")


class RaisingScheduledRotationRuntime(FakeRuntime):
    def scheduled_rotate(self) -> ConnectionState:
        raise RuntimeError("boom")


def make_profile(profile_id: str = "p1") -> Profile:
    return Profile(
        id=profile_id,
        name=profile_id,
        protocol=ProtocolType.VLESS,
        config={},
        source=ProfileSource.MANUAL,
        enabled=True,
        in_rotation_pool=True,
    )


class RuntimeWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.profile_store = ProfileStore(Path(self.tmpdir.name) / "profiles.json")
        self.profile = make_profile()
        self.profile_store.add(self.profile)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def make_runtime(self) -> WatchdogRuntime:
        driver = FakeWorkerDriver()
        return WatchdogRuntime(
            driver=driver,
            state_manager=StateManager(Path(self.tmpdir.name) / "state.toml"),
            profile_store=self.profile_store,
        )

    def test_worker_connects_profile_by_id_and_broadcasts_state(self) -> None:
        bus = EventBus()
        subscription = bus.subscribe()
        worker = RuntimeWorker(self.make_runtime(), bus)
        worker.start()
        try:
            response = worker.submit(COMMAND_CONNECT, {"profile_id": self.profile.id}, timeout=2.0)
            event = subscription.get(timeout=2.0)
        finally:
            worker.stop()

        self.assertTrue(response.ok)
        self.assertTrue(response.payload["connected"])
        self.assertEqual(response.payload["profile_id"], self.profile.id)
        self.assertEqual(response.payload["state"]["active_profile_id"], self.profile.id)
        self.assertEqual(event.event, EVENT_STATE_CHANGED)
        self.assertEqual(event.payload["active_profile_id"], self.profile.id)

    def test_worker_records_aggregate_metrics_when_enabled(self) -> None:
        metrics_path = Path(self.tmpdir.name) / "metrics.json"
        metrics_store = MetricsStore(metrics_path)
        metrics_store.save(MetricsDocument(enabled=True))
        bus = EventBus()
        runtime = FakeRuntime(self.profile_store)
        worker = RuntimeWorker(
            runtime,
            bus,
            metrics_recorder=MetricsRecorder(metrics_store),
        )
        worker.start()
        try:
            worker.submit(COMMAND_CONNECT, {"profile_id": self.profile.id}, timeout=2.0)
            worker.submit(COMMAND_ROTATE, {"force": True}, timeout=2.0)
            worker.submit(
                COMMAND_NODE_GROUP_AUTO_TEST,
                {"group_name": "paris"},
                timeout=2.0,
            )
            worker.submit(COMMAND_DISCONNECT, timeout=2.0)
        finally:
            worker.stop()

        counters = metrics_store.load().buckets[0].counters
        self.assertEqual(counters["command.connect.success"], 1)
        self.assertEqual(counters["profile.p1.connect.success"], 1)
        self.assertEqual(counters["rotation.manual.attempt"], 1)
        self.assertEqual(counters["profile.rotated.rotation.manual.recovered"], 1)
        self.assertEqual(counters["node_group.paris.auto_test.unavailable"], 1)
        self.assertEqual(counters["command.disconnect.success"], 1)

    def test_worker_status_returns_current_state_without_event(self) -> None:
        bus = EventBus()
        subscription = bus.subscribe()
        runtime = self.make_runtime()
        runtime.connect(self.profile)
        worker = RuntimeWorker(runtime, bus)
        worker.start()
        try:
            response = worker.submit(COMMAND_STATUS, timeout=2.0)
            with self.assertRaises(queue.Empty):
                subscription.get(timeout=0.05)
        finally:
            worker.stop()

        self.assertTrue(response.ok)
        self.assertEqual(response.payload["state"]["active_profile_id"], self.profile.id)

    def test_worker_disconnects_and_broadcasts_state(self) -> None:
        bus = EventBus()
        subscription = bus.subscribe()
        runtime = self.make_runtime()
        runtime.connect(self.profile)
        worker = RuntimeWorker(runtime, bus)
        worker.start()
        try:
            response = worker.submit(COMMAND_DISCONNECT, timeout=2.0)
            event = subscription.get(timeout=2.0)
        finally:
            worker.stop()

        self.assertTrue(response.ok)
        self.assertTrue(response.payload["disconnected"])
        self.assertEqual(response.payload["state"]["status"], "standby")
        self.assertEqual(event.event, EVENT_STATE_CHANGED)

    def test_worker_rotates_and_broadcasts_rotation_then_state(self) -> None:
        bus = EventBus()
        subscription = bus.subscribe()
        runtime = FakeRuntime(self.profile_store)
        worker = RuntimeWorker(runtime, bus)
        worker.start()
        try:
            response = worker.submit(COMMAND_ROTATE, {"force": True}, timeout=2.0)
            rotation_event = subscription.get(timeout=2.0)
            state_event = subscription.get(timeout=2.0)
        finally:
            worker.stop()

        self.assertTrue(response.ok)
        self.assertEqual(runtime.rotate_calls, [True])
        self.assertEqual(response.payload["state"]["active_profile_id"], "rotated")
        self.assertEqual(rotation_event.event, EVENT_ROTATION)
        self.assertEqual(state_event.event, EVENT_STATE_CHANGED)

    def test_worker_node_group_auto_test_returns_payload_without_state_event(self) -> None:
        bus = EventBus()
        subscription = bus.subscribe()
        runtime = FakeRuntime(self.profile_store)
        worker = RuntimeWorker(runtime, bus)
        worker.start()
        try:
            response = worker.submit(
                COMMAND_NODE_GROUP_AUTO_TEST, {"group_name": "paris"}, timeout=2.0
            )
            with self.assertRaises(queue.Empty):
                subscription.get(timeout=0.05)
        finally:
            worker.stop()

        self.assertTrue(response.ok)
        self.assertEqual(runtime.auto_test_calls, ["paris"])
        self.assertEqual(response.payload["group_name"], "paris")

    def test_worker_node_group_auto_test_requires_group_name_string(self) -> None:
        worker = RuntimeWorker(FakeRuntime(self.profile_store))
        worker.start()
        try:
            response = worker.submit(COMMAND_NODE_GROUP_AUTO_TEST, {"group_name": ""}, timeout=2.0)
        finally:
            worker.stop()

        self.assertFalse(response.ok)
        self.assertEqual(response.error, "group_name must be a non-empty string")

    def test_runtime_calls_run_on_single_worker_thread(self) -> None:
        runtime = ThreadTrackingRuntime(self.profile_store)
        caller_thread_id = threading.get_ident()
        worker = RuntimeWorker(runtime)
        worker.start()
        try:
            self.assertTrue(worker.submit(COMMAND_CONNECT, {"profile_id": self.profile.id}, timeout=2.0).ok)
            self.assertTrue(worker.submit(COMMAND_STATUS, timeout=2.0).ok)
            self.assertTrue(
                worker.submit(
                    COMMAND_NODE_GROUP_AUTO_TEST, {"group_name": "paris"}, timeout=2.0
                ).ok
            )
            self.assertTrue(worker.submit(COMMAND_DISCONNECT, timeout=2.0).ok)
        finally:
            worker.stop()

        self.assertTrue(runtime.thread_ids)
        self.assertEqual(len(set(runtime.thread_ids)), 1)
        self.assertNotEqual(runtime.thread_ids[0], caller_thread_id)

    def test_worker_rejects_missing_profile(self) -> None:
        worker = RuntimeWorker(self.make_runtime())
        worker.start()
        try:
            response = worker.submit(COMMAND_CONNECT, {"profile_id": "missing"}, timeout=2.0)
        finally:
            worker.stop()

        self.assertFalse(response.ok)
        self.assertEqual(response.error, "profile not found: missing")

    def test_worker_rejects_unknown_command(self) -> None:
        worker = RuntimeWorker(self.make_runtime())
        worker.start()
        try:
            response = worker.submit("future", timeout=2.0)
        finally:
            worker.stop()

        self.assertFalse(response.ok)
        self.assertIn("unknown command", response.error or "")

    def test_worker_processes_direct_queue_requests_sequentially(self) -> None:
        runtime = FakeRuntime(self.profile_store)
        worker = RuntimeWorker(runtime)
        first = WorkerRequest(command=COMMAND_CONNECT, payload={"profile_id": self.profile.id})
        second = WorkerRequest(command=COMMAND_DISCONNECT)
        worker.start()
        try:
            worker.submit_request(first)
            worker.submit_request(second)
            first_response = first.response_queue.get(timeout=2.0)
            second_response = second.response_queue.get(timeout=2.0)
        finally:
            worker.stop()

        self.assertTrue(first_response.ok)
        self.assertTrue(second_response.ok)
        self.assertEqual(runtime.disconnect_calls, 1)
        self.assertEqual(runtime.connected_profile_id, "")

    def test_submit_requires_running_worker(self) -> None:
        worker = RuntimeWorker(self.make_runtime())

        with self.assertRaises(RuntimeError):
            worker.submit_request(WorkerRequest(command=COMMAND_STATUS))

    def test_submit_tick_requires_running_worker(self) -> None:
        worker = RuntimeWorker(self.make_runtime())

        with self.assertRaises(RuntimeError):
            worker.submit_tick()

    def test_tick_always_broadcasts_health_check_event(self) -> None:
        bus = EventBus()
        subscription = bus.subscribe()
        runtime = FakeRuntime(self.profile_store)
        worker = RuntimeWorker(runtime, bus)
        worker.start()
        try:
            worker.submit_tick()
            event = subscription.get(timeout=2.0)
            worker.submit(COMMAND_STATUS, timeout=2.0)  # drain queue in order
        finally:
            worker.stop()

        self.assertEqual(event.event, EVENT_HEALTH_CHECK)
        self.assertEqual(event.payload["status"], "standby")

    def test_tick_broadcasts_state_changed_only_when_status_changes(self) -> None:
        bus = EventBus()
        subscription = bus.subscribe()
        runtime = FakeRuntime(self.profile_store)
        runtime.run_iteration_queue = [
            ConnectionState(status="standby", mode="standby"),
            ConnectionState(status="standby", mode="standby"),
            ConnectionState(status="recovered", mode="rules"),
        ]
        worker = RuntimeWorker(runtime, bus)
        worker.start()
        try:
            worker.submit_tick()
            worker.submit_tick()
            worker.submit_tick()
            worker.submit(COMMAND_STATUS, timeout=2.0)  # drain queue in order

            first = subscription.get(timeout=2.0)
            second = subscription.get(timeout=2.0)
            third = subscription.get(timeout=2.0)
            fourth = subscription.get(timeout=2.0)
            fifth = subscription.get(timeout=2.0)
            with self.assertRaises(queue.Empty):
                subscription.get(timeout=0.05)
        finally:
            worker.stop()

        # tick 1 (standby, first time seen): health_check + state_changed
        self.assertEqual(first.event, EVENT_HEALTH_CHECK)
        self.assertEqual(second.event, EVENT_STATE_CHANGED)
        # tick 2 (still standby, unchanged): only health_check
        self.assertEqual(third.event, EVENT_HEALTH_CHECK)
        # tick 3 (status changed to recovered): health_check + state_changed
        self.assertEqual(fourth.event, EVENT_HEALTH_CHECK)
        self.assertEqual(fifth.event, EVENT_STATE_CHANGED)
        self.assertEqual(fifth.payload["status"], "recovered")

    def test_tick_survives_run_iteration_exception_and_worker_keeps_serving(self) -> None:
        runtime = RaisingTickRuntime(self.profile_store)
        worker = RuntimeWorker(runtime)
        worker.start()
        try:
            worker.submit_tick()
            response = worker.submit(COMMAND_STATUS, timeout=2.0)
        finally:
            worker.stop()

        self.assertTrue(response.ok)

    def test_submit_scheduled_rotation_requires_running_worker(self) -> None:
        worker = RuntimeWorker(self.make_runtime())

        with self.assertRaises(RuntimeError):
            worker.submit_scheduled_rotation()

    def test_scheduled_rotation_broadcasts_rotation_then_state(self) -> None:
        bus = EventBus()
        subscription = bus.subscribe()
        runtime = FakeRuntime(self.profile_store)
        runtime.scheduled_rotate_result = ConnectionState(
            active_profile_id="rotated", mode="rules", status="recovered"
        )
        worker = RuntimeWorker(runtime, bus)
        worker.start()
        try:
            worker.submit_scheduled_rotation()
            rotation_event = subscription.get(timeout=2.0)
            state_event = subscription.get(timeout=2.0)
            worker.submit(COMMAND_STATUS, timeout=2.0)  # drain queue in order
        finally:
            worker.stop()

        self.assertEqual(runtime.scheduled_rotate_calls, 1)
        self.assertEqual(rotation_event.event, EVENT_ROTATION)
        self.assertEqual(rotation_event.payload["active_profile_id"], "rotated")
        self.assertEqual(state_event.event, EVENT_STATE_CHANGED)

    def test_scheduled_rotation_still_broadcasts_when_it_was_a_quiet_noop(self) -> None:
        # scheduled_rotate() itself decides "nothing to do" (disabled gate or
        # empty pool) and returns the current, unchanged state - the worker
        # must not try to guess whether a real rotation happened, it just
        # reports what scheduled_rotate() returned, same as manual rotate.
        bus = EventBus()
        subscription = bus.subscribe()
        runtime = FakeRuntime(self.profile_store)
        runtime.scheduled_rotate_result = ConnectionState(status="connected", mode="rules")
        worker = RuntimeWorker(runtime, bus)
        worker.start()
        try:
            worker.submit_scheduled_rotation()
            rotation_event = subscription.get(timeout=2.0)
            state_event = subscription.get(timeout=2.0)
        finally:
            worker.stop()

        self.assertEqual(rotation_event.event, EVENT_ROTATION)
        self.assertEqual(rotation_event.payload["status"], "connected")
        self.assertEqual(state_event.event, EVENT_STATE_CHANGED)

    def test_scheduled_rotation_survives_exception_and_worker_keeps_serving(self) -> None:
        runtime = RaisingScheduledRotationRuntime(self.profile_store)
        worker = RuntimeWorker(runtime)
        worker.start()
        try:
            worker.submit_scheduled_rotation()
            response = worker.submit(COMMAND_STATUS, timeout=2.0)
        finally:
            worker.stop()

        self.assertTrue(response.ok)


class EventBusTests(unittest.TestCase):
    def test_broadcast_reaches_all_active_subscribers(self) -> None:
        bus = EventBus()
        first = bus.subscribe()
        second = bus.subscribe()

        from daemon.protocol import Event

        bus.broadcast(Event(EVENT_STATE_CHANGED, {"status": "connected"}))

        self.assertEqual(first.get(timeout=1.0).payload["status"], "connected")
        self.assertEqual(second.get(timeout=1.0).payload["status"], "connected")

    def test_closed_subscription_stops_receiving_events(self) -> None:
        bus = EventBus()
        subscription = bus.subscribe()
        subscription.close()

        from daemon.protocol import Event

        bus.broadcast(Event(EVENT_STATE_CHANGED, {"status": "connected"}))

        self.assertEqual(bus.subscriber_count(), 0)
        with self.assertRaises(queue.Empty):
            subscription.get(timeout=0.05)


if __name__ == "__main__":
    unittest.main()
