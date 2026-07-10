from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cli.ipc.client import (
    EVENT_SOCKET_PATH_ENV,
    SOCKET_PATH_ENV,
    WatchdogIPCClient,
    default_event_socket_path,
    default_socket_path,
)
from cli.ipc.errors import (
    DAEMON_NOT_RUNNING_MESSAGE,
    DAEMON_TIMEOUT_MESSAGE,
    PERMISSION_DENIED_MESSAGE,
    STALE_SOCKET_MESSAGE,
    UNEXPECTED_RESPONSE_MESSAGE,
    DaemonNotRunningError,
    DaemonPermissionError,
    DaemonTimeoutError,
    StaleSocketError,
    UnexpectedDaemonResponseError,
)
from config.profile_store import ProfileStore
from daemon.ipc_server import IPCServer
from daemon.protocol import EVENT_STATE_CHANGED, encode_event
from daemon.protocol import encode_response
from daemon.runtime_worker import RuntimeWorker
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType


class FakeRuntime:
    def __init__(self, profile_store: ProfileStore) -> None:
        self.profile_store = profile_store
        self.connected_profile_id = ""
        self.rotate_calls: list[bool] = []
        self.auto_test_calls: list[str] = []

    def connect(self, profile: Profile) -> bool:
        self.connected_profile_id = profile.id
        return True

    def disconnect(self) -> bool:
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

    def node_group_auto_test(self, group_name: str) -> dict:
        self.auto_test_calls.append(group_name)
        return {"group_name": group_name, "result": "unavailable"}


class BlockingRuntime(FakeRuntime):
    def __init__(self, profile_store: ProfileStore) -> None:
        super().__init__(profile_store)
        self.connect_started = threading.Event()
        self.release_connect = threading.Event()

    def connect(self, profile: Profile) -> bool:
        self.connect_started.set()
        self.release_connect.wait(timeout=5.0)
        return super().connect(profile)


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


class WatchdogIPCClientIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.request_socket = self.root / "control.sock"
        self.event_socket = self.root / "control.events.sock"
        self.profile_store = ProfileStore(self.root / "profiles.json")
        self.profile = make_profile()
        self.profile_store.add(self.profile)
        self.runtime = FakeRuntime(self.profile_store)
        self.server = IPCServer(
            self.request_socket,
            self.event_socket,
            RuntimeWorker(self.runtime),
        )
        self.server.start()
        self.client = WatchdogIPCClient(self.request_socket, self.event_socket, timeout=2.0)

    def tearDown(self) -> None:
        self.server.stop()
        self.tmpdir.cleanup()

    def test_status_round_trip_against_real_server(self) -> None:
        response = self.client.status()

        self.assertTrue(response.ok)
        self.assertEqual(response.payload["state"]["status"], "standby")

    def test_connect_disconnect_and_rotate_against_real_server(self) -> None:
        connect_response = self.client.connect(self.profile.id)
        status_response = self.client.status()
        rotate_response = self.client.rotate(force=True)
        auto_test_response = self.client.node_group_auto_test("paris")
        disconnect_response = self.client.disconnect()

        self.assertTrue(connect_response.ok)
        self.assertEqual(status_response.payload["state"]["active_profile_id"], self.profile.id)
        self.assertTrue(rotate_response.ok)
        self.assertEqual(self.runtime.rotate_calls, [True])
        self.assertTrue(auto_test_response.ok)
        self.assertEqual(self.runtime.auto_test_calls, ["paris"])
        self.assertEqual(auto_test_response.payload["group_name"], "paris")
        self.assertTrue(disconnect_response.ok)
        self.assertEqual(disconnect_response.payload["state"]["status"], "standby")

    def test_events_stream_against_real_server(self) -> None:
        events = self.client.events()

        def trigger_connect() -> None:
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and self.server.worker.event_bus.subscriber_count() == 0:
                time.sleep(0.01)
            self.client.connect(self.profile.id)

        thread = threading.Thread(target=trigger_connect)
        thread.start()
        try:
            event = next(events)
        finally:
            thread.join(timeout=2.0)

        self.assertEqual(event.event, EVENT_STATE_CHANGED)
        self.assertEqual(event.payload["active_profile_id"], self.profile.id)

    def test_server_returns_structured_timeout_when_runtime_command_hangs(self) -> None:
        self.server.stop()
        self.runtime = BlockingRuntime(self.profile_store)
        self.server = IPCServer(
            self.request_socket,
            self.event_socket,
            RuntimeWorker(self.runtime),
            request_timeout_seconds=0.05,
        )
        self.server.start()
        self.client = WatchdogIPCClient(self.request_socket, self.event_socket, timeout=1.0)

        connect_response = self.client.connect(self.profile.id)
        self.assertFalse(connect_response.ok)
        self.assertEqual(connect_response.error, "daemon runtime command timed out")
        self.assertTrue(self.runtime.connect_started.is_set())

        status_response = self.client.status()
        self.assertFalse(status_response.ok)
        self.assertEqual(status_response.error, "daemon runtime command timed out")
        self.runtime.release_connect.set()


class WatchdogIPCClientErrorTests(unittest.TestCase):
    def test_missing_socket_maps_to_daemon_not_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = WatchdogIPCClient(Path(tmp) / "missing.sock", timeout=0.1)

            with self.assertRaises(DaemonNotRunningError) as cm:
                client.status()

        self.assertEqual(str(cm.exception), DAEMON_NOT_RUNNING_MESSAGE)

    def test_stale_socket_maps_to_stale_socket_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = Path(tmp) / "stale.sock"
            stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stale.bind(str(socket_path))
            stale.close()
            client = WatchdogIPCClient(socket_path, timeout=0.1)

            with self.assertRaises(StaleSocketError) as cm:
                client.status()

        self.assertEqual(str(cm.exception), STALE_SOCKET_MESSAGE)

    def test_permission_error_maps_to_daemon_permission_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = Path(tmp) / "control.sock"
            socket_path.write_text("", encoding="utf-8")
            client = WatchdogIPCClient(socket_path, timeout=0.1)

            with patch("socket.socket.connect", side_effect=PermissionError):
                with self.assertRaises(DaemonPermissionError) as cm:
                    client.status()

        self.assertEqual(str(cm.exception), PERMISSION_DENIED_MESSAGE)

    def test_permission_error_reading_socket_path_maps_to_daemon_permission_error(self) -> None:
        client = WatchdogIPCClient(Path("/run/watchdogvpn/control.sock"), timeout=0.1)

        with patch.object(Path, "exists", side_effect=PermissionError):
            with self.assertRaises(DaemonPermissionError) as cm:
                client.status()

        self.assertEqual(str(cm.exception), PERMISSION_DENIED_MESSAGE)

    def test_request_timeout_maps_to_daemon_timeout_error(self) -> None:
        with hanging_unix_server() as socket_path:
            client = WatchdogIPCClient(socket_path, timeout=0.1)

            with self.assertRaises(DaemonTimeoutError) as cm:
                client.status()

        self.assertEqual(str(cm.exception), DAEMON_TIMEOUT_MESSAGE)

    def test_node_group_auto_test_uses_extended_timeout(self) -> None:
        line = encode_response(True, {"group_name": "phase14-vm", "result": "unavailable"})
        with delayed_one_line_unix_server(line, delay=0.2) as socket_path:
            client = WatchdogIPCClient(socket_path, timeout=0.05)

            response = client.node_group_auto_test("phase14-vm")

        self.assertTrue(response.ok)
        self.assertEqual(response.payload["group_name"], "phase14-vm")

    def test_connect_uses_extended_lifecycle_timeout(self) -> None:
        line = encode_response(True, {"connected": True})
        with delayed_one_line_unix_server(line, delay=0.2) as socket_path:
            client = WatchdogIPCClient(socket_path, timeout=0.05)

            response = client.connect("slow-profile")

        self.assertTrue(response.ok)
        self.assertTrue(response.payload["connected"])

    def test_malformed_response_maps_to_unexpected_response_error(self) -> None:
        with one_line_unix_server(b"not-json\n") as socket_path:
            client = WatchdogIPCClient(socket_path, timeout=1.0)

            with self.assertRaises(UnexpectedDaemonResponseError) as cm:
                client.status()

        self.assertEqual(str(cm.exception), UNEXPECTED_RESPONSE_MESSAGE)

    def test_event_timeout_maps_to_daemon_timeout_error(self) -> None:
        with hanging_unix_server() as socket_path:
            client = WatchdogIPCClient(socket_path, socket_path, timeout=0.1)
            events = client.events()

            with self.assertRaises(DaemonTimeoutError):
                next(events)

    def test_malformed_event_maps_to_unexpected_response_error(self) -> None:
        with one_line_unix_server(b"not-json\n") as socket_path:
            client = WatchdogIPCClient(socket_path, socket_path, timeout=1.0)
            events = client.events()

            with self.assertRaises(UnexpectedDaemonResponseError):
                next(events)

    def test_closed_event_socket_stops_iteration(self) -> None:
        with one_line_unix_server(encode_event(EVENT_STATE_CHANGED, {"status": "connected"})) as socket_path:
            client = WatchdogIPCClient(socket_path, socket_path, timeout=1.0)
            events = client.events()
            self.assertEqual(next(events).event, EVENT_STATE_CHANGED)

            with self.assertRaises(StopIteration):
                next(events)


class WatchdogIPCClientPathTests(unittest.TestCase):
    def test_default_socket_path_uses_environment(self) -> None:
        with patch.dict(os.environ, {SOCKET_PATH_ENV: "/tmp/watchdogvpn-test.sock"}, clear=False):
            self.assertEqual(default_socket_path(), Path("/tmp/watchdogvpn-test.sock"))

    def test_default_event_socket_path_is_derived_from_request_socket(self) -> None:
        self.assertEqual(
            default_event_socket_path(Path("/run/watchdogvpn/control.sock")),
            Path("/run/watchdogvpn/control.events.sock"),
        )

    def test_default_event_socket_path_uses_environment(self) -> None:
        with patch.dict(os.environ, {EVENT_SOCKET_PATH_ENV: "/tmp/watchdogvpn-events.sock"}, clear=False):
            self.assertEqual(default_event_socket_path(Path("/tmp/request.sock")), Path("/tmp/watchdogvpn-events.sock"))


class one_line_unix_server:
    def __init__(self, line: bytes) -> None:
        self.line = line
        self.tmpdir = tempfile.TemporaryDirectory()
        self.socket_path = Path(self.tmpdir.name) / "server.sock"
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> Path:
        self.server.bind(str(self.socket_path))
        self.server.listen(1)
        self.thread.start()
        return self.socket_path

    def __exit__(self, exc_type, exc, tb) -> None:
        self.server.close()
        self.thread.join(timeout=2.0)
        self.tmpdir.cleanup()

    def _serve(self) -> None:
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        with conn:
            try:
                conn.sendall(self.line)
            except OSError:
                return


class delayed_one_line_unix_server(one_line_unix_server):
    def __init__(self, line: bytes, delay: float) -> None:
        super().__init__(line)
        self.delay = delay

    def _serve(self) -> None:
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        with conn:
            time.sleep(self.delay)
            try:
                conn.sendall(self.line)
            except OSError:
                return


class hanging_unix_server:
    def __init__(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.socket_path = Path(self.tmpdir.name) / "server.sock"
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> Path:
        self.server.bind(str(self.socket_path))
        self.server.listen(1)
        self.thread.start()
        return self.socket_path

    def __exit__(self, exc_type, exc, tb) -> None:
        self.server.close()
        self.thread.join(timeout=2.0)
        self.tmpdir.cleanup()

    def _serve(self) -> None:
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        with conn:
            time.sleep(0.5)


if __name__ == "__main__":
    unittest.main()
