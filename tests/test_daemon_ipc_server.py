from __future__ import annotations

import json
import queue
import socket
import stat
import tempfile
import time
import unittest
from pathlib import Path

from config.profile_store import ProfileStore
from daemon.ipc_server import DEFAULT_SOCKET_MODE, IPCServer
from daemon.protocol import (
    COMMAND_CONNECT,
    COMMAND_STATUS,
    EVENT_STATE_CHANGED,
    decode_event_line,
    decode_response_line,
    encode_request,
)
from daemon.runtime_worker import RuntimeWorker
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType


class FakeRuntime:
    def __init__(self, profile_store: ProfileStore) -> None:
        self.profile_store = profile_store
        self.connected_profile_id = ""

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

    def automatic_actions_enabled(self) -> bool:
        return True

    def rotate_now(self, force: bool = False) -> ConnectionState:
        self.connected_profile_id = "rotated"
        return ConnectionState(active_profile_id="rotated", mode="rules", status="recovered")


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


def read_line(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("socket closed before newline")
        chunks.append(chunk)
        if chunk == b"\n":
            return b"".join(chunks)


def wait_for(condition, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.01)
    raise TimeoutError("condition was not satisfied")


class DaemonIPCServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.request_socket = self.root / "request.sock"
        self.event_socket = self.root / "event.sock"
        self.profile_store = ProfileStore(self.root / "profiles.json")
        self.profile = make_profile()
        self.profile_store.add(self.profile)
        self.runtime = FakeRuntime(self.profile_store)
        self.worker = RuntimeWorker(self.runtime)
        self.server = IPCServer(self.request_socket, self.event_socket, self.worker)
        self.server.start()

    def tearDown(self) -> None:
        self.server.stop()
        self.tmpdir.cleanup()

    def request(self, command: str, payload: dict | None = None):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(self.request_socket))
            sock.sendall(encode_request(command, payload or {}))
            return decode_response_line(read_line(sock))

    def test_request_socket_status_round_trip(self) -> None:
        response = self.request(COMMAND_STATUS)

        self.assertTrue(response.ok)
        self.assertEqual(response.payload["state"]["status"], "standby")

    def test_request_socket_connects_profile(self) -> None:
        response = self.request(COMMAND_CONNECT, {"profile_id": self.profile.id})

        self.assertTrue(response.ok)
        self.assertEqual(response.payload["profile_id"], self.profile.id)
        self.assertEqual(self.runtime.connected_profile_id, self.profile.id)

    def test_request_socket_handles_malformed_line(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(self.request_socket))
            sock.sendall(b"not-json\n")
            response = decode_response_line(read_line(sock))

        self.assertFalse(response.ok)
        self.assertIn("invalid JSON message", response.error or "")

    def test_request_socket_handles_multiple_requests_on_one_connection(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(self.request_socket))
            sock.sendall(encode_request(COMMAND_STATUS))
            first = decode_response_line(read_line(sock))
            sock.sendall(encode_request(COMMAND_CONNECT, {"profile_id": self.profile.id}))
            second = decode_response_line(read_line(sock))

        self.assertTrue(first.ok)
        self.assertTrue(second.ok)
        self.assertEqual(second.payload["state"]["active_profile_id"], self.profile.id)

    def test_request_socket_tolerates_client_close_before_response(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(self.request_socket))
            sock.sendall(encode_request(COMMAND_STATUS))

        response = self.request(COMMAND_STATUS)

        self.assertTrue(response.ok)

    def test_event_socket_streams_state_change_events(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as event_sock:
            event_sock.settimeout(2.0)
            event_sock.connect(str(self.event_socket))
            wait_for(lambda: self.worker.event_bus.subscriber_count() == 1)

            response = self.request(COMMAND_CONNECT, {"profile_id": self.profile.id})
            event = decode_event_line(read_line(event_sock))

        self.assertTrue(response.ok)
        self.assertEqual(event.event, EVENT_STATE_CHANGED)
        self.assertEqual(event.payload["active_profile_id"], self.profile.id)

    def test_socket_files_have_explicit_permissions(self) -> None:
        request_mode = stat.S_IMODE(self.request_socket.stat().st_mode)
        event_mode = stat.S_IMODE(self.event_socket.stat().st_mode)

        self.assertEqual(request_mode, DEFAULT_SOCKET_MODE)
        self.assertEqual(event_mode, DEFAULT_SOCKET_MODE)

    def test_stop_removes_socket_files(self) -> None:
        self.server.stop()

        self.assertFalse(self.request_socket.exists())
        self.assertFalse(self.event_socket.exists())

    def test_stop_closes_active_event_subscription(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as event_sock:
            event_sock.connect(str(self.event_socket))
            wait_for(lambda: self.worker.event_bus.subscriber_count() == 1)

            self.server.stop()
            wait_for(lambda: self.worker.event_bus.subscriber_count() == 0)

        self.assertFalse(self.request_socket.exists())
        self.assertFalse(self.event_socket.exists())

    def test_existing_non_socket_path_is_rejected(self) -> None:
        self.server.stop()
        self.request_socket.write_text("not a socket", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            IPCServer(self.request_socket, self.event_socket, RuntimeWorker(self.runtime)).start()

    def test_start_failure_after_first_socket_cleans_up_request_socket(self) -> None:
        self.server.stop()
        self.event_socket.write_text("not a socket", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            IPCServer(self.request_socket, self.event_socket, RuntimeWorker(self.runtime)).start()

        self.assertFalse(self.request_socket.exists())
        self.assertTrue(self.event_socket.exists())


class DaemonIPCServerRawJSONTests(unittest.TestCase):
    def test_raw_socket_client_can_decode_response_as_json_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_store = ProfileStore(root / "profiles.json")
            runtime = FakeRuntime(profile_store)
            server = IPCServer(root / "request.sock", root / "event.sock", RuntimeWorker(runtime))
            server.start()
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.connect(str(root / "request.sock"))
                    sock.sendall(encode_request(COMMAND_STATUS))
                    data = json.loads(read_line(sock).decode("utf-8"))
            finally:
                server.stop()

        self.assertEqual(data["type"], "response")
        self.assertTrue(data["ok"])


if __name__ == "__main__":
    unittest.main()
