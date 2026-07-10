from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Iterator

from cli.ipc.errors import (
    DaemonNotRunningError,
    DaemonPermissionError,
    DaemonTimeoutError,
    StaleSocketError,
    UnexpectedDaemonResponseError,
)
from daemon.protocol import (
    COMMAND_CONNECT,
    COMMAND_DISCONNECT,
    COMMAND_NODE_GROUP_AUTO_TEST,
    COMMAND_ROTATE,
    COMMAND_STATUS,
    Event,
    ProtocolError,
    Response,
    decode_event_line,
    decode_response_line,
    encode_request,
)


DEFAULT_SOCKET_PATH = Path("/run/watchdogvpn/control.sock")
DEFAULT_TIMEOUT_SECONDS = 5.0
LIFECYCLE_MUTATION_TIMEOUT_SECONDS = 30.0
NODE_GROUP_AUTO_TEST_TIMEOUT_SECONDS = 120.0
SOCKET_PATH_ENV = "WATCHDOGVPN_SOCKET_PATH"
EVENT_SOCKET_PATH_ENV = "WATCHDOGVPN_EVENT_SOCKET_PATH"


class WatchdogIPCClient:
    def __init__(
        self,
        request_socket_path: Path | str | None = None,
        event_socket_path: Path | str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.request_socket_path = (
            Path(request_socket_path) if request_socket_path is not None else default_socket_path()
        )
        self.event_socket_path = (
            Path(event_socket_path)
            if event_socket_path is not None
            else default_event_socket_path(self.request_socket_path)
        )
        self.timeout = timeout

    def connect(self, profile_id: str) -> Response:
        return self.request(
            COMMAND_CONNECT,
            {"profile_id": profile_id},
            timeout=LIFECYCLE_MUTATION_TIMEOUT_SECONDS,
        )

    def disconnect(self) -> Response:
        return self.request(COMMAND_DISCONNECT, timeout=LIFECYCLE_MUTATION_TIMEOUT_SECONDS)

    def status(self) -> Response:
        return self.request(COMMAND_STATUS)

    def rotate(self, force: bool = False) -> Response:
        return self.request(
            COMMAND_ROTATE,
            {"force": force},
            timeout=LIFECYCLE_MUTATION_TIMEOUT_SECONDS,
        )

    def node_group_auto_test(self, group_name: str) -> Response:
        return self.request(
            COMMAND_NODE_GROUP_AUTO_TEST,
            {"group_name": group_name},
            timeout=NODE_GROUP_AUTO_TEST_TIMEOUT_SECONDS,
        )

    def request(self, command: str, payload: dict | None = None, timeout: float | None = None) -> Response:
        request_line = encode_request(command, payload or {})
        with self._connect(self.request_socket_path, timeout=timeout) as sock:
            try:
                sock.sendall(request_line)
                return decode_response_line(_read_line(sock))
            except socket.timeout as exc:
                raise DaemonTimeoutError() from exc
            except ProtocolError as exc:
                raise UnexpectedDaemonResponseError() from exc
            except EOFError as exc:
                raise UnexpectedDaemonResponseError() from exc
            except (BrokenPipeError, ConnectionResetError) as exc:
                raise UnexpectedDaemonResponseError() from exc

    def events(self) -> Iterator[Event]:
        with self._connect(self.event_socket_path) as sock:
            while True:
                try:
                    yield decode_event_line(_read_line(sock))
                except socket.timeout as exc:
                    raise DaemonTimeoutError() from exc
                except ProtocolError as exc:
                    raise UnexpectedDaemonResponseError() from exc
                except EOFError:
                    return

    def _connect(self, path: Path, timeout: float | None = None) -> socket.socket:
        try:
            exists = path.exists()
        except PermissionError as exc:
            raise DaemonPermissionError() from exc
        if not exists:
            raise DaemonNotRunningError()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout if timeout is None else timeout)
        try:
            sock.connect(str(path))
        except FileNotFoundError as exc:
            sock.close()
            raise DaemonNotRunningError() from exc
        except ConnectionRefusedError as exc:
            sock.close()
            raise StaleSocketError() from exc
        except PermissionError as exc:
            sock.close()
            raise DaemonPermissionError() from exc
        except socket.timeout as exc:
            sock.close()
            raise DaemonTimeoutError() from exc
        except OSError:
            sock.close()
            raise
        return sock


def default_socket_path() -> Path:
    return Path(os.environ.get(SOCKET_PATH_ENV, DEFAULT_SOCKET_PATH))


def default_event_socket_path(request_socket_path: Path | str | None = None) -> Path:
    env_path = os.environ.get(EVENT_SOCKET_PATH_ENV)
    if env_path:
        return Path(env_path)
    request_path = (
        Path(request_socket_path) if request_socket_path is not None else default_socket_path()
    )
    return request_path.with_name(f"{request_path.stem}.events{request_path.suffix}")


def _read_line(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("socket closed before newline")
        chunks.append(chunk)
        if chunk == b"\n":
            return b"".join(chunks)
