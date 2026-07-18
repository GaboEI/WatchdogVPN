from __future__ import annotations

import os
import socket
import uuid
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
    COMMAND_COMMAND_CANCEL,
    COMMAND_COMMAND_OUTCOME,
    COMMAND_DISCONNECT,
    COMMAND_NODE_GROUP_AUTO_TEST,
    COMMAND_ROTATE,
    COMMAND_STATUS,
    Event,
    MUTATING_COMMANDS,
    ProtocolError,
    Response,
    command_timeout_seconds,
    decode_event_line,
    decode_response_line,
    encode_request,
)


DEFAULT_SOCKET_PATH = Path("/run/watchdogvpn/control.sock")
TRANSPORT_GRACE_SECONDS = 5.0
DEFAULT_TIMEOUT_SECONDS = command_timeout_seconds(COMMAND_STATUS) + TRANSPORT_GRACE_SECONDS
LIFECYCLE_MUTATION_TIMEOUT_SECONDS = (
    command_timeout_seconds(COMMAND_CONNECT) + TRANSPORT_GRACE_SECONDS
)
NODE_GROUP_AUTO_TEST_TIMEOUT_SECONDS = (
    command_timeout_seconds(COMMAND_NODE_GROUP_AUTO_TEST) + TRANSPORT_GRACE_SECONDS
)
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
            timeout=_command_client_timeout(COMMAND_CONNECT),
        )

    def disconnect(self) -> Response:
        return self.request(COMMAND_DISCONNECT, timeout=_command_client_timeout(COMMAND_DISCONNECT))

    def status(self) -> Response:
        return self.request(COMMAND_STATUS)

    def rotate(self, force: bool = False) -> Response:
        return self.request(
            COMMAND_ROTATE,
            {"force": force},
            timeout=_command_client_timeout(COMMAND_ROTATE),
        )

    def node_group_auto_test(self, group_name: str) -> Response:
        return self.request(
            COMMAND_NODE_GROUP_AUTO_TEST,
            {"group_name": group_name},
            timeout=_command_client_timeout(COMMAND_NODE_GROUP_AUTO_TEST),
        )

    def command_outcome(self, command_id: str) -> Response:
        return self.request(
            COMMAND_COMMAND_OUTCOME,
            {"command_id": command_id},
            timeout=_command_client_timeout(COMMAND_COMMAND_OUTCOME),
        )

    def cancel_command(self, command_id: str) -> Response:
        return self.request(
            COMMAND_COMMAND_CANCEL,
            {"command_id": command_id},
            timeout=_command_client_timeout(COMMAND_COMMAND_CANCEL),
        )

    def request(
        self,
        command: str,
        payload: dict | None = None,
        timeout: float | None = None,
        *,
        command_id: str | None = None,
    ) -> Response:
        command_id = command_id or (
            str(uuid.uuid4()) if command in MUTATING_COMMANDS else None
        )
        request_line = encode_request(command, payload or {}, command_id=command_id)
        with self._connect(self.request_socket_path, timeout=timeout) as sock:
            try:
                sock.sendall(request_line)
                return decode_response_line(_read_line(sock))
            except socket.timeout as exc:
                raise DaemonTimeoutError(command_id=command_id) from exc
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
            # Path.exists() deliberately suppresses some OSError subclasses and
            # can therefore turn EACCES on a protected parent directory into a
            # false "socket does not exist" result.  stat() preserves the
            # distinction required by the public CLI error contract.
            path.stat()
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise DaemonNotRunningError() from exc
        except PermissionError as exc:
            raise DaemonPermissionError() from exc
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


def _command_client_timeout(command: str) -> float:
    return command_timeout_seconds(command) + TRANSPORT_GRACE_SECONDS
