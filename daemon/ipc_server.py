from __future__ import annotations

import os
import queue
import socket
import socketserver
import stat
import threading
from pathlib import Path

from daemon.protocol import (
    ProtocolError,
    decode_request_line,
    encode_event,
    encode_response,
)
from daemon.runtime_worker import RuntimeWorker


DEFAULT_SOCKET_MODE = 0o660
EVENT_POLL_TIMEOUT_SECONDS = 0.2
DEFAULT_REQUEST_TIMEOUT_SECONDS = 30.0


class ThreadingUnixStreamServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, *args, **kwargs) -> None:
        self.stopping = threading.Event()
        super().__init__(*args, **kwargs)

    def begin_shutdown(self) -> None:
        self.stopping.set()


class _RequestSocketServer(ThreadingUnixStreamServer):
    def __init__(
        self,
        socket_path: Path,
        worker: RuntimeWorker,
        request_timeout_seconds: float,
    ) -> None:
        self.socket_path = socket_path
        self.worker = worker
        self.request_timeout_seconds = request_timeout_seconds
        _prepare_socket_path(socket_path)
        super().__init__(str(socket_path), _RequestHandler)
        os.chmod(socket_path, DEFAULT_SOCKET_MODE)

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            _unlink_socket(self.socket_path)


class _EventSocketServer(ThreadingUnixStreamServer):
    def __init__(self, socket_path: Path, worker: RuntimeWorker) -> None:
        self.socket_path = socket_path
        self.worker = worker
        _prepare_socket_path(socket_path)
        super().__init__(str(socket_path), _EventHandler)
        os.chmod(socket_path, DEFAULT_SOCKET_MODE)

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            _unlink_socket(self.socket_path)


class _RequestHandler(socketserver.StreamRequestHandler):
    server: _RequestSocketServer

    def handle(self) -> None:
        for raw_line in self.rfile:
            try:
                request = decode_request_line(raw_line)
                response = self.server.worker.submit(
                    request.command,
                    request.payload,
                    timeout=self.server.request_timeout_seconds,
                )
            except ProtocolError as exc:
                response = encode_response(False, error=str(exc))
            except queue.Empty:
                response = encode_response(False, error="daemon runtime command timed out")
            except Exception as exc:
                response = encode_response(False, error=str(exc))
            else:
                response = encode_response(response.ok, response.payload, response.error)
            try:
                self.wfile.write(response)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                return


class _EventHandler(socketserver.StreamRequestHandler):
    server: _EventSocketServer

    def handle(self) -> None:
        subscription = self.server.worker.event_bus.subscribe()
        try:
            while not self.server.stopping.is_set():
                try:
                    event = subscription.get(timeout=EVENT_POLL_TIMEOUT_SECONDS)
                except queue.Empty:
                    continue
                try:
                    self.wfile.write(encode_event(event.event, event.payload))
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return
        finally:
            subscription.close()


class IPCServer:
    def __init__(
        self,
        request_socket_path: Path,
        event_socket_path: Path,
        worker: RuntimeWorker,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self.request_socket_path = request_socket_path
        self.event_socket_path = event_socket_path
        self.worker = worker
        self.request_timeout_seconds = request_timeout_seconds
        self._request_server: _RequestSocketServer | None = None
        self._event_server: _EventSocketServer | None = None
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        if self._request_server is not None or self._event_server is not None:
            return
        try:
            self.worker.start()
            self._request_server = _RequestSocketServer(
                self.request_socket_path,
                self.worker,
                self.request_timeout_seconds,
            )
            self._event_server = _EventSocketServer(self.event_socket_path, self.worker)
            self._threads = [
                threading.Thread(
                    target=self._request_server.serve_forever,
                    name="watchdogvpn-ipc-request",
                    daemon=True,
                ),
                threading.Thread(
                    target=self._event_server.serve_forever,
                    name="watchdogvpn-ipc-event",
                    daemon=True,
                ),
            ]
            for thread in self._threads:
                thread.start()
        except Exception:
            if self._request_server is not None:
                self._request_server.server_close()
            if self._event_server is not None:
                self._event_server.server_close()
            self.worker.stop()
            self._request_server = None
            self._event_server = None
            self._threads = []
            raise

    def stop(self) -> bool:
        servers = [self._request_server, self._event_server]
        for server in servers:
            if server is not None:
                server.begin_shutdown()
        for server in servers:
            if server is not None:
                server.shutdown()
        for server in servers:
            if server is not None:
                server.server_close()
        for thread in self._threads:
            thread.join(timeout=5.0)
        worker_stopped = self.worker.stop()
        self._request_server = None
        self._event_server = None
        self._threads = []
        return worker_stopped


def _prepare_socket_path(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        return
    mode = path.stat().st_mode
    if stat.S_ISSOCK(mode):
        path.unlink()
        return
    raise FileExistsError(f"socket path exists and is not a socket: {path}")


def _unlink_socket(path: Path) -> None:
    try:
        if path.exists() and stat.S_ISSOCK(path.stat().st_mode):
            path.unlink()
    except FileNotFoundError:
        return
