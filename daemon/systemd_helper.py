from __future__ import annotations

import os
import socket


def notify(message: str) -> None:
    notify_socket = os.environ.get("NOTIFY_SOCKET")
    if not notify_socket:
        return
    address = _notify_address(notify_socket)
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.connect(address)
        sock.sendall(message.encode("utf-8"))


def _notify_address(value: str) -> str | bytes:
    if value.startswith("@"):
        return b"\0" + value[1:].encode("utf-8")
    return value
