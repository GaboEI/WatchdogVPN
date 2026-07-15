from __future__ import annotations


DAEMON_NOT_RUNNING_MESSAGE = (
    "WatchdogVPN daemon is not running. Try: sudo systemctl start watchdogvpn "
    "(or: python3 -m daemon.main --standalone for dev mode)."
)
STALE_SOCKET_MESSAGE = (
    "Daemon socket is stale (process not responding). Try: sudo systemctl restart watchdogvpn."
)
PERMISSION_DENIED_MESSAGE = (
    "Permission denied connecting to the daemon. Your user must be in the 'watchdogvpn' "
    "group. Try: sudo usermod -aG watchdogvpn $USER, then log out and back in."
)
DAEMON_TIMEOUT_MESSAGE = (
    "Daemon did not respond in time (busy or stuck). Check: sudo journalctl -u watchdogvpn."
)
UNEXPECTED_RESPONSE_MESSAGE = "Unexpected response from daemon — client/daemon version mismatch?"


class WatchdogIPCError(RuntimeError):
    exit_code = 70


class DaemonNotRunningError(WatchdogIPCError):
    exit_code = 69

    def __init__(self) -> None:
        super().__init__(DAEMON_NOT_RUNNING_MESSAGE)


class StaleSocketError(WatchdogIPCError):
    exit_code = 70

    def __init__(self) -> None:
        super().__init__(STALE_SOCKET_MESSAGE)


class DaemonPermissionError(WatchdogIPCError):
    exit_code = 77

    def __init__(self) -> None:
        super().__init__(PERMISSION_DENIED_MESSAGE)


class DaemonTimeoutError(WatchdogIPCError):
    exit_code = 75

    def __init__(self, command_id: str | None = None) -> None:
        self.command_id = command_id
        message = DAEMON_TIMEOUT_MESSAGE
        if command_id is not None:
            message = (
                f"{message} The command may have reached the daemon; query its authoritative "
                f"outcome with: watchdog command outcome {command_id}"
            )
        super().__init__(message)


class UnexpectedDaemonResponseError(WatchdogIPCError):
    exit_code = 70

    def __init__(self) -> None:
        super().__init__(UNEXPECTED_RESPONSE_MESSAGE)
