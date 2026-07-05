from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from pathlib import Path

from core.watchdog import build_watchdog
from daemon.ipc_server import IPCServer
from daemon.runtime_worker import RuntimeWorker
from daemon.scheduled_rotation_loop import ScheduledRotationLoop
from daemon.watchdog_loop import WatchdogLoop
from daemon import systemd_helper


CAP_NET_BIND_SERVICE = 10
CAP_NET_ADMIN = 12
CAPABILITY_WARNING = (
    "Warning: running without CAP_NET_ADMIN/CAP_NET_BIND_SERVICE. TUN mode, "
    "kill switch, and privileged-port DNS hijack will fail. For full "
    "functionality, run via: sudo systemctl start watchdogvpn."
)
DEFAULT_SOCKET_PATH = Path("/run/watchdogvpn/control.sock")
SOCKET_PATH_ENV = "WATCHDOGVPN_SOCKET_PATH"
EVENT_SOCKET_PATH_ENV = "WATCHDOGVPN_EVENT_SOCKET_PATH"


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.standalone:
        _warn_if_standalone_lacks_capabilities()

    stop_event = threading.Event()
    _install_signal_handlers(stop_event)

    request_socket_path = _resolve_socket_path(args.socket_path)
    event_socket_path = _resolve_event_socket_path(request_socket_path)
    runtime = build_watchdog()
    reconcile_stale_tun_state = getattr(runtime.driver, "reconcile_stale_tun_state", None)
    if not args.standalone and callable(reconcile_stale_tun_state):
        reconcile_stale_tun_state()
    worker = RuntimeWorker(runtime)
    server = IPCServer(request_socket_path, event_socket_path, worker)
    watchdog_loop = WatchdogLoop(worker, app_config=runtime.app_config)
    scheduled_rotation_loop = ScheduledRotationLoop(worker, app_config=runtime.app_config)
    try:
        server.start()
        watchdog_loop.start()
        scheduled_rotation_loop.start()
        systemd_helper.notify("READY=1")
        stop_event.wait()
    finally:
        scheduled_rotation_loop.stop()
        watchdog_loop.stop()
        server.stop()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchdogvpn-daemon", description="WatchdogVPN daemon")
    parser.add_argument("--standalone", action="store_true", help="Run in foreground development mode")
    parser.add_argument("--socket-path", help="Unix request socket path")
    return parser


def _install_signal_handlers(stop_event: threading.Event) -> None:
    def handle_signal(signum, frame) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)


def _resolve_socket_path(socket_path: str | None) -> Path:
    if socket_path:
        return Path(socket_path)
    return Path(os.environ.get(SOCKET_PATH_ENV, DEFAULT_SOCKET_PATH))


def _resolve_event_socket_path(request_socket_path: Path) -> Path:
    env_path = os.environ.get(EVENT_SOCKET_PATH_ENV)
    if env_path:
        return Path(env_path)
    return request_socket_path.with_name(f"{request_socket_path.stem}.events{request_socket_path.suffix}")


def _warn_if_standalone_lacks_capabilities() -> None:
    try:
        status_text = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:
        print(CAPABILITY_WARNING, file=sys.stderr)
        return
    if not _has_required_capabilities(status_text):
        print(CAPABILITY_WARNING, file=sys.stderr)


def _has_required_capabilities(status_text: str) -> bool:
    cap_eff = _parse_cap_eff(status_text)
    if cap_eff is None:
        return False
    required = (1 << CAP_NET_ADMIN) | (1 << CAP_NET_BIND_SERVICE)
    return (cap_eff & required) == required


def _parse_cap_eff(status_text: str) -> int | None:
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            value = line.split(":", 1)[1].strip()
            try:
                return int(value, 16)
            except ValueError:
                return None
    return None


if __name__ == "__main__":
    raise SystemExit(main())
