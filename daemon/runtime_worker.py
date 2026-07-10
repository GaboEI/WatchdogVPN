from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass, field
from typing import Any, Protocol

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
    ALLOWED_COMMANDS,
    Event,
    Response,
    UnknownCommandError,
)
from metrics.recorder import MetricsRecorder
from models.connection_state import ConnectionState
from models.profile import Profile


LOGGER = logging.getLogger(__name__)


class RuntimeLike(Protocol):
    profile_store: Any

    def connect(self, profile: Profile) -> bool:
        ...

    def disconnect(self) -> bool:
        ...

    def status(self) -> ConnectionState:
        ...

    def rotate_now(self, force: bool = False) -> ConnectionState:
        ...

    def run_iteration(self) -> ConnectionState:
        ...

    def scheduled_rotate(self) -> ConnectionState:
        ...

    def node_group_auto_test(self, group_name: str) -> dict[str, Any]:
        ...


_STOP = object()
_TICK = object()
_SCHEDULED_ROTATE = object()


@dataclass(slots=True)
class WorkerRequest:
    command: str
    payload: dict[str, Any] = field(default_factory=dict)
    response_queue: "queue.Queue[Response]" = field(default_factory=queue.Queue)


class RuntimeWorker:
    def __init__(
        self,
        runtime: RuntimeLike,
        event_bus: EventBus | None = None,
        metrics_recorder: MetricsRecorder | None = None,
    ) -> None:
        self.runtime = runtime
        self.event_bus = event_bus or EventBus()
        self.metrics_recorder = metrics_recorder or MetricsRecorder()
        self._queue: "queue.Queue[WorkerRequest | object]" = queue.Queue()
        self._thread = threading.Thread(target=self._run, name="watchdogvpn-runtime-worker", daemon=True)
        self._started = threading.Event()
        self._stopped = threading.Event()
        self._last_tick_status: str | None = None

    def start(self) -> None:
        if self._thread.is_alive():
            return
        self._thread.start()
        self._started.wait(timeout=5.0)

    def stop(self, timeout: float | None = 5.0) -> None:
        if not self._thread.is_alive():
            return
        self._queue.put(_STOP)
        self._thread.join(timeout=timeout)

    def submit(
        self,
        command: str,
        payload: dict[str, Any] | None = None,
        timeout: float | None = 30.0,
    ) -> Response:
        request = WorkerRequest(command=command, payload=dict(payload or {}))
        self.submit_request(request)
        return request.response_queue.get(timeout=timeout)

    def submit_request(self, request: WorkerRequest) -> None:
        if not self._thread.is_alive():
            raise RuntimeError("runtime worker is not running")
        self._queue.put(request)

    def submit_tick(self) -> None:
        """Enqueue an autonomous health-check tick (see daemon.watchdog_loop).

        Fire-and-forget: goes through the same queue as IPC requests so it
        never runs concurrently with a connect/disconnect/rotate command,
        but nothing waits on a response.
        """
        if not self._thread.is_alive():
            raise RuntimeError("runtime worker is not running")
        self._queue.put(_TICK)

    def submit_scheduled_rotation(self) -> None:
        """Enqueue a proactive scheduled rotation (see daemon.scheduled_rotation_loop).

        Same fire-and-forget discipline as submit_tick: the timer only
        decides *when*, execution is always serialized on this single
        worker thread through WatchdogRuntime.scheduled_rotate(), which
        reuses the same pool_builder/RotationEngine path as reactive and
        manual rotation.
        """
        if not self._thread.is_alive():
            raise RuntimeError("runtime worker is not running")
        self._queue.put(_SCHEDULED_ROTATE)

    def is_running(self) -> bool:
        return self._thread.is_alive() and not self._stopped.is_set()

    def _run(self) -> None:
        self._started.set()
        try:
            while True:
                item = self._queue.get()
                if item is _STOP:
                    return
                if item is _TICK:
                    self._handle_tick()
                    continue
                if item is _SCHEDULED_ROTATE:
                    self._handle_scheduled_rotation()
                    continue
                if not isinstance(item, WorkerRequest):
                    continue
                item.response_queue.put(self._handle_request(item))
        finally:
            self._stopped.set()

    def _handle_tick(self) -> None:
        # A tick has no caller waiting on a response - an unexpected
        # exception here must never escape and kill this thread, since it
        # also serves every IPC connect/disconnect/status/rotate command.
        try:
            state = self.runtime.run_iteration()
        except Exception:
            LOGGER.error("watchdog_tick_failed", exc_info=True)
            self.metrics_recorder.record_runtime_error("watchdog_tick_failed")
            return
        state_payload = _state_payload(state)
        self.metrics_recorder.record_health_check(state)
        self.event_bus.broadcast(Event(EVENT_HEALTH_CHECK, state_payload))
        if state_payload.get("status") != self._last_tick_status:
            self._last_tick_status = state_payload.get("status")
            self._broadcast_state(state_payload)

    def _handle_scheduled_rotation(self) -> None:
        # Same reasoning as _handle_tick: no caller is waiting on a
        # response, and an unexpected exception must never kill this
        # thread since it also serves every IPC command.
        try:
            state = self.runtime.scheduled_rotate()
        except Exception:
            LOGGER.error("scheduled_rotation_failed", exc_info=True)
            self.metrics_recorder.record_runtime_error("scheduled_rotation_failed")
            return
        state_payload = _state_payload(state)
        self.metrics_recorder.record_scheduled_rotation(state)
        # Mirrors _handle_rotate: EVENT_ROTATION means "a rotation was
        # requested", not "it succeeded" - the payload's status says what
        # actually happened (including a quiet no-op from scheduled_rotate
        # when the feature is disabled or the pool is empty).
        self.event_bus.broadcast(Event(EVENT_ROTATION, state_payload))
        self._broadcast_state(state_payload)

    def _handle_request(self, request: WorkerRequest) -> Response:
        try:
            if request.command not in ALLOWED_COMMANDS:
                raise UnknownCommandError(f"unknown command: {request.command}")
            if request.command == COMMAND_CONNECT:
                return self._handle_connect(request.payload)
            if request.command == COMMAND_DISCONNECT:
                return self._handle_disconnect()
            if request.command == COMMAND_STATUS:
                return self._handle_status()
            if request.command == COMMAND_ROTATE:
                return self._handle_rotate(request.payload)
            if request.command == COMMAND_NODE_GROUP_AUTO_TEST:
                return self._handle_node_group_auto_test(request.payload)
            raise UnknownCommandError(f"unknown command: {request.command}")
        except Exception as exc:
            return Response(ok=False, error=str(exc))

    def _handle_connect(self, payload: dict[str, Any]) -> Response:
        profile_id = _require_string(payload.get("profile_id"), "profile_id")
        profile = self.runtime.profile_store.get(profile_id)
        if profile is None:
            return Response(ok=False, error=f"profile not found: {profile_id}")
        connected = self.runtime.connect(profile)
        state = self.runtime.status()
        state_payload = _state_payload(state)
        self.metrics_recorder.record_connection_result(
            profile_id=profile.id,
            connected=connected,
        )
        self._broadcast_state(state_payload)
        response_payload = {
            "connected": connected,
            "profile_id": profile.id,
            "state": state_payload,
        }
        if not connected:
            error_detail = str(getattr(self.runtime, "last_error", "") or "").strip()
            if error_detail:
                response_payload["error_detail"] = error_detail
        return Response(
            ok=connected,
            payload=response_payload,
            error=None if connected else "connect failed",
        )

    def _handle_disconnect(self) -> Response:
        disconnected = self.runtime.disconnect()
        state = self.runtime.status()
        state_payload = _state_payload(state)
        self.metrics_recorder.record_disconnect_result(disconnected=disconnected)
        self._broadcast_state(state_payload)
        return Response(
            ok=disconnected,
            payload={
                "disconnected": disconnected,
                "state": state_payload,
            },
            error=None if disconnected else "disconnect failed",
        )

    def _handle_status(self) -> Response:
        return Response(ok=True, payload={"state": _state_payload(self.runtime.status())})

    def _handle_rotate(self, payload: dict[str, Any]) -> Response:
        force = payload.get("force", False)
        if not isinstance(force, bool):
            return Response(ok=False, error="force must be a boolean")
        state = self.runtime.rotate_now(force=force)
        state_payload = _state_payload(state)
        self.metrics_recorder.record_manual_rotation(state)
        self.event_bus.broadcast(Event(EVENT_ROTATION, state_payload))
        self._broadcast_state(state_payload)
        return Response(ok=True, payload={"state": state_payload})

    def _handle_node_group_auto_test(self, payload: dict[str, Any]) -> Response:
        group_name = _require_string(payload.get("group_name"), "group_name")
        result = self.runtime.node_group_auto_test(group_name)
        self.metrics_recorder.record_node_group_auto_test(
            group_name=group_name,
            result=str(result.get("result", "unknown")),
        )
        return Response(ok=True, payload=result)

    def _broadcast_state(self, state_payload: dict[str, Any]) -> None:
        self.event_bus.broadcast(Event(EVENT_STATE_CHANGED, state_payload))


def _state_payload(state: ConnectionState) -> dict[str, Any]:
    return state.to_dict()


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()
